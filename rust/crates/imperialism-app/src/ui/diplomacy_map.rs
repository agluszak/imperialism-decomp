//! Recovered `TDiplomacyMapView` nation masks, 540×300 raster, and label layout.
//!
//! Tile fills and hit testing use the 5-pixel diplomacy scale with the odd-row hex
//! offset. Label anchors omit that offset, matching the recovered overlay geometry.

use super::retail_raster::{IndexedRasterExt, indexed_picture};
use super::retail_raster_text::RetailRasterTextPainter;
use bevy::prelude::*;
use imperialism_core::*;
use imperialism_formats::IndexedPicture;

pub const DIPLOMACY_MAP_WIDTH: i32 = 540;
pub const DIPLOMACY_MAP_HEIGHT: i32 = 300;
pub const DIPLOMACY_TILE_SCALE: i32 = 5;
pub const DIPLOMACY_ODD_ROW_OFFSET: i32 = 2;
const EMPTY_HIT: u8 = 0xff;
const OFF_MAP: u8 = 0x10;
const SELECTION_OUTLINE: u8 = 0x13;
const LABEL_HEIGHT: i32 = 12;
const EMPTY_OTHER_WIDTH: i32 = 0x5a;
const LABEL_NUDGE_LIMIT: i32 = 0x14;
const NATION_SLOT_COUNT: usize = NationId::COUNT as usize;

#[derive(Clone, Component, Debug)]
pub struct DiplomacyMapGeometry {
    hit: Vec<u8>,
}

impl Default for DiplomacyMapGeometry {
    fn default() -> Self {
        Self::empty()
    }
}

impl DiplomacyMapGeometry {
    fn empty() -> Self {
        Self {
            hit: vec![EMPTY_HIT; (DIPLOMACY_MAP_WIDTH * DIPLOMACY_MAP_HEIGHT) as usize],
        }
    }

    pub fn nation_at_pixel(&self, x: i32, y: i32) -> Option<NationId> {
        if !(0..DIPLOMACY_MAP_WIDTH).contains(&x) || !(0..DIPLOMACY_MAP_HEIGHT).contains(&y) {
            return None;
        }
        let slot = self.hit[(y * DIPLOMACY_MAP_WIDTH + x) as usize];
        NationId::try_new(slot)
    }

    pub fn nation_at_normalized(&self, normalized: Vec2) -> Option<NationId> {
        let x = ((normalized.x + 0.5) * DIPLOMACY_MAP_WIDTH as f32).floor() as i32;
        let y = ((normalized.y + 0.5) * DIPLOMACY_MAP_HEIGHT as f32).floor() as i32;
        self.nation_at_pixel(x, y)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DiplomacyLabelSeed<'a> {
    pub name: &'a str,
    pub column: u16,
    pub row: u16,
}

pub fn diplomacy_tile_pixel(row: u16, column: u16) -> IVec2 {
    IVec2::new(
        i32::from(column) * DIPLOMACY_TILE_SCALE + i32::from(row & 1) * DIPLOMACY_ODD_ROW_OFFSET,
        i32::from(row) * DIPLOMACY_TILE_SCALE,
    )
}

pub fn diplomacy_label_anchor(row: u16, column: u16) -> IVec2 {
    IVec2::new(
        i32::from(column) * DIPLOMACY_TILE_SCALE,
        i32::from(row) * DIPLOMACY_TILE_SCALE - 6,
    )
}

pub fn compose_diplomacy_map(
    owner_at: impl Fn(TileId) -> Option<NationId>,
    fill: impl Fn(NationId) -> u8,
    selected: Option<NationId>,
) -> (IndexedPicture, DiplomacyMapGeometry) {
    let mut picture = indexed_picture(DIPLOMACY_MAP_WIDTH, DIPLOMACY_MAP_HEIGHT, OFF_MAP);
    let mut geometry = DiplomacyMapGeometry::empty();
    let map_geometry = MapGeometry::new(MapTopology::Bounded);
    for tile in TileId::all() {
        let Some(nation) = owner_at(tile) else {
            continue;
        };
        let (row, column) = map_geometry.row_column(tile);
        let origin = diplomacy_tile_pixel(row, column);
        let color = fill(nation);
        let slot = nation.get();
        for dy in 0..DIPLOMACY_TILE_SCALE {
            for dx in 0..DIPLOMACY_TILE_SCALE {
                let point = origin + IVec2::new(dx, dy);
                picture.put(point, color);
                if (0..DIPLOMACY_MAP_WIDTH).contains(&point.x)
                    && (0..DIPLOMACY_MAP_HEIGHT).contains(&point.y)
                {
                    geometry.hit[(point.y * DIPLOMACY_MAP_WIDTH + point.x) as usize] = slot;
                }
            }
        }
    }
    if let Some(selected) = selected {
        outline_nation(&mut picture, &geometry, selected);
    }
    (picture, geometry)
}

pub fn layout_diplomacy_map_labels(
    seeds: &[Option<DiplomacyLabelSeed<'_>>],
    measure: impl Fn(&str) -> i32,
) -> Vec<(usize, IRect)> {
    let mut widths = [0_i32; NATION_SLOT_COUNT];
    let mut xs = [0_i32; NATION_SLOT_COUNT];
    let mut ys = [0_i32; NATION_SLOT_COUNT];
    let mut placed = Vec::new();
    for (index, seed) in seeds.iter().enumerate().take(NATION_SLOT_COUNT) {
        let Some(seed) = seed else {
            continue;
        };
        if seed.name.is_empty() {
            continue;
        }
        let width = measure(seed.name);
        let anchor = diplomacy_label_anchor(seed.row, seed.column);
        let x = anchor.x - width / 2;
        let y = resolve_label_y(index, x, anchor.y, width, &widths, &xs, &ys);
        widths[index] = width;
        xs[index] = x;
        ys[index] = y;
        let rect = clamp_rect_preserving_size(
            IRect::new(x, y, x + width, y + LABEL_HEIGHT),
            IRect::new(0, 0, DIPLOMACY_MAP_WIDTH, DIPLOMACY_MAP_HEIGHT),
        );
        placed.push((index, rect));
    }
    placed
}

pub fn draw_diplomacy_map_labels(
    picture: &mut IndexedPicture,
    painter: &mut RetailRasterTextPainter<'_>,
    seeds: &[Option<DiplomacyLabelSeed<'_>>],
    labels: &[(usize, IRect)],
) {
    for &(index, rect) in labels {
        let Some(seed) = seeds.get(index).copied().flatten() else {
            continue;
        };
        let origin = IVec2::new(rect.min.x, rect.max.y);
        painter.draw(picture, origin + IVec2::ONE, seed.name, 0xd2);
        painter.draw(picture, origin, seed.name, 0x13);
    }
}

fn outline_nation(
    picture: &mut IndexedPicture,
    geometry: &DiplomacyMapGeometry,
    selected: NationId,
) {
    let slot = selected.get();
    for y in 0..DIPLOMACY_MAP_HEIGHT {
        for x in 0..DIPLOMACY_MAP_WIDTH {
            let index = (y * DIPLOMACY_MAP_WIDTH + x) as usize;
            if geometry.hit[index] != slot {
                continue;
            }
            let edge = [(x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)]
                .into_iter()
                .any(|(nx, ny)| {
                    geometry
                        .nation_at_pixel(nx, ny)
                        .is_none_or(|nation| nation != selected)
                });
            if edge {
                picture.put(IVec2::new(x, y), SELECTION_OUTLINE);
            }
        }
    }
}

fn resolve_label_y(
    _index: usize,
    label_x: i32,
    mut label_y: i32,
    text_width: i32,
    widths: &[i32; NATION_SLOT_COUNT],
    xs: &[i32; NATION_SLOT_COUNT],
    ys: &[i32; NATION_SLOT_COUNT],
) -> i32 {
    let mut attempts = 0;
    let mut placed_index = 0;
    while placed_index < NATION_SLOT_COUNT {
        let mut other_width = widths[placed_index];
        if other_width == 0 {
            other_width = EMPTY_OTHER_WIDTH;
        }
        let other_y = ys[placed_index];
        let other_x = xs[placed_index];
        if label_y >= other_y
            && label_y <= other_y + 10
            && label_x >= other_x
            && label_x <= other_width + other_x
        {
            label_y += 1;
            attempts += 1;
            if attempts < LABEL_NUDGE_LIMIT {
                placed_index = 0;
                continue;
            }
            placed_index += 1;
            continue;
        }
        if label_y >= other_y - 10
            && label_y <= other_y
            && label_x >= other_x - text_width
            && label_x <= other_x
        {
            label_y -= 1;
            attempts += 1;
            if attempts < LABEL_NUDGE_LIMIT {
                placed_index = 0;
                continue;
            }
        }
        placed_index += 1;
    }
    label_y
}

fn clamp_rect_preserving_size(rect: IRect, bounds: IRect) -> IRect {
    let width = rect.width();
    let height = rect.height();
    let mut x = rect.min.x;
    let mut y = rect.min.y;
    if x < bounds.min.x {
        x = bounds.min.x;
    }
    if y < bounds.min.y {
        y = bounds.min.y;
    }
    if x + width > bounds.max.x {
        x = bounds.max.x - width;
    }
    if y + height > bounds.max.y {
        y = bounds.max.y - height;
    }
    IRect::new(x, y, x + width, y + height)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn odd_rows_shift_hit_pixels_but_not_label_anchors() {
        assert_eq!(diplomacy_tile_pixel(0, 2), IVec2::new(10, 0));
        assert_eq!(diplomacy_tile_pixel(1, 2), IVec2::new(12, 5));
        assert_eq!(diplomacy_label_anchor(1, 2), IVec2::new(10, -1));
    }

    #[test]
    fn compose_fills_owned_tiles_and_hit_tests_the_odd_row_offset() {
        let owner = NationId::new(0);
        let (picture, geometry) = compose_diplomacy_map(
            |tile| {
                let (row, column) = MapGeometry::new(MapTopology::Bounded).row_column(tile);
                (row == 1 && column == 2).then_some(owner)
            },
            |_| 0x16,
            None,
        );
        assert_eq!(picture.width, DIPLOMACY_MAP_WIDTH as u32);
        assert_eq!(picture.height, DIPLOMACY_MAP_HEIGHT as u32);
        let origin = diplomacy_tile_pixel(1, 2);
        assert_eq!(
            picture.pixels[(origin.y * DIPLOMACY_MAP_WIDTH + origin.x) as usize],
            0x16
        );
        assert_eq!(geometry.nation_at_pixel(origin.x, origin.y), Some(owner));
        assert_eq!(geometry.nation_at_pixel(10, 5), None);
    }

    #[test]
    fn selected_nation_gets_a_one_pixel_outline() {
        let owner = NationId::new(3);
        let (picture, geometry) = compose_diplomacy_map(
            |tile| {
                let (row, column) = MapGeometry::new(MapTopology::Bounded).row_column(tile);
                (row == 4 && column == 4).then_some(owner)
            },
            |_| 0x24,
            Some(owner),
        );
        let origin = diplomacy_tile_pixel(4, 4);
        assert_eq!(geometry.nation_at_pixel(origin.x, origin.y), Some(owner));
        assert_eq!(
            picture.pixels[(origin.y * DIPLOMACY_MAP_WIDTH + origin.x) as usize],
            SELECTION_OUTLINE
        );
        let interior = origin + IVec2::new(2, 2);
        assert_eq!(
            picture.pixels[(interior.y * DIPLOMACY_MAP_WIDTH + interior.x) as usize],
            0x24
        );
    }

    #[test]
    fn overlapping_labels_slide_until_they_clear() {
        let seeds = {
            let mut seeds = [None; NATION_SLOT_COUNT];
            seeds[0] = Some(DiplomacyLabelSeed {
                name: "France",
                column: 10,
                row: 10,
            });
            seeds[1] = Some(DiplomacyLabelSeed {
                name: "Spain",
                column: 10,
                row: 10,
            });
            seeds
        };
        let labels = layout_diplomacy_map_labels(&seeds, |name| name.len() as i32);
        assert_eq!(labels.len(), 2);
        assert_ne!(labels[0].1.min.y, labels[1].1.min.y);
    }
}
