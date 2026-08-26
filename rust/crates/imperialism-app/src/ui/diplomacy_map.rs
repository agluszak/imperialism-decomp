//! Recovered `TDiplomacyMapView` nation masks, 540×300 raster, and label layout.
//!
//! Tile fills and hit testing use the 5-pixel diplomacy scale with the odd-row hex
//! offset. Label anchors omit that offset, matching the recovered overlay geometry.
//! Nation names are ordinary Bevy text children positioned by the recovered
//! collision-layout algorithm once Bevy has measured each label.

use super::retail::RetailUiAssets;
use super::retail_raster::{IndexedRasterExt, indexed_picture};
use bevy::prelude::*;
use imperialism_core::*;
use imperialism_formats::{IndexedPicture, RetailTextStylePreset};

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

pub fn diplomacy_tile_pixel(row: u16, column: u16) -> IVec2 {
    IVec2::new(
        i32::from(column) * DIPLOMACY_TILE_SCALE + i32::from(row & 1) * DIPLOMACY_ODD_ROW_OFFSET,
        i32::from(row) * DIPLOMACY_TILE_SCALE,
    )
}

fn diplomacy_label_anchor(row: u16, column: u16) -> IVec2 {
    IVec2::new(
        i32::from(column) * DIPLOMACY_TILE_SCALE,
        i32::from(row) * DIPLOMACY_TILE_SCALE - 6,
    )
}

/// A nation-name label placed on the diplomacy map by the recovered collision
/// layout. `rect` is the label's absolute position/size in map pixels.
#[derive(Clone, Copy, Debug)]
pub struct PlacedDiplomacyLabel {
    pub nation: NationId,
    pub rect: IRect,
}

/// Recovered `TDiplomacyMapView::DrawNames` collision layout. Keeps the retail
/// 23-entry width/x/y tables internally (indexed by `NationId`) and returns each
/// country's placement; callers hand in semantic identities, never row/column
/// DTOs.
pub fn layout_diplomacy_labels<'a>(
    labels: impl IntoIterator<Item = (NationId, &'a str, TileId)>,
    geometry: MapGeometry,
    widths: &NationTable<i32>,
) -> Vec<PlacedDiplomacyLabel> {
    let mut xs = NationTable::default();
    let mut ys = NationTable::default();
    let mut placed = Vec::new();
    for (nation, name, tile) in labels {
        if name.is_empty() {
            continue;
        }
        let (row, column) = geometry.row_column(tile);
        let width = widths[nation];
        let anchor = diplomacy_label_anchor(row, column);
        let x = anchor.x - width / 2;
        let y = resolve_label_y(x, anchor.y, width, widths, &xs, &ys);
        xs[nation] = x;
        ys[nation] = y;
        let rect = clamp_rect_preserving_size(
            IRect::new(x, y, x + width, y + LABEL_HEIGHT),
            IRect::new(0, 0, DIPLOMACY_MAP_WIDTH, DIPLOMACY_MAP_HEIGHT),
        );
        placed.push(PlacedDiplomacyLabel { nation, rect });
    }
    placed
}

/// A nation-name label spawned as a Bevy `Text` child of the map. Bevy measures
/// its laid-out width, then `layout_diplomacy_nation_label_entities` applies the
/// recovered collision layout.
#[derive(Component, Clone)]
pub struct DiplomacyNationLabel {
    nation: NationId,
    name: String,
    anchor: TileId,
    measured: Option<i32>,
}

/// Spawn one Book Antiqua-10 `Text` child per country at its overlay anchor.
/// The map node must be `DIPLOMACY_MAP_WIDTH`×`DIPLOMACY_MAP_HEIGHT`.
pub fn spawn_diplomacy_nation_labels(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    map: Entity,
    labels: impl IntoIterator<Item = (NationId, String, TileId)>,
) {
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset::built(10, 1))
        .expect("retail diplomacy map label style");
    let geometry = MapGeometry::new(MapTopology::Bounded);
    for (nation, name, tile) in labels {
        if name.is_empty() {
            continue;
        }
        let (row, column) = geometry.row_column(tile);
        let anchor = diplomacy_label_anchor(row, column);
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(anchor.x),
                top: px(anchor.y),
                ..default()
            },
            Text::new(name.clone()),
            font.clone(),
            layout,
            line_height,
            TextColor(assets.palette_color(0x13)),
            TextShadow {
                offset: Vec2::ONE,
                color: assets.palette_color(0xd2),
            },
            Pickable::IGNORE,
            DiplomacyNationLabel {
                nation,
                name,
                anchor: tile,
                measured: None,
            },
            ChildOf(map),
        ));
    }
}

/// Measures every diplomacy-map label through Bevy's text layout and, once all
/// widths are known, applies the recovered collision-layout positions.
pub fn layout_diplomacy_nation_label_entities(
    mut labels: Query<(Entity, &mut DiplomacyNationLabel, &ComputedNode)>,
    mut nodes: Query<&mut Node>,
) {
    let mut all_measured = true;
    for (_, mut label, computed) in &mut labels {
        if label.measured.is_none() {
            let width = computed.size.x.round() as i32;
            if width <= 0 {
                all_measured = false;
            } else {
                label.measured = Some(width);
            }
        }
    }
    if !all_measured {
        return;
    }
    let geometry = MapGeometry::new(MapTopology::Bounded);
    let mut widths = NationTable::default();
    let mut placed: Vec<(Entity, NationId, String, TileId)> = Vec::new();
    for (entity, label, _) in &mut labels {
        let Some(width) = label.measured else {
            continue;
        };
        widths[label.nation] = width;
        placed.push((entity, label.nation, label.name.clone(), label.anchor));
    }
    let items = placed
        .iter()
        .map(|&(_, nation, ref name, tile)| (nation, name.as_str(), tile))
        .collect::<Vec<_>>();
    for placed_label in layout_diplomacy_labels(items, geometry, &widths) {
        let Some((entity, _, _, _)) = placed
            .iter()
            .find(|(_, nation, _, _)| *nation == placed_label.nation)
        else {
            continue;
        };
        if let Ok(mut node) = nodes.get_mut(*entity) {
            let rect = placed_label.rect;
            node.left = px(rect.min.x);
            node.top = px(rect.min.y);
            node.width = px(rect.width());
            node.height = px(rect.height());
        }
    }
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
    label_x: i32,
    mut label_y: i32,
    text_width: i32,
    widths: &NationTable<i32>,
    xs: &NationTable<i32>,
    ys: &NationTable<i32>,
) -> i32 {
    let mut attempts = 0;
    let mut placed_slot = 0_u8;
    while usize::from(placed_slot) < NATION_SLOT_COUNT {
        let mut other_width = widths[NationId::new(placed_slot)];
        if other_width == 0 {
            other_width = EMPTY_OTHER_WIDTH;
        }
        let other_y = ys[NationId::new(placed_slot)];
        let other_x = xs[NationId::new(placed_slot)];
        if label_y >= other_y
            && label_y <= other_y + 10
            && label_x >= other_x
            && label_x <= other_width + other_x
        {
            label_y += 1;
            attempts += 1;
            if attempts < LABEL_NUDGE_LIMIT {
                placed_slot = 0;
                continue;
            }
            placed_slot += 1;
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
                placed_slot = 0;
                continue;
            }
        }
        placed_slot += 1;
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
        let geometry = MapGeometry::new(MapTopology::Bounded);
        let nation = NationId::new(0);
        let other = NationId::new(1);
        let tile = geometry.tile(10, 10).expect("test tile in bounds");
        let labels = [(nation, "France", tile), (other, "Spain", tile)];
        let mut widths = NationTable::default();
        widths[nation] = 6;
        widths[other] = 5;
        let placed = layout_diplomacy_labels(labels, geometry, &widths);
        assert_eq!(placed.len(), 2);
        assert_ne!(placed[0].rect.min.y, placed[1].rect.min.y);
        assert_eq!(placed[0].nation, nation);
        assert_eq!(placed[1].nation, other);
    }
}
