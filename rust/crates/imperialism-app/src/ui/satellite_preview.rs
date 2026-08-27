//! Retail `TMapPreviewView` owner/satellite-map composition.

use bevy::prelude::*;
use imperialism_core::*;
use imperialism_formats::{DibPalette, IndexedPicture};

use super::retail_palette::{major_nation_palette, view_mgr_color};
use super::retail_raster::{IndexedRasterExt, indexed_picture};

pub(crate) const OWNER_MAP_WIDTH: usize = 324;
pub(crate) const OWNER_MAP_HEIGHT: usize = 180;
const OFF_MAP_PALETTE: u8 = 0x10;
const SELECTED_EDGE_PALETTE: u8 = 0x13;

pub(crate) struct SatellitePreview {
    picture: IndexedPicture,
}

impl Default for SatellitePreview {
    fn default() -> Self {
        Self {
            picture: indexed_picture(
                OWNER_MAP_WIDTH as i32,
                OWNER_MAP_HEIGHT as i32,
                OFF_MAP_PALETTE,
            ),
        }
    }
}

impl SatellitePreview {
    pub(crate) fn compose(owner_at: impl Fn(TileId) -> Option<TileOwnerTag>) -> Self {
        Self::compose_with_fill(owner_at, nation_owner_palette)
    }

    fn compose_with_fill(
        owner_at: impl Fn(TileId) -> Option<TileOwnerTag>,
        fill: impl Fn(NationId) -> u8,
    ) -> Self {
        let mut map = Self::default();
        // TMapPreviewView always requests bounded neighbors, even if the
        // selected setup topology wraps horizontally.
        let geometry = MapGeometry::new(MapTopology::Bounded);
        for tile in TileId::all() {
            let (row, column) = geometry.row_column(tile);
            let odd_row = row & 1 != 0;
            let pixel_x = 3 * usize::from(column) + usize::from(odd_row);
            let pixel_y = 3 * usize::from(row);
            let neighbors = geometry
                .neighbors(tile)
                .map(|neighbor| owner_tag(&owner_at, neighbor));
            let owner = owner_tag(&owner_at, Some(tile));
            let upper_left = if owner == neighbors[5] {
                owner
            } else if (odd_row && neighbors[5] == neighbors[4])
                || (!odd_row && neighbors[5] == neighbors[0] && neighbors[4] == neighbors[0])
            {
                neighbors[5]
            } else {
                PreviewOwner::Border
            };
            let upper_middle = if odd_row {
                if owner == neighbors[5] {
                    owner
                } else {
                    PreviewOwner::Border
                }
            } else if owner == neighbors[0] || owner == neighbors[5] {
                owner
            } else {
                PreviewOwner::Border
            };
            let upper_right = if odd_row {
                if owner == neighbors[0] || (owner == neighbors[1] && owner == neighbors[5]) {
                    owner
                } else {
                    PreviewOwner::Border
                }
            } else if owner == neighbors[0] {
                owner
            } else {
                PreviewOwner::Border
            };
            let left = if owner == neighbors[4] {
                owner
            } else {
                PreviewOwner::Border
            };
            let microtile = [
                [upper_left, upper_middle, upper_right],
                [left, owner, owner],
                [left, owner, owner],
            ];
            for (local_y, row) in microtile.into_iter().enumerate() {
                for (local_x, owner) in row.into_iter().enumerate() {
                    map.write_pixel(pixel_y + local_y, pixel_x + local_x, owner, &fill);
                }
            }
        }
        map
    }

    pub(crate) fn major_nation_at(&self, normalized_position: Vec2) -> Option<MajorNationId> {
        let column = ((normalized_position.x + 0.5) * OWNER_MAP_WIDTH as f32).floor();
        let row = ((normalized_position.y + 0.5) * OWNER_MAP_HEIGHT as f32).floor();
        if !(0.0..OWNER_MAP_WIDTH as f32).contains(&column)
            || !(0.0..OWNER_MAP_HEIGHT as f32).contains(&row)
        {
            return None;
        }
        let pixel = self.picture.pixels[row as usize * OWNER_MAP_WIDTH + column as usize];
        MajorNationId::all().find(|&nation| major_nation_palette(nation) == pixel)
    }

    pub(crate) fn to_image(&self, palette: &DibPalette) -> Image {
        self.picture.to_keyed_image(palette, OFF_MAP_PALETTE)
    }

    fn write_pixel(
        &mut self,
        row: usize,
        column: usize,
        owner: PreviewOwner,
        fill: &impl Fn(NationId) -> u8,
    ) {
        // The native 324-byte row stride lets the final odd-row hex write
        // x=324, which becomes x=0 on the next visible row. Keep that linear
        // behavior; only the write past the final row is not visible here.
        let index = row * OWNER_MAP_WIDTH + column;
        if let Some(pixel) = self.picture.pixels.get_mut(index) {
            *pixel = preview_palette(owner, fill);
        }
    }

    pub(crate) fn enhance(&mut self, selected_nation: NationId) {
        let selected_palette = view_mgr_color(i16::from(selected_nation.get()));
        for row in 1..OWNER_MAP_HEIGHT - 1 {
            for column in 1..OWNER_MAP_WIDTH - 1 {
                let index = row * OWNER_MAP_WIDTH + column;
                if !is_selection_maskable(self.picture.pixels[index]) {
                    continue;
                }
                self.picture.pixels[index] = if self.picture.pixels[index - 1] == selected_palette
                    || self.picture.pixels[index + 1] == selected_palette
                    || self.picture.pixels[index - OWNER_MAP_WIDTH] == selected_palette
                    || self.picture.pixels[index + OWNER_MAP_WIDTH] == selected_palette
                {
                    SELECTED_EDGE_PALETTE
                } else {
                    0
                };
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreviewOwner {
    Border,
    Unowned,
    Tagged(TileOwnerTag),
}

fn owner_tag(
    owner_at: &impl Fn(TileId) -> Option<TileOwnerTag>,
    tile: Option<TileId>,
) -> PreviewOwner {
    match tile {
        // TakeSatellitePhoto changes every owner tag outside the 23 nations
        // to -1 before comparing neighbors. Sea zones remain one ocean.
        Some(tile) => owner_at(tile)
            .filter(|owner| owner.nation().is_some())
            .map_or(PreviewOwner::Unowned, PreviewOwner::Tagged),
        None => PreviewOwner::Unowned,
    }
}

fn preview_palette(owner: PreviewOwner, fill: &impl Fn(NationId) -> u8) -> u8 {
    match owner {
        PreviewOwner::Border => 0,
        PreviewOwner::Unowned => OFF_MAP_PALETTE,
        PreviewOwner::Tagged(tag) => tag.nation().map_or(OFF_MAP_PALETTE, fill),
    }
}

pub(crate) fn nation_owner_palette(nation: NationId) -> u8 {
    MajorNationId::from_nation(nation)
        .map(major_nation_palette)
        .unwrap_or_else(|| view_mgr_color(0x0b))
}

fn is_selection_maskable(palette: u8) -> bool {
    palette == SELECTED_EDGE_PALETTE || matches!(palette, 0 | 2 | 0x0f | 6 | 0x20 | 5 | 0xca)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiles(owner: Option<TileOwnerTag>) -> Vec<GeneratedTerrainTile> {
        vec![
            GeneratedTerrainTile {
                terrain: TerrainKind::Plains,
                river: None,
                owner,
                gate: None,
                province: None,
            };
            STRATEGIC_TILE_COUNT
        ]
    }

    #[test]
    fn distinct_sea_zones_render_as_one_unbordered_ocean() {
        let mut tiles = tiles(Some(TileOwnerTag::new(NationId::COUNT)));
        tiles[usize::from(TileId::new(1000).get())].owner =
            Some(TileOwnerTag::new(NationId::COUNT + 1));

        let map = SatellitePreview::compose(|tile| tiles[usize::from(tile.get())].owner);

        assert!(
            map.picture
                .pixels
                .iter()
                .all(|&pixel| pixel == OFF_MAP_PALETTE)
        );
    }

    #[test]
    fn selection_enhancement_uses_the_retail_white_palette_index() {
        let mut map = SatellitePreview::default();
        let index = 90 * OWNER_MAP_WIDTH + 90;
        map.picture.pixels[index] = 0;
        map.picture.pixels[index + 1] = nation_owner_palette(MajorNationId::new(4).nation());

        map.enhance(MajorNationId::new(4).nation());

        assert_eq!(map.picture.pixels[index], SELECTED_EDGE_PALETTE);
    }

    #[test]
    fn retains_the_native_odd_row_stride_spill() {
        let mut tiles = tiles(None);
        tiles[STRATEGIC_MAP_WIDTH as usize + 107].owner = Some(TileOwnerTag::new(0));

        let map = SatellitePreview::compose(|tile| tiles[usize::from(tile.get())].owner);

        assert_eq!(map.picture.pixels[5 * OWNER_MAP_WIDTH], 0x16);
    }

    #[test]
    fn hit_testing_samples_the_retail_major_nation_palette() {
        let nation = MajorNationId::new(4);
        let map = SatellitePreview::compose(|_| Some(TileOwnerTag::from_nation(nation.nation())));

        assert_eq!(map.major_nation_at(Vec2::ZERO), Some(nation));
        assert_eq!(map.major_nation_at(Vec2::new(0.5, 0.0)), None);
    }
}
