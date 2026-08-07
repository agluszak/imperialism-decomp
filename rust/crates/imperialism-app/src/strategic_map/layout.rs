use bevy::prelude::*;
use imperialism_core::{STRATEGIC_MAP_HEIGHT, STRATEGIC_MAP_WIDTH, STRATEGIC_TILE_COUNT, TileId};
use imperialism_formats::StrategicMapAssetManifest;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StrategicMapLayout {
    pub(crate) tile_width: f32,
    pub(crate) tile_height: f32,
    row_stride: f32,
    odd_row_offset: f32,
    pixel_width: u32,
    pixel_height: u32,
}

impl StrategicMapLayout {
    pub fn new(manifest: &StrategicMapAssetManifest) -> Self {
        let [tile_width, tile_height] = manifest.tile_size;
        let pixel_width = u32::from(STRATEGIC_MAP_WIDTH) * tile_width + manifest.odd_row_offset;
        let pixel_height =
            (u32::from(STRATEGIC_MAP_HEIGHT) - 1) * manifest.row_stride + tile_height;
        Self {
            tile_width: tile_width as f32,
            tile_height: tile_height as f32,
            row_stride: manifest.row_stride as f32,
            odd_row_offset: manifest.odd_row_offset as f32,
            pixel_width,
            pixel_height,
        }
    }

    pub const fn pixel_size(self) -> [u32; 2] {
        [self.pixel_width, self.pixel_height]
    }

    pub fn tile_center(self, tile: TileId) -> Option<Vec2> {
        if usize::from(tile.get()) >= STRATEGIC_TILE_COUNT {
            return None;
        }
        Some(self.pixel_to_world(self.tile_center_pixel(tile)))
    }

    pub fn hit_test(self, logical_position: Vec2) -> Option<TileId> {
        let pixel = self.world_to_pixel(logical_position);
        let mut best = None;
        let mut best_distance = f32::INFINITY;
        for index in 0..STRATEGIC_TILE_COUNT {
            let tile = TileId::new(index as u16);
            let center = self.tile_center_pixel(tile);
            if !self.contains_pixel(center, pixel) {
                continue;
            }
            let distance = center.distance_squared(pixel);
            if distance < best_distance {
                best = Some(tile);
                best_distance = distance;
            }
        }
        best
    }

    pub(crate) fn tile_center_pixel(self, tile: TileId) -> Vec2 {
        let row = tile.get() / STRATEGIC_MAP_WIDTH;
        let column = tile.get() % STRATEGIC_MAP_WIDTH;
        Vec2::new(
            f32::from(column) * self.tile_width
                + if row & 1 != 0 {
                    self.odd_row_offset
                } else {
                    0.0
                }
                + self.tile_width * 0.5,
            f32::from(row) * self.row_stride + self.tile_height * 0.5,
        )
    }

    pub(crate) fn contains_pixel(self, center: Vec2, point: Vec2) -> bool {
        let delta = (point - center).abs();
        let half_width = self.tile_width * 0.5;
        let half_height = self.tile_height * 0.5;
        if delta.y > half_height {
            return false;
        }
        let quarter_height = self.tile_height * 0.25;
        let allowed_x = if delta.y <= quarter_height {
            half_width
        } else {
            half_width - (delta.y - quarter_height) * (half_width * 0.5 / quarter_height)
        };
        delta.x <= allowed_x
    }

    fn world_to_pixel(self, point: Vec2) -> Vec2 {
        Vec2::new(
            point.x + self.pixel_width as f32 * 0.5,
            self.pixel_height as f32 * 0.5 - point.y,
        )
    }

    fn pixel_to_world(self, point: Vec2) -> Vec2 {
        Vec2::new(
            point.x - self.pixel_width as f32 * 0.5,
            self.pixel_height as f32 * 0.5 - point.y,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_formats::Rgba8;

    fn map_manifest() -> StrategicMapAssetManifest {
        StrategicMapAssetManifest {
            tile_size: [8, 8],
            row_stride: 6,
            odd_row_offset: 4,
            terrain_palette: vec![Rgba8([0, 0, 0, 255]); 8],
            nation_palette: vec![Rgba8([0, 0, 0, 255]); 23],
            city_marker: Rgba8([0, 0, 0, 255]),
            army_marker: Rgba8([0, 0, 0, 255]),
            navy_marker: Rgba8([0, 0, 0, 255]),
            selection_marker: Rgba8([0, 0, 0, 255]),
        }
    }

    #[test]
    fn maps_retail_hex_centers_back_to_typed_tiles() {
        let layout = StrategicMapLayout::new(&map_manifest());
        for tile in [TileId::new(0), TileId::new(108), TileId::new(6479)] {
            let center = layout.tile_center(tile).unwrap();
            assert_eq!(layout.hit_test(center), Some(tile));
        }
    }

    #[test]
    fn rejects_points_outside_the_rendered_map() {
        let layout = StrategicMapLayout::new(&map_manifest());
        assert_eq!(layout.pixel_size(), [868, 362]);
        assert_eq!(layout.hit_test(Vec2::new(-500.0, 0.0)), None);
        assert_eq!(layout.hit_test(Vec2::new(0.0, 300.0)), None);
    }
}
