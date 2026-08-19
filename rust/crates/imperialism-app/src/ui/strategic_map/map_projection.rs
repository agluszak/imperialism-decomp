use super::map_interaction::OceanViewport;
use super::{TILE_SIZE, VIEWPORT_HEIGHT, VIEWPORT_WIDTH};
use bevy::prelude::*;
use imperialism_core::*;

pub(super) const OCEAN_CELL_SIZE: i32 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProjectedTile {
    pub(super) tile: TileId,
    pub(super) origin: IVec2,
}

pub(super) struct DetailedMapProjection {
    geometry: MapGeometry,
    origin_row: i32,
    origin_column: i32,
}

impl DetailedMapProjection {
    pub(super) fn new(geometry: MapGeometry, view_origin: TileId) -> Self {
        let (row, column) = geometry.row_column(view_origin);
        Self {
            geometry,
            origin_row: i32::from(row),
            origin_column: i32::from(column),
        }
    }

    pub(super) fn visible_tiles(&self) -> impl Iterator<Item = ProjectedTile> + '_ {
        (0..=7).flat_map(move |row_delta| {
            (-1..=8).filter_map(move |column_delta| self.cell(row_delta, column_delta))
        })
    }

    pub(super) fn tile_origin(&self, tile: TileId) -> Option<IVec2> {
        let (row, column) = self.geometry.row_column(tile);
        let row_delta = i32::from(row) - self.origin_row;
        let column_delta = i32::from(column) - self.origin_column;
        let width = i32::from(STRATEGIC_MAP_WIDTH);
        [column_delta, column_delta - width, column_delta + width]
            .into_iter()
            .find_map(|column_delta| {
                self.cell(row_delta, column_delta)
                    .filter(|projected| projected.tile == tile)
                    .map(|projected| projected.origin)
            })
    }

    pub(super) fn tile_at(&self, point: IVec2) -> Option<TileId> {
        if !(0..VIEWPORT_WIDTH as i32).contains(&point.x)
            || !(0..VIEWPORT_HEIGHT as i32).contains(&point.y)
        {
            return None;
        }
        let row_delta = point.y / TILE_SIZE;
        let row = self.origin_row + row_delta;
        let stagger = if row & 1 != 0 { TILE_SIZE / 2 } else { 0 };
        let column_delta = (point.x - stagger).div_euclid(TILE_SIZE);
        self.cell(row_delta, column_delta)
            .map(|projected| projected.tile)
    }

    fn cell(&self, row_delta: i32, column_delta: i32) -> Option<ProjectedTile> {
        if !(0..=7).contains(&row_delta) || !(-1..=8).contains(&column_delta) {
            return None;
        }
        let row = self.origin_row + row_delta;
        if !(0..i32::from(STRATEGIC_MAP_HEIGHT)).contains(&row) {
            return None;
        }
        let origin = IVec2::new(
            column_delta * TILE_SIZE + if row & 1 != 0 { TILE_SIZE / 2 } else { 0 },
            row_delta * TILE_SIZE,
        );
        if origin.x >= VIEWPORT_WIDTH as i32 || origin.x + TILE_SIZE <= 0 {
            return None;
        }
        let column = (self.origin_column + column_delta).rem_euclid(i32::from(STRATEGIC_MAP_WIDTH));
        self.geometry
            .tile(row as u16, column as u16)
            .map(|tile| ProjectedTile { tile, origin })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OceanCell {
    Tile(ProjectedTile),
    BoundedBlank { origin: IVec2 },
}

pub(super) struct OceanProjection {
    geometry: MapGeometry,
    origin: IVec2,
    blank_wrapped_left: bool,
    blank_wrapped_right: bool,
}

impl OceanProjection {
    pub(super) fn new(geometry: MapGeometry, viewport: &OceanViewport) -> Self {
        let bounded = !geometry.wraps_horizontally();
        Self {
            geometry,
            origin: viewport.origin,
            blank_wrapped_left: bounded && (viewport.origin.x < 2 || viewport.origin.x > 100),
            blank_wrapped_right: bounded && viewport.origin.x <= 100 && viewport.origin.x > 70,
        }
    }

    pub(super) fn visible_cells(&self) -> Vec<OceanCell> {
        let mut cells = Vec::with_capacity(28 * 33);
        for row_delta in 0..28 {
            for column_delta in 0..=32 {
                if let Some(cell) = self.cell(row_delta, column_delta) {
                    cells.push(cell);
                }
            }
        }
        cells
    }

    pub(super) fn tile_origin(&self, tile: TileId) -> Option<IVec2> {
        let (row, column) = self.geometry.row_column(tile);
        let row_delta = i32::from(row) - self.origin.y;
        let column_delta = i32::from(column) - self.origin.x;
        let width = i32::from(STRATEGIC_MAP_WIDTH);
        [column_delta, column_delta - width, column_delta + width]
            .into_iter()
            .find_map(|column_delta| match self.cell(row_delta, column_delta) {
                Some(OceanCell::Tile(projected)) if projected.tile == tile => {
                    Some(projected.origin)
                }
                Some(OceanCell::Tile(_)) | Some(OceanCell::BoundedBlank { .. }) | None => None,
            })
    }

    pub(super) fn tile_at(&self, point: IVec2) -> Option<TileId> {
        if !(0..VIEWPORT_WIDTH as i32).contains(&point.x)
            || !(0..VIEWPORT_HEIGHT as i32).contains(&point.y)
        {
            return None;
        }
        let row_delta = point.y / OCEAN_CELL_SIZE;
        let row = self.origin.y + row_delta;
        let adjusted_x = point.x + if row & 1 == 0 { OCEAN_CELL_SIZE / 2 } else { 0 };
        let column_delta = adjusted_x / OCEAN_CELL_SIZE;
        match self.cell(row_delta, column_delta) {
            Some(OceanCell::Tile(projected)) => Some(projected.tile),
            Some(OceanCell::BoundedBlank { .. }) | None => None,
        }
    }

    pub(super) fn tile_center(&self, tile: TileId) -> Option<Vec2> {
        self.tile_origin(tile)
            .map(|origin| (origin + IVec2::splat(OCEAN_CELL_SIZE / 2)).as_vec2())
    }

    pub(super) fn route_segment(
        &self,
        start_column_x2: i32,
        start_row: i32,
        end_column_x2: i32,
        end_row: i32,
    ) -> (IVec2, IVec2) {
        let viewport_column_x2 = self.origin.x * 2 + 1;
        let mut start_x = (start_column_x2 - viewport_column_x2 + 216).rem_euclid(216);
        let mut end_x = (end_column_x2 - viewport_column_x2 + 216).rem_euclid(216);
        if (start_x - end_x).abs() > 108 {
            if start_x > 108 {
                start_x -= 216;
            } else if end_x > 108 {
                end_x -= 216;
            }
        }
        (
            IVec2::new(start_x * 8, (start_row - self.origin.y) * OCEAN_CELL_SIZE),
            IVec2::new(end_x * 8, (end_row - self.origin.y) * OCEAN_CELL_SIZE),
        )
    }

    fn cell(&self, row_delta: i32, column_delta: i32) -> Option<OceanCell> {
        if !(0..28).contains(&row_delta) || !(0..=32).contains(&column_delta) {
            return None;
        }
        let row = self.origin.y + row_delta;
        if !(0..i32::from(STRATEGIC_MAP_HEIGHT)).contains(&row) {
            return None;
        }
        let origin = IVec2::new(
            column_delta * OCEAN_CELL_SIZE - if row & 1 == 0 { OCEAN_CELL_SIZE / 2 } else { 0 },
            row_delta * OCEAN_CELL_SIZE,
        );
        let unwrapped_column = self.origin.x + column_delta;
        let column = if unwrapped_column >= i32::from(STRATEGIC_MAP_WIDTH) {
            if self.blank_wrapped_right {
                return Some(OceanCell::BoundedBlank { origin });
            }
            unwrapped_column - i32::from(STRATEGIC_MAP_WIDTH)
        } else if self.blank_wrapped_left && unwrapped_column > 60 {
            return Some(OceanCell::BoundedBlank { origin });
        } else {
            unwrapped_column
        };
        self.geometry
            .tile(row as u16, column as u16)
            .map(|tile| OceanCell::Tile(ProjectedTile { tile, origin }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn viewport_contains(point: IVec2) -> bool {
        (0..VIEWPORT_WIDTH as i32).contains(&point.x)
            && (0..VIEWPORT_HEIGHT as i32).contains(&point.y)
    }

    #[test]
    fn detailed_projection_round_trips_visible_tiles_at_both_wrap_edges() {
        for topology in [MapTopology::Bounded, MapTopology::Wrapping] {
            let geometry = MapGeometry::new(topology);
            for origin in [geometry.tile(1, 0).unwrap(), geometry.tile(2, 107).unwrap()] {
                let projection = DetailedMapProjection::new(geometry, origin);
                for projected in projection.visible_tiles() {
                    assert_eq!(
                        projection.tile_origin(projected.tile),
                        Some(projected.origin)
                    );
                    let center = projected.origin + IVec2::splat(TILE_SIZE / 2);
                    if viewport_contains(center) {
                        assert_eq!(projection.tile_at(center), Some(projected.tile));
                    }
                }
            }
        }
    }

    #[test]
    fn ocean_projection_round_trips_tiles_and_rejects_bounded_blanks() {
        for topology in [MapTopology::Bounded, MapTopology::Wrapping] {
            let geometry = MapGeometry::new(topology);
            for origin in [IVec2::new(0, 1), IVec2::new(76, 2)] {
                let projection = OceanProjection::new(geometry, &OceanViewport { origin });
                for cell in projection.visible_cells() {
                    match cell {
                        OceanCell::Tile(projected) => {
                            assert_eq!(
                                projection.tile_origin(projected.tile),
                                Some(projected.origin)
                            );
                            let center = projected.origin + IVec2::splat(OCEAN_CELL_SIZE / 2);
                            if viewport_contains(center) {
                                assert_eq!(projection.tile_at(center), Some(projected.tile));
                            }
                        }
                        OceanCell::BoundedBlank { origin } => {
                            let center = origin + IVec2::splat(OCEAN_CELL_SIZE / 2);
                            if viewport_contains(center) {
                                assert_eq!(projection.tile_at(center), None);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn route_projection_keeps_the_short_wrapped_segment() {
        let geometry = MapGeometry::new(MapTopology::Wrapping);
        let projection = OceanProjection::new(
            geometry,
            &OceanViewport {
                origin: IVec2::ZERO,
            },
        );

        assert_eq!(
            projection.route_segment(215, 3, 1, 4),
            (IVec2::new(-16, 48), IVec2::new(0, 64))
        );
    }
}
