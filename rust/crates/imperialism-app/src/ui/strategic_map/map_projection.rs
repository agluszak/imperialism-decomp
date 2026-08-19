use super::map_interaction::OceanViewport;
use super::{TILE_SIZE, VIEWPORT_HEIGHT, VIEWPORT_WIDTH};
use bevy::prelude::*;
use imperialism_core::*;

const OCEAN_TILE: i32 = 16;

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

    pub(super) fn visible_tiles(&self) -> Vec<ProjectedTile> {
        let mut tiles = Vec::with_capacity(80);
        for row_delta in 0..=7 {
            for column_delta in -1..=8 {
                if let Some(tile) = self.cell(row_delta, column_delta) {
                    tiles.push(tile);
                }
            }
        }
        tiles
    }

    pub(super) fn tile_origin(&self, tile: TileId) -> Option<IVec2> {
        self.visible_tiles()
            .into_iter()
            .find(|projected| projected.tile == tile)
            .map(|projected| projected.origin)
    }

    pub(super) fn tile_at(&self, point: IVec2) -> Option<TileId> {
        if !(0..VIEWPORT_WIDTH as i32).contains(&point.x)
            || !(0..VIEWPORT_HEIGHT as i32).contains(&point.y)
        {
            return None;
        }
        self.visible_tiles()
            .into_iter()
            .find(|projected| {
                IRect::from_corners(projected.origin, projected.origin + IVec2::splat(TILE_SIZE))
                    .contains(point)
            })
            .map(|projected| projected.tile)
    }

    fn cell(&self, row_delta: i32, column_delta: i32) -> Option<ProjectedTile> {
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
        self.visible_cells()
            .into_iter()
            .find_map(|cell| match cell {
                OceanCell::Tile(projected) if projected.tile == tile => Some(projected.origin),
                OceanCell::Tile(_) | OceanCell::BoundedBlank { .. } => None,
            })
    }

    pub(super) fn tile_at(&self, point: IVec2) -> Option<TileId> {
        if !(0..VIEWPORT_WIDTH as i32).contains(&point.x)
            || !(0..VIEWPORT_HEIGHT as i32).contains(&point.y)
        {
            return None;
        }
        self.visible_cells()
            .into_iter()
            .find_map(|cell| match cell {
                OceanCell::Tile(projected)
                    if IRect::from_corners(
                        projected.origin,
                        projected.origin + IVec2::splat(OCEAN_TILE),
                    )
                    .contains(point) =>
                {
                    Some(projected.tile)
                }
                OceanCell::Tile(_) | OceanCell::BoundedBlank { .. } => None,
            })
    }

    pub(super) fn tile_center(&self, tile: TileId) -> Option<Vec2> {
        self.tile_origin(tile)
            .map(|origin| (origin + IVec2::splat(OCEAN_TILE / 2)).as_vec2())
    }

    fn cell(&self, row_delta: i32, column_delta: i32) -> Option<OceanCell> {
        let row = self.origin.y + row_delta;
        if !(0..i32::from(STRATEGIC_MAP_HEIGHT)).contains(&row) {
            return None;
        }
        let origin = IVec2::new(
            column_delta * OCEAN_TILE - if row & 1 == 0 { OCEAN_TILE / 2 } else { 0 },
            row_delta * OCEAN_TILE,
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
