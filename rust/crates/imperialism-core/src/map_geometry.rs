use crate::TileId;
use serde::{Deserialize, Serialize};

pub const STRATEGIC_MAP_WIDTH: u16 = 108;
pub const STRATEGIC_MAP_HEIGHT: u16 = 60;
pub const STRATEGIC_TILE_COUNT: usize =
    STRATEGIC_MAP_WIDTH as usize * STRATEGIC_MAP_HEIGHT as usize;

/// The byte stored by the retail map model for its horizontal-edge behavior.
///
/// Despite the recovered C++ field name, zero enables horizontal wrapping and
/// every nonzero value rejects coordinates beyond the left and right edges.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RetailTopologyByte(u8);

impl RetailTopologyByte {
    pub const fn from_retail_byte(value: u8) -> Self {
        Self(value)
    }

    pub const fn retail_byte(self) -> u8 {
        self.0
    }

    pub const fn wraps_horizontally(self) -> bool {
        self.0 == 0
    }

    /// Produces the canonical byte written by the setup UI for the requested
    /// semantic topology. Reading still preserves arbitrary nonzero bytes.
    pub const fn from_wraps_horizontally(wraps_horizontally: bool) -> Self {
        Self(if wraps_horizontally { 0 } else { 1 })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HexDirection {
    NorthEast = 0,
    East = 1,
    SouthEast = 2,
    SouthWest = 3,
    West = 4,
    NorthWest = 5,
}

impl HexDirection {
    pub const ALL: [Self; 6] = [
        Self::NorthEast,
        Self::East,
        Self::SouthEast,
        Self::SouthWest,
        Self::West,
        Self::NorthWest,
    ];

    pub(crate) const fn opposite(self) -> Self {
        match self {
            Self::NorthEast => Self::SouthWest,
            Self::East => Self::West,
            Self::SouthEast => Self::NorthWest,
            Self::SouthWest => Self::NorthEast,
            Self::West => Self::East,
            Self::NorthWest => Self::SouthEast,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapGeometry {
    wraps_horizontally: bool,
}

impl MapGeometry {
    pub const fn new(wraps_horizontally: bool) -> Self {
        Self { wraps_horizontally }
    }

    pub const fn wraps_horizontally(self) -> bool {
        self.wraps_horizontally
    }

    pub fn tile(self, row: u16, column: u16) -> Option<TileId> {
        if row >= STRATEGIC_MAP_HEIGHT || column >= STRATEGIC_MAP_WIDTH {
            return None;
        }
        Some(TileId::new(row * STRATEGIC_MAP_WIDTH + column))
    }

    pub fn row_column(self, tile: TileId) -> Option<(u16, u16)> {
        let index = tile.get();
        if usize::from(index) >= STRATEGIC_TILE_COUNT {
            return None;
        }
        Some((index / STRATEGIC_MAP_WIDTH, index % STRATEGIC_MAP_WIDTH))
    }

    pub fn neighbor(self, tile: TileId, direction: HexDirection) -> Option<TileId> {
        let (row, column) = self.row_column(tile)?;
        let odd_row = row & 1 != 0;
        let (row_delta, column_delta) = match direction {
            HexDirection::NorthEast => (-1, i16::from(odd_row)),
            HexDirection::East => (0, 1),
            HexDirection::SouthEast => (1, i16::from(odd_row)),
            HexDirection::SouthWest => (1, if odd_row { 0 } else { -1 }),
            HexDirection::West => (0, -1),
            HexDirection::NorthWest => (-1, if odd_row { 0 } else { -1 }),
        };
        let next_row = i32::from(row) + row_delta;
        if !(0..i32::from(STRATEGIC_MAP_HEIGHT)).contains(&next_row) {
            return None;
        }
        let mut next_column = i32::from(column) + i32::from(column_delta);
        if self.wraps_horizontally {
            next_column = next_column.rem_euclid(i32::from(STRATEGIC_MAP_WIDTH));
        } else if !(0..i32::from(STRATEGIC_MAP_WIDTH)).contains(&next_column) {
            return None;
        }
        self.tile(next_row as u16, next_column as u16)
    }

    pub(crate) fn direction_to(self, source: TileId, destination: TileId) -> Option<HexDirection> {
        HexDirection::ALL
            .into_iter()
            .find(|&direction| self.neighbor(source, direction) == Some(destination))
    }

    pub fn neighbors(self, tile: TileId) -> [Option<TileId>; 6] {
        HexDirection::ALL.map(|direction| self.neighbor(tile, direction))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_the_retail_topology_byte_encoding() {
        let wrapping = RetailTopologyByte::from_retail_byte(0);
        let bounded = RetailTopologyByte::from_retail_byte(7);
        assert!(wrapping.wraps_horizontally());
        assert!(!bounded.wraps_horizontally());
        assert_eq!(bounded.retail_byte(), 7);
        assert_eq!(
            RetailTopologyByte::from_wraps_horizontally(true).retail_byte(),
            0
        );
        assert_eq!(
            RetailTopologyByte::from_wraps_horizontally(false).retail_byte(),
            1
        );
    }

    #[test]
    fn round_trips_retail_tile_coordinates() {
        let geometry = MapGeometry::new(true);
        let last = geometry.tile(59, 107).unwrap();
        assert_eq!(last.get(), 6479);
        assert_eq!(geometry.row_column(last), Some((59, 107)));
        assert_eq!(geometry.row_column(TileId::new(6480)), None);
    }

    #[test]
    fn uses_the_retail_odd_row_neighbor_layout() {
        let geometry = MapGeometry::new(true);
        let even = geometry.tile(2, 10).unwrap();
        let odd = geometry.tile(3, 10).unwrap();
        assert_eq!(
            geometry.neighbor(even, HexDirection::NorthEast),
            geometry.tile(1, 10)
        );
        assert_eq!(
            geometry.neighbor(even, HexDirection::NorthWest),
            geometry.tile(1, 9)
        );
        assert_eq!(
            geometry.neighbor(odd, HexDirection::NorthEast),
            geometry.tile(2, 11)
        );
        assert_eq!(
            geometry.neighbor(odd, HexDirection::NorthWest),
            geometry.tile(2, 10)
        );
    }

    #[test]
    fn applies_the_retail_horizontal_and_vertical_edge_rules() {
        let wrapping = MapGeometry::new(true);
        let bounded = MapGeometry::new(false);
        let left = wrapping.tile(2, 0).unwrap();
        assert_eq!(
            wrapping.neighbor(left, HexDirection::West),
            wrapping.tile(2, 107)
        );
        assert_eq!(bounded.neighbor(left, HexDirection::West), None);
        assert_eq!(
            wrapping.neighbor(left, HexDirection::NorthWest),
            wrapping.tile(1, 107)
        );
        let top = wrapping.tile(0, 20).unwrap();
        assert_eq!(wrapping.neighbor(top, HexDirection::NorthEast), None);
    }
}
