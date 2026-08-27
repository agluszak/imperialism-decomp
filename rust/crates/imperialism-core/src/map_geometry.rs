use crate::TileId;
use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Serialize};

pub const STRATEGIC_MAP_WIDTH: u16 = 108;
pub const STRATEGIC_MAP_HEIGHT: u16 = 60;
pub const STRATEGIC_TILE_COUNT: usize =
    STRATEGIC_MAP_WIDTH as usize * STRATEGIC_MAP_HEIGHT as usize;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MapTopology {
    Wrapping,
    Bounded,
}

impl MapTopology {
    pub const fn wraps_horizontally(self) -> bool {
        matches!(self, Self::Wrapping)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, PartialEq, Serialize)]
#[repr(u8)]
pub enum HexDirection {
    NorthEast = 0,
    East = 1,
    SouthEast = 2,
    SouthWest = 3,
    West = 4,
    NorthWest = 5,
}

pub type HexDirectionTable<T> = EnumMap<HexDirection, T>;

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

    pub(crate) const fn next_clockwise(self) -> Self {
        match self {
            Self::NorthEast => Self::East,
            Self::East => Self::SouthEast,
            Self::SouthEast => Self::SouthWest,
            Self::SouthWest => Self::West,
            Self::West => Self::NorthWest,
            Self::NorthWest => Self::NorthEast,
        }
    }

    pub(crate) const fn previous_clockwise(self) -> Self {
        match self {
            Self::NorthEast => Self::NorthWest,
            Self::East => Self::NorthEast,
            Self::SouthEast => Self::East,
            Self::SouthWest => Self::SouthEast,
            Self::West => Self::SouthWest,
            Self::NorthWest => Self::West,
        }
    }

    pub(crate) const fn retail(self) -> u8 {
        self as u8
    }

    pub const fn bit(self) -> u8 {
        match self {
            Self::NorthEast => 1,
            Self::East => 2,
            Self::SouthEast => 4,
            Self::SouthWest => 8,
            Self::West => 16,
            Self::NorthWest => 32,
        }
    }

    pub(crate) fn from_retail(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::NorthEast),
            1 => Some(Self::East),
            2 => Some(Self::SouthEast),
            3 => Some(Self::SouthWest),
            4 => Some(Self::West),
            5 => Some(Self::NorthWest),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapGeometry {
    topology: MapTopology,
}

impl MapGeometry {
    pub const fn new(topology: MapTopology) -> Self {
        Self { topology }
    }

    pub const fn wraps_horizontally(self) -> bool {
        self.topology.wraps_horizontally()
    }

    pub fn tile(self, row: u16, column: u16) -> Option<TileId> {
        if row >= STRATEGIC_MAP_HEIGHT || column >= STRATEGIC_MAP_WIDTH {
            return None;
        }
        Some(TileId::from_index_unchecked(
            row * STRATEGIC_MAP_WIDTH + column,
        ))
    }

    pub const fn row_column(self, tile: TileId) -> (u16, u16) {
        let index = tile.get();
        (index / STRATEGIC_MAP_WIDTH, index % STRATEGIC_MAP_WIDTH)
    }

    pub fn neighbor(self, tile: TileId, direction: HexDirection) -> Option<TileId> {
        let (row, column) = self.row_column(tile);
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
        if self.topology.wraps_horizontally() {
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
    fn round_trips_retail_tile_coordinates() {
        let geometry = MapGeometry::new(MapTopology::Wrapping);
        let last = geometry.tile(59, 107).unwrap();
        assert_eq!(last.get(), 6479);
        assert_eq!(geometry.row_column(last), (59, 107));
    }

    #[test]
    fn uses_the_retail_odd_row_neighbor_layout() {
        let geometry = MapGeometry::new(MapTopology::Wrapping);
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
        let wrapping = MapGeometry::new(MapTopology::Wrapping);
        let bounded = MapGeometry::new(MapTopology::Bounded);
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
