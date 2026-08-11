use crate::*;
use serde::{Deserialize, Serialize};

/// Retail's authoritative `TOcean` state.
///
/// The position of each entry in `zones` is its `TZone::contextOrdinal14`.
/// Routes retain their serialized order because it is also their drawing order.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ocean {
    pub zones: Vec<ZoneKind>,
    pub routes: Vec<OceanRoute>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ZoneKind {
    Zone(Zone),
    PortZone(PortZone),
}

/// The saved semantic state shared by `TZone` and `TPortZone`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Zone {
    pub display_name: String,
    pub status_code: Option<i16>,
    pub target_tile: Option<TileId>,
    pub seed_owner: Option<TileOwnerTag>,
    pub active_tile: Option<TileId>,
    pub primary_neighbors: Vec<OceanZoneId>,
    pub secondary_neighbors: Vec<ProvinceId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortZone {
    pub zone: Zone,
    pub port_tile: TileId,
}

/// One route-line record in doubled-column strategic-map coordinates.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OceanRoute {
    pub start_column: i32,
    pub start_row: i32,
    pub end_column: i32,
    pub end_row: i32,
}
