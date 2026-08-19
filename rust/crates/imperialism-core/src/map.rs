use crate::*;
use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Index, IndexMut};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum BorderInfluenceMode {
    FreshMap,
    OwnerChanged,
}

/// Retail's authoritative `TMapMgr` state without its MFC/ABI scaffolding.
///
/// The terrain and province tables deliberately live together: retail map
/// operations update both tables as one object, while each country's ordered
/// province list remains a separate, observable index.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MapMgr {
    pub topology: MapTopology,
    pub map_data_ready: bool,
    pub recruit_search_active: bool,
    pub city_score_total: i32,
    pub scenario_tag: String,
    #[serde(
        serialize_with = "serialize_strategic_tiles",
        deserialize_with = "deserialize_strategic_tiles"
    )]
    pub tiles: Box<[TileState; STRATEGIC_TILE_COUNT]>,
    pub provinces: ProvinceTable<ProvinceState>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub pending_river_mouth_tile: Option<TileId>,
    /// Retail `g_nNextRegionMarkerId`. Not saved; a freshly loaded process starts at 1.
    #[serde(skip_serializing, default = "next_region_marker_id_after_load")]
    pub(crate) next_region_marker_id: i32,
}

fn next_region_marker_id_after_load() -> i32 {
    1
}

#[allow(clippy::borrowed_box)]
fn serialize_strategic_tiles<S>(
    tiles: &Box<[TileState; STRATEGIC_TILE_COUNT]>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    tiles.as_slice().serialize(serializer)
}

fn deserialize_strategic_tiles<'de, D>(
    deserializer: D,
) -> Result<Box<[TileState; STRATEGIC_TILE_COUNT]>, D::Error>
where
    D: Deserializer<'de>,
{
    let tiles = Box::<[TileState]>::deserialize(deserializer)?;
    tiles.try_into().map_err(|tiles: Box<[TileState]>| {
        serde::de::Error::custom(format!(
            "strategic map has {} tiles; expected {STRATEGIC_TILE_COUNT}",
            tiles.len()
        ))
    })
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn boxed_strategic_tiles(
    tiles: impl Into<Box<[TileState]>>,
) -> Box<[TileState; STRATEGIC_TILE_COUNT]> {
    tiles
        .into()
        .try_into()
        .unwrap_or_else(|tiles: Box<[TileState]>| {
            panic!(
                "strategic map must have the retail fixed tile count; got {}",
                tiles.len()
            )
        })
}

impl MapMgr {
    pub fn new(topology: MapTopology, tiles: impl Into<Box<[TileState]>>) -> Self {
        Self::from_parts(topology, tiles, ProvinceTable::default())
    }

    pub fn from_parts(
        topology: MapTopology,
        tiles: impl Into<Box<[TileState]>>,
        provinces: ProvinceTable<ProvinceState>,
    ) -> Self {
        let tiles = boxed_strategic_tiles(tiles);
        Self {
            topology,
            map_data_ready: false,
            recruit_search_active: false,
            city_score_total: 0,
            scenario_tag: String::new(),
            tiles,
            provinces,
            pending_river_mouth_tile: None,
            next_region_marker_id: next_region_marker_id_after_load(),
        }
    }

    /// `TMapMgr::FloodFillTileRegionMarker` consumes `g_nNextRegionMarkerId` and then
    /// stores `(short)id + 1`. The start tile is stamped with the low 8 bits.
    pub(crate) fn allocate_region_marker(&mut self) -> RegionId {
        let marker = RegionId::new(self.next_region_marker_id as u8);
        self.next_region_marker_id = i32::from(self.next_region_marker_id as i32) + 1;
        marker
    }

    pub const fn geometry(&self) -> crate::MapGeometry {
        crate::MapGeometry::new(self.topology)
    }

    /// Retail 9-by-7 strategic-map viewport origin centered on `tile`.
    pub fn viewport_origin_centered_on(&self, tile: TileId) -> TileId {
        const VIEWPORT_TILE_SPAN: i32 = 9;

        let geometry = self.geometry();
        let MapPosition { row, column } = geometry.position(tile);
        let mut column = i32::from(column) - VIEWPORT_TILE_SPAN / 2;
        if self.topology == MapTopology::Bounded {
            column = column.clamp(1, 0x6e - VIEWPORT_TILE_SPAN);
        }
        if column < 0 {
            column += STRATEGIC_MAP_WIDTH;
        } else if column >= STRATEGIC_MAP_WIDTH {
            column -= STRATEGIC_MAP_WIDTH;
        }
        let row = (i32::from(row) - 3).clamp(0, 0x35);
        geometry
            .tile(MapPosition::new(row, column))
            .expect("retail strategic-map viewport origin is inside the map")
    }

    /// Applies a one-cell row and column delta to a strategic viewport origin.
    pub fn scrolled_viewport_origin(
        &self,
        origin: TileId,
        row_delta: i32,
        column_delta: i32,
    ) -> TileId {
        const VIEWPORT_TILE_SPAN: i32 = 9;
        const MAX_ORIGIN_ROW: i32 = 0x35;

        let geometry = self.geometry();
        let MapPosition { row, column } = geometry.position(origin);
        debug_assert!((-1..=1).contains(&row_delta));
        debug_assert!((-1..=1).contains(&column_delta));
        let row = (i32::from(row) + row_delta).clamp(0, MAX_ORIGIN_ROW);
        let column = if self.topology.wraps_horizontally() {
            (i32::from(column) + column_delta).rem_euclid(STRATEGIC_MAP_WIDTH)
        } else {
            (i32::from(column) + column_delta).clamp(1, 0x6e - VIEWPORT_TILE_SPAN)
        };
        geometry
            .tile(MapPosition::new(row, column))
            .expect("retail strategic viewport origin is inside the map")
    }

    /// Retail `TMapDialog::SetMapDialogCellCoordinatesAndRefresh` origin commit.
    pub fn viewport_origin_from_upper_left(&self, column: i32, row: i32) -> TileId {
        const VIEWPORT_TILE_SPAN: i32 = 9;
        const MAX_ORIGIN_ROW: i32 = 0x35;

        let mut column = column;
        let mut row = row;
        if !self.topology.wraps_horizontally() {
            column = column.clamp(1, 0x6e - VIEWPORT_TILE_SPAN);
        }
        if column < 0 {
            column += STRATEGIC_MAP_WIDTH;
        } else if column >= STRATEGIC_MAP_WIDTH {
            column -= STRATEGIC_MAP_WIDTH;
        }
        row = row.clamp(0, MAX_ORIGIN_ROW);
        self.geometry()
            .tile(MapPosition::new(row, column))
            .expect("retail strategic viewport origin is inside the map")
    }

    /// Retail `ComputeRepresentativeTileIndexForNationWithWrapBias`.
    #[allow(clippy::manual_checked_ops)] // Retail guards both integer divisions with tileCount != 0.
    pub(crate) fn representative_tile_index_for_nation(
        &self,
        nation: NationId,
        home_tile: Option<TileId>,
        wrap_bias: bool,
    ) -> Option<TileId> {
        let owner = TileContext::from_nation(nation);
        let home_region_class = home_tile.map(|home| {
            let province = self[home]
                .province
                .expect("a nation's home tile belongs to a province");
            self.provinces[province]
                .region_class
                .expect("a home province has a generated region class")
        });
        let mut column_sum = 0_u32;
        let mut row_sum = 0_u32;
        let mut tile_count = 0_u32;
        let mut west_count = 0_u32;
        let mut east_count = 0_u32;

        for tile in TileId::all() {
            if self[tile].owner_nation != Some(owner) {
                continue;
            }
            if let Some(home_region_class) = home_region_class {
                let province = self[tile]
                    .province
                    .expect("nation-owned terrain belongs to a province");
                if self.provinces[province].region_class != Some(home_region_class) {
                    continue;
                }
            }
            let MapPosition { row, column } = self.geometry().position(tile);
            west_count += u32::from(column < 0x19);
            east_count += u32::from(column > 0x53);
            column_sum += column as u32;
            row_sum += row as u32;
            tile_count += 1;
        }

        if west_count != 0 && east_count != 0 {
            if wrap_bias {
                column_sum += west_count * STRATEGIC_MAP_WIDTH as u32;
            } else {
                column_sum = 0;
                row_sum = 0;
                tile_count = 0;
                for tile in TileId::all() {
                    if self[tile].owner_nation != Some(owner) {
                        continue;
                    }
                    let MapPosition {
                        row,
                        column: mut column,
                    } = self.geometry().position(tile);
                    if column < 0x36 && west_count < east_count {
                        column = 0x6b;
                    }
                    if column > 0x36 && east_count < west_count {
                        column = 0;
                    }
                    column_sum += column as u32;
                    row_sum += row as u32;
                    tile_count += 1;
                }
            }
        }

        if tile_count != 0 {
            let column = column_sum / tile_count % STRATEGIC_MAP_WIDTH as u32;
            let row = row_sum / tile_count;
            return self
                .geometry()
                .tile(MapPosition::new(row as i32, column as i32));
        }

        self.tiles
            .iter()
            .rposition(|tile| tile.owner_nation == Some(owner))
            .map(|index| TileId::new(index))
    }

    /// Retail `UpdateTilePrimaryAndSecondaryNeighborLinksByPriority`.
    pub(crate) fn province_neighbor_links(
        &self,
        province: ProvinceId,
        city_tile: TileId,
    ) -> (TileId, TileId) {
        const PRIORITY: TerrainKindTable<i32> =
            TerrainKindTable::from_array([10, 4, 7, 6, 8, 0, 9, 5]);

        let neighbors = self.geometry().neighbors(city_tile);
        let mut primary = None;
        let mut primary_priority = 1;
        for (direction, neighbor) in HexDirection::ALL.into_iter().zip(neighbors) {
            let Some(neighbor) = neighbor else {
                continue;
            };
            let tile = &self[neighbor];
            let priority = PRIORITY[tile.terrain];
            if tile.province == Some(province) && primary_priority < priority {
                primary = Some((direction, neighbor));
                primary_priority = priority;
            }
        }
        let (primary_direction, primary) =
            primary.expect("province capital requires one same-province neighbor");

        let mut secondary = None;
        let mut secondary_priority = -1;
        for (direction, neighbor) in HexDirection::ALL.into_iter().zip(neighbors) {
            let Some(neighbor) = neighbor else {
                continue;
            };
            if direction == primary_direction {
                continue;
            }
            let tile = &self[neighbor];
            let mut priority = PRIORITY[tile.terrain];
            if tile.province == Some(province) {
                priority += 0x14;
            }
            if secondary_priority < priority {
                secondary = Some(neighbor);
                secondary_priority = priority;
            }
        }
        (
            primary,
            secondary.expect("province capital requires a second map neighbor"),
        )
    }

    /// Retail `TMapMgr::SetOwner`.
    ///
    /// The owner-border cache is rebuilt for the changed tile and its six
    /// neighbors. A town marker on a port/city tile moves between the two
    /// great powers' ordered town lists before province-level country dispatch.
    pub fn set_owner(&mut self, nations: &mut Nations, tile: TileId, new_owner: NationId) {
        let old_owner = self[tile].owner_nation;
        let new_owner_tag = Some(TileContext::from_nation(new_owner));
        if old_owner == new_owner_tag {
            return;
        }

        self[tile].owner_nation = new_owner_tag;
        self[tile].owner_border_mask = 0;
        self.update_tile_neighbor_border_influence_counters(
            tile,
            BorderInfluenceMode::OwnerChanged,
        );

        let neighbors = self.geometry().neighbors(tile);
        for neighbor in neighbors.into_iter().flatten() {
            self[neighbor].owner_border_mask = 0;
            self.update_tile_neighbor_border_influence_counters(
                neighbor,
                BorderInfluenceMode::OwnerChanged,
            );
        }

        if self[tile].flags.bits() & 0x14 == 0 {
            return;
        }
        let Some(old_owner) = old_owner.and_then(TileContext::nation) else {
            return;
        };
        let Some(old_owner) = NationId::as_major(old_owner) else {
            return;
        };
        let Some((_, mut town)) = nations.majors[&old_owner].towns.shift_remove_entry(&tile) else {
            return;
        };
        town.owner_nation = new_owner;
        let new_owner = NationId::as_major(new_owner)
            .expect("town-bearing tile transfer requires a great-power destination");
        nations.majors[&new_owner].towns.insert(tile, town);
    }

    /// Retail `TMapMgr::UpdateTileNeighborBorderInfluenceCounters`.
    ///
    /// This is deliberately additive. Fresh-map construction calls it on
    /// zeroed records, while `SetOwner` clears only the owner-border byte before
    /// owner change and leaves the other two caches untouched.
    pub(crate) fn update_tile_neighbor_border_influence_counters(
        &mut self,
        tile: TileId,
        mode: BorderInfluenceMode,
    ) {
        const DIRECTION_BITS: HexDirectionTable<u8> =
            HexDirectionTable::from_array([1, 2, 4, 8, 16, 32]);

        let neighbors = HexDirectionTable::from_array(self.geometry().neighbors(tile));
        let terrain = self[tile].terrain;
        let owner = self[tile].owner_nation;
        let province = self[tile].province;
        let mut owner_border_mask = self[tile].owner_border_mask;
        let mut city_border_mask = self[tile].city_border_mask;
        let mut water_adjacency_mask = self[tile].water_adjacency_mask;

        for direction in HexDirection::ALL {
            let neighbor = neighbors[direction];
            let Some(neighbor) = neighbor else {
                owner_border_mask = owner_border_mask.wrapping_add(DIRECTION_BITS[direction]);
                continue;
            };
            if terrain == TerrainKind::Water {
                if mode == BorderInfluenceMode::FreshMap
                    && self[neighbor].terrain == TerrainKind::Water
                    && self[neighbor].owner_nation != owner
                {
                    owner_border_mask = owner_border_mask.wrapping_add(DIRECTION_BITS[direction]);
                }
            } else if self[neighbor].terrain == TerrainKind::Water {
                water_adjacency_mask = water_adjacency_mask.wrapping_add(DIRECTION_BITS[direction]);
            } else {
                if self[neighbor].owner_nation != owner {
                    owner_border_mask = owner_border_mask.wrapping_add(DIRECTION_BITS[direction]);
                }
                if mode != BorderInfluenceMode::OwnerChanged && self[neighbor].province != province
                {
                    city_border_mask = city_border_mask.wrapping_add(DIRECTION_BITS[direction]);
                }
            }
        }

        if terrain == TerrainKind::Water {
            for direction in HexDirection::ALL {
                let (Some(neighbor_a), Some(neighbor_b)) =
                    (neighbors[direction], neighbors[direction.next_clockwise()])
                else {
                    continue;
                };
                if self[neighbor_a].terrain != TerrainKind::Water
                    && self[neighbor_b].terrain != TerrainKind::Water
                {
                    if self[neighbor_a].owner_nation != self[neighbor_b].owner_nation {
                        owner_border_mask =
                            owner_border_mask.wrapping_add(DIRECTION_BITS[direction]);
                    }
                    if mode != BorderInfluenceMode::OwnerChanged
                        && self[neighbor_a].province != self[neighbor_b].province
                    {
                        city_border_mask = city_border_mask.wrapping_add(DIRECTION_BITS[direction]);
                    }
                }
            }
        }

        if mode != BorderInfluenceMode::OwnerChanged
            && city_border_mask & 2 != 0
            && city_border_mask & 1 != 0
            && let (Some(east), Some(north_east)) = (
                neighbors[HexDirection::East],
                neighbors[HexDirection::NorthEast],
            )
            && self[east].province != self[north_east].province
        {
            city_border_mask = city_border_mask.wrapping_add(0x40);
        }
        if mode != BorderInfluenceMode::OwnerChanged
            && city_border_mask & 2 != 0
            && city_border_mask & 4 != 0
            && let (Some(east), Some(south_east)) = (
                neighbors[HexDirection::East],
                neighbors[HexDirection::SouthEast],
            )
            && self[east].province != self[south_east].province
        {
            city_border_mask = city_border_mask.wrapping_add(0x80);
        }

        if owner_border_mask & 2 != 0
            && owner_border_mask & 1 != 0
            && let (Some(east), Some(north_east)) = (
                neighbors[HexDirection::East],
                neighbors[HexDirection::NorthEast],
            )
            && self[east].owner_nation != self[north_east].owner_nation
        {
            owner_border_mask = owner_border_mask.wrapping_add(0x40);
        }
        if owner_border_mask & 2 != 0
            && owner_border_mask & 4 != 0
            && let (Some(east), Some(south_east)) = (
                neighbors[HexDirection::East],
                neighbors[HexDirection::SouthEast],
            )
            && self[east].owner_nation != self[south_east].owner_nation
        {
            owner_border_mask = owner_border_mask.wrapping_add(0x80);
        }

        self[tile].owner_border_mask = owner_border_mask;
        self[tile].city_border_mask = city_border_mask;
        self[tile].water_adjacency_mask = water_adjacency_mask;
    }
}

impl Index<TileId> for MapMgr {
    type Output = TileState;

    fn index(&self, index: TileId) -> &Self::Output {
        &self.tiles[index.index()]
    }
}

impl IndexMut<TileId> for MapMgr {
    fn index_mut(&mut self, index: TileId) -> &mut Self::Output {
        &mut self.tiles[index.index()]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TileState {
    pub terrain: TerrainKind,
    pub rendering: TileRendering,
    pub owner_nation: Option<TileContext>,
    pub former_owner_nation: Option<TileContext>,
    pub secondary_owner_nation: Option<MajorNationId>,
    pub owner_border_mask: u8,
    pub city_border_mask: u8,
    pub water_adjacency_mask: u8,
    pub province: Option<ProvinceId>,
    /// Retail `TTerrainStateRecord::gateFlag`.
    pub gate: i8,
    /// Retail `TTerrainStateRecord::recruitSearchVisited0e`.
    pub recruit_search_visited: u8,
    /// Retail `TTerrainStateRecord::perTileVisitedFlag0f`.
    pub per_tile_visited: i8,
    /// Retail `TTerrainStateRecord::tileActionOrdinal1a`.
    pub tile_action_ordinal: i32,
    pub development: TileDevelopment,
    pub edge_resources: [Option<crate::ResourceKind>; 2],
    /// Completed directional transport links from this tile.
    pub transport_links: TileTransportLinks,
    /// Directional rail sections that have been ordered but not yet completed.
    pub pending_rail_links: TileTransportLinks,
    pub action: Option<TileAction>,
    pub flags: TileFlags,
    pub region: Option<RegionId>,
}

impl TileState {
    /// River connectivity derived from the saved river picture sprite.
    ///
    /// Retail stores one `riverSpriteCode` per tile. Connection/flow semantics are a pure
    /// function of that sprite; do not persist a second river field beside it.
    pub const fn river(self) -> Option<RiverSegment> {
        match self.rendering.river_sprite {
            Some(sprite) => Some(sprite.segment()),
            None => None,
        }
    }
}

/// The resolved per-tile picture choices consumed by retail's strategic-map renderer.
///
/// These values are stable observable state: retail saves and restores them instead of
/// rerunning the random picture-assignment pass when a game is loaded.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct TileRendering {
    pub sprite_variant: u8,
    pub river_sprite: Option<RiverSprite>,
    pub transition_mask: u8,
    pub coast_or_secondary_mask: u8,
}

impl TileRendering {
    pub const fn from_retail(
        sprite_variant: u8,
        river_sprite: u8,
        transition_mask: u8,
        coast_or_secondary_mask: u8,
    ) -> Option<Self> {
        if sprite_variant > 0x3f || transition_mask > 0x3f || coast_or_secondary_mask > 0x3f {
            return None;
        }
        let river_sprite = if river_sprite == 0 {
            None
        } else {
            match RiverSprite::from_retail(river_sprite) {
                Some(sprite) => Some(sprite),
                None => return None,
            }
        };
        Some(Self {
            sprite_variant,
            river_sprite,
            transition_mask,
            coast_or_secondary_mask,
        })
    }
}

impl<'de> Deserialize<'de> for TileRendering {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedTileRendering {
            sprite_variant: u8,
            river_sprite: Option<RiverSprite>,
            transition_mask: u8,
            coast_or_secondary_mask: u8,
        }

        let rendering = SerializedTileRendering::deserialize(deserializer)?;
        if rendering.sprite_variant > 0x3f
            || rendering.transition_mask > 0x3f
            || rendering.coast_or_secondary_mask > 0x3f
        {
            return Err(serde::de::Error::custom(
                "tile rendering variant and masks must be between 0 and 0x3f",
            ));
        }
        Ok(Self {
            sprite_variant: rendering.sprite_variant,
            river_sprite: rendering.river_sprite,
            transition_mask: rendering.transition_mask,
            coast_or_secondary_mask: rendering.coast_or_secondary_mask,
        })
    }
}

/// One finalized retail `TTerrainStateRecord::riverSpriteCode` picture choice.
///
/// This is the sole authoritative river fact on a finished tile. Connectivity is derived.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RiverSprite(u8);

impl RiverSprite {
    pub const fn from_retail(value: u8) -> Option<Self> {
        if value >= 0x0b && value <= 0x3a {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Canonical picture sprite for a generation-time connection code (`1..=0x15`).
    ///
    /// Map generation works in connection space until `AssignPictToTile` picks a concrete
    /// picture; tests and provisional stamps use the first retail sprite that maps to the code.
    pub const fn canonical_for_connection(connection_code: u8) -> Option<Self> {
        let retail = match connection_code {
            1 => 0x0b,
            2 => 0x0c,
            3 => 0x0d,
            4 => 0x0f,
            5 => 0x11,
            6 => 0x15,
            7 => 0x17,
            8 => 0x19,
            9 => 0x1a,
            0x0a => 0x2b,
            0x0b => 0x2c,
            0x0c => 0x2e,
            0x0d => 0x2f,
            0x0e => 0x30,
            0x0f => 0x32,
            0x10 => 0x37,
            0x11 => 0x38,
            0x12 => 0x3a,
            0x13 => 0x33,
            0x14 => 0x34,
            0x15 => 0x36,
            _ => return None,
        };
        Self::from_retail(retail)
    }

    pub const fn retail(self) -> u8 {
        self.0
    }

    /// Retail `RiverConnectionCode` mapping from a saved picture sprite.
    pub const fn connection_code(self) -> u8 {
        const FLOW_CONNECTIONS: [u8; 16] = [1, 2, 3, 3, 4, 4, 5, 5, 5, 5, 6, 6, 7, 7, 8, 9];
        let mut sprite = self.0;
        if sprite >= 0x1b && sprite <= 0x2a {
            sprite -= 0x10;
        }
        if sprite >= 0x0b && sprite <= 0x1a {
            return FLOW_CONNECTIONS[(sprite - 0x0b) as usize];
        }
        match sprite {
            0x2b => 0x0a,
            0x2c | 0x2d => 0x0b,
            0x2e => 0x0c,
            0x2f => 0x0d,
            0x30 | 0x31 => 0x0e,
            0x32 => 0x0f,
            0x33 => 0x13,
            0x34 | 0x35 => 0x14,
            0x36 => 0x15,
            0x37 => 0x10,
            0x38 | 0x39 => 0x11,
            0x3a => 0x12,
            _ => panic!("RiverSprite invariant broken: no connection mapping"),
        }
    }

    pub const fn segment(self) -> RiverSegment {
        RiverSegment {
            connection_code: self.connection_code(),
        }
    }
}

impl<'de> Deserialize<'de> for RiverSprite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::from_retail(value)
            .ok_or_else(|| serde::de::Error::custom("river sprite must be between 0x0b and 0x3a"))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, PartialEq, Serialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum TerrainKind {
    Plains,
    Forest,
    Hills,
    Mountain,
    Swamp,
    Water,
    Desert,
    Farmland,
}

pub type TerrainKindTable<T> = EnumMap<TerrainKind, T>;

impl TerrainKind {
    pub const fn from_retail(value: i8) -> Option<Self> {
        match value {
            0 => Some(Self::Plains),
            1 => Some(Self::Forest),
            2 => Some(Self::Hills),
            3 => Some(Self::Mountain),
            4 => Some(Self::Swamp),
            5 => Some(Self::Water),
            6 => Some(Self::Desert),
            7 => Some(Self::Farmland),
            _ => None,
        }
    }

    pub const fn retail(self) -> i8 {
        match self {
            Self::Plains => 0,
            Self::Forest => 1,
            Self::Hills => 2,
            Self::Mountain => 3,
            Self::Swamp => 4,
            Self::Water => 5,
            Self::Desert => 6,
            Self::Farmland => 7,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TileAction(i32);

impl<'de> Deserialize<'de> for TileAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i32::deserialize(deserializer)?;
        Self::try_from_retail(value)
            .ok_or_else(|| serde::de::Error::custom("tile action -1 is represented by None"))
    }
}

impl TileAction {
    pub const fn try_from_retail(value: i32) -> Option<Self> {
        if value == -1 { None } else { Some(Self(value)) }
    }

    pub const fn retail(self) -> i32 {
        self.0
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(transparent)]
    pub struct TileFlags: u16 {
        /// Set by `ResetTileToBaseTransportFlag`; consumers use this as the base-transport test.
        const BASE_TRANSPORT = 1 << 0;
        const RECRUITMENT_RESERVED = 1 << 1;
        /// Retail `activeFlags1c` bit 2, set by `QueuePortConstructionOrder` and tested by `HasPortInProvince`.
        const PORT = 1 << 2;
        /// Set by `SetProvinceCapitalTileFlagBit08`, which also advances the province fort level.
        const PROVINCE_CAPITAL_FORTIFICATION = 1 << 3;
        /// Depot marker written by `QueueDepotConstructionOrder`.
        const DEPOT = 1 << 4;
        /// The city marker bit tested independently by map and unit consumers.
        const CITY_MARKER = 1 << 5;

        /// Complete state written for a fallback or re-anchored province capital.
        const PROVINCE_ANCHOR_STATE = 0x22;
        /// Complete state written for a minor nation's home tile.
        const MINOR_HOME_STATE = 0x21;
        /// Complete state written by `PlaceCity`.
        const PLACED_CITY_STATE = 0x37;
    }
}

impl TileFlags {
    pub(crate) fn has_base_transport(self) -> bool {
        self.contains(Self::BASE_TRANSPORT)
    }

    pub fn is_city(self) -> bool {
        self.contains(Self::CITY_MARKER)
    }

    pub(crate) fn clear_city_marker(&mut self) {
        self.remove(Self::CITY_MARKER);
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RegionId(u8);

impl RegionId {
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RiverSegment {
    connection_code: u8,
}

impl<'de> Deserialize<'de> for RiverSegment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedRiverSegment {
            connection_code: u8,
        }

        let segment = SerializedRiverSegment::deserialize(deserializer)?;
        if !(1..=0x15).contains(&segment.connection_code) {
            return Err(serde::de::Error::custom(
                "river connection code must be between 1 and 0x15",
            ));
        }
        Ok(Self {
            connection_code: segment.connection_code,
        })
    }
}

impl RiverSegment {
    /// Constructs the canonical river-connection code produced by retail map
    /// generation. Zero is the no-river sentinel; 1 through 0x15 are the
    /// interior, source, and water-mouth connection forms.
    pub const fn from_connection_code(connection_code: u8) -> Option<Self> {
        if connection_code == 0 {
            None
        } else {
            assert!(connection_code <= 0x15, "invalid river connection code");
            Some(Self { connection_code })
        }
    }

    pub const fn connection_code(self) -> u8 {
        self.connection_code
    }

    pub(crate) const fn flow_type(self) -> Option<usize> {
        if self.connection_code >= 1 && self.connection_code <= 9 {
            Some((self.connection_code - 1) as usize)
        } else {
            None
        }
    }
}

impl Default for TileState {
    fn default() -> Self {
        Self {
            terrain: TerrainKind::Plains,
            rendering: TileRendering::default(),
            owner_nation: None,
            former_owner_nation: None,
            secondary_owner_nation: None,
            owner_border_mask: 0,
            city_border_mask: 0,
            water_adjacency_mask: 0,
            province: None,
            gate: 0,
            recruit_search_visited: 0,
            per_tile_visited: 0,
            tile_action_ordinal: -1,
            development: TileDevelopment::default(),
            edge_resources: [None; 2],
            transport_links: TileTransportLinks::default(),
            pending_rail_links: TileTransportLinks::default(),
            action: None,
            flags: TileFlags::empty(),
            region: None,
        }
    }
}

bitflags::bitflags! {
    /// The six directional links that may leave a strategic-map tile.
    #[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
    pub struct TileTransportLinks: u8 {
        const NORTH_EAST = 1 << 0;
        const EAST = 1 << 1;
        const SOUTH_EAST = 1 << 2;
        const SOUTH_WEST = 1 << 3;
        const WEST = 1 << 4;
        const NORTH_WEST = 1 << 5;
    }
}

impl TileTransportLinks {
    pub(crate) const fn for_direction(direction: HexDirection) -> Self {
        match direction {
            HexDirection::NorthEast => Self::NORTH_EAST,
            HexDirection::East => Self::EAST,
            HexDirection::SouthEast => Self::SOUTH_EAST,
            HexDirection::SouthWest => Self::SOUTH_WEST,
            HexDirection::West => Self::WEST,
            HexDirection::NorthWest => Self::NORTH_WEST,
        }
    }

    pub(crate) fn insert_direction(&mut self, direction: HexDirection) {
        self.insert(Self::for_direction(direction));
    }
}

/// One independently-progressed resource-development channel on a map tile.
///
/// Retail stores both channels in one byte, but game rules operate on them as
/// separate levels.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DevelopmentLevel(u8);

impl DevelopmentLevel {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub(crate) fn advance(&mut self) {
        self.0 += 1;
    }
}

impl Default for DevelopmentLevel {
    fn default() -> Self {
        Self::ZERO
    }
}

/// The two resource-development channels and their discovery visibility.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TileDevelopment {
    pub surface: DevelopmentLevel,
    pub extractive: DevelopmentLevel,
    /// Major nations that can see the tile's resource information.
    pub resource_visible_to_majors: MajorNationTable<bool>,
}

impl Default for TileDevelopment {
    fn default() -> Self {
        Self {
            surface: DevelopmentLevel::ZERO,
            extractive: DevelopmentLevel::ZERO,
            resource_visible_to_majors: MajorNationTable::default(),
        }
    }
}

impl TileDevelopment {
    /// Retail `TTerrainStateRecord::developmentClassNibbles0c` as a whole signed byte.
    pub(crate) fn packed_byte(self) -> i8 {
        ((self.extractive.get() << 4) | self.surface.get()) as i8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tile_flags_keep_city_marker_and_complete_state_writes_separate() {
        assert!(TileFlags::PROVINCE_ANCHOR_STATE.is_city());
        assert!(TileFlags::MINOR_HOME_STATE.is_city());
        assert!(TileFlags::PLACED_CITY_STATE.is_city());
        assert!(!TileFlags::PROVINCE_ANCHOR_STATE.has_base_transport());
        assert!(TileFlags::MINOR_HOME_STATE.has_base_transport());

        let mut sibling = TileFlags::PLACED_CITY_STATE | TileFlags::PROVINCE_CAPITAL_FORTIFICATION;
        sibling.clear_city_marker();
        assert_eq!(sibling.bits(), 0x1f);
    }

    #[test]
    fn river_connection_codes_index_only_two_ended_flows() {
        assert_eq!(
            RiverSegment::from_connection_code(1).unwrap().flow_type(),
            Some(0)
        );
        assert_eq!(
            RiverSegment::from_connection_code(9).unwrap().flow_type(),
            Some(8)
        );
        assert_eq!(
            RiverSegment::from_connection_code(0x0a)
                .unwrap()
                .flow_type(),
            None
        );
        assert_eq!(
            RiverSegment::from_connection_code(0x15)
                .unwrap()
                .flow_type(),
            None
        );
        assert_eq!(RiverSegment::from_connection_code(0), None);
        assert!(serde_json::from_str::<RiverSegment>(r#"{"connection_code":0}"#).is_err());
        assert!(serde_json::from_str::<RiverSegment>(r#"{"connection_code":22}"#).is_err());
    }

    #[test]
    fn river_sprite_is_the_sole_tile_river_fact() {
        for (sprite, connection_code) in [
            (0x0b, 1),
            (0x0d, 3),
            (0x0e, 3),
            (0x1a, 9),
            (0x1b, 1),
            (0x2a, 9),
            (0x2b, 0x0a),
            (0x2c, 0x0b),
            (0x2d, 0x0b),
            (0x32, 0x0f),
            (0x33, 0x13),
            (0x37, 0x10),
            (0x38, 0x11),
            (0x39, 0x11),
            (0x3a, 0x12),
        ] {
            let sprite = RiverSprite::from_retail(sprite).unwrap();
            assert_eq!(sprite.connection_code(), connection_code);
            assert_eq!(sprite.segment().connection_code(), connection_code);
            let tile = TileState {
                rendering: TileRendering {
                    river_sprite: Some(sprite),
                    ..TileRendering::default()
                },
                ..TileState::default()
            };
            assert_eq!(tile.river().unwrap().connection_code(), connection_code);
        }
        assert_eq!(TileState::default().river(), None);
        assert_eq!(
            RiverSprite::canonical_for_connection(4)
                .unwrap()
                .connection_code(),
            4
        );
    }

    #[test]
    fn strategic_viewport_scroll_wraps_and_clamps_at_retail_edges() {
        let tiles = vec![TileState::default(); STRATEGIC_TILE_COUNT];
        let wrapping = MapMgr::new(MapTopology::Wrapping, tiles.clone());
        let origin = wrapping.geometry().tile(MapPosition::new(0, 0)).unwrap();
        let next = wrapping.scrolled_viewport_origin(origin, -1, -1);
        assert_eq!(
            wrapping.geometry().position(next),
            MapPosition::new(0, STRATEGIC_MAP_WIDTH - 1),
        );
        let origin = wrapping.geometry().tile(MapPosition::new(53, 107)).unwrap();
        let next = wrapping.scrolled_viewport_origin(origin, 1, 1);
        assert_eq!(wrapping.geometry().position(next), MapPosition::new(53, 0));

        let bounded = MapMgr::new(MapTopology::Bounded, tiles);
        let origin = bounded.geometry().tile(MapPosition::new(0, 1)).unwrap();
        assert_eq!(bounded.scrolled_viewport_origin(origin, -1, -1), origin);
        let origin = bounded.geometry().tile(MapPosition::new(53, 101)).unwrap();
        assert_eq!(bounded.scrolled_viewport_origin(origin, 1, 1), origin);
        let origin = bounded.geometry().tile(MapPosition::new(52, 100)).unwrap();
        let next = bounded.scrolled_viewport_origin(origin, 1, 1);
        assert_eq!(bounded.geometry().position(next), MapPosition::new(53, 101));
    }

    #[test]
    fn minimap_upper_left_clamps_like_the_map_dialog() {
        let tiles = vec![TileState::default(); STRATEGIC_TILE_COUNT];
        let wrapping = MapMgr::new(MapTopology::Wrapping, tiles.clone());
        assert_eq!(
            wrapping
                .geometry()
                .position(wrapping.viewport_origin_from_upper_left(-1, -4)),
            MapPosition::new(0, STRATEGIC_MAP_WIDTH - 1)
        );
        assert_eq!(
            wrapping
                .geometry()
                .position(wrapping.viewport_origin_from_upper_left(108, 60)),
            MapPosition::new(53, 0)
        );

        let bounded = MapMgr::new(MapTopology::Bounded, tiles);
        assert_eq!(
            bounded
                .geometry()
                .position(bounded.viewport_origin_from_upper_left(0, 60)),
            MapPosition::new(53, 1)
        );
        assert_eq!(
            bounded
                .geometry()
                .position(bounded.viewport_origin_from_upper_left(107, 0)),
            MapPosition::new(0, 101)
        );
    }
}
