//! Capital-site selection (`TCitySiteView`) and `TMapMgr::PlaceCity` for random-game start.

use crate::{
    Difficulty, GameState, HexDirection, MajorNationId, MapGeometry, NationId, RegionId,
    STRATEGIC_MAP_HEIGHT, STRATEGIC_MAP_WIDTH, StrategicMap, TerrainKind, TileFlags, TileId,
    TileOwnerTag, TownState,
};

const TERRAIN_FLOW_DIRECTIONS: [[HexDirection; 2]; 9] = [
    [HexDirection::NorthEast, HexDirection::SouthEast],
    [HexDirection::NorthEast, HexDirection::SouthWest],
    [HexDirection::NorthEast, HexDirection::West],
    [HexDirection::East, HexDirection::SouthWest],
    [HexDirection::East, HexDirection::West],
    [HexDirection::East, HexDirection::NorthWest],
    [HexDirection::SouthEast, HexDirection::West],
    [HexDirection::SouthEast, HexDirection::NorthWest],
    [HexDirection::SouthWest, HexDirection::NorthWest],
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CitySiteError {
    #[error("tile is not owned by the active nation")]
    NotOwned,
    #[error("terrain cannot host a city")]
    UnsupportedTerrain,
    #[error("tile is not a valid secondary-nation home-site candidate")]
    InvalidHomeSite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapitalSite {
    tile: TileId,
    nation: MajorNationId,
}
impl CapitalSite {
    pub const fn tile(self) -> TileId {
        self.tile
    }

    pub const fn nation(self) -> MajorNationId {
        self.nation
    }
}

/// Retail difficulties that dispatch the city-site selector (`difficultyLevel > 1`).
pub const fn requires_capital_site_selection(difficulty: Difficulty) -> bool {
    matches!(
        difficulty,
        Difficulty::Normal | Difficulty::Hard | Difficulty::NighOnImpossible
    )
}

/// Terrain kinds accepted by `TCitySiteView::HandleMapClickByInteractionMode`.
pub const fn supports_city_site_terrain(terrain: TerrainKind) -> bool {
    matches!(
        terrain,
        TerrainKind::Plains | TerrainKind::Farmland | TerrainKind::Forest | TerrainKind::Desert
    )
}

/// Sea-neighbor / river-flow check from `TMapMgr::IsValidSecondaryNationHomeTileCandidate`.
pub fn is_valid_secondary_nation_home_tile_candidate(world: &StrategicMap, tile: TileId) -> bool {
    let geometry = world.geometry();
    let tile_state = &world[tile];
    let home_nation = tile_state.owner_nation;
    let terrain = tile_state.terrain;

    let mut is_valid = false;
    if terrain != TerrainKind::Mountain && terrain != TerrainKind::Hills {
        for direction in HexDirection::ALL {
            let neighbor = home_site_scan_neighbor(tile, direction);
            let sea = &world[neighbor];
            if sea.terrain != TerrainKind::Water {
                continue;
            }
            is_valid = true;
            for sea_direction in HexDirection::ALL {
                let sea_neighbor = home_site_scan_neighbor(neighbor, sea_direction);
                let around = &world[sea_neighbor];
                if home_site_neighbor_conflicts(around.owner_nation, home_nation) {
                    is_valid = false;
                    break;
                }
            }
            // Retail rejects sea tiles whose action state is not "none" (-1).
            if sea.action.is_some() {
                is_valid = false;
            }
            if is_valid {
                break;
            }
        }
    }

    if !is_valid
        && tile_state.river.is_some()
        && river_reaches_sea_without_crossing_nation(world, &geometry, tile)
    {
        is_valid = true;
    }
    is_valid
}

/// This one retail predicate always uses the 217-wide doubled-column wrap and
/// vertical clamp, independent of the session map-topology flag.
fn home_site_scan_neighbor(tile: TileId, direction: HexDirection) -> TileId {
    const COLUMN_X2_DELTAS: [i32; 6] = [1, 2, 1, -1, -2, -1];
    const ROW_DELTAS: [i32; 6] = [-1, 0, 1, 1, 0, -1];
    const RASTER_WIDTH: i32 = STRATEGIC_MAP_WIDTH as i32 * 2;

    let row = i32::from(tile.get() / STRATEGIC_MAP_WIDTH);
    let column = i32::from(tile.get() % STRATEGIC_MAP_WIDTH);
    let index = direction as usize;
    let mut column_x2 = row % 2 + column * 2 + COLUMN_X2_DELTAS[index];
    let row = (row + ROW_DELTAS[index]).clamp(0, i32::from(STRATEGIC_MAP_HEIGHT) - 1);
    if column_x2 >= RASTER_WIDTH {
        column_x2 -= RASTER_WIDTH + 1;
    } else if column_x2 < 0 {
        column_x2 += RASTER_WIDTH;
    }
    let tile = column_x2 / 2 + row * i32::from(STRATEGIC_MAP_WIDTH);
    TileId::new(u16::try_from(tile).expect("retail home-site scan produced a valid tile"))
}

fn home_site_neighbor_conflicts(owner: Option<TileOwnerTag>, home: Option<TileOwnerTag>) -> bool {
    match owner {
        None => home.is_some(),
        Some(owner) => owner.get() < NationId::COUNT && Some(owner) != home,
    }
}

/// Validates a capital-site click the way `TCitySiteView::HandleMapClickByInteractionMode` does
/// before opening `ShowNewCityDialog`.
pub fn validate_capital_site_selection(
    state: &GameState,
    nation: MajorNationId,
    tile: TileId,
) -> Result<CapitalSite, CitySiteError> {
    let tile_state = &state.world[tile];
    let active = TileOwnerTag::from_nation(nation.nation());
    if tile_state.owner_nation != Some(active) {
        return Err(CitySiteError::NotOwned);
    }
    if !supports_city_site_terrain(tile_state.terrain) {
        return Err(CitySiteError::UnsupportedTerrain);
    }
    if !is_valid_secondary_nation_home_tile_candidate(&state.world, tile) {
        return Err(CitySiteError::InvalidHomeSite);
    }
    Ok(CapitalSite { tile, nation })
}

/// Tile marking from `TMapMgr::PlaceCity` that fits the current [`TileState`] fields.
pub fn place_city(world: &mut StrategicMap, tile: TileId, owner_nation: TileOwnerTag) {
    world.tile_mut(tile).flags = TileFlags::PLACED_CITY_STATE;
    flood_fill_region_marker(world, tile, owner_nation);
}

/// Confirm the New City dialog: `PlaceCity` then advance into the strategic-map phase.
///
/// Retail follows with `StartNextPhase()` (phase 2 → naming/AI homes → strategic map event).
/// This port applies the human capital binding and lands on phase `5`, the strategic-map
/// display phase after `case 4`.
pub fn confirm_capital_site(state: &mut GameState, site: CapitalSite) {
    let tile = site.tile();
    let owner = TileOwnerTag::from_nation(site.nation().nation());
    place_city(&mut state.world, tile, owner);
    bind_home_city_tile(state, site.nation(), tile);
    state.turn.phase = crate::PhaseCode::STRATEGIC_MAP;
}

/// Introductory/Easy path: no city-site selector; bind the frog-city marker and enter the map.
pub fn enter_strategic_map_without_capital_selection(state: &mut GameState, nation: MajorNationId) {
    let home = state
        .nations
        .city(nation)
        .home_town
        .map(TownState::tile)
        .expect("generated Introductory/Easy game has a home town tile");
    bind_home_city_tile(state, nation, home);
    state.turn.phase = crate::PhaseCode::STRATEGIC_MAP;
}

fn bind_home_city_tile(state: &mut GameState, nation: MajorNationId, tile: TileId) {
    let nation_state = state.nations.major_mut(nation);
    nation_state.common.home_tile = Some(tile);
    nation_state.city.home_town = Some(TownState::for_frog_city(tile));
}

fn flood_fill_region_marker(world: &mut StrategicMap, tile: TileId, owner_nation: TileOwnerTag) {
    let geometry = world.geometry();
    let marker = next_region_marker(world);
    world.tile_mut(tile).region = Some(marker);
    for neighbor in geometry.neighbors(tile).into_iter().flatten() {
        let neighbor_state = world.tile_mut(neighbor);
        if neighbor_state.owner_nation != Some(owner_nation) {
            continue;
        }
        if neighbor_state.region.is_some() {
            continue;
        }
        neighbor_state.region = Some(marker);
    }
}

fn next_region_marker(world: &StrategicMap) -> RegionId {
    // Retail `g_nNextRegionMarkerId` starts at 1, not 0.
    let max = world
        .iter()
        .filter_map(|tile| tile.region)
        .map(RegionId::get)
        .max()
        .unwrap_or(0);
    RegionId::new(max + 1)
}

/// `EvaluateTerrainFlowCrossNationBoundaryToSea` (0x00563b70): try both ends of the
/// sprite-defined river chain. A candidate qualifies only when one walk reaches
/// water or the map edge without crossing into a differently owned tile.
fn river_reaches_sea_without_crossing_nation(
    world: &StrategicMap,
    geometry: &MapGeometry,
    start: TileId,
) -> bool {
    let start_owner = world[start].owner_nation;
    let Some(flow_type) = world[start].river.and_then(|river| river.flow_type()) else {
        return false;
    };
    for (attempt, mut direction) in TERRAIN_FLOW_DIRECTIONS[flow_type].into_iter().enumerate() {
        let mut crossed_boundary = false;
        let mut current = start;

        for _ in 0..100 {
            let Some(next) = geometry.neighbor(current, direction) else {
                return !crossed_boundary;
            };
            current = next;
            let tile = &world[current];
            if tile.terrain == TerrainKind::Water {
                return !crossed_boundary;
            }

            let Some(next_flow_type) = tile.river.and_then(|river| river.flow_type()) else {
                break;
            };
            if tile.owner_nation != start_owner {
                if attempt != 0 {
                    return false;
                }
                crossed_boundary = true;
            }

            let incoming = direction.opposite();
            let pair = TERRAIN_FLOW_DIRECTIONS[next_flow_type];
            direction = if pair[0] == incoming {
                pair[1]
            } else if pair[1] == incoming {
                pair[0]
            } else {
                break;
            };
        }
    }
    false
}

/// `TraceTerrainFlowToNearestSeaTile` for port-zone creation.
pub(crate) fn trace_terrain_flow_to_nearest_sea_tile(
    world: &StrategicMap,
    start: TileId,
) -> Option<TileId> {
    let geometry = world.geometry();
    let flow_type = world[start].river.and_then(|river| river.flow_type())?;

    for mut direction in TERRAIN_FLOW_DIRECTIONS[flow_type] {
        let mut current = start;
        for _ in 0..100 {
            let Some(next) = geometry.neighbor(current, direction) else {
                break;
            };
            current = next;
            let tile = &world[current];
            if tile.terrain == TerrainKind::Water {
                return Some(current);
            }

            let Some(next_flow_type) = tile.river.and_then(|river| river.flow_type()) else {
                break;
            };
            let incoming = direction.opposite();
            let pair = TERRAIN_FLOW_DIRECTIONS[next_flow_type];
            direction = if pair[0] == incoming {
                pair[1]
            } else if pair[1] == incoming {
                pair[0]
            } else {
                break;
            };
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    fn initial_seed_one_preview() -> crate::RandomSetupPreview {
        let mut sea_zone_marker_crt = RetailCrtRng::from_state(1);
        let _ = sea_zone_marker_crt.next_rand();
        generate_random_setup_preview_with_clock_seed(
            b"Woopnist",
            MapTopology::Wrapping,
            1,
            sea_zone_marker_crt,
        )
    }

    fn normal_start() -> GameState {
        let preview = initial_seed_one_preview();
        create_random_game(&preview, MajorNationId::new(6), Difficulty::Normal, 1)
    }

    #[test]
    fn normal_and_harder_require_capital_selection() {
        assert!(!requires_capital_site_selection(Difficulty::Introductory));
        assert!(!requires_capital_site_selection(Difficulty::Easy));
        assert!(requires_capital_site_selection(Difficulty::Normal));
        assert!(requires_capital_site_selection(Difficulty::Hard));
    }

    #[test]
    fn confirm_capital_site_places_city_and_enters_strategic_map_phase() {
        let mut state = normal_start();
        assert_eq!(state.turn.phase, crate::PhaseCode::CAPITAL_SELECTION);
        assert_eq!(
            state.nations.majors[MajorNationId::new(6)].common.home_tile,
            None
        );

        let tile = (0..TileId::COUNT)
            .map(TileId::new)
            .find(|&tile| {
                let t = &state.world[tile];
                t.owner_nation == Some(TileOwnerTag::new(6))
                    && supports_city_site_terrain(t.terrain)
            })
            .expect("human owns some city-capable terrain");

        // Force a valid sea neighbor so the candidate check is deterministic.
        let geometry = state.world.geometry();
        let sea = geometry
            .neighbors(tile)
            .into_iter()
            .flatten()
            .next()
            .expect("interior tiles still have neighbors on a wrapping map");
        state.world.tile_mut(sea).terrain = TerrainKind::Water;
        state.world.tile_mut(sea).owner_nation = Some(TileOwnerTag::new(6));
        state.world.tile_mut(sea).action = None;
        for direction in HexDirection::ALL {
            let around = home_site_scan_neighbor(sea, direction);
            state.world.tile_mut(around).owner_nation = Some(TileOwnerTag::new(6));
        }

        let site = validate_capital_site_selection(&state, MajorNationId::new(6), tile).unwrap();
        confirm_capital_site(&mut state, site);

        assert_eq!(state.turn.phase, crate::PhaseCode::STRATEGIC_MAP);
        assert_eq!(state.world[tile].flags, TileFlags::PLACED_CITY_STATE);
        assert!(state.world[tile].flags.is_city());
        assert_eq!(
            state.nations.majors[MajorNationId::new(6)].common.home_tile,
            Some(tile)
        );
        assert!(
            state.world[tile].region.is_some(),
            "PlaceCity flood-fills a region"
        );
        assert_eq!(
            state.nations.majors[MajorNationId::new(6)]
                .city
                .home_town
                .map(TownState::tile),
            Some(tile)
        );
    }

    #[test]
    fn easy_path_binds_frog_city_without_selector() {
        let preview = initial_seed_one_preview();
        let mut state = create_random_game(&preview, MajorNationId::new(6), Difficulty::Easy, 1);
        enter_strategic_map_without_capital_selection(&mut state, MajorNationId::new(6));
        assert_eq!(state.turn.phase, crate::PhaseCode::STRATEGIC_MAP);
        assert_eq!(
            state.nations.majors[MajorNationId::new(6)].common.home_tile,
            Some(TileId::new(0))
        );
    }

    #[test]
    fn rejects_unowned_or_mountain_tiles() {
        let state = normal_start();
        let foreign = (0..TileId::COUNT)
            .map(TileId::new)
            .find(|&tile| state.world[tile].owner_nation != Some(TileOwnerTag::new(6)))
            .unwrap();
        assert_eq!(
            validate_capital_site_selection(&state, MajorNationId::new(6), foreign),
            Err(CitySiteError::NotOwned)
        );
    }

    #[test]
    fn home_site_sea_scan_uses_its_retail_edge_wrap_and_owner_test() {
        let owner = TileOwnerTag::new(6);
        let mut world = StrategicMap::new(
            MapTopology::Bounded,
            vec![crate::TileState::default(); crate::STRATEGIC_TILE_COUNT],
        )
        .unwrap();
        for index in 0..TileId::COUNT {
            world.tile_mut(TileId::new(index)).owner_nation = Some(owner);
        }
        let candidate = TileId::new(0);
        let wrapped_sea = TileId::new(107);
        world.tile_mut(wrapped_sea).terrain = TerrainKind::Water;

        assert!(is_valid_secondary_nation_home_tile_candidate(
            &world, candidate
        ));

        world.tile_mut(TileId::new(106)).owner_nation = None;
        assert!(!is_valid_secondary_nation_home_tile_candidate(
            &world, candidate
        ));
    }

    #[test]
    fn river_walk_tries_both_ends_and_rejects_a_cross_nation_chain() {
        let mut world = StrategicMap::new(
            MapTopology::Bounded,
            vec![crate::TileState::default(); crate::STRATEGIC_TILE_COUNT],
        )
        .unwrap();
        let geometry = world.geometry();
        let start = geometry.tile(10, 10).unwrap();
        let south_east = geometry.neighbor(start, HexDirection::SouthEast).unwrap();
        let water = geometry.neighbor(south_east, HexDirection::East).unwrap();
        let owner = TileOwnerTag::new(6);
        world.tile_mut(start).owner_nation = Some(owner);
        world.tile_mut(start).river = crate::RiverSegment::from_connection_code(1);
        world.tile_mut(south_east).owner_nation = Some(owner);
        world.tile_mut(south_east).river = crate::RiverSegment::from_connection_code(6);
        world.tile_mut(water).terrain = TerrainKind::Water;

        assert!(river_reaches_sea_without_crossing_nation(
            &world, &geometry, start
        ));

        world.tile_mut(south_east).owner_nation = Some(TileOwnerTag::new(5));
        assert!(!river_reaches_sea_without_crossing_nation(
            &world, &geometry, start
        ));
    }
}
