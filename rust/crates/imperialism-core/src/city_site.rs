//! Capital-site selection (`TCitySiteView`) and `TMapMgr::PlaceCity` for random-game start.

use crate::{
    Difficulty, GameState, HexDirection, MajorNationId, MapGeometry, MapMgr, NationId, RegionId,
    STRATEGIC_MAP_HEIGHT, STRATEGIC_MAP_WIDTH, TerrainKind, TileFlags, TileId, TileOwnerTag,
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

impl MapMgr {
    /// Retail `TMapMgr::SeedValidCitySiteCandidateTilesForNation`.
    pub(crate) fn seed_valid_city_site_candidate_tiles_for_nation(
        &mut self,
        nation: MajorNationId,
    ) {
        let owner = TileOwnerTag::from_nation(nation.nation());
        self.recruit_search_active = true;
        for index in 0..TileId::COUNT {
            let tile = TileId::new(index);
            let is_candidate = {
                let state = &self[tile];
                state.owner_nation == Some(owner)
                    && !matches!(
                        state.terrain,
                        TerrainKind::Hills | TerrainKind::Mountain | TerrainKind::Swamp
                    )
                    && is_valid_secondary_nation_home_tile_candidate(self, tile)
            };
            self[tile].recruit_search_visited = u8::from(!is_candidate);
        }
    }
}

/// Sea-neighbor / river-flow check from `TMapMgr::IsValidSecondaryNationHomeTileCandidate`.
pub fn is_valid_secondary_nation_home_tile_candidate(world: &MapMgr, tile: TileId) -> bool {
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
        && tile_state.river().is_some()
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
    let tile_state = &state.map[tile];
    let active = TileOwnerTag::from_nation(nation.nation());
    if tile_state.owner_nation != Some(active) {
        return Err(CitySiteError::NotOwned);
    }
    if !supports_city_site_terrain(tile_state.terrain) {
        return Err(CitySiteError::UnsupportedTerrain);
    }
    if !is_valid_secondary_nation_home_tile_candidate(&state.map, tile) {
        return Err(CitySiteError::InvalidHomeSite);
    }
    Ok(CapitalSite { tile, nation })
}

/// Tile marking from `TMapMgr::PlaceCity` that fits the current [`TileState`] fields.
pub fn place_city(world: &mut MapMgr, tile: TileId, owner_nation: TileOwnerTag) {
    world[tile].flags = TileFlags::PLACED_CITY_STATE;
    flood_fill_region_marker(world, tile, owner_nation);
}

/// Confirm the New City dialog: `PlaceCity`, then enter the opening-turn tail.
///
/// Retail follows with `StartNextPhase()` through season advance, technology, and
/// the newspaper.
pub fn confirm_capital_site(state: &mut GameState, site: CapitalSite) -> crate::TurnStop {
    let tile = site.tile();
    let owner = TileOwnerTag::from_nation(site.nation().nation());
    place_city(&mut state.map, tile, owner);
    bind_home_city_tile(state, site.nation(), tile);
    state.turn.phase = crate::PhaseCode::SEASON_ADVANCE;
    state.advance_turn()
}

/// Introductory/Easy path: no city-site selector; bind the frog-city marker and
/// enter the opening-turn tail.
pub fn enter_strategic_map_without_capital_selection(
    state: &mut GameState,
    nation: MajorNationId,
) -> crate::TurnStop {
    let home = state
        .nations
        .major(nation)
        .towns
        .first()
        .map(|town| town.tile)
        .expect("generated Introductory/Easy game has a home town tile");
    bind_home_city_tile(state, nation, home);
    state.turn.phase = crate::PhaseCode::SEASON_ADVANCE;
    state.advance_turn()
}

fn bind_home_city_tile(state: &mut GameState, nation: MajorNationId, tile: TileId) {
    let nation_state = state.nations.major_mut(nation);
    nation_state.common.home_tile = Some(tile);
    let home_town = nation_state
        .towns
        .first_mut()
        .expect("great power capital placement requires its FrogCity marker");
    home_town.name = "FrogCity".to_owned();
    home_town.tile = tile;
    home_town.owner_nation = nation.nation();
}

fn flood_fill_region_marker(world: &mut MapMgr, tile: TileId, owner_nation: TileOwnerTag) {
    let geometry = world.geometry();
    let marker = next_region_marker(world);
    world[tile].region = Some(marker);
    for neighbor in geometry.neighbors(tile).into_iter().flatten() {
        let neighbor_state = &mut world[neighbor];
        if neighbor_state.owner_nation != Some(owner_nation) {
            continue;
        }
        if neighbor_state.region.is_some() {
            continue;
        }
        neighbor_state.region = Some(marker);
    }
}

fn next_region_marker(world: &MapMgr) -> RegionId {
    // Retail `g_nNextRegionMarkerId` starts at 1, not 0.
    let max = world
        .tiles
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
    world: &MapMgr,
    geometry: &MapGeometry,
    start: TileId,
) -> bool {
    let start_owner = world[start].owner_nation;
    let Some(flow_type) = world[start].river().and_then(|river| river.flow_type()) else {
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

            let Some(next_flow_type) = tile.river().and_then(|river| river.flow_type()) else {
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
    world: &MapMgr,
    start: TileId,
) -> Option<TileId> {
    let geometry = world.geometry();
    let flow_type = world[start].river().and_then(|river| river.flow_type())?;

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

            let Some(next_flow_type) = tile.river().and_then(|river| river.flow_type()) else {
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
        create_random_game(
            &preview,
            MajorNationId::new(6),
            Difficulty::Normal,
            "Testland",
            true,
            1,
            &crate::test_support::random_game_names(),
        )
    }

    #[test]
    fn confirm_capital_site_places_city_and_enters_technology_advances_phase() {
        let mut state = normal_start();
        assert_eq!(state.turn.phase, crate::PhaseCode::CAPITAL_SELECTION);
        assert_eq!(
            state.nations.majors[MajorNationId::new(6)].common.home_tile,
            None
        );

        let tile = (0..TileId::COUNT)
            .map(TileId::new)
            .find(|&tile| {
                let t = &state.map[tile];
                t.owner_nation == Some(TileOwnerTag::new(6))
                    && supports_city_site_terrain(t.terrain)
            })
            .expect("human owns some city-capable terrain");

        // Force a valid sea neighbor so the candidate check is deterministic.
        let geometry = state.map.geometry();
        let sea = geometry
            .neighbors(tile)
            .into_iter()
            .flatten()
            .next()
            .expect("interior tiles still have neighbors on a wrapping map");
        state.map[sea].terrain = TerrainKind::Water;
        state.map[sea].owner_nation = Some(TileOwnerTag::new(6));
        state.map[sea].action = None;
        for direction in HexDirection::ALL {
            let around = home_site_scan_neighbor(sea, direction);
            state.map[around].owner_nation = Some(TileOwnerTag::new(6));
        }

        let site = validate_capital_site_selection(&state, MajorNationId::new(6), tile).unwrap();
        confirm_capital_site(&mut state, site);

        assert!(matches!(
            state.turn.phase,
            crate::PhaseCode::TECHNOLOGY_ADVANCES | crate::PhaseCode::NEWSPAPER
        ));
        assert_eq!(state.turn.economic_turn, 1);
        assert_eq!(
            state.nations.majors[MajorNationId::new(6)].towns[0].name,
            "FrogCity"
        );
        assert_eq!(state.map[tile].flags, TileFlags::PLACED_CITY_STATE);
        assert!(state.map[tile].flags.is_city());
        assert_eq!(
            state.nations.majors[MajorNationId::new(6)].common.home_tile,
            Some(tile)
        );
        assert!(
            state.map[tile].region.is_some(),
            "PlaceCity flood-fills a region"
        );
        assert_eq!(
            state.nations.majors[MajorNationId::new(6)]
                .towns
                .first()
                .map(|town| town.tile),
            Some(tile)
        );
    }

    #[test]
    fn easy_path_binds_frog_city_without_selector() {
        let preview = initial_seed_one_preview();
        let mut state = create_random_game(
            &preview,
            MajorNationId::new(6),
            Difficulty::Easy,
            "Testland",
            true,
            1,
            &crate::test_support::random_game_names(),
        );
        let home = state.nations.majors[MajorNationId::new(6)]
            .towns
            .first()
            .map(|town| town.tile)
            .expect("Easy setup places the human Frog City");
        assert_eq!(
            state.nations.majors[MajorNationId::new(6)].towns[0].name,
            "FrogCity"
        );
        assert_eq!(state.map[home].owner_nation, Some(TileOwnerTag::new(6)));
        assert!(state.map[home].flags.is_city());
        enter_strategic_map_without_capital_selection(&mut state, MajorNationId::new(6));
        assert!(matches!(
            state.turn.phase,
            crate::PhaseCode::TECHNOLOGY_ADVANCES | crate::PhaseCode::NEWSPAPER
        ));
        assert_eq!(state.turn.economic_turn, 1);
        assert_eq!(
            state.nations.majors[MajorNationId::new(6)].common.home_tile,
            Some(home)
        );
        state.rebuild_nation_resource_yields(MajorNationId::new(6));
    }

    #[test]
    fn home_site_sea_scan_uses_its_retail_edge_wrap_and_owner_test() {
        let owner = TileOwnerTag::new(6);
        let mut world = MapMgr::new(
            MapTopology::Bounded,
            vec![crate::TileState::default(); crate::STRATEGIC_TILE_COUNT],
        );
        for index in 0..TileId::COUNT {
            world[TileId::new(index)].owner_nation = Some(owner);
        }
        let candidate = TileId::new(0);
        let wrapped_sea = TileId::new(107);
        world[wrapped_sea].terrain = TerrainKind::Water;

        assert!(is_valid_secondary_nation_home_tile_candidate(
            &world, candidate
        ));

        world[TileId::new(106)].owner_nation = None;
        assert!(!is_valid_secondary_nation_home_tile_candidate(
            &world, candidate
        ));
    }

    #[test]
    fn river_walk_tries_both_ends_and_rejects_a_cross_nation_chain() {
        let mut world = MapMgr::new(
            MapTopology::Bounded,
            vec![crate::TileState::default(); crate::STRATEGIC_TILE_COUNT],
        );
        let geometry = world.geometry();
        let start = geometry.tile(10, 10).unwrap();
        let south_east = geometry.neighbor(start, HexDirection::SouthEast).unwrap();
        let water = geometry.neighbor(south_east, HexDirection::East).unwrap();
        let owner = TileOwnerTag::new(6);
        world[start].owner_nation = Some(owner);
        world[start].rendering.river_sprite = crate::RiverSprite::canonical_for_connection(1);
        world[south_east].owner_nation = Some(owner);
        world[south_east].rendering.river_sprite = crate::RiverSprite::canonical_for_connection(6);
        world[water].terrain = TerrainKind::Water;

        assert!(river_reaches_sea_without_crossing_nation(
            &world, &geometry, start
        ));

        world[south_east].owner_nation = Some(TileOwnerTag::new(5));
        assert!(!river_reaches_sea_without_crossing_nation(
            &world, &geometry, start
        ));
    }
}
