//! Capital-site selection (`TCitySiteView`) and `TMapMgr::PlaceCity` for random-game start.

use crate::{
    Difficulty, GameState, HexDirection, MajorNationId, MapGeometry, MapMgr, NationId,
    ResourceKind, ResourceTable, STRATEGIC_MAP_HEIGHT, STRATEGIC_MAP_WIDTH, TerrainKind, TileFlags,
    TileId, TileOwnerTag, all_resources,
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

/// Neighbor-tile yields and food capacity shown by `TPlaceCityDialog::StuffValues`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapitalSiteReport {
    pub yields: ResourceTable<i16>,
    pub total_food: i16,
    pub sustainable_population: i16,
}

impl CapitalSiteReport {
    pub fn visible_resource_count(self) -> i16 {
        all_resources()
            .filter(|&resource| self.yields[resource] != 0)
            .count() as i16
    }
}

impl CitySiteError {
    /// `TSimMgr::GetString` offset into group `0x273b` for a rejected map click.
    pub fn message_offset(self, state: &GameState, tile: TileId) -> i16 {
        match self {
            Self::NotOwned => {
                if state.map()[tile].terrain == TerrainKind::Water {
                    3
                } else {
                    0
                }
            }
            Self::UnsupportedTerrain | Self::InvalidHomeSite => {
                if supports_city_site_terrain(state.map()[tile].terrain)
                    && state.can_build_port_at_tile(tile)
                {
                    2
                } else {
                    1
                }
            }
        }
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
        for tile in TileId::all() {
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

/// `TTown::CalculateCityResources` plus the New City dialog's food-sustain math.
pub fn capital_site_report(state: &GameState, site: CapitalSite) -> CapitalSiteReport {
    let university = &state.technology.city_capabilities_by_nation[site.nation()].university;
    let yields = crate::create_random_game::calculate_city_resources(
        &state.map,
        site.tile(),
        site.nation(),
        university,
    );
    let (total_food, sustainable_population) = sustainable_food_population(&yields);
    CapitalSiteReport {
        yields,
        total_food,
        sustainable_population,
    }
}

fn sustainable_food_population(yields: &ResourceTable<i16>) -> (i16, i16) {
    let mut primary_food = yields[ResourceKind::Grain];
    let mut secondary_food = yields[ResourceKind::Fruit];
    let mut alternate_food = yields[ResourceKind::Fish] + yields[ResourceKind::Livestock];
    let total_food = primary_food + secondary_food + alternate_food;
    let mut sustainable_population = 0_i16;
    for unit in 0..total_food {
        let food_pool = if unit % 4 == 1 {
            &mut secondary_food
        } else if unit % 4 == 3 {
            &mut alternate_food
        } else {
            &mut primary_food
        };
        if *food_pool != 0 {
            *food_pool -= 1;
            sustainable_population += 1;
        }
    }
    (total_food, sustainable_population)
}

/// Tile marking from `TMapMgr::PlaceCity` that fits the current [`TileState`] fields.
pub fn place_city(world: &mut MapMgr, tile: TileId, owner_nation: TileOwnerTag) {
    world[tile].flags = TileFlags::PLACED_CITY_STATE;
    flood_fill_region_marker(world, tile, owner_nation);
}

/// Confirm the New City dialog: `PlaceCity`, then the opening-turn tail.
///
/// Retail follows with `StartNextPhase()` through season advance, technology, and
/// the newspaper.
pub fn confirm_capital_site(
    state: &mut GameState,
    site: CapitalSite,
    story_ids: &[i32],
) -> crate::TurnStop {
    let tile = site.tile();
    let owner = TileOwnerTag::from_nation(site.nation().nation());
    place_city(&mut state.map, tile, owner);
    bind_home_city_tile(state, site.nation(), tile);
    state.advance_turn(story_ids)
}

/// Introductory/Easy path: no city-site selector; bind the frog-city marker and
/// enter the opening-turn tail through the same phase dispatcher.
pub fn enter_strategic_map_without_capital_selection(
    state: &mut GameState,
    nation: MajorNationId,
    story_ids: &[i32],
) -> crate::TurnStop {
    let home = state
        .nations
        .major(nation)
        .towns
        .first()
        .map(|town| town.tile)
        .expect("generated Introductory/Easy game has a home town tile");
    bind_home_city_tile(state, nation, home);
    state.advance_turn(story_ids)
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
    let marker = world.allocate_region_marker();
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

    fn assert_opening_civilians(state: &GameState, nation: MajorNationId, count: usize) {
        let units: Vec<_> = state
            .civilian_units()
            .filter(|(_, unit)| unit.nation() == nation.nation())
            .collect();
        assert_eq!(units.len(), count);
        assert!(
            units
                .iter()
                .all(|unit| *unit.order() == CivilianWorkOrder::Idle)
        );
        assert!(units.iter().all(|unit| unit.location().tile().is_some()));
        let expected_kinds = match count {
            2 => vec![CivilianUnitKind::Prospector, CivilianUnitKind::Engineer],
            5 => vec![
                CivilianUnitKind::Prospector,
                CivilianUnitKind::Engineer,
                CivilianUnitKind::Prospector,
                CivilianUnitKind::Miner,
                CivilianUnitKind::Farmer,
            ],
            _ => panic!("unexpected opening civilian count {count}"),
        };
        let kinds: Vec<_> = units.iter().map(|unit| unit.unit_type()).collect();
        assert_eq!(kinds, expected_kinds);
        let trader = state.nations.city(nation).ship_order_count_by_type[ShipType::Trader];
        assert_eq!(trader, if count == 5 { 8 } else { 2 });
    }

    fn assert_map_centers_on_first_idle_civilian(state: &mut GameState) {
        let civilian = state
            .first_idle_civilian_tile(state.turn().active_nation)
            .expect("opening civilians include an idle unit on the map");
        let expected = state.map().viewport_origin_centered_on(civilian);
        state.center_map_on_first_idle_civilian();
        assert_eq!(state.map_view_origin(), expected);
        let home = state
            .nations
            .major(
                MajorNationId::from_nation(state.turn().active_nation)
                    .expect("active nation is a great power"),
            )
            .common
            .home_tile
            .expect("opening map centering requires a home tile");
        let geometry = state.map().geometry();
        let (home_row, home_column) = geometry.row_column(home);
        let (origin_row, origin_column) = geometry.row_column(state.map_view_origin());
        let row_delta = i32::from(home_row) - i32::from(origin_row);
        let mut column_delta = i32::from(home_column) - i32::from(origin_column);
        if column_delta < 0 {
            column_delta += i32::from(STRATEGIC_MAP_WIDTH);
        }
        assert!(
            (0..7).contains(&row_delta),
            "capital row {home_row} is outside the 7-row viewport from {origin_row}"
        );
        assert!(
            (0..9).contains(&column_delta),
            "capital column {home_column} is outside the 9-column viewport from {origin_column}"
        );
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

        let tile = TileId::all()
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
        state.map[sea].owner_nation = Some(TileOwnerTag::new(0x17));
        state.map[sea].action = None;
        for direction in HexDirection::ALL {
            let around = home_site_scan_neighbor(sea, direction);
            state.map[around].owner_nation = Some(TileOwnerTag::new(6));
        }

        let site = validate_capital_site_selection(&state, MajorNationId::new(6), tile).unwrap();
        let mut story_ids = vec![1; 360];
        story_ids[0] = -1003;
        let stop = confirm_capital_site(&mut state, site, &story_ids);

        assert!(matches!(
            (stop, state.turn.phase),
            (
                crate::TurnStop::TechnologyAdvance,
                crate::PhaseCode::NEWSPAPER
            ) | (crate::TurnStop::Newspaper, crate::PhaseCode::RETURN_TO_MAP)
        ));
        assert_eq!(state.turn.economic_turn, 1);
        assert_eq!(
            state.nations.majors[MajorNationId::new(6)].towns[0].name,
            "FrogCity"
        );
        assert!(state.map[tile].flags.is_city());
        if let Some(province) = state.map[tile].province
            && let Some(capital) = state.map.provinces[province].city_tile()
            && state.map[capital].flags.has_base_transport()
        {
            assert!(
                state.map[capital]
                    .flags
                    .contains(TileFlags::PROVINCE_CAPITAL_FORTIFICATION),
                "InitialMilitia fortifies each owned province capital with base transport"
            );
        }
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
        assert_opening_civilians(&state, MajorNationId::new(6), 2);
        assert!(
            state
                .military_units()
                .any(|(_, unit)| unit.nation() == MajorNationId::new(6).nation()),
            "SetHomeCityTileAndDisplayName runs InitialMilitia for the confirmed capital"
        );
        assert!(
            state.nations.majors[MajorNationId::new(6)]
                .common
                .unit_name_counter
                > 1,
            "InitialMilitia names opening units through persistent country counters"
        );
        for nation in (0..MajorNationId::COUNT)
            .map(MajorNationId::new)
            .filter(|nation| state.nations.major(*nation).common.home_tile.is_some())
        {
            assert_eq!(
                state.diplomacy.standings[nation.nation()][nation.nation()],
                0x100
            );
        }
        assert_map_centers_on_first_idle_civilian(&mut state);
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
        let mut story_ids = vec![1; 360];
        story_ids[0] = -1003;
        let stop = enter_strategic_map_without_capital_selection(
            &mut state,
            MajorNationId::new(6),
            &story_ids,
        );
        assert!(matches!(
            (stop, state.turn.phase),
            (
                crate::TurnStop::TechnologyAdvance,
                crate::PhaseCode::NEWSPAPER
            ) | (crate::TurnStop::Newspaper, crate::PhaseCode::RETURN_TO_MAP)
        ));
        assert_eq!(state.turn.economic_turn, 1);
        assert_eq!(
            state.nations.majors[MajorNationId::new(6)].common.home_tile,
            Some(home)
        );
        assert!(
            state
                .military_units()
                .any(|(_, unit)| unit.nation() == MajorNationId::new(6).nation()),
            "SetHomeCityTileAndDisplayName runs InitialMilitia for the Easy-path capital"
        );
        state.rebuild_nation_resource_yields(MajorNationId::new(6));
        assert_opening_civilians(&state, MajorNationId::new(6), 2);
        assert_map_centers_on_first_idle_civilian(&mut state);
    }

    #[test]
    fn introductory_path_grants_five_human_civilians_and_centers_on_the_first() {
        let preview = initial_seed_one_preview();
        let mut state = create_random_game(
            &preview,
            MajorNationId::new(6),
            Difficulty::Introductory,
            "Testland",
            true,
            1,
            &crate::test_support::random_game_names(),
        );
        enter_strategic_map_without_capital_selection(&mut state, MajorNationId::new(6), &[]);
        assert_opening_civilians(&state, MajorNationId::new(6), 5);
        for nation in MajorNationId::all() {
            if nation == MajorNationId::new(6)
                || state.nations.major(nation).common.home_tile.is_none()
            {
                continue;
            }
            assert_opening_civilians(&state, nation, 2);
        }
        assert_map_centers_on_first_idle_civilian(&mut state);
    }

    #[test]
    fn new_city_food_uses_the_grain_fruit_alternate_rotation() {
        let mut yields = ResourceTable::default();
        yields[ResourceKind::Grain] = 4;
        yields[ResourceKind::Fruit] = 1;
        yields[ResourceKind::Fish] = 1;
        yields[ResourceKind::Livestock] = 1;
        // Rotation is grain, fruit, grain, alternate. Fruit runs out after the
        // first fruit slot, so later fruit beats are skipped.
        assert_eq!(sustainable_food_population(&yields), (7, 6));

        yields = ResourceTable::default();
        yields[ResourceKind::Grain] = 2;
        yields[ResourceKind::Timber] = 3;
        // Only `total_food` beats run, so the second grain slot (unit 2) never happens.
        assert_eq!(sustainable_food_population(&yields), (2, 1));
        let report = CapitalSiteReport {
            yields,
            total_food: 2,
            sustainable_population: 1,
        };
        assert_eq!(report.visible_resource_count(), 2);
    }

    #[test]
    fn home_site_sea_scan_uses_its_retail_edge_wrap_and_owner_test() {
        let owner = TileOwnerTag::new(6);
        let mut world = MapMgr::new(
            MapTopology::Bounded,
            vec![crate::TileState::default(); crate::STRATEGIC_TILE_COUNT],
        );
        for tile in TileId::all() {
            world[tile].owner_nation = Some(owner);
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
