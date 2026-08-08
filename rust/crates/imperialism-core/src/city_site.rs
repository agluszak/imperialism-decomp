//! Capital-site selection (`TCitySiteView`) and `TMapMgr::PlaceCity` for random-game start.

use crate::{
    Difficulty, GameState, MajorNationId, MapGeometry, RegionId, StrategicMap, TerrainKind,
    TileFlags, TileId, TileOwnerTag,
};

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
        for neighbor in geometry.neighbors(tile).into_iter().flatten() {
            let sea = &world[neighbor];
            if sea.terrain != TerrainKind::Water {
                continue;
            }
            is_valid = true;
            for sea_neighbor in geometry.neighbors(neighbor).into_iter().flatten() {
                let around = &world[sea_neighbor];
                if let Some(owner) = around.owner_nation
                    && owner.is_claimed_nation()
                    && Some(owner) != home_nation
                {
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
        && !river_crosses_nation_boundary_to_sea(world, &geometry, tile)
    {
        is_valid = true;
    }
    is_valid
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
    world[tile].flags = TileFlags::PLACED_CITY_STATE;
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
pub fn enter_strategic_map_without_capital_selection(
    state: &mut GameState,
    nation: MajorNationId,
) -> Result<(), CitySiteError> {
    let home = state
        .nations
        .city(nation)
        .home_town_tile
        .ok_or(CitySiteError::InvalidHomeSite)?;
    bind_home_city_tile(state, nation, home);
    state.turn.phase = crate::PhaseCode::STRATEGIC_MAP;
    Ok(())
}

fn bind_home_city_tile(state: &mut GameState, nation: MajorNationId, tile: TileId) {
    let nation_state = state.nations.major_mut(nation);
    nation_state.common.home_tile = Some(tile);
    nation_state.city.home_town_tile = Some(tile);
}

fn flood_fill_region_marker(world: &mut StrategicMap, tile: TileId, owner_nation: TileOwnerTag) {
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

fn next_region_marker(world: &StrategicMap) -> RegionId {
    // Retail `g_nNextRegionMarkerId` starts at 1, not 0.
    let max = world
        .iter()
        .filter_map(|tile| tile.region)
        .map(RegionId::get)
        .max()
        .unwrap_or(0);
    RegionId::new(max.saturating_add(1))
}

/// Simplified retail river-flow boundary check: walk `river_sprite_code` until water or a
/// foreign tile. Returns true when the flow crosses into another claimed nation before sea.
fn river_crosses_nation_boundary_to_sea(
    world: &StrategicMap,
    geometry: &MapGeometry,
    start: TileId,
) -> bool {
    let home = world[start].owner_nation;
    let mut current = start;
    for _ in 0..64 {
        let tile = &world[current];
        if tile.terrain == TerrainKind::Water {
            return false;
        }
        if tile.owner_nation != home
            && let Some(owner) = tile.owner_nation
            && owner.is_claimed_nation()
        {
            return true;
        }
        let Some(direction) = tile.river.and_then(|river| river.flow_direction()) else {
            return false;
        };
        let Some(next) = geometry.neighbor(current, direction) else {
            return false;
        };
        current = next;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Difficulty, MajorNationId, MapTopology, create_random_game,
        generate_random_setup_preview_with_clock_seed,
    };

    fn normal_start() -> GameState {
        let preview =
            generate_random_setup_preview_with_clock_seed(b"Woopnist", MapTopology::Wrapping, 1);
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
            state.nations.major(MajorNationId::new(6)).common.home_tile,
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
        state.world[sea].terrain = TerrainKind::Water;
        state.world[sea].owner_nation = None;
        state.world[sea].action = None;
        for around in geometry.neighbors(sea).into_iter().flatten() {
            let around_state = &mut state.world[around];
            if around_state
                .owner_nation
                .is_some_and(|owner| owner.get() != 6)
            {
                around_state.owner_nation = Some(TileOwnerTag::new(6));
            }
        }

        let site = validate_capital_site_selection(&state, MajorNationId::new(6), tile).unwrap();
        confirm_capital_site(&mut state, site);

        assert_eq!(state.turn.phase, crate::PhaseCode::STRATEGIC_MAP);
        assert_eq!(state.world[tile].flags, TileFlags::PLACED_CITY_STATE);
        assert!(state.world[tile].flags.is_city());
        assert_eq!(
            state.nations.major(MajorNationId::new(6)).common.home_tile,
            Some(tile)
        );
        assert!(
            state.world[tile].region.is_some(),
            "PlaceCity flood-fills a region"
        );
        assert_eq!(
            state.nations.city(MajorNationId::new(6)).home_town_tile,
            Some(tile)
        );
    }

    #[test]
    fn easy_path_binds_frog_city_without_selector() {
        let preview =
            generate_random_setup_preview_with_clock_seed(b"Woopnist", MapTopology::Wrapping, 1);
        let mut state = create_random_game(&preview, MajorNationId::new(6), Difficulty::Easy, 1);
        enter_strategic_map_without_capital_selection(&mut state, MajorNationId::new(6)).unwrap();
        assert_eq!(state.turn.phase, crate::PhaseCode::STRATEGIC_MAP);
        assert_eq!(
            state.nations.major(MajorNationId::new(6)).common.home_tile,
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
}
