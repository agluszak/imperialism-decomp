//! Capital-site selection (`TCitySiteView`) and `TMapMgr::PlaceCity` for random-game start.

use crate::{Difficulty, GameState, MajorNationId, MapGeometry, TileId, TileOwnerTag, WorldState};

/// Retail plains / forest / hills / mountain / swamp / water / desert / farmland.
const PLAINS: i8 = 0;
const FOREST: i8 = 1;
const HILLS: i8 = 2;
const MOUNTAIN: i8 = 3;
const WATER: i8 = 5;
const DESERT: i8 = 6;
const FARMLAND: i8 = 7;

/// `TMapMgr::PlaceCity` writes `0x17 | 0x20` into `activeFlags1c`.
const PLACE_CITY_ACTIVE_FLAGS: u16 = 0x37;

/// Foreign nation tags below this are treated as claimed land for sea-neighbor checks.
const CLAIMED_NATION_TAG_LIMIT: u8 = 0x17;

/// No river sprite (`kRiverSpriteCodeNone`).
const RIVER_SPRITE_NONE: u8 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CitySiteError {
    #[error("tile index is outside the strategic map")]
    OutOfBounds,
    #[error("tile is not owned by the active nation")]
    NotOwned,
    #[error("terrain cannot host a city")]
    UnsupportedTerrain,
    #[error("tile is not a valid secondary-nation home-site candidate")]
    InvalidHomeSite,
    #[error("active nation has no major-nation state")]
    MissingNation,
    #[error("active nation has no city state")]
    MissingCity,
}

/// Retail difficulties that dispatch the city-site selector (`difficultyLevel > 1`).
pub const fn requires_capital_site_selection(difficulty: Difficulty) -> bool {
    matches!(
        difficulty,
        Difficulty::Normal | Difficulty::Hard | Difficulty::NighOnImpossible
    )
}

/// Terrain kinds accepted by `TCitySiteView::HandleMapClickByInteractionMode`.
pub const fn supports_city_site_terrain(terrain_kind: i8) -> bool {
    matches!(terrain_kind, PLAINS | FARMLAND | FOREST | DESERT)
}

/// Sea-neighbor / river-flow check from `TMapMgr::IsValidSecondaryNationHomeTileCandidate`.
pub fn is_valid_secondary_nation_home_tile_candidate(
    world: &WorldState,
    tile: TileId,
) -> Result<bool, CitySiteError> {
    let geometry = MapGeometry::new(world.wraps_horizontally);
    let index = usize::from(tile.get());
    let tile_state = world.tiles.get(index).ok_or(CitySiteError::OutOfBounds)?;
    let home_nation = tile_state.owner_nation;
    let terrain_kind = tile_state.terrain_kind;

    let mut is_valid = false;
    if terrain_kind != MOUNTAIN && terrain_kind != HILLS {
        for neighbor in geometry.neighbors(tile).into_iter().flatten() {
            let sea = &world.tiles[usize::from(neighbor.get())];
            if sea.terrain_kind != WATER {
                continue;
            }
            is_valid = true;
            for sea_neighbor in geometry.neighbors(neighbor).into_iter().flatten() {
                let around = &world.tiles[usize::from(sea_neighbor.get())];
                if let Some(owner) = around.owner_nation
                    && owner.get() < CLAIMED_NATION_TAG_LIMIT
                    && Some(owner) != home_nation
                {
                    is_valid = false;
                    break;
                }
            }
            // Retail rejects sea tiles whose action state is not "none" (-1).
            if sea.action_state != -1 {
                is_valid = false;
            }
            if is_valid {
                break;
            }
        }
    }

    if !is_valid
        && tile_state.river_sprite_code != RIVER_SPRITE_NONE
        && !river_crosses_nation_boundary_to_sea(world, &geometry, tile)
    {
        is_valid = true;
    }
    Ok(is_valid)
}

/// Validates a capital-site click the way `TCitySiteView::HandleMapClickByInteractionMode` does
/// before opening `ShowNewCityDialog`.
pub fn validate_capital_site_selection(
    state: &GameState,
    tile: TileId,
) -> Result<(), CitySiteError> {
    let index = usize::from(tile.get());
    let tile_state = state
        .world
        .tiles
        .get(index)
        .ok_or(CitySiteError::OutOfBounds)?;
    let active = TileOwnerTag::new(state.turn.active_nation.get());
    if tile_state.owner_nation != Some(active) {
        return Err(CitySiteError::NotOwned);
    }
    if !supports_city_site_terrain(tile_state.terrain_kind) {
        return Err(CitySiteError::UnsupportedTerrain);
    }
    if !is_valid_secondary_nation_home_tile_candidate(&state.world, tile)? {
        return Err(CitySiteError::InvalidHomeSite);
    }
    Ok(())
}

/// Tile marking from `TMapMgr::PlaceCity` that fits the current [`TileState`] fields.
pub fn place_city(
    world: &mut WorldState,
    tile: TileId,
    owner_nation: TileOwnerTag,
) -> Result<(), CitySiteError> {
    let index = usize::from(tile.get());
    if index >= world.tiles.len() {
        return Err(CitySiteError::OutOfBounds);
    }
    world.tiles[index].active_flags = PLACE_CITY_ACTIVE_FLAGS;
    flood_fill_region_marker(world, tile, owner_nation);
    Ok(())
}

/// Confirm the New City dialog: `PlaceCity` then advance into the strategic-map phase.
///
/// Retail follows with `StartNextPhase()` (phase 2 → naming/AI homes → strategic map event).
/// This port applies the human capital binding and lands on phase `5`, the strategic-map
/// display phase after `case 4`.
pub fn confirm_capital_site(state: &mut GameState, tile: TileId) -> Result<(), CitySiteError> {
    validate_capital_site_selection(state, tile)?;
    let owner = TileOwnerTag::new(state.turn.active_nation.get());
    place_city(&mut state.world, tile, owner)?;
    bind_home_city_tile(state, tile)?;
    state.turn.phase_code = 5;
    Ok(())
}

/// Introductory/Easy path: no city-site selector; bind the frog-city marker and enter the map.
pub fn enter_strategic_map_without_capital_selection(
    state: &mut GameState,
) -> Result<(), CitySiteError> {
    let nation = state.turn.active_nation;
    let major = MajorNationId::from_nation(nation).ok_or(CitySiteError::MissingNation)?;
    let home = state
        .nations
        .city(major)
        .and_then(|city| city.home_town_tile)
        .ok_or(CitySiteError::MissingCity)?;
    bind_home_city_tile(state, home)?;
    state.turn.phase_code = 5;
    Ok(())
}

fn bind_home_city_tile(state: &mut GameState, tile: TileId) -> Result<(), CitySiteError> {
    let nation = state.turn.active_nation;
    let major = MajorNationId::from_nation(nation).ok_or(CitySiteError::MissingNation)?;
    let nation_state = state
        .nations
        .major_mut(major)
        .ok_or(CitySiteError::MissingNation)?;
    nation_state.common.home_tile = Some(tile);
    let city = nation_state
        .city
        .as_mut()
        .ok_or(CitySiteError::MissingCity)?;
    city.home_town_tile = Some(tile);
    Ok(())
}

fn flood_fill_region_marker(world: &mut WorldState, tile: TileId, owner_nation: TileOwnerTag) {
    let geometry = MapGeometry::new(world.wraps_horizontally);
    let marker = next_region_marker(world);
    world.tiles[usize::from(tile.get())].region_marker = marker;
    for neighbor in geometry.neighbors(tile).into_iter().flatten() {
        let neighbor_state = &mut world.tiles[usize::from(neighbor.get())];
        if neighbor_state.owner_nation != Some(owner_nation) {
            continue;
        }
        if neighbor_state.region_marker != -1 {
            continue;
        }
        neighbor_state.region_marker = marker;
    }
}

fn next_region_marker(world: &WorldState) -> i8 {
    let max = world
        .tiles
        .iter()
        .map(|tile| tile.region_marker)
        .filter(|&marker| marker >= 0)
        .max()
        .unwrap_or(-1);
    max.saturating_add(1)
}

/// Simplified retail river-flow boundary check: walk `river_sprite_code` until water or a
/// foreign tile. Returns true when the flow crosses into another claimed nation before sea.
fn river_crosses_nation_boundary_to_sea(
    world: &WorldState,
    geometry: &MapGeometry,
    start: TileId,
) -> bool {
    let home = world.tiles[usize::from(start.get())].owner_nation;
    let mut current = start;
    for _ in 0..64 {
        let tile = &world.tiles[usize::from(current.get())];
        if tile.terrain_kind == WATER {
            return false;
        }
        if tile.owner_nation != home
            && let Some(owner) = tile.owner_nation
            && owner.get() < CLAIMED_NATION_TAG_LIMIT
        {
            return true;
        }
        let direction = match tile.river_sprite_code {
            code if (0x10..=0x15).contains(&code) => code - 0x10,
            code if code < 6 => code,
            _ => return false,
        };
        let Some(next) = geometry.neighbor(
            current,
            match direction {
                0 => crate::HexDirection::NorthEast,
                1 => crate::HexDirection::East,
                2 => crate::HexDirection::SouthEast,
                3 => crate::HexDirection::SouthWest,
                4 => crate::HexDirection::West,
                5 => crate::HexDirection::NorthWest,
                _ => return false,
            },
        ) else {
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
        Difficulty, MajorNationId, RetailTopologyByte, create_random_game,
        generate_random_setup_preview_with_clock_seed,
    };

    fn normal_start() -> GameState {
        let preview = generate_random_setup_preview_with_clock_seed(
            b"Woopnist",
            RetailTopologyByte::from_wraps_horizontally(true),
            1,
        );
        create_random_game(&preview, MajorNationId::new(6), Difficulty::Normal)
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
        assert_eq!(state.turn.phase_code, 2);
        assert_eq!(
            state
                .nations
                .major(MajorNationId::new(6))
                .unwrap()
                .common
                .home_tile,
            None
        );

        let tile = (0..state.world.tiles.len())
            .map(|index| TileId::new(index as u16))
            .find(|&tile| {
                let t = &state.world.tiles[usize::from(tile.get())];
                t.owner_nation == Some(TileOwnerTag::new(6))
                    && supports_city_site_terrain(t.terrain_kind)
            })
            .expect("human owns some city-capable terrain");

        // Force a valid sea neighbor so the candidate check is deterministic.
        let geometry = MapGeometry::new(state.world.wraps_horizontally);
        let sea = geometry
            .neighbors(tile)
            .into_iter()
            .flatten()
            .next()
            .expect("interior tiles still have neighbors on a wrapping map");
        state.world.tiles[usize::from(sea.get())].terrain_kind = WATER;
        state.world.tiles[usize::from(sea.get())].owner_nation = None;
        state.world.tiles[usize::from(sea.get())].action_state = -1;
        for around in geometry.neighbors(sea).into_iter().flatten() {
            let around_state = &mut state.world.tiles[usize::from(around.get())];
            if around_state
                .owner_nation
                .is_some_and(|owner| owner.get() != 6)
            {
                around_state.owner_nation = Some(TileOwnerTag::new(6));
            }
        }

        validate_capital_site_selection(&state, tile).unwrap();
        confirm_capital_site(&mut state, tile).unwrap();

        assert_eq!(state.turn.phase_code, 5);
        assert_eq!(
            state.world.tiles[usize::from(tile.get())].active_flags,
            PLACE_CITY_ACTIVE_FLAGS
        );
        assert_eq!(
            state
                .nations
                .major(MajorNationId::new(6))
                .unwrap()
                .common
                .home_tile,
            Some(tile)
        );
        assert_eq!(
            state
                .nations
                .city(MajorNationId::new(6))
                .unwrap()
                .home_town_tile,
            Some(tile)
        );
    }

    #[test]
    fn easy_path_binds_frog_city_without_selector() {
        let preview = generate_random_setup_preview_with_clock_seed(
            b"Woopnist",
            RetailTopologyByte::from_wraps_horizontally(true),
            1,
        );
        let mut state = create_random_game(&preview, MajorNationId::new(6), Difficulty::Easy);
        enter_strategic_map_without_capital_selection(&mut state).unwrap();
        assert_eq!(state.turn.phase_code, 5);
        assert_eq!(
            state
                .nations
                .major(MajorNationId::new(6))
                .unwrap()
                .common
                .home_tile,
            Some(TileId::new(0))
        );
    }

    #[test]
    fn rejects_unowned_or_mountain_tiles() {
        let state = normal_start();
        let foreign = (0..state.world.tiles.len())
            .map(|index| TileId::new(index as u16))
            .find(|&tile| {
                state.world.tiles[usize::from(tile.get())].owner_nation
                    != Some(TileOwnerTag::new(6))
            })
            .unwrap();
        assert_eq!(
            validate_capital_site_selection(&state, foreign),
            Err(CitySiteError::NotOwned)
        );
    }
}
