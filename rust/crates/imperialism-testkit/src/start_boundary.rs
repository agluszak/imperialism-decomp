//! Allowlisted Normal random-game start-boundary projection.
//!
//! Full `GameState` equality is not the gate yet. This subset grows with
//! `create_random_game` as tile post-passes, AI capitals, and militia land.
//!
//! Tile `terrain_kind` / `owner_nation` are filled from the retained preview in
//! create, but nation bootstrap (PlaceCity, minor homes) rewrites many of those
//! fields before the Normal start capture. The allowlist therefore claims
//! provinces (stable) plus turn / nation / city stock fields that already match.

use imperialism_core::{
    CityState, GameState, LaborPool, MAJOR_NATION_COUNT, MajorNationId, NATION_COUNT, NationId,
    NationState, ProductionSlot, ResourceTable, TurnState, all_resources,
};
use serde::Serialize;

use crate::{Difference, first_serialized_difference};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RandomGameStartBoundarySubset {
    pub turn: TurnState,
    pub wraps_horizontally: bool,
    pub tile_provinces: Vec<Option<i16>>,
    pub nations: Vec<StartBoundaryNation>,
    pub cities: Vec<Option<StartBoundaryCity>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StartBoundaryNation {
    pub encoded_nation_slot: i16,
    pub owner_nation: i16,
    pub treasury: i32,
    /// Only projected for the human major (pre-capital `home_tile == -1`).
    pub home_tile: Option<i32>,
    pub major: Option<StartBoundaryMajor>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct StartBoundaryMajor {
    pub diplomacy_eligible: bool,
    pub capacities: [i16; 4],
    pub turn_finished: bool,
    pub diplomacy_budget_base: i32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StartBoundaryCity {
    /// Human Frog City marker at tile 0. AI capitals stay out until placement.
    pub home_town_tile: Option<i16>,
    pub stock_by_type: ResourceTable<i16>,
    pub production_orders: [i16; 6],
    pub population_count: i16,
    pub population_strength: i16,
    pub baseline_labor: LaborPool,
}

/// Projects the fields currently claimed by the random-game start-boundary port.
pub fn project_random_game_start_boundary(state: &GameState) -> RandomGameStartBoundarySubset {
    RandomGameStartBoundarySubset {
        turn: state.turn,
        wraps_horizontally: state.world.wraps_horizontally,
        tile_provinces: state.world.tiles.iter().map(|tile| tile.province).collect(),
        nations: (0..NATION_COUNT as u8)
            .map(|slot| {
                let nation = state.nations[NationId::new(slot)]
                    .as_ref()
                    .expect("start-boundary nations are fully populated");
                project_nation(nation)
            })
            .collect(),
        cities: (0..MAJOR_NATION_COUNT as u8)
            .map(|slot| {
                state.cities[MajorNationId::new(slot)].as_ref().map(|city| {
                    project_city(city, state.turn.selected_nation == NationId::new(slot))
                })
            })
            .collect(),
    }
}

fn project_nation(nation: &NationState) -> StartBoundaryNation {
    let human = nation.major().is_some_and(|major| major.diplomacy_eligible);
    StartBoundaryNation {
        encoded_nation_slot: nation.common.encoded_nation_slot,
        owner_nation: nation.common.owner_nation,
        treasury: nation.common.treasury,
        home_tile: human.then_some(nation.common.home_tile),
        major: nation.major().map(|major| StartBoundaryMajor {
            diplomacy_eligible: major.diplomacy_eligible,
            capacities: major.capacities,
            turn_finished: major.turn_finished,
            diplomacy_budget_base: major.diplomacy_budget_base,
        }),
    }
}

fn project_city(city: &CityState, human: bool) -> StartBoundaryCity {
    let production_orders = [
        city.production_orders[ProductionSlot::new(7).unwrap()],
        city.production_orders[ProductionSlot::new(8).unwrap()],
        city.production_orders[ProductionSlot::new(9).unwrap()],
        city.production_orders[ProductionSlot::new(10).unwrap()],
        city.production_orders[ProductionSlot::new(13).unwrap()],
        city.production_orders[ProductionSlot::new(14).unwrap()],
    ];
    let mut stock_by_type = ResourceTable::default();
    for resource in all_resources() {
        stock_by_type[resource] = city.stock_by_type[resource];
    }
    StartBoundaryCity {
        home_town_tile: human
            .then_some(city.home_town_tile)
            .filter(|&tile| tile >= 0),
        stock_by_type,
        production_orders,
        population_count: city.population.count,
        population_strength: city.population.strength,
        baseline_labor: city
            .population
            .baseline_labor
            .expect("scenario cities have baseline labor"),
    }
}

pub fn compare_random_game_start_boundary(
    original: &GameState,
    reimplementation: &GameState,
) -> Result<Option<Difference>, serde_json::Error> {
    first_serialized_difference(
        &project_random_game_start_boundary(original),
        &project_random_game_start_boundary(reimplementation),
    )
}
