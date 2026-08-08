//! Allowlisted subset for the Normal pre-capital `create_random_game` boundary.
//!
//! Grow this one block at a time as retail post-passes and Accept bootstrap land.
//! Delete it once complete `GameState` equality holds for several seeds.

use imperialism_core::{
    GameState, MajorNation, MajorNationTable, MilitaryUnitState, MinorNation, MinorNationTable,
    NationPendingWork, Nations, PendingWorkState, RetailCrtRng, RetailLcg, RngState, TurnState,
    WorldState,
};
use serde::{Deserialize, Serialize};

/// Currently compared blocks of the capital-selection-ready boundary.
///
/// Includes turn state, all nations, military units (minor militia), and the map/CRT RNG
/// streams after Accept bootstrap. Tile bodies, zone RNG, and pending-work join next.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandomGameStartBoundarySubset {
    pub turn: TurnState,
    pub majors: MajorNationTable<Option<MajorNation>>,
    pub minors: MinorNationTable<Option<MinorNation>>,
    pub military_units: Vec<MilitaryUnitState>,
    pub map_generation: RetailLcg,
    pub crt_rand: RetailCrtRng,
}

impl RandomGameStartBoundarySubset {
    pub fn from_game_state(state: &GameState) -> Self {
        Self {
            turn: state.turn,
            majors: state.nations.majors.clone(),
            minors: state.nations.minors.clone(),
            military_units: state.military_units.clone(),
            map_generation: state.rng.map_generation,
            crt_rand: state.rng.crt_rand,
        }
    }

    /// Project into a `GameState`-shaped value so [`crate::assert_game_state_eq`] can diff it.
    pub fn into_comparable(self) -> GameState {
        GameState {
            turn: self.turn,
            persistent_unit_id_counter: 0,
            world: WorldState {
                wraps_horizontally: false,
                tiles: Vec::new(),
            },
            rng: RngState {
                crt_rand: self.crt_rand,
                map_generation: self.map_generation,
                zone_status: RetailLcg::from_state(0),
            },
            market: Default::default(),
            nations: Nations {
                majors: self.majors,
                minors: self.minors,
            },
            military_units: self.military_units,
            civilian_units: Vec::new(),
            ships: Vec::new(),
            task_forces: Vec::new(),
            missions: Vec::new(),
            pending: PendingWorkState {
                nations: MajorNationTable::from_fn(|_| NationPendingWork {
                    turn_events: Vec::new(),
                    proposals: Vec::new(),
                    turn_summary: Vec::new(),
                    turn_start_events: Vec::new(),
                }),
                war_transitions: Vec::new(),
            },
        }
    }
}
