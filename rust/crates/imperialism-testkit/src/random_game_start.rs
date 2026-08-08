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
/// Includes turn, world tiles, all nations, military units, and the three RNG streams
/// after Accept bootstrap. Pending-work / empty unit lists join when those bootstrap
/// paths land; then delete this allowlist for full `GameState` equality.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandomGameStartBoundarySubset {
    pub turn: TurnState,
    pub world: WorldState,
    pub majors: MajorNationTable<Option<MajorNation>>,
    pub minors: MinorNationTable<Option<MinorNation>>,
    pub military_units: Vec<MilitaryUnitState>,
    pub map_generation: RetailLcg,
    pub crt_rand: RetailCrtRng,
    pub zone_status: RetailLcg,
}

impl RandomGameStartBoundarySubset {
    pub fn from_game_state(state: &GameState) -> Self {
        Self {
            turn: state.turn,
            world: state.world.clone(),
            majors: state.nations.majors.clone(),
            minors: state.nations.minors.clone(),
            military_units: state.military_units.clone(),
            map_generation: state.rng.map_generation,
            crt_rand: state.rng.crt_rand,
            zone_status: state.rng.zone_status,
        }
    }

    /// Project into a `GameState`-shaped value so [`crate::assert_game_state_eq`] can diff it.
    pub fn into_comparable(self) -> GameState {
        GameState {
            turn: self.turn,
            persistent_unit_id_counter: 0,
            world: self.world,
            rng: RngState {
                crt_rand: self.crt_rand,
                map_generation: self.map_generation,
                zone_status: self.zone_status,
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
