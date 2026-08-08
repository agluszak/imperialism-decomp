//! Allowlisted subset for the Normal pre-capital `create_random_game` boundary.
//!
//! Grow this one block at a time as retail post-passes and Accept bootstrap land.
//! Delete it once complete `GameState` equality holds for several seeds.

use imperialism_core::{
    GameState, MajorNation, MajorNationId, MajorNationTable, MinorNationTable, NationPendingWork,
    Nations, PendingWorkState, RetailCrtRng, RetailLcg, RngState, TurnState, WorldState,
};
use serde::{Deserialize, Serialize};

/// Currently compared blocks of the capital-selection-ready boundary.
///
/// Includes turn state, human nation/city bootstrap, and the map-generation LCG after
/// preview post-passes (icon variants → province capitals → GuaranteeResources). Tile
/// bodies, AI capitals, militia, CRT/zone RNG, and pending-work join as each retail
/// operation lands.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandomGameStartBoundarySubset {
    pub turn: TurnState,
    pub human_nation: MajorNation,
    /// `RngState.map_generation` after Accept-time post-passes.
    pub map_generation: RetailLcg,
}

impl RandomGameStartBoundarySubset {
    pub fn from_game_state(state: &GameState) -> Self {
        let human = state.turn.selected_nation;
        let major = MajorNationId::from_nation(human).expect("selected nation is a major");
        Self {
            turn: state.turn,
            human_nation: state
                .nations
                .major(major)
                .cloned()
                .expect("human nation slot is occupied"),
            map_generation: state.rng.map_generation,
        }
    }

    /// Project into a `GameState`-shaped value so [`crate::assert_game_state_eq`] can diff it.
    pub fn into_comparable(self) -> GameState {
        let human = self.turn.selected_nation;
        let major = MajorNationId::from_nation(human).expect("selected nation is a major");
        let mut majors = MajorNationTable::from_fn(|_| None);
        majors[major] = Some(self.human_nation);
        GameState {
            turn: self.turn,
            persistent_unit_id_counter: 0,
            world: WorldState {
                wraps_horizontally: false,
                tiles: Vec::new(),
            },
            rng: RngState {
                crt_rand: RetailCrtRng::from_state(0),
                map_generation: self.map_generation,
                zone_status: RetailLcg::from_state(0),
            },
            market: Default::default(),
            nations: Nations {
                majors,
                minors: MinorNationTable::from_fn(|_| None),
            },
            military_units: Vec::new(),
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
