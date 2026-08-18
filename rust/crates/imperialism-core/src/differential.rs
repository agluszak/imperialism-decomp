//! Retail-substep entry points and map-generation traces for C++ integration tests.
//!
//! These are not the gameplay API. Call `GameState::do_military`,
//! `do_military_cleanup`, `do_combat_moves`, `resume_after_land_battle`,
//! `pay_for_military`, and `finish_player_orders` from production code.

use crate::military_cleanup::NationOrderPriorityMetrics as Metrics;
use crate::{
    CombatMovesContinuation, GameState, MajorNationId, MilitaryUnitId, NavyOrdersContinuation,
};
use serde::{Deserialize, Serialize};

pub use crate::random_map::{
    CoarseMap, CoarseMapAttempt, CoarseMapGrid, CoarseMapTrace, trace_coarse_random_map,
};
pub use crate::random_map_terrain::{
    RandomMapTerrainAttemptTrace, RandomMapTerrainStageTrace, RandomMapTerrainTrace,
    trace_random_map_terrain,
};

pub fn select_and_queue_advisory_map_missions(state: &mut GameState) {
    state.select_and_queue_advisory_map_missions();
}

pub fn do_army_movement(state: &mut GameState, nation: MajorNationId) {
    state.do_army_movement(nation);
}

pub fn do_military_with_tactical_battles(state: &mut GameState) -> Option<NavyOrdersContinuation> {
    state.do_military_with_tactical_battles()
}

pub fn resume_combat_moves(
    state: &mut GameState,
    continuation: CombatMovesContinuation,
) -> Option<CombatMovesContinuation> {
    state.resume_combat_moves(continuation)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArmyBattleUnitSnapshot {
    pub source: MilitaryUnitId,
    pub side: u8,
    pub tile: i32,
    pub action_points: i32,
    pub strength: i32,
    pub morale: i32,
    pub state: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArmyBattleSnapshot {
    pub selected: Option<MilitaryUnitId>,
    pub current_side: u8,
    pub round: i32,
    pub outcome: i32,
    pub units: Vec<ArmyBattleUnitSnapshot>,
    pub fort_strength: [i32; 8],
    pub crt_rand: u32,
}

pub fn army_battle_snapshot(state: &GameState) -> Option<ArmyBattleSnapshot> {
    state.army_battle_differential_snapshot()
}

pub fn reassess_control_sea_missions(state: &mut GameState) {
    state.reassess_control_sea_missions();
}

/// IEEE-754 bits of `RecomputeNationOrderPriorityMetrics` for native comparison.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NationOrderPriorityMetrics {
    pub queue_divergence: [u32; 7],
    pub mobile_score: [u32; 7],
    pub mobile_divergence: [u32; 7],
    pub combined_divergence: [u32; 7],
    pub weighted_military: [u32; 7],
    pub expansion_pressure: [u32; 7],
    pub unit_divergence: [u32; 7],
    pub mission_pressure: [u32; 7],
}

impl From<&Metrics> for NationOrderPriorityMetrics {
    fn from(metrics: &Metrics) -> Self {
        Self {
            queue_divergence: metrics.queue_divergence.map(f32::to_bits),
            mobile_score: metrics.mobile_score.map(f32::to_bits),
            mobile_divergence: metrics.mobile_divergence.map(f32::to_bits),
            combined_divergence: metrics.combined_divergence.map(f32::to_bits),
            weighted_military: metrics.weighted_military.map(f32::to_bits),
            expansion_pressure: metrics.expansion_pressure.map(f32::to_bits),
            unit_divergence: metrics.unit_divergence.map(f32::to_bits),
            mission_pressure: metrics.mission_pressure.map(f32::to_bits),
        }
    }
}

pub fn recompute_nation_order_priority_metrics(state: &GameState) -> NationOrderPriorityMetrics {
    NationOrderPriorityMetrics::from(&state.recompute_nation_order_priority_metrics())
}
