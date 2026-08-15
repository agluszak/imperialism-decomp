//! Retail-substep entry points used by C++ native-case integration tests.
//!
//! These are not the gameplay API. Call `GameState::do_military`,
//! `do_military_cleanup`, `do_combat_moves`, `resume_after_land_battle`,
//! `pay_for_military`, and `finish_player_orders` from production code.

use crate::military_cleanup::NationOrderPriorityMetrics as Metrics;
use crate::*;
use serde::{Deserialize, Serialize};

pub fn apply_military_orders(state: &mut GameState) {
    state.apply_military_orders();
}

pub fn select_and_queue_advisory_map_missions(state: &mut GameState) {
    state.select_and_queue_advisory_map_missions();
}

pub fn do_army_movement(state: &mut GameState, nation: MajorNationId) {
    state.do_army_movement(nation);
}

pub fn resume_combat_moves(
    state: &mut GameState,
    continuation: CombatMovesContinuation,
) -> Option<CombatMovesContinuation> {
    state.resume_combat_moves(continuation)
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
