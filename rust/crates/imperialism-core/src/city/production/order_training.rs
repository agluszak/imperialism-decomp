//! Trade-school training order helpers.

use crate::*;
use super::*;

pub(crate) fn training_max_order(
    level: TrainingLevel,
    progress: &mut ProductionProgress,
    city: &CityState,
    owner: &GreatPowerState,
    treasury: i32,
) -> i16 {
    let production = &city.population.production_labor;
    let (paper_per_unit, cash_per_unit, workforce_limit) = match level {
        TrainingLevel::Medium => (1_i16, 100_i32, production.low.min(city.population.strength)),
        TrainingLevel::High => (
            2_i16,
            1_000_i32,
            production.medium.min(city.population.strength / 2),
        ),
    };

    let cash_limit = if !owner.controller.is_human() {
        workforce_limit
    } else {
        let affordable = (treasury + owner.diplomacy_budget_base / 100).max(0) / cash_per_unit;
        if affordable < i32::from(workforce_limit) {
            affordable as i16
        } else {
            workforce_limit
        }
    };
    let paper_limit = city.stockpile[ResourceKind::Paper] / paper_per_unit;

    progress.limiting_constraint = ProductionConstraint::Workforce;
    let mut limit = workforce_limit;
    if cash_limit < limit {
        progress.limiting_constraint = ProductionConstraint::Treasury;
        limit = cash_limit;
    }
    if paper_limit < limit {
        progress.limiting_constraint = ProductionConstraint::Resources;
        limit = paper_limit;
    }
    if i32::from(progress.quantity) + i32::from(limit) > 99 {
        limit = 99 - progress.quantity;
    }
    progress.quantity + limit
}

pub(crate) fn set_training_quantity(
    level: TrainingLevel,
    progress: &mut ProductionProgress,
    city: &mut CityState,
    owner: &GreatPowerState,
    treasury: &mut i32,
    quantity: i16,
) -> bool {
    let delta = quantity - progress.quantity;
    if quantity > training_max_order(level, progress, city, owner, *treasury) || quantity < 0 {
        return false;
    }
    progress.quantity = quantity;

    let (paper_change, cash_change) = match level {
        TrainingLevel::Medium => (delta, i32::from(delta) * 100),
        TrainingLevel::High => (delta * 2, i32::from(delta) * 1_000),
    };
    city.adjust_stock(ResourceKind::Paper, -paper_change);
    *treasury -= cash_change;
    city.population.make_unavailable(level.input_band(), delta);
    true
}

pub(crate) fn produce_training(
    level: TrainingLevel,
    progress: &mut ProductionProgress,
    city: &mut CityState,
    owner: &mut GreatPowerState,
) {
    if progress.quantity == 0 {
        return;
    }
    let baseline = &mut city.population.baseline_labor;

    match level {
        TrainingLevel::Medium => {
            baseline.low -= progress.quantity;
            baseline.medium += progress.quantity;
        }
        TrainingLevel::High => {
            let new_level = i32::from(baseline.high) + i32::from(progress.quantity);
            if new_level >= 10 {
                let payload = if owner.pending_actions[PendingActionKind::UniversityExpansion]
                    .status()
                    < crate::PendingActionStatus::Queued
                {
                    Some(2)
                } else if new_level >= 30
                    && owner.pending_actions[PendingActionKind::UniversityExpansion].status()
                        <= crate::PendingActionStatus::Level3
                {
                    Some(3)
                } else {
                    None
                };
                if let Some(payload) = payload {
                    set_pending_action(owner, PendingActionKind::UniversityExpansion, payload);
                }
            }
            baseline.medium -= progress.quantity;
            baseline.high += progress.quantity;
        }
    }
    progress.quantity = 0;
}
