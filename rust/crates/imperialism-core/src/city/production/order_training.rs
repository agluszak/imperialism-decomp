//! Trade-school training order helpers.

use super::*;
use crate::*;

pub(crate) fn training_limit(
    level: TrainingLevel,
    progress: &ProductionProgress,
    city: &CityState,
    owner: &GreatPowerState,
    treasury: i32,
) -> OrderLimit {
    let production = &city.population.production_labor;
    let (paper_per_unit, cash_per_unit, workforce_limit) = match level {
        TrainingLevel::Medium => (1, 100_i32, production.low.min(city.population.strength)),
        TrainingLevel::High => (
            2,
            1_000_i32,
            production.medium.min(city.population.strength / 2),
        ),
    };

    let cash_limit = if !owner.diplomacy_eligible {
        workforce_limit
    } else {
        let affordable = (treasury + owner.diplomacy_budget_base / 100).max(0) / cash_per_unit;
        if affordable < workforce_limit {
            affordable
        } else {
            workforce_limit
        }
    };
    let paper_limit = city.stockpile[ResourceKind::Paper] / paper_per_unit;

    let mut limit = OrderLimit {
        maximum: workforce_limit,
        constraint: ProductionConstraint::Workforce,
    };
    limit.min_with(cash_limit, ProductionConstraint::Treasury);
    limit.min_with(paper_limit, ProductionConstraint::Resources);
    if progress.quantity + limit.maximum > 99 {
        limit.maximum = 99 - progress.quantity;
    }
    OrderLimit {
        maximum: progress.quantity + limit.maximum,
        constraint: limit.constraint,
    }
}

pub(crate) fn set_training_quantity(
    level: TrainingLevel,
    progress: &mut ProductionProgress,
    stockpile: &mut Stockpile,
    population: &mut PopulationState,
    treasury: &mut i32,
    limit: OrderLimit,
    quantity: i32,
) -> bool {
    let Some(delta) = progress.try_set(limit, quantity) else {
        return false;
    };

    let (paper_change, cash_change) = match level {
        TrainingLevel::Medium => (delta, delta * 100),
        TrainingLevel::High => (delta * 2, delta * 1_000),
    };
    stockpile.add_and_verify(ResourceKind::Paper, -paper_change);
    *treasury -= cash_change;
    population.make_unavailable(level.input_band(), delta);
    true
}

pub(crate) fn produce_training(
    level: TrainingLevel,
    progress: &mut ProductionProgress,
    population: &mut PopulationState,
    owner: &mut GreatPowerState,
) {
    if progress.quantity == 0 {
        return;
    }
    let baseline = &mut population.baseline_labor;

    match level {
        TrainingLevel::Medium => {
            baseline.low -= progress.quantity;
            baseline.medium += progress.quantity;
        }
        TrainingLevel::High => {
            let new_level = baseline.high + progress.quantity;
            if new_level >= 10 {
                let stage = if owner.pending_actions.university_expansion.is_idle() {
                    Some(2)
                } else if new_level >= 30
                    && !matches!(
                        owner.pending_actions.university_expansion,
                        crate::UniversityExpansion::Level3
                    )
                {
                    Some(3)
                } else {
                    None
                };
                if let Some(stage) = stage {
                    owner
                        .pending_actions
                        .university_expansion
                        .queue_stage(stage);
                }
            }
            baseline.medium -= progress.quantity;
            baseline.high += progress.quantity;
        }
    }
    progress.quantity = 0;
}
