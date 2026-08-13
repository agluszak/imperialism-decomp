//! Civilian and military recruitment order helpers.

use super::*;
use crate::*;

pub(crate) fn recruit_limit(
    progress: &ProductionProgress,
    spec: RecruitmentOrderSpec,
    city: &CityState,
    owner: &GreatPowerState,
    treasury: i32,
) -> OrderLimit {
    let production = &city.population.production_labor;
    let (available, divisor) = match spec.workforce {
        SkillBand::Low => (production.low, 1),
        SkillBand::Medium => (production.medium, 2),
        SkillBand::High => (production.high, 4),
    };
    let workforce_limit = available.min(city.population.strength / divisor);

    let primary_limit = city.stockpile[spec.primary.resource] / spec.primary.per_unit();
    let secondary_limit = if let Some(secondary) = spec.secondary {
        city.stockpile[secondary.resource] / secondary.per_unit()
    } else {
        primary_limit
    };
    let mut constraint = ProductionConstraint::Workforce;
    let mut limit = workforce_limit;
    if primary_limit < limit {
        constraint = ProductionConstraint::Resources;
        limit = primary_limit;
    }
    if secondary_limit < limit {
        constraint = ProductionConstraint::Resources;
        limit = secondary_limit;
    }
    if spec.cash_per_unit != 0 && owner.controller.is_human() {
        let affordable =
            (owner.available_diplomacy_budget(treasury) / i32::from(spec.cash_per_unit)).max(0);
        if affordable < i32::from(limit) {
            constraint = ProductionConstraint::Treasury;
            limit = affordable as i16;
        }
    }
    OrderLimit {
        maximum: progress.quantity + limit,
        constraint,
    }
}

pub(crate) fn set_recruit_quantity(
    progress: &mut ProductionProgress,
    spec: RecruitmentOrderSpec,
    stockpile: &mut Stockpile,
    population: &mut PopulationState,
    treasury: &mut i32,
    limit: OrderLimit,
    quantity: i16,
) -> bool {
    let delta = quantity - progress.quantity;
    progress.limiting_constraint = limit.constraint;
    if quantity > limit.maximum || quantity < 0 {
        return false;
    }
    progress.quantity = quantity;

    stockpile.wrapping_add_and_verify(
        spec.primary.resource,
        (spec.primary.per_unit() * delta).wrapping_neg(),
    );
    if let Some(secondary) = spec.secondary {
        stockpile.wrapping_add_and_verify(
            secondary.resource,
            (secondary.per_unit() * delta).wrapping_neg(),
        );
    }
    population.remove_population(spec.workforce, delta);
    let cash_change = i32::from(spec.cash_per_unit) * i32::from(delta);
    *treasury -= cash_change;
    true
}
