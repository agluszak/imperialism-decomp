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
    let mut limit = OrderLimit {
        maximum: workforce_limit,
        constraint: ProductionConstraint::Workforce,
    };
    limit.min_with(primary_limit, ProductionConstraint::Resources);
    limit.min_with(secondary_limit, ProductionConstraint::Resources);
    if spec.cash_per_unit != 0 && owner.diplomacy_eligible {
        let affordable =
            (owner.available_diplomacy_budget(treasury) / i32::from(spec.cash_per_unit)).max(0);
        if affordable < i32::from(limit.maximum) {
            limit.min_with(affordable as i16, ProductionConstraint::Treasury);
        }
    }
    OrderLimit {
        maximum: progress.quantity + limit.maximum,
        constraint: limit.constraint,
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
    let Some(delta) = progress.try_set(limit, quantity) else {
        return false;
    };

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
