//! Civilian and military recruitment order helpers.

use super::*;
use crate::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn max_recruit_order(
    progress: &mut ProductionProgress,
    primary: ResourceCost,
    secondary: Option<ResourceCost>,
    cash_per_unit: i16,
    workforce: SkillBand,
    city: &CityState,
    owner: &GreatPowerState,
    treasury: i32,
) -> i16 {
    let production = &city.population.production_labor;
    let (available, divisor) = match workforce {
        SkillBand::Low => (production.low, 1),
        SkillBand::Medium => (production.medium, 2),
        SkillBand::High => (production.high, 4),
    };
    let workforce_limit = available.min(city.population.strength / divisor);

    let primary_limit = city.stockpile[primary.resource] / primary.per_unit();
    let secondary_limit = if let Some(secondary) = secondary {
        city.stockpile[secondary.resource] / secondary.per_unit()
    } else {
        primary_limit
    };
    progress.limiting_constraint = ProductionConstraint::Workforce;
    let mut limit = workforce_limit;
    if primary_limit < limit {
        progress.limiting_constraint = ProductionConstraint::Resources;
        limit = primary_limit;
    }
    if secondary_limit < limit {
        progress.limiting_constraint = ProductionConstraint::Resources;
        limit = secondary_limit;
    }
    if cash_per_unit != 0 && owner.controller.is_human() {
        let affordable =
            (owner.available_diplomacy_budget(treasury) / i32::from(cash_per_unit)).max(0);
        if affordable < i32::from(limit) {
            progress.limiting_constraint = ProductionConstraint::Treasury;
            limit = affordable as i16;
        }
    }
    progress.quantity + limit
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn set_recruit_quantity(
    progress: &mut ProductionProgress,
    primary: ResourceCost,
    secondary: Option<ResourceCost>,
    cash_per_unit: i16,
    workforce: SkillBand,
    city: &mut CityState,
    owner: &GreatPowerState,
    treasury: &mut i32,
    quantity: i16,
) -> bool {
    let delta = quantity - progress.quantity;
    if quantity
        > max_recruit_order(
            progress,
            primary,
            secondary,
            cash_per_unit,
            workforce,
            city,
            owner,
            *treasury,
        )
        || quantity < 0
    {
        return false;
    }
    progress.quantity = quantity;

    apply_resource_cost(city, primary, delta);
    if let Some(secondary) = secondary {
        apply_resource_cost(city, secondary, delta);
    }
    city.population.remove_population(workforce, delta);
    let cash_change = i32::from(cash_per_unit) * i32::from(delta);
    *treasury -= cash_change;
    true
}
