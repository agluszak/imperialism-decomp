//! Population growth, food processing, capacity, expansion, and power-plant order helpers.

use super::*;
use crate::*;

pub(crate) fn population_growth_max_order(
    progress: &mut ProductionProgress,
    city: &CityState,
) -> i16 {
    let mut limit = city.stockpile[ResourceKind::Furniture] + progress.quantity;
    limit = limit.min(city.stockpile[ResourceKind::Clothing] + progress.quantity);
    limit = limit.min(city.stockpile[ResourceKind::Food] + progress.quantity);
    let capacity_limit =
        city.production_accum[CityFacilitySlot::RegionalPopulation] + progress.quantity;

    progress.limiting_constraint = ProductionConstraint::Resources;
    if capacity_limit < limit {
        progress.limiting_constraint = ProductionConstraint::Capacity;
        limit = capacity_limit;
    }
    limit
}

pub(crate) fn set_population_growth_quantity(
    progress: &mut ProductionProgress,
    city: &mut CityState,
    quantity: i16,
) -> bool {
    let delta = quantity - progress.quantity;
    if quantity > population_growth_max_order(progress, city) || quantity < 0 {
        return false;
    }
    progress.quantity = quantity;
    city.adjust_stock(ResourceKind::Furniture, -delta);
    city.adjust_stock(ResourceKind::Clothing, -delta);
    city.adjust_stock(ResourceKind::Food, -delta);
    city.production_accum[CityFacilitySlot::RegionalPopulation] -= delta;
    true
}

pub(crate) fn produce_population_growth(
    progress: &mut ProductionProgress,
    city: &mut CityState,
    owner: &GreatPowerState,
    owned_region_count: i32,
) {
    city.population.baseline_labor.low += progress.quantity;
    city.population.production_labor.low += progress.quantity;
    city.population.count += progress.quantity;

    city.production_accum[CityFacilitySlot::RegionalPopulation] =
        retail_region_capacity(owner, owned_region_count);
    progress.quantity = 0;
}

pub(crate) fn food_processing_max_order(progress: &ProductionProgress, city: &CityState) -> i16 {
    let mut limit = city.stockpile[ResourceKind::Grain] / 2;
    let animal_food = city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock];
    let workforce_limit = city.population.strength / 2;
    limit = limit.min(city.stockpile[ResourceKind::Fruit]);
    limit = limit.min(animal_food);
    limit = limit.min(workforce_limit);
    progress.quantity + limit * 2
}

pub(crate) fn set_food_processing_quantity(
    progress: &mut ProductionProgress,
    city: &mut CityState,
    mut quantity: i16,
) -> bool {
    if quantity & 1 != 0 {
        quantity += 1;
    }
    let previous_quantity = progress.quantity;
    if quantity > food_processing_max_order(progress, city) || quantity < 0 {
        return false;
    }
    progress.quantity = quantity;

    let half_delta = (quantity - previous_quantity) / 2;
    city.adjust_stock(ResourceKind::Grain, half_delta * -2);
    city.adjust_stock(ResourceKind::Fruit, -half_delta);
    city.population.strength -= half_delta * 2;

    let livestock_index = ResourceKind::Livestock;
    let livestock = city.stockpile[livestock_index];
    if livestock < half_delta {
        city.stockpile.set_nonnegative(livestock_index, 0);
        let fish_change = half_delta - livestock;
        city.adjust_stock(ResourceKind::Fish, -fish_change);
    } else {
        city.adjust_stock(ResourceKind::Livestock, -half_delta);
    }
    true
}

pub(crate) fn produce_food_processing(progress: &mut ProductionProgress, city: &mut CityState) {
    city.adjust_stock(ResourceKind::Food, progress.quantity);
    progress.quantity = 0;
    progress.reserved_workforce = 0;
}

pub(crate) fn capacity_max_order(
    state: &mut RequestedCityOrderState,
    city: &CityState,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
    production_slot: CityFacilitySlot,
) -> i16 {
    let workforce_limit = city.population.strength / 2 + state.progress.quantity;
    let production_limit = city.production_accum[production_slot] + state.progress.quantity;
    let resource_limit =
        (state.progress.tracking_by_resource[primary_input] + city.stockpile[primary_input]).min(
            state.progress.tracking_by_resource[secondary_input] + city.stockpile[secondary_input],
        );

    state.progress.limiting_constraint = ProductionConstraint::Capacity;
    let mut limit = production_limit;
    if workforce_limit < limit {
        state.progress.limiting_constraint = ProductionConstraint::Workforce;
        limit = workforce_limit;
    }
    if resource_limit < limit {
        state.progress.limiting_constraint = ProductionConstraint::Resources;
        limit = resource_limit;
    }
    limit
}

pub(crate) fn set_capacity_quantity(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
    production_slot: CityFacilitySlot,
    quantity: i16,
) -> bool {
    let delta = quantity - state.progress.quantity;
    if quantity > capacity_max_order(state, city, primary_input, secondary_input, production_slot)
        || quantity < 0
    {
        return false;
    }

    state.progress.quantity = quantity;
    state.requested_quantity = quantity;
    reserve_primary_and_secondary(
        city,
        &mut state.progress.tracking_by_resource,
        primary_input,
        Some(secondary_input),
        delta,
    );
    let workforce_change = delta * 2;
    city.population.strength -= workforce_change;
    state.progress.reserved_workforce += workforce_change;
    let production = &mut city.production_accum[production_slot];
    *production -= delta;
    true
}

pub(crate) fn produce_capacity(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    owner: &mut GreatPowerState,
    target: CapacityTarget,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
    owned_region_count: i32,
) {
    if state.progress.quantity == 0 {
        return;
    }

    match target {
        CapacityTarget::Transport => {
            owner.capacities.transport += state.progress.quantity;
        }
        CapacityTarget::Production(slot) => {
            let base = city.production_orders[slot];
            apply_production_increase(state, city, slot, base);
        }
        CapacityTarget::RegionalPopulation => {
            let base = retail_region_capacity(owner, owned_region_count);
            apply_production_increase(state, city, target.slot(), base);
        }
    }

    state.requested_quantity = 0;
    state.progress.quantity = 0;
    state.progress.tracking_by_resource[primary_input] = 0;
    state.progress.tracking_by_resource[secondary_input] = 0;
    state.progress.reserved_workforce = 0;
}

#[allow(dead_code)]
pub(crate) fn restock_capacity(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
    production_slot: CityFacilitySlot,
) -> bool {
    let max_order =
        capacity_max_order(state, city, primary_input, secondary_input, production_slot);
    let saved_requested_quantity = state.requested_quantity;
    state.progress.quantity = 0;
    if max_order < saved_requested_quantity
        && state.progress.limiting_constraint == ProductionConstraint::Resources
    {
        let accepted = set_capacity_quantity(
            state,
            city,
            primary_input,
            secondary_input,
            production_slot,
            max_order,
        );
        state.requested_quantity = saved_requested_quantity;
        accepted
    } else {
        set_capacity_quantity(
            state,
            city,
            primary_input,
            secondary_input,
            production_slot,
            saved_requested_quantity,
        )
    }
}

#[allow(dead_code)]
pub(crate) fn apply_production_increase(
    state: &RequestedCityOrderState,
    city: &mut CityState,
    slot: CityFacilitySlot,
    base: i16,
) {
    let new_value = base + state.progress.quantity;
    let delta = new_value - city.production_orders[slot];
    city.production_accum[slot] += delta;
    city.production_orders[slot] = new_value;
}

pub(crate) fn expansion_max_order(
    state: &RequestedCityOrderState,
    city: &CityState,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
) -> i16 {
    (state.progress.tracking_by_resource[primary_input] + city.stockpile[primary_input])
        .min(state.progress.tracking_by_resource[secondary_input] + city.stockpile[secondary_input])
}

pub(crate) fn set_expansion_quantity(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
    quantity: i16,
) -> bool {
    let delta = quantity - state.progress.quantity;
    if quantity > expansion_max_order(state, city, primary_input, secondary_input) || quantity < 0 {
        return false;
    }

    state.progress.quantity = quantity;
    state.requested_quantity = quantity;
    reserve_primary_and_secondary(
        city,
        &mut state.progress.tracking_by_resource,
        primary_input,
        Some(secondary_input),
        delta,
    );
    true
}

pub(crate) fn produce_expansion(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    owner: &GreatPowerState,
    target: ExpansionTarget,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
    owned_region_count: i32,
) {
    if state.progress.quantity == 0 {
        return;
    }

    let (slot, base) = match target {
        ExpansionTarget::Production(slot) => (slot, city.production_orders[slot]),
        ExpansionTarget::RegionalPopulation => (
            target.slot(),
            retail_region_capacity(owner, owned_region_count),
        ),
    };
    let new_value = base + state.progress.quantity;
    let delta = new_value - city.production_orders[slot];
    city.production_accum[slot] += delta;
    city.production_orders[slot] = new_value;

    state.requested_quantity = 0;
    state.progress.quantity = 0;
    state.progress.tracking_by_resource[primary_input] = 0;
    state.progress.tracking_by_resource[secondary_input] = 0;
}

#[allow(dead_code)]
pub(crate) fn restock_expansion(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
) -> bool {
    let max_order = expansion_max_order(state, city, primary_input, secondary_input);
    let saved_requested_quantity = state.requested_quantity;
    state.progress.quantity = 0;
    if max_order < saved_requested_quantity
        && state.progress.limiting_constraint == ProductionConstraint::Resources
    {
        let accepted =
            set_expansion_quantity(state, city, primary_input, secondary_input, max_order);
        state.requested_quantity = saved_requested_quantity;
        accepted
    } else {
        set_expansion_quantity(
            state,
            city,
            primary_input,
            secondary_input,
            saved_requested_quantity,
        )
    }
}

pub(crate) fn power_plant_max_order(state: &PowerPlantOrderState, city: &CityState) -> i16 {
    state.progress.quantity + city.stockpile[ResourceKind::Fuel] * 6
}

pub(crate) fn set_power_plant_quantity(
    state: &mut PowerPlantOrderState,
    city: &mut CityState,
    quantity: i16,
) -> bool {
    let delta = quantity - state.progress.quantity;
    if quantity > power_plant_max_order(state, city) || quantity < 0 {
        return false;
    }
    state.progress.quantity = quantity;

    if i32::from(city.population.strength) < -i32::from(delta) {
        state.progress.quantity -= delta;
        return false;
    }

    state.desired_quantity = quantity;
    city.adjust_stock(ResourceKind::Fuel, -(delta / 6));
    let previous_power = city.population.extra;
    city.power_available = quantity;
    city.population.extra = quantity;
    let power_change = quantity - previous_power;
    city.population.strength += power_change;
    true
}

pub(crate) const fn produce_power_plant(_state: &PowerPlantOrderState) {}

pub(crate) fn restock_power_plant(state: &mut PowerPlantOrderState, city: &mut CityState) -> bool {
    let max_order = power_plant_max_order(state, city);
    let saved_desired_quantity = state.desired_quantity;
    state.progress.quantity = 0;
    if max_order < saved_desired_quantity {
        let accepted = set_power_plant_quantity(state, city, max_order);
        state.desired_quantity = saved_desired_quantity;
        accepted
    } else {
        set_power_plant_quantity(state, city, saved_desired_quantity)
    }
}

pub(crate) fn retail_region_capacity(owner: &GreatPowerState, owned_region_count: i32) -> i16 {
    let divisor = if owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion]
        .status()
        .has_reached(crate::PendingActionStatus::Level3)
    {
        3
    } else {
        4
    };
    let capacity = owned_region_count / divisor;
    if capacity > 1 { capacity as i16 } else { 1 }
}
