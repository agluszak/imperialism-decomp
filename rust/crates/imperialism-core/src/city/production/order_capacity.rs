//! Population growth, food processing, capacity, expansion, and power-plant order helpers.

use super::*;
use crate::*;

pub(crate) fn population_growth_limit(
    progress: &ProductionProgress,
    city: &CityState,
) -> OrderLimit {
    let mut limit = city.stockpile[ResourceKind::Furniture] + progress.quantity;
    limit = limit.min(city.stockpile[ResourceKind::Clothing] + progress.quantity);
    limit = limit.min(city.stockpile[ResourceKind::Food] + progress.quantity);
    let capacity_limit =
        city.production_accum[CityFacilitySlot::RegionalPopulation] + progress.quantity;

    let mut constraint = ProductionConstraint::Resources;
    if capacity_limit < limit {
        constraint = ProductionConstraint::Capacity;
        limit = capacity_limit;
    }
    OrderLimit {
        maximum: limit,
        constraint,
    }
}

pub(crate) fn set_population_growth_quantity(
    progress: &mut ProductionProgress,
    stockpile: &mut Stockpile,
    production_accum: &mut ProductionTable<i16>,
    limit: OrderLimit,
    quantity: i16,
) -> bool {
    let delta = quantity - progress.quantity;
    progress.limiting_constraint = limit.constraint;
    if quantity > limit.maximum || quantity < 0 {
        return false;
    }
    progress.quantity = quantity;
    stockpile.wrapping_add_and_verify(ResourceKind::Furniture, delta.wrapping_neg());
    stockpile.wrapping_add_and_verify(ResourceKind::Clothing, delta.wrapping_neg());
    stockpile.wrapping_add_and_verify(ResourceKind::Food, delta.wrapping_neg());
    production_accum[CityFacilitySlot::RegionalPopulation] -= delta;
    true
}

pub(crate) fn produce_population_growth(
    progress: &mut ProductionProgress,
    population: &mut PopulationState,
    production_accum: &mut ProductionTable<i16>,
    owner: &GreatPowerState,
    owned_region_count: usize,
) {
    population.baseline_labor.low += progress.quantity;
    population.production_labor.low += progress.quantity;
    population.count += progress.quantity;

    production_accum[CityFacilitySlot::RegionalPopulation] =
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
    stockpile: &mut Stockpile,
    population: &mut PopulationState,
    maximum: i16,
    mut quantity: i16,
) -> bool {
    if quantity & 1 != 0 {
        quantity += 1;
    }
    let previous_quantity = progress.quantity;
    if quantity > maximum || quantity < 0 {
        return false;
    }
    progress.quantity = quantity;

    let half_delta = (quantity - previous_quantity) / 2;
    stockpile.wrapping_add_and_verify(ResourceKind::Grain, (half_delta * 2).wrapping_neg());
    stockpile.wrapping_add_and_verify(ResourceKind::Fruit, half_delta.wrapping_neg());
    population.strength -= half_delta * 2;

    let livestock = stockpile[ResourceKind::Livestock];
    if livestock < half_delta {
        stockpile[ResourceKind::Livestock] = 0;
        stockpile.verify_stocks();
        stockpile.wrapping_add(ResourceKind::Fish, (half_delta - livestock).wrapping_neg());
    } else {
        stockpile.wrapping_add(ResourceKind::Livestock, half_delta.wrapping_neg());
    }
    stockpile.verify_stocks();
    true
}

pub(crate) fn produce_food_processing(
    progress: &mut ProductionProgress,
    stockpile: &mut Stockpile,
) {
    stockpile.wrapping_add_and_verify(ResourceKind::Food, progress.quantity);
    progress.quantity = 0;
}

pub(crate) fn transport_capacity_limit(
    state: &RequestedCityOrderState,
    city: &CityState,
) -> OrderLimit {
    let (primary_input, secondary_input) = TRANSPORT_CAPACITY_INPUTS;
    let workforce_limit = city.population.strength / 2 + state.progress.quantity;
    let production_limit =
        city.production_accum[CityFacilitySlot::Transport] + state.progress.quantity;
    let resource_limit = (state.tracking_by_resource[primary_input]
        + city.stockpile[primary_input])
        .min(state.tracking_by_resource[secondary_input] + city.stockpile[secondary_input]);

    let mut constraint = ProductionConstraint::Capacity;
    let mut limit = production_limit;
    if workforce_limit < limit {
        constraint = ProductionConstraint::Workforce;
        limit = workforce_limit;
    }
    if resource_limit < limit {
        constraint = ProductionConstraint::Resources;
        limit = resource_limit;
    }
    OrderLimit {
        maximum: limit,
        constraint,
    }
}

pub(crate) fn set_transport_capacity_quantity(
    state: &mut RequestedCityOrderState,
    stockpile: &mut Stockpile,
    population: &mut PopulationState,
    production_accum: &mut ProductionTable<i16>,
    limit: OrderLimit,
    quantity: i16,
) -> bool {
    let (primary_input, secondary_input) = TRANSPORT_CAPACITY_INPUTS;
    let delta = quantity - state.progress.quantity;
    state.progress.limiting_constraint = limit.constraint;
    if quantity > limit.maximum || quantity < 0 {
        return false;
    }

    state.progress.quantity = quantity;
    state.requested_quantity = quantity;
    reserve_primary_and_secondary(
        stockpile,
        &mut state.tracking_by_resource,
        primary_input,
        Some(secondary_input),
        delta,
    );
    let workforce_change = delta * 2;
    population.strength -= workforce_change;
    let production = &mut production_accum[CityFacilitySlot::Transport];
    *production -= delta;
    true
}

pub(crate) fn produce_transport_capacity(
    state: &mut RequestedCityOrderState,
    owner: &mut GreatPowerState,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
) {
    if state.progress.quantity == 0 {
        return;
    }

    owner.capacities.transport += state.progress.quantity;

    state.requested_quantity = 0;
    state.progress.quantity = 0;
    state.tracking_by_resource[primary_input] = 0;
    state.tracking_by_resource[secondary_input] = 0;
}

pub(crate) fn expansion_max_order(
    state: &RequestedCityOrderState,
    city: &CityState,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
) -> i16 {
    (state.tracking_by_resource[primary_input] + city.stockpile[primary_input])
        .min(state.tracking_by_resource[secondary_input] + city.stockpile[secondary_input])
}

pub(crate) fn set_expansion_quantity(
    state: &mut RequestedCityOrderState,
    stockpile: &mut Stockpile,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
    maximum: i16,
    quantity: i16,
) -> bool {
    let delta = quantity - state.progress.quantity;
    if quantity > maximum || quantity < 0 {
        return false;
    }

    state.progress.quantity = quantity;
    state.requested_quantity = quantity;
    reserve_primary_and_secondary(
        stockpile,
        &mut state.tracking_by_resource,
        primary_input,
        Some(secondary_input),
        delta,
    );
    true
}

pub(crate) fn produce_expansion(
    state: &mut RequestedCityOrderState,
    production_orders: &mut ProductionTable<i16>,
    production_accum: &mut ProductionTable<i16>,
    facility: ExpandableFacility,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
) {
    if state.progress.quantity == 0 {
        return;
    }

    let slot = facility.slot();
    let base = production_orders[slot];
    let new_value = base + state.progress.quantity;
    let delta = new_value - production_orders[slot];
    production_accum[slot] += delta;
    production_orders[slot] = new_value;

    state.requested_quantity = 0;
    state.progress.quantity = 0;
    state.tracking_by_resource[primary_input] = 0;
    state.tracking_by_resource[secondary_input] = 0;
}

pub(crate) fn power_plant_max_order(state: &PowerPlantOrderState, city: &CityState) -> i16 {
    state.progress.quantity + city.stockpile[ResourceKind::Fuel] * 6
}

pub(crate) fn set_power_plant_quantity(
    state: &mut PowerPlantOrderState,
    stockpile: &mut Stockpile,
    population: &mut PopulationState,
    power_available: &mut i16,
    maximum: i16,
    quantity: i16,
) -> bool {
    let delta = quantity - state.progress.quantity;
    if quantity > maximum || quantity < 0 {
        return false;
    }
    state.progress.quantity = quantity;

    if i32::from(population.strength) < -i32::from(delta) {
        state.progress.quantity -= delta;
        return false;
    }

    state.desired_quantity = quantity;
    stockpile.wrapping_add_and_verify(ResourceKind::Fuel, -(delta / 6));
    let previous_power = population.extra;
    *power_available = quantity;
    population.extra = quantity;
    let power_change = quantity - previous_power;
    population.strength += power_change;
    true
}

pub(crate) fn restock_power_plant(
    state: &mut PowerPlantOrderState,
    stockpile: &mut Stockpile,
    population: &mut PopulationState,
    power_available: &mut i16,
) -> bool {
    let max_order = state.progress.quantity + stockpile[ResourceKind::Fuel] * 6;
    let saved_desired_quantity = state.desired_quantity;
    state.progress.quantity = 0;
    if max_order < saved_desired_quantity {
        let accepted = set_power_plant_quantity(
            state,
            stockpile,
            population,
            power_available,
            max_order,
            max_order,
        );
        state.desired_quantity = saved_desired_quantity;
        accepted
    } else {
        set_power_plant_quantity(
            state,
            stockpile,
            population,
            power_available,
            max_order,
            saved_desired_quantity,
        )
    }
}

pub(crate) fn retail_region_capacity(owner: &GreatPowerState, owned_region_count: usize) -> i16 {
    let divisor = if owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion]
        .status()
        .has_reached(crate::PendingActionStatus::completed(0))
    {
        3
    } else {
        4
    };
    let capacity = owned_region_count / divisor;
    if capacity > 1 { capacity as i16 } else { 1 }
}
