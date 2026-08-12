//! Manufactured-item order helpers and shared input reservation.

use super::*;
use crate::*;

pub(crate) fn item_limit(
    state: &RequestedCityOrderState,
    city: &CityState,
    spec: ItemOrderSpec,
) -> OrderLimit {
    item_limit_from_fields(
        state,
        &city.stockpile,
        &city.population,
        &city.production_accum,
        spec,
    )
}

pub(crate) fn item_limit_from_fields(
    state: &RequestedCityOrderState,
    stockpile: &Stockpile,
    population: &PopulationState,
    production_accum: &ProductionTable<i16>,
    spec: ItemOrderSpec,
) -> OrderLimit {
    let workforce_limit = population.strength / 2 + state.progress.quantity;
    let production_limit = production_accum[spec.production_slot] + state.progress.quantity;
    let resource_limit = match spec.inputs {
        ItemInputs::Double(primary) => {
            let index = primary;
            (state.progress.tracking_by_resource[index] + stockpile[index]) / 2
        }
        ItemInputs::Both(primary, secondary) => {
            let primary_index = primary;
            let secondary_index = secondary;
            let primary_limit =
                state.progress.tracking_by_resource[primary_index] + stockpile[primary_index];
            let secondary_limit =
                state.progress.tracking_by_resource[secondary_index] + stockpile[secondary_index];
            primary_limit.min(secondary_limit)
        }
        ItemInputs::Either(primary, secondary) => {
            let primary_index = primary;
            let secondary_index = secondary;
            (state.progress.tracking_by_resource[secondary_index]
                + state.progress.tracking_by_resource[primary_index]
                + stockpile[secondary_index]
                + stockpile[primary_index])
                / 2
        }
    };

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

pub(crate) fn set_item_quantity(
    state: &mut RequestedCityOrderState,
    stockpile: &mut Stockpile,
    population: &mut PopulationState,
    production_accum: &mut ProductionTable<i16>,
    spec: ItemOrderSpec,
    limit: OrderLimit,
    quantity: i16,
) -> bool {
    let delta = quantity - state.progress.quantity;
    state.progress.limiting_constraint = limit.constraint;
    if quantity > limit.maximum || quantity < 0 {
        return false;
    }

    state.progress.quantity = quantity;
    state.requested_quantity = quantity;
    match spec.inputs {
        ItemInputs::Double(primary) => {
            reserve_primary_and_secondary(
                stockpile,
                &mut state.progress.tracking_by_resource,
                primary,
                None,
                delta * 2,
            );
        }
        ItemInputs::Both(primary, secondary) => {
            reserve_primary_and_secondary(
                stockpile,
                &mut state.progress.tracking_by_resource,
                primary,
                Some(secondary),
                delta,
            );
        }
        ItemInputs::Either(primary, secondary) => {
            let (mut primary_change, mut secondary_change) = if delta > 0 {
                (delta, delta)
            } else {
                let release = -delta;
                (release, release)
            };
            let primary_available = if delta > 0 {
                stockpile[primary]
            } else {
                state.progress.tracking_by_resource[primary]
            };
            let secondary_available = if delta > 0 {
                stockpile[secondary]
            } else {
                state.progress.tracking_by_resource[secondary]
            };

            if primary_available < primary_change {
                let shortfall = primary_change - primary_available;
                primary_change -= shortfall;
                secondary_change += shortfall;
            } else if secondary_available < secondary_change {
                let shortfall = secondary_change - secondary_available;
                secondary_change -= shortfall;
                primary_change += shortfall;
            }
            if delta < 0 {
                primary_change = -primary_change;
                secondary_change = -secondary_change;
            }
            apply_tracked_input_change(
                stockpile,
                &mut state.progress.tracking_by_resource,
                primary,
                primary_change,
            );
            apply_tracked_input_change(
                stockpile,
                &mut state.progress.tracking_by_resource,
                secondary,
                secondary_change,
            );
        }
    }

    let workforce_change = delta * 2;
    population.strength -= workforce_change;
    state.progress.reserved_workforce += workforce_change;
    let production = &mut production_accum[spec.production_slot];
    *production -= delta;
    true
}

pub(crate) fn produce_item(
    state: &mut RequestedCityOrderState,
    stockpile: &mut Stockpile,
    production_accum: &mut ProductionTable<i16>,
    rolling_item_production_score: &mut i32,
    spec: ItemOrderSpec,
) {
    let production = &mut production_accum[spec.production_slot];
    *production += state.progress.quantity;
    stockpile.credit(spec.output, state.progress.quantity);
    *rolling_item_production_score += i32::from(state.progress.quantity);
    match spec.inputs {
        ItemInputs::Double(primary) => {
            state.progress.tracking_by_resource[primary] = 0;
        }
        ItemInputs::Both(primary, secondary) | ItemInputs::Either(primary, secondary) => {
            state.progress.tracking_by_resource[primary] = 0;
            state.progress.tracking_by_resource[secondary] = 0;
        }
    }
    state.progress.reserved_workforce = 0;
    state.progress.accumulated_value += i32::from(state.progress.quantity);
}

pub(crate) fn restock_item(
    state: &mut RequestedCityOrderState,
    stockpile: &mut Stockpile,
    population: &mut PopulationState,
    production_accum: &mut ProductionTable<i16>,
    spec: ItemOrderSpec,
) -> bool {
    let limit = item_limit_from_fields(state, stockpile, population, production_accum, spec);
    state.progress.limiting_constraint = limit.constraint;
    let saved_requested_quantity = state.requested_quantity;
    state.progress.quantity = 0;
    if limit.maximum < saved_requested_quantity
        && state.progress.limiting_constraint == ProductionConstraint::Resources
    {
        let accepted = set_item_quantity(
            state,
            stockpile,
            population,
            production_accum,
            spec,
            limit,
            limit.maximum,
        );
        state.requested_quantity = saved_requested_quantity;
        accepted
    } else {
        set_item_quantity(
            state,
            stockpile,
            population,
            production_accum,
            spec,
            limit,
            saved_requested_quantity,
        )
    }
}

pub(crate) fn apply_tracked_input_change(
    stockpile: &mut Stockpile,
    tracking: &mut ResourceTable<i16>,
    resource: ResourceKind,
    change: i16,
) {
    stockpile.credit(resource, -change);
    tracking[resource] += change;
}

pub(crate) fn reserve_primary_and_secondary(
    stockpile: &mut Stockpile,
    tracking: &mut ResourceTable<i16>,
    primary: ResourceKind,
    secondary: Option<ResourceKind>,
    change: i16,
) {
    apply_tracked_input_change(stockpile, tracking, primary, change);
    if let Some(secondary) = secondary {
        apply_tracked_input_change(stockpile, tracking, secondary, change);
    }
}
