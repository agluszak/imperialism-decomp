//! Manufactured-item order helpers and shared input reservation.

use super::*;
use crate::*;

pub(crate) fn item_max_order(
    state: &mut RequestedCityOrderState,
    city: &CityState,
    spec: ItemOrderSpec,
) -> i16 {
    let workforce_limit = city.population.strength / 2 + state.progress.quantity;
    let production_limit = city.production_accum[spec.production_slot] + state.progress.quantity;
    let resource_limit = match spec.inputs {
        ItemInputs::Double(primary) => {
            let index = primary;
            (state.progress.tracking_by_resource[index] + city.stockpile[index]) / 2
        }
        ItemInputs::Both(primary, secondary) => {
            let primary_index = primary;
            let secondary_index = secondary;
            let primary_limit =
                state.progress.tracking_by_resource[primary_index] + city.stockpile[primary_index];
            let secondary_limit = state.progress.tracking_by_resource[secondary_index]
                + city.stockpile[secondary_index];
            primary_limit.min(secondary_limit)
        }
        ItemInputs::Either(primary, secondary) => {
            let primary_index = primary;
            let secondary_index = secondary;
            (state.progress.tracking_by_resource[secondary_index]
                + state.progress.tracking_by_resource[primary_index]
                + city.stockpile[secondary_index]
                + city.stockpile[primary_index])
                / 2
        }
    };

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

pub(crate) fn set_item_quantity(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    spec: ItemOrderSpec,
    quantity: i16,
) -> bool {
    let delta = quantity - state.progress.quantity;
    if quantity > item_max_order(state, city, spec) || quantity < 0 {
        return false;
    }

    state.progress.quantity = quantity;
    state.requested_quantity = quantity;
    match spec.inputs {
        ItemInputs::Double(primary) => {
            reserve_primary_and_secondary(
                city,
                &mut state.progress.tracking_by_resource,
                primary,
                None,
                delta * 2,
            );
        }
        ItemInputs::Both(primary, secondary) => {
            reserve_primary_and_secondary(
                city,
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
                city.stockpile[primary]
            } else {
                state.progress.tracking_by_resource[primary]
            };
            let secondary_available = if delta > 0 {
                city.stockpile[secondary]
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
                city,
                &mut state.progress.tracking_by_resource,
                primary,
                primary_change,
            );
            apply_tracked_input_change(
                city,
                &mut state.progress.tracking_by_resource,
                secondary,
                secondary_change,
            );
        }
    }

    let workforce_change = delta * 2;
    city.population.strength -= workforce_change;
    state.progress.reserved_workforce += workforce_change;
    let production = &mut city.production_accum[spec.production_slot];
    *production -= delta;
    true
}

pub(crate) fn produce_item(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    spec: ItemOrderSpec,
) {
    let production = &mut city.production_accum[spec.production_slot];
    *production += state.progress.quantity;
    city.adjust_stock(spec.output, state.progress.quantity);
    city.rolling_item_production_score += i32::from(state.progress.quantity);
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
    city: &mut CityState,
    spec: ItemOrderSpec,
) -> bool {
    let max_order = item_max_order(state, city, spec);
    let saved_requested_quantity = state.requested_quantity;
    state.progress.quantity = 0;
    if max_order < saved_requested_quantity
        && state.progress.limiting_constraint == ProductionConstraint::Resources
    {
        let accepted = set_item_quantity(state, city, spec, max_order);
        state.requested_quantity = saved_requested_quantity;
        accepted
    } else {
        set_item_quantity(state, city, spec, saved_requested_quantity)
    }
}

pub(crate) fn apply_tracked_input_change(
    city: &mut CityState,
    tracking: &mut ResourceTable<i16>,
    resource: ResourceKind,
    change: i16,
) {
    city.adjust_stock(resource, -change);
    tracking[resource] += change;
}

pub(crate) fn reserve_primary_and_secondary(
    city: &mut CityState,
    tracking: &mut ResourceTable<i16>,
    primary: ResourceKind,
    secondary: Option<ResourceKind>,
    change: i16,
) {
    apply_tracked_input_change(city, tracking, primary, change);
    if let Some(secondary) = secondary {
        apply_tracked_input_change(city, tracking, secondary, change);
    }
}
