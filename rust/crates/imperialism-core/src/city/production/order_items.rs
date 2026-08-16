//! Manufactured-item order helpers and shared input reservation.

use super::*;
use crate::*;

pub(crate) fn item_limit(
    state: &RequestedCityOrderState,
    city: &CityState,
    item: ManufacturedItem,
) -> OrderLimit {
    item_limit_from_fields(
        state,
        &city.stockpile,
        &city.population,
        &city.production_accum,
        item,
    )
}

pub(crate) fn item_limit_from_fields(
    state: &RequestedCityOrderState,
    stockpile: &Stockpile,
    population: &PopulationState,
    production_accum: &ProductionTable<i16>,
    item: ManufacturedItem,
) -> OrderLimit {
    let workforce_limit = population.strength / 2 + state.progress.quantity;
    let production_limit = production_accum[item.facility()] + state.progress.quantity;
    let resource_limit = match item.inputs() {
        ItemInputs::Double(primary) => {
            (state.tracking_by_resource[primary] + stockpile[primary]) / 2
        }
        ItemInputs::Both(primary, secondary) => {
            let primary_limit = state.tracking_by_resource[primary] + stockpile[primary];
            let secondary_limit = state.tracking_by_resource[secondary] + stockpile[secondary];
            primary_limit.min(secondary_limit)
        }
        ItemInputs::Either(primary, secondary) => {
            (state.tracking_by_resource[secondary]
                + state.tracking_by_resource[primary]
                + stockpile[secondary]
                + stockpile[primary])
                / 2
        }
    };

    let mut limit = OrderLimit {
        maximum: production_limit,
        constraint: ProductionConstraint::Capacity,
    };
    limit.min_with(workforce_limit, ProductionConstraint::Workforce);
    limit.min_with(resource_limit, ProductionConstraint::Resources);
    limit
}

pub(crate) fn set_item_quantity(
    state: &mut RequestedCityOrderState,
    stockpile: &mut Stockpile,
    population: &mut PopulationState,
    production_accum: &mut ProductionTable<i16>,
    item: ManufacturedItem,
    limit: OrderLimit,
    quantity: i16,
) -> bool {
    let Some(delta) = state.progress.try_set(limit, quantity) else {
        return false;
    };

    state.requested_quantity = quantity;
    match item.inputs() {
        ItemInputs::Double(primary) => {
            reserve_primary_and_secondary(
                stockpile,
                &mut state.tracking_by_resource,
                primary,
                None,
                delta * 2,
            );
        }
        ItemInputs::Both(primary, secondary) => {
            reserve_primary_and_secondary(
                stockpile,
                &mut state.tracking_by_resource,
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
                state.tracking_by_resource[primary]
            };
            let secondary_available = if delta > 0 {
                stockpile[secondary]
            } else {
                state.tracking_by_resource[secondary]
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
                &mut state.tracking_by_resource,
                primary,
                primary_change,
            );
            apply_tracked_input_change(
                stockpile,
                &mut state.tracking_by_resource,
                secondary,
                secondary_change,
            );
        }
    }

    let workforce_change = delta * 2;
    population.strength -= workforce_change;
    let production = &mut production_accum[item.facility()];
    *production -= delta;
    true
}

pub(crate) fn produce_item(
    state: &mut RequestedCityOrderState,
    stockpile: &mut Stockpile,
    production_accum: &mut ProductionTable<i16>,
    rolling_item_production_score: &mut i32,
    item: ManufacturedItem,
) {
    let production = &mut production_accum[item.facility()];
    *production += state.progress.quantity;
    stockpile.wrapping_add(item.resource(), state.progress.quantity);
    stockpile.verify_stocks();
    *rolling_item_production_score += i32::from(state.progress.quantity);
    match item.inputs() {
        ItemInputs::Double(primary) => {
            state.tracking_by_resource[primary] = 0;
        }
        ItemInputs::Both(primary, secondary) | ItemInputs::Either(primary, secondary) => {
            state.tracking_by_resource[primary] = 0;
            state.tracking_by_resource[secondary] = 0;
        }
    }
    state.accumulated_value += i32::from(state.progress.quantity);
}

pub(crate) fn restock_item(
    state: &mut RequestedCityOrderState,
    stockpile: &mut Stockpile,
    population: &mut PopulationState,
    production_accum: &mut ProductionTable<i16>,
    item: ManufacturedItem,
) -> bool {
    let limit = item_limit_from_fields(state, stockpile, population, production_accum, item);
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
            item,
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
            item,
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
    stockpile.wrapping_add(resource, change.wrapping_neg());
    stockpile.verify_stocks();
    tracking[resource] = tracking[resource].wrapping_add(change);
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
