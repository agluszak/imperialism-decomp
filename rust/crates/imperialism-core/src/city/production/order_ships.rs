//! Shipyard order helpers.

use super::*;
use crate::*;

pub(crate) fn ship_max_order(state: &ShipOrderState, city: &CityState) -> i32 {
    let costs = ship_order_costs(state.ship_type);
    let mut limit = 10_000;
    for (resource, cost) in costs.iter() {
        if cost != 0 {
            limit = limit.min(city.stockpile[resource] / cost);
        }
    }
    state.progress.quantity + limit
}

pub(crate) fn set_ship_quantity(
    state: &mut ShipOrderState,
    stockpile: &mut Stockpile,
    maximum: i32,
    quantity: i32,
) -> bool {
    let Some(delta) = state.progress.try_set_within(maximum, quantity) else {
        return false;
    };
    let costs = ship_order_costs(state.ship_type);
    for (resource, cost) in costs.iter() {
        stockpile.wrapping_add_and_verify(resource, -(cost * delta));
    }
    true
}
