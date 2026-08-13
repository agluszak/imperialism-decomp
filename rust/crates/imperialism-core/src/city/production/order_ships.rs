//! Shipyard order helpers.

use super::*;
use crate::*;

pub(crate) fn ship_max_order(state: &ShipOrderState, city: &CityState) -> i16 {
    let costs = ship_order_costs(state.ship_type);
    let mut limit = 10_000_i16;
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
    maximum: i16,
    quantity: i16,
) -> bool {
    let delta = quantity - state.progress.quantity;
    if quantity > maximum || quantity < 0 {
        return false;
    }
    state.progress.quantity = quantity;
    let costs = ship_order_costs(state.ship_type);
    for (resource, cost) in costs.iter() {
        stockpile.wrapping_add_and_verify(resource, -(cost * delta));
    }
    true
}
