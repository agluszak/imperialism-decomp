//! Shipyard order helpers.

use super::*;
use crate::*;

pub(crate) fn ship_max_order(state: &ShipOrderState, city: &CityState) -> i16 {
    let costs = ship_order_costs(state.ship_type);
    let mut limit = 10_000_i16;
    for resource in [
        ResourceKind::Lumber,
        ResourceKind::Fabric,
        ResourceKind::Arms,
        ResourceKind::Steel,
        ResourceKind::Coal,
        ResourceKind::Fuel,
    ] {
        let cost = costs[resource];
        if cost != 0 {
            limit = limit.min(city.stockpile[resource] / cost);
        }
    }
    state.progress.quantity + limit
}

pub(crate) fn set_ship_quantity(
    state: &mut ShipOrderState,
    city: &mut CityState,
    quantity: i16,
) -> bool {
    let delta = quantity - state.progress.quantity;
    if quantity > ship_max_order(state, city) || quantity < 0 {
        return false;
    }
    state.progress.quantity = quantity;
    let costs = ship_order_costs(state.ship_type);
    for resource in [
        ResourceKind::Lumber,
        ResourceKind::Fabric,
        ResourceKind::Arms,
        ResourceKind::Steel,
        ResourceKind::Coal,
        ResourceKind::Fuel,
    ] {
        city.adjust_stock(resource, -(costs[resource] * delta));
    }
    true
}
