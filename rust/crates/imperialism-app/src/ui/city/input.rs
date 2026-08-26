use super::*;
use crate::ui::retail_amount_bar::{
    INDUSTRY_AMOUNT_BAR, amount_bar_click_value, amount_bar_x_from_normalized,
    quantize_amount_bar_value,
};

pub(in crate::ui::city) fn on_city_amount_bar_click(
    mut click: On<Pointer<Click>>,
    views: Query<&IndustryView>,
    mut session: ResMut<GameSession>,
) {
    let Some(position) = click.hit.position else {
        return;
    };
    click.propagate(false);
    let nation = session.active_major_nation();
    for view in &views {
        let page = INDUSTRY_PAGES
            .iter()
            .find(|page| page.slot == view.slot)
            .expect("industry dialog view has a recovered page");
        for (binding, order) in page.orders.iter().zip(&view.orders) {
            if click.entity != order.bar {
                continue;
            }
            let city = &session.game.nations().major(nation).city;
            let capacity = city.production_orders[view.slot];
            let previous = match binding.order {
                CityOrderId::Item(output) => city.orders.items[output].progress.quantity,
                _ => unreachable!("industry amount bar has an item order"),
            };
            let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
            let x = amount_bar_x_from_normalized(geometry, position.x);
            let quantity = amount_bar_click_value(geometry, x, previous);
            session
                .game
                .set_city_order_quantity(nation, binding.order, quantity);
            return;
        }
    }
}

pub(in crate::ui::city) fn on_city_rail_amount_bar_click(
    mut click: On<Pointer<Click>>,
    views: Query<&RailView>,
    mut session: ResMut<GameSession>,
) {
    let Some(position) = click.hit.position else {
        return;
    };
    click.propagate(false);
    let nation = session.active_major_nation();
    for view in &views {
        if click.entity != view.bar {
            continue;
        }
        let city = &session.game.nations().major(nation).city;
        let capacity = match view.order {
            CityOrderId::FoodProcessing | CityOrderId::TransportCapacity => {
                let labor = city.population.production_labor();
                ((labor.high * 2 + labor.medium) * 2 + city.population.extra() + labor.low) / 2
            }
            _ => session.game.city_order_limit(nation, view.order).maximum,
        };
        let previous = session.game.city_order_quantity(nation, view.order);
        let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
        let x = amount_bar_x_from_normalized(geometry, position.x);
        let quantity =
            quantize_amount_bar_value(amount_bar_click_value(geometry, x, previous), view.step);
        session
            .game
            .set_city_order_quantity(nation, view.order, quantity);
        return;
    }
}

pub(in crate::ui::city) fn on_city_order_adjust(
    activate: On<Activate>,
    actions: Query<&CityOrderAdjust>,
    mut session: ResMut<GameSession>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let nation = session.active_major_nation();
    session
        .game
        .adjust_city_order(nation, action.order, action.delta);
}
