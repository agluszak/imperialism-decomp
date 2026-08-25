use super::*;
use crate::ui::retail_amount_bar::{
    INDUSTRY_AMOUNT_BAR, amount_bar_click_value, amount_bar_x_from_normalized,
    quantize_amount_bar_value,
};

pub(in crate::ui::city) fn on_city_amount_bar_click(
    mut click: On<Pointer<Click>>,
    bars: Query<(&RelativeCursorPosition, &CityIndustryAmountBar)>,
    mut session: ResMut<GameSession>,
) {
    let Ok((cursor, bar)) = bars.get(click.entity) else {
        return;
    };
    let Some(normalized) = cursor.normalized.filter(|_| cursor.cursor_over()) else {
        return;
    };
    click.propagate(false);

    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    let capacity = city.production_orders[bar.slot];
    let previous = match bar.order {
        CityOrderId::Item(output) => city.orders.items[output].progress.quantity,
        _ => unreachable!("industry amount bar has an item order"),
    };
    let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
    let x = amount_bar_x_from_normalized(geometry, normalized.x);
    let quantity = amount_bar_click_value(geometry, x, previous);
    session
        .game
        .set_city_order_quantity(nation, bar.order, quantity);
}

pub(in crate::ui::city) fn on_city_rail_amount_bar_click(
    mut click: On<Pointer<Click>>,
    bars: Query<(&RelativeCursorPosition, &CityRailAmountBar)>,
    mut session: ResMut<GameSession>,
) {
    let Ok((cursor, bar)) = bars.get(click.entity) else {
        return;
    };
    let Some(normalized) = cursor.normalized.filter(|_| cursor.cursor_over()) else {
        return;
    };
    click.propagate(false);

    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    let capacity = match bar.order {
        CityOrderId::FoodProcessing | CityOrderId::TransportCapacity => {
            let labor = city.population.production_labor();
            ((labor.high * 2 + labor.medium) * 2 + city.population.extra() + labor.low) / 2
        }
        _ => session.game.city_order_limit(nation, bar.order).maximum,
    };
    let previous = session.game.city_order_quantity(nation, bar.order);
    let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
    let x = amount_bar_x_from_normalized(geometry, normalized.x);
    let quantity =
        quantize_amount_bar_value(amount_bar_click_value(geometry, x, previous), bar.step);
    session
        .game
        .set_city_order_quantity(nation, bar.order, quantity);
}

pub(in crate::ui::city) fn on_city_order_adjust(
    activate: On<Activate>,
    actions: Query<&CityOrderAdjust>,
    mut views: Query<&mut CityRowSelection>,
    mut session: ResMut<GameSession>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    if let Some(selection_entity) = action.selection
        && let Ok(mut selection) = views.get_mut(selection_entity)
        && recruitment_kind_matches(selection.order, action.order)
    {
        selection.order = action.order;
    }
    let nation = session.active_major_nation();
    session
        .game
        .adjust_city_order(nation, action.order, action.delta);
}
