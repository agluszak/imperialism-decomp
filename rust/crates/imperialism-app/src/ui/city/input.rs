use super::*;

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
    let x = (((normalized.x + 0.5) * f32::from(INDUSTRY_BAR_WIDTH)).floor() as i16)
        .clamp(0, INDUSTRY_BAR_WIDTH - 1);
    let city = &session.game.nations().major(nation).city;
    let capacity = city.production_orders[bar.slot];
    let previous = match bar.order {
        CityOrderId::Item(output) => city.orders.items[output].progress.quantity,
        _ => unreachable!("industry amount bar has an item order"),
    };
    let mut quantity = if capacity > 0
        && i32::from(x) < i32::from(INDUSTRY_BAR_WIDTH) / (i32::from(capacity) * 2)
    {
        0
    } else if capacity > 0 {
        (i32::from(x) * i32::from(capacity) / i32::from(INDUSTRY_BAR_WIDTH) + 1) as i16
    } else {
        1
    };
    if quantity == 0 && x != 0 && previous == 0 {
        quantity = 1;
    }
    session
        .game
        .set_city_order_quantity(nation, bar.order, quantity);
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
