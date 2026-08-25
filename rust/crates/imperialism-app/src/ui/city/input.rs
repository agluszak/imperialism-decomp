use super::*;
use crate::ui::retail_amount_bar::{
    INDUSTRY_AMOUNT_BAR, amount_bar_click_value, amount_bar_x_from_normalized,
    quantize_amount_bar_value,
};

pub(in crate::ui::city) fn on_city_amount_bar_click(
    mut click: On<Pointer<Click>>,
    bars: Query<(&RelativeCursorPosition, &CityAmountBar)>,
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
    let capacity = amount_bar_capacity(city, bar.order, nation, &session.game);
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
    mut commands: Commands,
    mut session: ResMut<GameSession>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    if let Some(selection) = action.selection {
        commands
            .entity(selection)
            .insert(CityOrderSelection(action.order));
    }
    let nation = session.active_major_nation();
    session
        .game
        .adjust_city_order(nation, action.order, action.delta);
}
