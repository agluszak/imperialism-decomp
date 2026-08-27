use super::*;
use crate::ui::retail_amount_bar::{
    AmountBarStyle, amount_bar_click_value, amount_bar_geometry, amount_bar_x_from_normalized,
    quantize_amount_bar_value,
};

pub(in crate::ui::city) fn city_building_name(
    assets: &RetailUiAssets,
    slot: CityFacilitySlot,
) -> String {
    city_string(assets, CITY_BUILDING_STRING_GROUP, i16::from(slot.retail()))
}

pub(in crate::ui::city) struct CityOrderRow {
    pub(in crate::ui::city) row: Entity,
    pub(in crate::ui::city) quantity: Entity,
    pub(in crate::ui::city) bar: Option<Entity>,
}

impl CityOrderRow {
    pub(in crate::ui::city) fn set_available(&self, commands: &mut Commands, available: bool) {
        commands.entity(self.row).insert(if available {
            Visibility::Visible
        } else {
            Visibility::Hidden
        });
    }
}

fn amount_bar_range_for_order(game: &GameState, nation: MajorNationId, order: CityOrderId) -> i16 {
    let city = &game.nations().major(nation).city;
    match order {
        CityOrderId::Item(item) => city.production_orders[item.facility()],
        CityOrderId::FoodProcessing | CityOrderId::TransportCapacity => {
            let labor = city.population.production_labor();
            ((labor.high * 2 + labor.medium) * 2 + city.population.extra() + labor.low) / 2
        }
        _ => game.city_order_limit(nation, order).maximum,
    }
}

/// Industry/Rail/`TAmtBarCluster` rows: binder owns `+/-` and bar clicks.
pub(in crate::ui::city) fn bind_industry_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    order: CityOrderId,
    tag: FourCc,
    step: i16,
) -> CityOrderRow {
    let row = tree.find(root, tag);
    let decrease = tree.find(row, fourcc!("left"));
    let increase = tree.find(row, fourcc!("rght"));
    let quantity = tree.find(row, fourcc!("move"));
    let bar = tree.find(row, fourcc!("bar "));
    let bind_step = |commands: &mut Commands, entity: Entity, delta: i16| {
        commands.entity(entity).observe(
            move |_: On<Activate>, mut session: ResMut<GameSession>| {
                let nation = session.active_major_nation();
                session.game.adjust_city_order(nation, order, delta);
            },
        );
    };
    bind_step(commands, decrease, -step);
    bind_step(commands, increase, step);
    commands.entity(bar).observe(
        move |mut click: On<Pointer<Click>>, mut session: ResMut<GameSession>| {
            let Some(position) = click.hit.position else {
                return;
            };
            click.propagate(false);
            let nation = session.active_major_nation();
            let previous = session.game.city_order_quantity(nation, order);
            let range = amount_bar_range_for_order(&session.game, nation, order);
            let geometry = amount_bar_geometry(AmountBarStyle::Production, range);
            let x = amount_bar_x_from_normalized(geometry, position.x);
            let value = amount_bar_click_value(geometry, x, previous);
            let quantity = quantize_amount_bar_value(value, step);
            session
                .game
                .set_city_order_quantity(nation, order, quantity);
        },
    );
    CityOrderRow {
        row,
        quantity,
        bar: Some(bar),
    }
}

pub(in crate::ui::city) fn bind_recruitment_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    order: CityOrderId,
    tag: FourCc,
) -> CityOrderRow {
    let row = tree.find(root, tag);
    let decrease = tree.find(row, fourcc!("minu"));
    let increase = tree.find(row, fourcc!("plus"));
    let quantity = tree.find(row, fourcc!("numb"));
    let bind_step = |commands: &mut Commands, entity: Entity, delta: i16| {
        commands.entity(entity).observe(
            move |_: On<Activate>, mut session: ResMut<GameSession>| {
                let nation = session.active_major_nation();
                session.game.adjust_city_order(nation, order, delta);
            },
        );
    };
    bind_step(commands, decrease, -1);
    bind_step(commands, increase, 1);
    CityOrderRow {
        row,
        quantity,
        bar: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specialized_city_buildings_use_the_one_based_retail_name_indexes() {
        assert_eq!(
            city_string_index(i16::from(CityFacilitySlot::OilRefinery.retail())),
            7
        );
        assert_eq!(
            city_string_index(i16::from(CityFacilitySlot::Shipyard.retail())),
            8
        );
        assert_eq!(
            city_string_index(i16::from(CityFacilitySlot::Armory.retail())),
            9
        );
    }
}
