use super::*;
use crate::ui::retail_amount_bar::quantize_amount_bar_value;

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

/// Industry/Rail/`TAmtBarCluster` rows: `RetailAmountSelector` owns `+/-`.
/// Observe cluster and bar [`ValueChange`] (selector emits on the cluster; bar clicks on the bar).
pub(in crate::ui::city) fn bind_industry_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    order: CityOrderId,
    tag: FourCc,
    step: i16,
) -> CityOrderRow {
    let row = tree.find(root, tag);
    let quantity = tree.find(row, fourcc!("move"));
    let bar = tree.find(row, fourcc!("bar "));
    let bind_value = |commands: &mut Commands, entity: Entity| {
        commands.entity(entity).observe(
            move |change: On<ValueChange<i16>>, mut session: ResMut<GameSession>| {
                let nation = session.active_major_nation();
                let quantity = quantize_amount_bar_value(change.value, step);
                session
                    .game
                    .set_city_order_quantity(nation, order, quantity);
            },
        );
    };
    bind_value(commands, row);
    bind_value(commands, bar);
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
