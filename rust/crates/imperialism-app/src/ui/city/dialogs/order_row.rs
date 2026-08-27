use super::*;

pub(in crate::ui::city) fn city_building_name(
    assets: &RetailUiAssets,
    slot: CityFacilitySlot,
) -> String {
    city_string(assets, CITY_BUILDING_STRING_GROUP, i16::from(slot.retail()))
}

pub(in crate::ui::city) struct CityOrderRow {
    pub(in crate::ui::city) row: Entity,
    pub(in crate::ui::city) quantity: Entity,
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

fn bind_city_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    order: CityOrderId,
    tag: FourCc,
    decrease_tag: FourCc,
    increase_tag: FourCc,
    quantity_tag: FourCc,
    step: i16,
) -> CityOrderRow {
    let row = tree.find(root, tag);
    let decrease = tree.find(row, decrease_tag);
    let increase = tree.find(row, increase_tag);
    let quantity = tree.find(row, quantity_tag);
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
    CityOrderRow { row, quantity }
}

pub(in crate::ui::city) fn bind_industry_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    order: CityOrderId,
    tag: FourCc,
    step: i16,
) -> CityOrderRow {
    bind_city_order_row(
        commands,
        root,
        tree,
        order,
        tag,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        step,
    )
}

pub(in crate::ui::city) fn bind_recruitment_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    order: CityOrderId,
    tag: FourCc,
) -> CityOrderRow {
    bind_city_order_row(
        commands,
        root,
        tree,
        order,
        tag,
        fourcc!("minu"),
        fourcc!("plus"),
        fourcc!("numb"),
        1,
    )
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
