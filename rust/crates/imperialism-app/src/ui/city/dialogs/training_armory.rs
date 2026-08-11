use super::*;

pub(in crate::ui::city) fn bind_training_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    building_name: String,
) {
    let root = bind_city_dialog_root(commands, spawned, nation, CityFacilitySlot::TradeSchool);
    let name = spawned
        .require_unique(fourcc!("name"))
        .expect("validated trade-school name binding");
    commands.entity(name).insert(Text::new(building_name));
    for (tag, text) in [(fourcc!("cos1"), "$100"), (fourcc!("cos2"), "$1,000")] {
        let entity = spawned
            .require_unique(tag)
            .expect("validated trade-school cost binding");
        commands.entity(entity).insert(Text::new(text));
    }
    bind_city_order_controls(
        commands,
        catalog,
        spawned,
        root,
        nation,
        &TRAINING_ORDERS,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        1,
    );
    for (tag, value) in [
        (
            fourcc!("pap1"),
            CityValue::AvailableStockIndicator(ResourceKind::Paper, 1),
        ),
        (
            fourcc!("pap2"),
            CityValue::AvailableStockIndicator(ResourceKind::Paper, 2),
        ),
        (fourcc!("mon1"), CityValue::AvailableBudgetIndicator(100)),
        (fourcc!("mon2"), CityValue::AvailableBudgetIndicator(1_000)),
        (
            fourcc!("untV"),
            CityValue::TrainingLaborIndicator(TrainingLevel::Medium),
        ),
        (
            fourcc!("traV"),
            CityValue::TrainingLaborIndicator(TrainingLevel::High),
        ),
    ] {
        let entity = spawned
            .require_unique(tag)
            .expect("validated trade-school availability binding");
        commands.entity(entity).insert((
            Text::new("X"),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
        ));
    }
}

pub(in crate::ui::city) fn bind_armory_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    title: String,
) {
    let root = bind_city_dialog_root(commands, spawned, nation, CityFacilitySlot::Armory);
    let title_control = spawned
        .require_unique(fourcc!("titl"))
        .expect("validated Armory title binding");
    commands.entity(title_control).insert(Text::new(title));
    commands.entity(root).insert(ArmorySelection {
        category: MilitaryRecruitmentCategory::LightInfantry,
    });
    bind_city_order_controls(
        commands,
        catalog,
        spawned,
        root,
        nation,
        &ARMORY_ORDERS,
        fourcc!("minu"),
        fourcc!("plus"),
        fourcc!("numb"),
        1,
    );
    for binding in &ARMORY_ORDERS {
        let CityOrderId::MilitaryRecruit(category) = binding.order else {
            unreachable!("armory binding has a military recruitment order");
        };
        let button = spawned
            .require_unique(armory_button_tag(category))
            .expect("validated armory row button binding");
        let mut button_commands = commands.entity(button);
        button_commands.insert(ArmoryRowChoice {
            dialog: root,
            category,
        });
        if category == MilitaryRecruitmentCategory::LightInfantry {
            button_commands.insert(Checked);
        } else {
            button_commands.remove::<Checked>();
        }
        let quantity = spawned
            .require_under(catalog, binding.tag, fourcc!("numb"))
            .expect("validated armory quantity binding");
        commands.entity(quantity).insert((
            InteractionDisabled,
            CityValueBinding {
                dialog: Some(root),
                value: CityValue::ArmoryOrderQuantity(category),
            },
        ));
    }
    for (tag, value) in [
        (fourcc!("unit"), CityValue::ArmoryUnitKind),
        (fourcc!("cos0"), CityValue::ArmoryWorkforceCost),
        (fourcc!("cos1"), CityValue::ArmoryPrimaryCost),
        (fourcc!("cos2"), CityValue::ArmorySecondaryCost),
        (fourcc!("cos3"), CityValue::ArmoryCashCost),
        (fourcc!("ava0"), CityValue::ArmoryWorkforceAvailable),
        (fourcc!("ava1"), CityValue::ArmoryPrimaryAvailable),
        (fourcc!("ava2"), CityValue::ArmorySecondaryAvailable),
        (fourcc!("ava3"), CityValue::ArmoryTreasuryAvailable),
    ] {
        let entity = spawned
            .require_unique(tag)
            .expect("validated armory detail binding");
        commands.entity(entity).insert((
            Text::new(""),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
        ));
    }
}
