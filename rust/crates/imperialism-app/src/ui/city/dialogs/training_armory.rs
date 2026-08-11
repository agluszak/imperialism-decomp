use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct TrainingDialogControls {
    orders: Vec<CityOrderControl>,
    paper_one: Entity,
    paper_two: Entity,
    money_one: Entity,
    money_two: Entity,
    medium_labor: Entity,
    high_labor: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct ArmoryDialogControls {
    orders: Vec<CityOrderControl>,
    unit: Entity,
    workforce_cost: Entity,
    primary_cost: Entity,
    secondary_cost: Entity,
    cash_cost: Entity,
    workforce_available: Entity,
    primary_available: Entity,
    secondary_available: Entity,
    treasury_available: Entity,
}

pub(in crate::ui::city) fn bind_training_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    building_name: String,
) {
    let root = bind_city_dialog_root(commands, spawned, nation, CityFacilitySlot::TradeSchool);
    let name = spawned.unique(fourcc!("name"));
    commands.entity(name).insert(Text::new(building_name));
    for (tag, text) in [(fourcc!("cos1"), "$100"), (fourcc!("cos2"), "$1,000")] {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert(Text::new(text));
    }
    let orders = bind_city_order_controls(
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
    let [
        paper_one,
        paper_two,
        money_one,
        money_two,
        medium_labor,
        high_labor,
    ] = [
        fourcc!("pap1"),
        fourcc!("pap2"),
        fourcc!("mon1"),
        fourcc!("mon2"),
        fourcc!("untV"),
        fourcc!("traV"),
    ]
    .map(|tag| {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert(Text::new("X"));
        entity
    });
    commands.entity(root).insert(TrainingDialogControls {
        orders,
        paper_one,
        paper_two,
        money_one,
        money_two,
        medium_labor,
        high_labor,
    });
}

pub(in crate::ui::city) fn bind_armory_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    title: String,
) {
    let root = bind_city_dialog_root(commands, spawned, nation, CityFacilitySlot::Armory);
    let title_control = spawned.unique(fourcc!("titl"));
    commands.entity(title_control).insert(Text::new(title));
    commands.entity(root).insert(ArmorySelection {
        category: MilitaryRecruitmentCategory::LightInfantry,
    });
    let orders = bind_city_order_controls(
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
        let button = spawned.unique(armory_button_tag(category));
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
        let quantity = spawned.under(catalog, binding.tag, fourcc!("numb"));
        commands.entity(quantity).insert(InteractionDisabled);
    }
    let [
        unit,
        workforce_cost,
        primary_cost,
        secondary_cost,
        cash_cost,
        workforce_available,
        primary_available,
        secondary_available,
        treasury_available,
    ] = [
        fourcc!("unit"),
        fourcc!("cos0"),
        fourcc!("cos1"),
        fourcc!("cos2"),
        fourcc!("cos3"),
        fourcc!("ava0"),
        fourcc!("ava1"),
        fourcc!("ava2"),
        fourcc!("ava3"),
    ]
    .map(|tag| {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert(Text::new(""));
        entity
    });
    commands.entity(root).insert(ArmoryDialogControls {
        orders,
        unit,
        workforce_cost,
        primary_cost,
        secondary_cost,
        cash_cost,
        workforce_available,
        primary_available,
        secondary_available,
        treasury_available,
    });
}

pub(in crate::ui::city) fn sync_training_dialog(
    session: Res<GameSession>,
    dialogs: Query<(&TrainingDialogControls, Ref<CityBuildingDialog>)>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
) {
    for (controls, dialog) in &dialogs {
        if !session.is_changed() && !dialog.is_added() {
            continue;
        }
        let major = session.0.nations().major(dialog.nation);
        let city = &major.city;
        for control in &controls.orders {
            let CityOrderId::Training(level) = control.order else {
                unreachable!("Trade School control has a training order");
            };
            texts
                .get_mut(control.quantity)
                .expect("Trade School order quantity has text")
                .0 = city.orders.training[level].quantity.to_string();
        }

        let production = city.population.production_labor();
        let strength = city.population.strength();
        for (entity, visible) in [
            (controls.paper_one, city.stockpile[ResourceKind::Paper] >= 1),
            (controls.paper_two, city.stockpile[ResourceKind::Paper] >= 2),
            (
                controls.money_one,
                major
                    .economy
                    .available_diplomacy_budget(major.common.treasury)
                    >= 100,
            ),
            (
                controls.money_two,
                major
                    .economy
                    .available_diplomacy_budget(major.common.treasury)
                    >= 1_000,
            ),
            (controls.medium_labor, production.low.min(strength) != 0),
            (
                controls.high_labor,
                production.medium.min(strength / 2) != 0,
            ),
        ] {
            *visibilities
                .get_mut(entity)
                .expect("Trade School indicator has visibility") = if visible {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        }
    }
}

pub(in crate::ui::city) fn sync_armory_dialog(
    session: Res<GameSession>,
    dialogs: Query<(
        &ArmoryDialogControls,
        Ref<CityBuildingDialog>,
        Ref<ArmorySelection>,
    )>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
) {
    for (controls, dialog, selection) in &dialogs {
        if !session.is_changed()
            && !dialog.is_added()
            && !selection.is_added()
            && !selection.is_changed()
        {
            continue;
        }
        let major = session.0.nations().major(dialog.nation);
        let city = &major.city;
        for control in &controls.orders {
            let CityOrderId::MilitaryRecruit(category) = control.order else {
                unreachable!("Armory control has a military recruitment order");
            };
            texts
                .get_mut(control.quantity)
                .expect("Armory order quantity has text")
                .0 = city.orders.military_recruitment[category]
                .progress
                .quantity
                .to_string();
        }

        let order = &city.orders.military_recruitment[selection.category];
        let spec = military_recruitment_spec(order.unit_kind)
            .expect("Armory row has a recruitable retail unit recipe");
        let production = city.population.production_labor();
        let strength = city.population.strength();
        let (workforce, strength_divisor) = match spec.workforce {
            SkillBand::Low => (production.low, 1),
            SkillBand::Medium => (production.medium, 2),
            SkillBand::High => (production.high, 4),
        };
        for (entity, value) in [
            (controls.workforce_cost, 1),
            (controls.primary_cost, spec.primary.per_unit()),
            (
                controls.workforce_available,
                workforce.min(strength / strength_divisor),
            ),
            (
                controls.primary_available,
                city.stockpile[spec.primary.resource],
            ),
        ] {
            texts
                .get_mut(entity)
                .expect("Armory numeric control has text")
                .0 = value.to_string();
        }
        texts
            .get_mut(controls.unit)
            .expect("Armory unit control has text")
            .0 = format!("{:?}", order.unit_kind);
        texts
            .get_mut(controls.cash_cost)
            .expect("Armory cash cost has text")
            .0 = format_currency(i32::from(spec.cash_per_unit));
        texts
            .get_mut(controls.treasury_available)
            .expect("Armory treasury has text")
            .0 = format_currency(major.common.treasury);

        let [mut secondary_cost, mut secondary_available] = texts
            .get_many_mut([controls.secondary_cost, controls.secondary_available])
            .expect("Armory secondary controls have text");
        let secondary_visible = if let Some(secondary) = spec.secondary {
            secondary_cost.0 = secondary.per_unit().to_string();
            secondary_available.0 = city.stockpile[secondary.resource].to_string();
            true
        } else {
            secondary_cost.0.clear();
            secondary_available.0.clear();
            false
        };
        for entity in [controls.secondary_cost, controls.secondary_available] {
            *visibilities
                .get_mut(entity)
                .expect("Armory secondary control has visibility") = if secondary_visible {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        }
    }
}
