use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct ArmorySelection {
    pub(in crate::ui::city) category: MilitaryRecruitmentCategory,
}

#[derive(Component)]
pub(in crate::ui::city) struct ArmoryRowChoice {
    pub(in crate::ui::city) category: MilitaryRecruitmentCategory,
}

pub(in crate::ui::city) fn bind_training_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    building_name: String,
) {
    bind_city_dialog_root(commands, spawned, CityFacilitySlot::TradeSchool);
    let name = spawned.unique(fourcc!("name"));
    commands.entity(name).insert(Text::new(building_name));
    for (tag, text) in [(fourcc!("cos1"), "$100"), (fourcc!("cos2"), "$1,000")] {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert(Text::new(text));
    }
    bind_city_order_controls(
        commands,
        catalog,
        spawned,
        &TRAINING_ORDERS,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        1,
    );
    for tag in [
        fourcc!("pap1"),
        fourcc!("pap2"),
        fourcc!("mon1"),
        fourcc!("mon2"),
        fourcc!("untV"),
        fourcc!("traV"),
    ] {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert(Text::new("X"));
    }
}

pub(in crate::ui::city) fn bind_armory_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    title: String,
) {
    let root = bind_city_dialog_root(commands, spawned, CityFacilitySlot::Armory);
    let title_control = spawned.unique(fourcc!("titl"));
    commands.entity(title_control).insert(Text::new(title));
    commands.entity(root).insert(ArmorySelection {
        category: MilitaryRecruitmentCategory::LightInfantry,
    });
    bind_city_order_controls(
        commands,
        catalog,
        spawned,
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
        commands.entity(button).insert(ArmoryRowChoice { category });
        let quantity = spawned.under(catalog, binding.tag, fourcc!("numb"));
        commands.entity(quantity).insert(InteractionDisabled);
    }
    for tag in [
        fourcc!("unit"),
        fourcc!("cos0"),
        fourcc!("cos1"),
        fourcc!("cos2"),
        fourcc!("cos3"),
        fourcc!("ava0"),
        fourcc!("ava1"),
        fourcc!("ava2"),
        fourcc!("ava3"),
    ] {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert(Text::new(""));
    }
}

pub(in crate::ui::city) fn sync_training_dialog(
    session: Res<GameSession>,
    catalog: Res<UiCatalogResource>,
    dialogs: Query<(&SpawnedView, Ref<CityBuildingDialog>)>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City active nation is a major nation");
    for (spawned, dialog) in &dialogs {
        if dialog.slot != CityFacilitySlot::TradeSchool {
            continue;
        }
        if !session.is_changed() && !dialog.is_added() {
            continue;
        }
        let major = session.0.nations().major(nation);
        let city = &major.city;
        for binding in &TRAINING_ORDERS {
            let CityOrderId::Training(level) = binding.order else {
                unreachable!("Trade School control has a training order");
            };
            texts
                .get_mut(spawned.under(&catalog, binding.tag, fourcc!("move")))
                .expect("Trade School order quantity has text")
                .0 = city.orders.training[level].quantity.to_string();
        }

        let production = city.population.production_labor();
        let strength = city.population.strength();
        let budget = major
            .economy
            .available_diplomacy_budget(major.common.treasury);
        for (tag, visible) in [
            (fourcc!("pap1"), city.stockpile[ResourceKind::Paper] >= 1),
            (fourcc!("pap2"), city.stockpile[ResourceKind::Paper] >= 2),
            (fourcc!("mon1"), budget >= 100),
            (fourcc!("mon2"), budget >= 1_000),
            (fourcc!("untV"), production.low.min(strength) != 0),
            (fourcc!("traV"), production.medium.min(strength / 2) != 0),
        ] {
            *visibilities
                .get_mut(spawned.unique(tag))
                .expect("Trade School indicator has visibility") = if visible {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        }
    }
}

pub(in crate::ui::city) fn sync_armory_dialog(
    mut commands: Commands,
    session: Res<GameSession>,
    catalog: Res<UiCatalogResource>,
    dialogs: Query<(&SpawnedView, Ref<ArmorySelection>)>,
    rows: Query<(&ArmoryRowChoice, Has<Checked>)>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City active nation is a major nation");
    for (spawned, selection) in &dialogs {
        if !session.is_changed() && !selection.is_changed() {
            continue;
        }
        for binding in ARMORY_ORDERS {
            let CityOrderId::MilitaryRecruit(category) = binding.order else {
                unreachable!("Armory binding has a military recruitment order");
            };
            let button = spawned.unique(armory_button_tag(category));
            let (_, checked) = rows
                .get(button)
                .expect("Armory button has its retail row choice");
            if checked != (category == selection.category) {
                if checked {
                    commands.entity(button).remove::<Checked>();
                } else {
                    commands.entity(button).insert(Checked);
                }
            }
        }
        let major = session.0.nations().major(nation);
        let city = &major.city;
        for binding in &ARMORY_ORDERS {
            let CityOrderId::MilitaryRecruit(category) = binding.order else {
                unreachable!("Armory control has a military recruitment order");
            };
            texts
                .get_mut(spawned.under(&catalog, binding.tag, fourcc!("numb")))
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
        for (tag, value) in [
            (fourcc!("cos0"), 1),
            (fourcc!("cos1"), spec.primary.per_unit()),
            (fourcc!("ava0"), workforce.min(strength / strength_divisor)),
            (fourcc!("ava1"), city.stockpile[spec.primary.resource]),
        ] {
            texts
                .get_mut(spawned.unique(tag))
                .expect("Armory numeric control has text")
                .0 = value.to_string();
        }
        texts
            .get_mut(spawned.unique(fourcc!("unit")))
            .expect("Armory unit control has text")
            .0 = format!("{:?}", order.unit_kind);
        texts
            .get_mut(spawned.unique(fourcc!("cos3")))
            .expect("Armory cash cost has text")
            .0 = format_currency(i32::from(spec.cash_per_unit));
        texts
            .get_mut(spawned.unique(fourcc!("ava3")))
            .expect("Armory treasury has text")
            .0 = format_currency(major.common.treasury);

        let secondary_cost_entity = spawned.unique(fourcc!("cos2"));
        let secondary_available_entity = spawned.unique(fourcc!("ava2"));
        let [mut secondary_cost, mut secondary_available] = texts
            .get_many_mut([secondary_cost_entity, secondary_available_entity])
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
        for entity in [secondary_cost_entity, secondary_available_entity] {
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
