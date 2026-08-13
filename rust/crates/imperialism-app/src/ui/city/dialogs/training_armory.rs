use super::*;

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) enum TrainingIndicator {
    Paper { minimum: i16 },
    Money { minimum: i32 },
    UntrainedAvailable,
    TrainedAvailable,
}

#[derive(Component)]
pub(in crate::ui::city) struct ArmorySelection {
    pub(in crate::ui::city) category: MilitaryRecruitmentCategory,
}

#[derive(Component)]
pub(in crate::ui::city) struct ArmoryRowChoice {
    pub(in crate::ui::city) category: MilitaryRecruitmentCategory,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) enum ArmoryDetail {
    UnitName,
    WorkforceCost,
    PrimaryCost,
    SecondaryCost,
    CashCost,
    WorkforceAvailable,
    PrimaryAvailable,
    SecondaryAvailable,
    Treasury,
}

pub(in crate::ui::city) fn configure_training_dialog(
    commands: &mut Commands,
    assets: &RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::TradeSchool);
    bind_training_dialog(commands, root, children, tags, building_name);
}

pub(in crate::ui::city) fn bind_training_dialog(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    building_name: String,
) {
    bind_city_dialog_root(
        commands,
        root,
        children,
        tags,
        CityFacilitySlot::TradeSchool,
    );
    let name = find_descendant(root, fourcc!("name"), children, tags);
    commands.entity(name).insert(Text::new(building_name));
    for (tag, text) in [(fourcc!("cos1"), "$100"), (fourcc!("cos2"), "$1,000")] {
        let entity = find_descendant(root, tag, children, tags);
        commands.entity(entity).insert(Text::new(text));
    }
    for binding in TRAINING_ORDERS {
        bind_city_order_control(
            commands,
            root,
            children,
            tags,
            binding,
            fourcc!("left"),
            fourcc!("rght"),
            fourcc!("move"),
            1,
        );
    }
    let paper_one = find_descendant(root, fourcc!("pap1"), children, tags);
    let paper_two = find_descendant(root, fourcc!("pap2"), children, tags);
    let money_one = find_descendant(root, fourcc!("mon1"), children, tags);
    let money_two = find_descendant(root, fourcc!("mon2"), children, tags);
    let untrained_available = find_descendant(root, fourcc!("untV"), children, tags);
    let trained_available = find_descendant(root, fourcc!("traV"), children, tags);
    commands
        .entity(paper_one)
        .insert((Text::new("X"), TrainingIndicator::Paper { minimum: 1 }));
    commands
        .entity(paper_two)
        .insert((Text::new("X"), TrainingIndicator::Paper { minimum: 2 }));
    commands
        .entity(money_one)
        .insert((Text::new("X"), TrainingIndicator::Money { minimum: 100 }));
    commands
        .entity(money_two)
        .insert((Text::new("X"), TrainingIndicator::Money { minimum: 1_000 }));
    commands
        .entity(untrained_available)
        .insert((Text::new("X"), TrainingIndicator::UntrainedAvailable));
    commands
        .entity(trained_available)
        .insert((Text::new("X"), TrainingIndicator::TrainedAvailable));
}

pub(in crate::ui::city) fn configure_armory_dialog(
    commands: &mut Commands,
    assets: &RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) {
    let title = assets
        .string(0x271c, 0x20)
        .expect("retail English Armory title");
    bind_city_dialog_root(commands, root, children, tags, CityFacilitySlot::Armory);
    let title_control = find_descendant(root, fourcc!("titl"), children, tags);
    commands.entity(title_control).insert(Text::new(title));
    for binding in ARMORY_ORDERS {
        let CityOrderId::MilitaryRecruit(category) = binding.order else {
            unreachable!("armory binding has a military recruitment order");
        };
        let quantity = bind_city_order_control(
            commands,
            root,
            children,
            tags,
            binding,
            fourcc!("minu"),
            fourcc!("plus"),
            fourcc!("numb"),
            1,
        );
        let button = find_descendant(root, armory_button_tag(category), children, tags);
        commands.entity(button).insert(ArmoryRowChoice { category });
        commands.entity(quantity).insert(InteractionDisabled);
    }
    for (tag, detail) in [
        (fourcc!("unit"), ArmoryDetail::UnitName),
        (fourcc!("cos0"), ArmoryDetail::WorkforceCost),
        (fourcc!("cos1"), ArmoryDetail::PrimaryCost),
        (fourcc!("cos2"), ArmoryDetail::SecondaryCost),
        (fourcc!("cos3"), ArmoryDetail::CashCost),
        (fourcc!("ava0"), ArmoryDetail::WorkforceAvailable),
        (fourcc!("ava1"), ArmoryDetail::PrimaryAvailable),
        (fourcc!("ava2"), ArmoryDetail::SecondaryAvailable),
        (fourcc!("ava3"), ArmoryDetail::Treasury),
    ] {
        let entity = find_descendant(root, tag, children, tags);
        commands.entity(entity).insert((Text::new(""), detail));
    }
    commands.entity(root).insert(ArmorySelection {
        category: MilitaryRecruitmentCategory::LightInfantry,
    });
}

pub(in crate::ui::city) fn on_armory_row_selected(
    change: On<ValueChange<bool>>,
    rows: Query<&ArmoryRowChoice>,
    mut views: Query<&mut ArmorySelection>,
) {
    if !change.value {
        return;
    }
    let Ok(row) = rows.get(change.source) else {
        return;
    };
    views
        .single_mut()
        .expect("Armory row has one open Armory dialog")
        .category = row.category;
}

pub(in crate::ui::city) fn on_armory_order_selected(
    activate: On<Activate>,
    actions: Query<&CityOrderAdjust>,
    mut views: Query<&mut ArmorySelection>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let CityOrderId::MilitaryRecruit(category) = action.order else {
        return;
    };
    views
        .single_mut()
        .expect("Armory order has one open Armory dialog")
        .category = category;
}

fn city_projection_idle(session: &Res<GameSession>, added: bool) -> bool {
    !session.is_changed() && !added
}

pub(in crate::ui::city) fn sync_training_dialog(
    session: Res<GameSession>,
    added: Query<(), Added<TrainingIndicator>>,
    mut indicators: Query<(&TrainingIndicator, &mut Visibility)>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let nation = city_active_nation(&session);
    let major = session.0.nations().major(nation);
    let city = &major.city;
    let production = city.population.production_labor();
    let strength = city.population.strength();
    let budget = major
        .economy
        .available_diplomacy_budget(major.common.treasury);
    for (indicator, mut visibility) in &mut indicators {
        let visible = match *indicator {
            TrainingIndicator::Paper { minimum } => city.stockpile[ResourceKind::Paper] >= minimum,
            TrainingIndicator::Money { minimum } => budget >= minimum,
            TrainingIndicator::UntrainedAvailable => production.low.min(strength) != 0,
            TrainingIndicator::TrainedAvailable => production.medium.min(strength / 2) != 0,
        };
        *visibility = if visible {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
}

pub(in crate::ui::city) fn sync_armory_selection(
    mut commands: Commands,
    session: Res<GameSession>,
    selections: Query<Ref<ArmorySelection>>,
    rows: Query<(Entity, &ArmoryRowChoice, Has<Checked>)>,
) {
    let Some(selection) = selections.iter().next() else {
        return;
    };
    if !session.is_changed() && !selection.is_changed() && !selection.is_added() {
        return;
    }
    for (entity, row, checked) in &rows {
        let should_check = row.category == selection.category;
        if should_check && !checked {
            commands.entity(entity).insert(Checked);
        } else if !should_check && checked {
            commands.entity(entity).remove::<Checked>();
        }
    }
}

pub(in crate::ui::city) fn sync_armory_details(
    session: Res<GameSession>,
    selections: Query<Ref<ArmorySelection>>,
    mut texts: Query<(&ArmoryDetail, &mut Text)>,
    mut visibilities: Query<(&ArmoryDetail, &mut Visibility)>,
) {
    let Some(selection) = selections.iter().next() else {
        return;
    };
    if !session.is_changed() && !selection.is_changed() && !selection.is_added() {
        return;
    }
    let nation = city_active_nation(&session);
    let major = session.0.nations().major(nation);
    let city = &major.city;
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
    let secondary = spec.secondary;
    for (detail, mut text) in &mut texts {
        text.0 = match detail {
            ArmoryDetail::UnitName => format!("{:?}", order.unit_kind),
            ArmoryDetail::WorkforceCost => 1.to_string(),
            ArmoryDetail::PrimaryCost => spec.primary.per_unit().to_string(),
            ArmoryDetail::SecondaryCost => secondary
                .map(|item| item.per_unit().to_string())
                .unwrap_or_default(),
            ArmoryDetail::CashCost => format_currency(i32::from(spec.cash_per_unit)),
            ArmoryDetail::WorkforceAvailable => {
                workforce.min(strength / strength_divisor).to_string()
            }
            ArmoryDetail::PrimaryAvailable => city.stockpile[spec.primary.resource].to_string(),
            ArmoryDetail::SecondaryAvailable => secondary
                .map(|item| city.stockpile[item.resource].to_string())
                .unwrap_or_default(),
            ArmoryDetail::Treasury => format_currency(major.common.treasury),
        };
    }
    let secondary_visible = if secondary.is_some() {
        Visibility::Visible
    } else {
        Visibility::Hidden
    };
    for (detail, mut visibility) in &mut visibilities {
        if matches!(
            detail,
            ArmoryDetail::SecondaryCost | ArmoryDetail::SecondaryAvailable
        ) {
            *visibility = secondary_visible;
        }
    }
}
