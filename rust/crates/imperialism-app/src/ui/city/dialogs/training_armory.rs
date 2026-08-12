use super::*;

struct TrainingOrderControl {
    level: TrainingLevel,
    quantity: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct TrainingView {
    orders: Vec<TrainingOrderControl>,
    paper_one: Entity,
    paper_two: Entity,
    money_one: Entity,
    money_two: Entity,
    untrained_available: Entity,
    trained_available: Entity,
}

struct ArmoryOrderControl {
    category: MilitaryRecruitmentCategory,
    button: Entity,
    quantity: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct ArmoryView {
    category: MilitaryRecruitmentCategory,
    orders: Vec<ArmoryOrderControl>,
    unit: Entity,
    workforce_cost: Entity,
    primary_cost: Entity,
    secondary_cost: Entity,
    cash_cost: Entity,
    workforce_available: Entity,
    primary_available: Entity,
    secondary_available: Entity,
    treasury: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct ArmoryRowChoice {
    pub(in crate::ui::city) category: MilitaryRecruitmentCategory,
}

pub(in crate::ui::city) fn configure_training_dialog(
    ui: &mut UiSpawner,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
) {
    let building_name = city_building_name(ui, CityFacilitySlot::TradeSchool);
    bind_training_dialog(&mut ui.commands, catalog, spawned, building_name);
}

pub(in crate::ui::city) fn bind_training_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    building_name: String,
) {
    let root = bind_city_dialog_root(commands, spawned, CityFacilitySlot::TradeSchool);
    let name = spawned.unique(fourcc!("name"));
    commands.entity(name).insert(Text::new(building_name));
    for (tag, text) in [(fourcc!("cos1"), "$100"), (fourcc!("cos2"), "$1,000")] {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert(Text::new(text));
    }
    let mut orders = Vec::with_capacity(TRAINING_ORDERS.len());
    for binding in TRAINING_ORDERS {
        let CityOrderId::Training(level) = binding.order else {
            unreachable!("Trade School control has a training order");
        };
        let quantity = bind_city_order_control(
            commands,
            catalog,
            spawned,
            binding,
            fourcc!("left"),
            fourcc!("rght"),
            fourcc!("move"),
            1,
        );
        orders.push(TrainingOrderControl { level, quantity });
    }
    let paper_one = spawned.unique(fourcc!("pap1"));
    let paper_two = spawned.unique(fourcc!("pap2"));
    let money_one = spawned.unique(fourcc!("mon1"));
    let money_two = spawned.unique(fourcc!("mon2"));
    let untrained_available = spawned.unique(fourcc!("untV"));
    let trained_available = spawned.unique(fourcc!("traV"));
    for entity in [
        paper_one,
        paper_two,
        money_one,
        money_two,
        untrained_available,
        trained_available,
    ] {
        commands.entity(entity).insert(Text::new("X"));
    }
    commands.entity(root).insert(TrainingView {
        orders,
        paper_one,
        paper_two,
        money_one,
        money_two,
        untrained_available,
        trained_available,
    });
}

pub(in crate::ui::city) fn configure_armory_dialog(
    ui: &mut UiSpawner,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
) {
    let title = ui
        .string(0x271c, 0x20)
        .expect("retail English Armory title");
    let commands = &mut ui.commands;
    let root = bind_city_dialog_root(commands, spawned, CityFacilitySlot::Armory);
    let title_control = spawned.unique(fourcc!("titl"));
    commands.entity(title_control).insert(Text::new(title));
    let mut orders = Vec::with_capacity(ARMORY_ORDERS.len());
    for binding in ARMORY_ORDERS {
        let CityOrderId::MilitaryRecruit(category) = binding.order else {
            unreachable!("armory binding has a military recruitment order");
        };
        let quantity = bind_city_order_control(
            commands,
            catalog,
            spawned,
            binding,
            fourcc!("minu"),
            fourcc!("plus"),
            fourcc!("numb"),
            1,
        );
        let button = spawned.unique(armory_button_tag(category));
        commands.entity(button).insert(ArmoryRowChoice { category });
        commands.entity(quantity).insert(InteractionDisabled);
        orders.push(ArmoryOrderControl {
            category,
            button,
            quantity,
        });
    }
    let unit = spawned.unique(fourcc!("unit"));
    let workforce_cost = spawned.unique(fourcc!("cos0"));
    let primary_cost = spawned.unique(fourcc!("cos1"));
    let secondary_cost = spawned.unique(fourcc!("cos2"));
    let cash_cost = spawned.unique(fourcc!("cos3"));
    let workforce_available = spawned.unique(fourcc!("ava0"));
    let primary_available = spawned.unique(fourcc!("ava1"));
    let secondary_available = spawned.unique(fourcc!("ava2"));
    let treasury = spawned.unique(fourcc!("ava3"));
    for entity in [
        unit,
        workforce_cost,
        primary_cost,
        secondary_cost,
        cash_cost,
        workforce_available,
        primary_available,
        secondary_available,
        treasury,
    ] {
        commands.entity(entity).insert(Text::new(""));
    }
    commands.entity(root).insert(ArmoryView {
        category: MilitaryRecruitmentCategory::LightInfantry,
        orders,
        unit,
        workforce_cost,
        primary_cost,
        secondary_cost,
        cash_cost,
        workforce_available,
        primary_available,
        secondary_available,
        treasury,
    });
}

pub(in crate::ui::city) fn on_armory_row_selected(
    change: On<ValueChange<bool>>,
    rows: Query<&ArmoryRowChoice>,
    mut views: Query<&mut ArmoryView>,
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
    mut views: Query<&mut ArmoryView>,
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

pub(in crate::ui::city) fn sync_training_dialog(
    session: Res<GameSession>,
    dialogs: Query<Ref<TrainingView>>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City active nation is a major nation");
    for view in &dialogs {
        if !session.is_changed() && !view.is_added() {
            continue;
        }
        let major = session.0.nations().major(nation);
        let city = &major.city;
        for order in &view.orders {
            texts
                .get_mut(order.quantity)
                .expect("Trade School order quantity has text")
                .0 = city.orders.training[order.level].quantity.to_string();
        }

        let production = city.population.production_labor();
        let strength = city.population.strength();
        let budget = major
            .economy
            .available_diplomacy_budget(major.common.treasury);
        for (entity, visible) in [
            (view.paper_one, city.stockpile[ResourceKind::Paper] >= 1),
            (view.paper_two, city.stockpile[ResourceKind::Paper] >= 2),
            (view.money_one, budget >= 100),
            (view.money_two, budget >= 1_000),
            (view.untrained_available, production.low.min(strength) != 0),
            (
                view.trained_available,
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
    mut commands: Commands,
    session: Res<GameSession>,
    dialogs: Query<Ref<ArmoryView>>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City active nation is a major nation");
    for view in &dialogs {
        if !session.is_changed() && !view.is_changed() {
            continue;
        }
        for order in &view.orders {
            if order.category == view.category {
                commands.entity(order.button).insert(Checked);
            } else {
                commands.entity(order.button).remove::<Checked>();
            }
        }
        let major = session.0.nations().major(nation);
        let city = &major.city;
        for order in &view.orders {
            texts
                .get_mut(order.quantity)
                .expect("Armory order quantity has text")
                .0 = city.orders.military_recruitment[order.category]
                .progress
                .quantity
                .to_string();
        }

        let order = &city.orders.military_recruitment[view.category];
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
            (view.workforce_cost, 1),
            (view.primary_cost, spec.primary.per_unit()),
            (
                view.workforce_available,
                workforce.min(strength / strength_divisor),
            ),
            (
                view.primary_available,
                city.stockpile[spec.primary.resource],
            ),
        ] {
            texts
                .get_mut(entity)
                .expect("Armory numeric control has text")
                .0 = value.to_string();
        }
        texts
            .get_mut(view.unit)
            .expect("Armory unit control has text")
            .0 = format!("{:?}", order.unit_kind);
        texts
            .get_mut(view.cash_cost)
            .expect("Armory cash cost has text")
            .0 = format_currency(i32::from(spec.cash_per_unit));
        texts
            .get_mut(view.treasury)
            .expect("Armory treasury has text")
            .0 = format_currency(major.common.treasury);

        let [mut secondary_cost, mut secondary_available] = texts
            .get_many_mut([view.secondary_cost, view.secondary_available])
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
        for entity in [view.secondary_cost, view.secondary_available] {
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
