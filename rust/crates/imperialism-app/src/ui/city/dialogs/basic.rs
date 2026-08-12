use super::*;

struct WarehouseStockControl {
    resource: ResourceKind,
    entity: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct WarehouseView {
    stocks: Vec<WarehouseStockControl>,
    labor: Entity,
    power: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct FoodProcessingView {
    quantity: Entity,
    labor: Entity,
    grain: Entity,
    fruit: Entity,
    fish_and_livestock: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct PowerPlantView {
    quantity: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct TransportCapacityView {
    quantity: Entity,
    labor: Entity,
    lumber: Entity,
    steel: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct PopulationView {
    capacity_template: String,
    province_template: String,
    quantity: Entity,
    food: Entity,
    clothing: Entity,
    furniture: Entity,
    capacity: Entity,
    provinces: Entity,
}

pub(in crate::ui::city) fn configure_warehouse_dialog(
    ui: &mut UiSpawner,
    spawned: &SpawnedView,
    state: &GameState,
) {
    let building_name = city_building_name(ui, CityFacilitySlot::Warehouse);
    let oil_drilling_available = state.technology().oil_drilling_available();
    let (title_font, title_layout, _) = ui
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail Warehouse title text style");
    let (value_font, value_layout, _) = ui
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: 1,
        })
        .expect("retail Warehouse value text style");
    let text_color = ui.palette_color(0);
    let root = bind_city_dialog_root(&mut ui.commands, spawned, CityFacilitySlot::Warehouse);
    let name = spawned.unique(fourcc!("name"));
    ui.commands.entity(name).insert((
        Text::new(building_name),
        title_font,
        title_layout,
        TextColor(text_color),
    ));

    let mut stocks = Vec::with_capacity(WAREHOUSE_STOCKS.len());
    for &(resource, tag) in &WAREHOUSE_STOCKS {
        let control = spawned.unique(tag);
        ui.commands.entity(control).insert((
            Text::new(""),
            value_font.clone(),
            value_layout,
            TextColor(text_color),
        ));
        stocks.push(WarehouseStockControl {
            resource,
            entity: control,
        });
    }
    let labor = spawned.unique(fourcc!("labo"));
    let power = spawned.unique(fourcc!("powe"));
    for control in [labor, power] {
        ui.commands.entity(control).insert((
            Text::new(""),
            value_font.clone(),
            value_layout,
            TextColor(text_color),
        ));
    }
    ui.commands.entity(root).insert(WarehouseView {
        stocks,
        labor,
        power,
    });
    for tag in [fourcc!("oil "), fourcc!("fuel"), fourcc!("powe")] {
        let control = spawned.unique(tag);
        let mut control_commands = ui.commands.entity(control);
        if oil_drilling_available {
            control_commands
                .insert(Visibility::Visible)
                .remove::<InteractionDisabled>();
        } else {
            control_commands.insert((Visibility::Hidden, InteractionDisabled));
        }
    }
    if !oil_drilling_available {
        return;
    }

    let picture = PictureId::new(9215);
    let dialog = spawned.unique(fourcc!("DLOG"));
    match ui.picture(picture) {
        Ok(handle) => {
            ui.commands.entity(dialog).insert(ImageNode::new(handle));
        }
        Err(error) => warn!("could not load Warehouse picture {picture}: {error}"),
    }
    ui.commands
        .entity(dialog)
        .entry::<Node>()
        .and_modify(|mut node| node.overflow = Overflow::clip());
    for tag in [fourcc!("WIND"), fourcc!("DLOG")] {
        let entity = spawned.unique(tag);
        ui.commands
            .entity(entity)
            .entry::<Node>()
            .and_modify(|mut node| {
                node.width = px(176);
                node.height = px(335);
            });
    }
    for tag in [
        fourcc!("hors"),
        fourcc!("food"),
        fourcc!("labo"),
        fourcc!("grai"),
        fourcc!("prod"),
        fourcc!("live"),
    ] {
        let entity = spawned.unique(tag);
        ui.commands
            .entity(entity)
            .entry::<Node>()
            .and_modify(|mut node| {
                let Val::Px(top) = node.top else {
                    panic!("catalog Warehouse control has fixed retail coordinates");
                };
                node.top = px(top + 176.0);
            });
    }
}

pub(in crate::ui::city) fn bind_rail_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    slot: CityFacilitySlot,
    building_name: String,
    binding: CityOrderBinding,
    step: i16,
) -> Entity {
    bind_city_dialog_root(commands, spawned, slot);
    let name_control = spawned.unique(fourcc!("name"));
    commands
        .entity(name_control)
        .insert(Text::new(building_name));
    bind_city_order_control(
        commands,
        catalog,
        spawned,
        binding,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        step,
    )
}

pub(in crate::ui::city) fn configure_food_dialog(
    ui: &mut UiSpawner,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
) {
    let building_name = city_building_name(ui, CityFacilitySlot::FoodProcessing);
    let commands = &mut ui.commands;
    let quantity = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        CityFacilitySlot::FoodProcessing,
        building_name,
        FOOD_ORDER,
        2,
    );
    let labor = spawned.unique(fourcc!("labV"));
    let grain = spawned.unique(fourcc!("grai"));
    let fruit = spawned.unique(fourcc!("prod"));
    let fish_and_livestock = spawned.unique(fourcc!("fish"));
    for entity in [labor, grain, fruit, fish_and_livestock] {
        commands.entity(entity).insert(Text::new("X"));
    }
    commands.entity(spawned.root).insert(FoodProcessingView {
        quantity,
        labor,
        grain,
        fruit,
        fish_and_livestock,
    });
}

pub(in crate::ui::city) fn configure_power_dialog(
    ui: &mut UiSpawner,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
) {
    let building_name = city_building_name(ui, CityFacilitySlot::PowerPlant);
    let commands = &mut ui.commands;
    let quantity = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        CityFacilitySlot::PowerPlant,
        building_name,
        POWER_ORDER,
        6,
    );
    commands
        .entity(spawned.root)
        .insert(PowerPlantView { quantity });
    let fuel = spawned.unique(fourcc!("fuel"));
    commands
        .entity(fuel)
        .insert((Text::new("X"), Visibility::Hidden));
}

pub(in crate::ui::city) fn configure_transport_capacity_dialog(
    ui: &mut UiSpawner,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
) {
    let building_name = city_building_name(ui, CityFacilitySlot::Transport);
    let commands = &mut ui.commands;
    let quantity = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        CityFacilitySlot::Transport,
        building_name,
        TRANSPORT_CAPACITY_ORDER,
        1,
    );
    let labor = spawned.unique(fourcc!("labV"));
    let lumber = spawned.unique(fourcc!("lumb"));
    let steel = spawned.unique(fourcc!("stee"));
    for entity in [labor, lumber, steel] {
        commands.entity(entity).insert(Text::new("X"));
    }
    commands.entity(spawned.root).insert(TransportCapacityView {
        quantity,
        labor,
        lumber,
        steel,
    });
}

pub(in crate::ui::city) fn configure_population_dialog(
    ui: &mut UiSpawner,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
) {
    let building_name = city_building_name(ui, CityFacilitySlot::RegionalPopulation);
    let capacity_template = city_string(ui, CITY_TEXT_STRING_GROUP, 0x10);
    let province_template = city_string(ui, CITY_TEXT_STRING_GROUP, 0x1d);
    let commands = &mut ui.commands;
    let quantity = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        CityFacilitySlot::RegionalPopulation,
        building_name,
        POPULATION_ORDER,
        1,
    );
    let food = spawned.unique(fourcc!("food"));
    let clothing = spawned.unique(fourcc!("clot"));
    let furniture = spawned.unique(fourcc!("furn"));
    let capacity = spawned.unique(fourcc!("capT"));
    let provinces = spawned.unique(fourcc!("prov"));
    for entity in [food, clothing, furniture] {
        commands.entity(entity).insert(Text::new("X"));
    }
    for entity in [capacity, provinces] {
        commands.entity(entity).insert(Text::new(""));
    }
    commands.entity(spawned.root).insert(PopulationView {
        capacity_template,
        province_template,
        quantity,
        food,
        clothing,
        furniture,
        capacity,
        provinces,
    });
}

pub(in crate::ui::city) fn sync_warehouse_dialog(
    session: Res<GameSession>,
    dialogs: Query<Ref<WarehouseView>>,
    mut texts: Query<&mut Text>,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City active nation is a major nation");
    for view in &dialogs {
        if !session.is_changed() && !view.is_added() {
            continue;
        }
        let city = &session.0.nations().major(nation).city;
        for stock in &view.stocks {
            let value = if stock.resource == ResourceKind::Livestock {
                city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock]
            } else {
                city.stockpile[stock.resource]
            };
            texts
                .get_mut(stock.entity)
                .expect("Warehouse stock control belongs to its dialog")
                .0 = value.to_string();
        }
        texts
            .get_mut(view.labor)
            .expect("Warehouse labor control belongs to its dialog")
            .0 = city.population.strength().to_string();
        texts
            .get_mut(view.power)
            .expect("Warehouse power control belongs to its dialog")
            .0 = city.power_available.to_string();
    }
}

pub(in crate::ui::city) fn sync_food_dialog(
    session: Res<GameSession>,
    dialogs: Query<Ref<FoodProcessingView>>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City active nation is a major nation");
    for view in &dialogs {
        if !session.is_changed() && !view.is_added() {
            continue;
        }
        let city = &session.0.nations().major(nation).city;
        let status = session.0.city_order_status(nation, FOOD_ORDER.order);
        texts
            .get_mut(view.quantity)
            .expect("Food Processing order control belongs to its dialog")
            .0 = status.quantity.to_string();
        for (entity, visible) in [
            (view.labor, city.population.strength() >= 2),
            (view.grain, city.stockpile[ResourceKind::Grain] >= 2),
            (view.fruit, city.stockpile[ResourceKind::Fruit] >= 1),
            (
                view.fish_and_livestock,
                city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock] >= 1,
            ),
        ] {
            *visibilities
                .get_mut(entity)
                .expect("Food Processing indicator belongs to its dialog") = if visible {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        }
    }
}

pub(in crate::ui::city) fn sync_power_dialog(
    session: Res<GameSession>,
    dialogs: Query<Ref<PowerPlantView>>,
    mut texts: Query<&mut Text>,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City active nation is a major nation");
    for view in &dialogs {
        if !session.is_changed() && !view.is_added() {
            continue;
        }
        let status = session.0.city_order_status(nation, POWER_ORDER.order);
        texts
            .get_mut(view.quantity)
            .expect("Power Plant order control belongs to its dialog")
            .0 = status.quantity.to_string();
    }
}

pub(in crate::ui::city) fn sync_transport_capacity_dialog(
    session: Res<GameSession>,
    dialogs: Query<Ref<TransportCapacityView>>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City active nation is a major nation");
    for view in &dialogs {
        if !session.is_changed() && !view.is_added() {
            continue;
        }
        let city = &session.0.nations().major(nation).city;
        let status = session
            .0
            .city_order_status(nation, TRANSPORT_CAPACITY_ORDER.order);
        texts
            .get_mut(view.quantity)
            .expect("Transport order control belongs to its dialog")
            .0 = status.quantity.to_string();
        for (entity, visible) in [
            (view.labor, city.population.strength() >= 2),
            (view.lumber, city.stockpile[ResourceKind::Lumber] < 1),
            (view.steel, city.stockpile[ResourceKind::Steel] < 1),
        ] {
            *visibilities
                .get_mut(entity)
                .expect("Transport indicator belongs to its dialog") = if visible {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        }
    }
}

pub(in crate::ui::city) fn sync_population_dialog(
    session: Res<GameSession>,
    dialogs: Query<Ref<PopulationView>>,
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
        let status = session.0.city_order_status(nation, POPULATION_ORDER.order);
        texts
            .get_mut(view.quantity)
            .expect("Population order control belongs to its dialog")
            .0 = status.quantity.to_string();
        for (entity, resource) in [
            (view.food, ResourceKind::Food),
            (view.clothing, ResourceKind::Clothing),
            (view.furniture, ResourceKind::Furniture),
        ] {
            *visibilities
                .get_mut(entity)
                .expect("Population stock indicator belongs to its dialog") =
                if city.stockpile[resource] >= 1 {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
        }
        let owned_regions = major.common.owned_region_count();
        texts
            .get_mut(view.capacity)
            .expect("Population capacity control belongs to its dialog")
            .0 = format_retail_number(
            &view.capacity_template,
            city.building_type(
                CityFacilitySlot::RegionalPopulation,
                &major.economy,
                owned_regions as i32,
            ),
        );
        texts
            .get_mut(view.provinces)
            .expect("Population province control belongs to its dialog")
            .0 = format_retail_number(&view.province_template, owned_regions as i16);
    }
}
