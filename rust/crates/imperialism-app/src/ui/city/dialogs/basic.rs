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
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    state: &GameState,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::Warehouse);
    let oil_drilling_available = state.technology().oil_drilling_available();
    let (title_font, title_layout, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail Warehouse title text style");
    let (value_font, value_layout, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: 1,
        })
        .expect("retail Warehouse value text style");
    let text_color = assets.palette_color(0);
    bind_city_dialog_root(commands, root, children, tags, CityFacilitySlot::Warehouse);
    let name = find_descendant(root, fourcc!("name"), children, tags);
    commands.entity(name).insert((
        Text::new(building_name),
        title_font,
        title_layout,
        TextColor(text_color),
    ));

    let mut stocks = Vec::with_capacity(WAREHOUSE_STOCKS.len());
    for &(resource, tag) in &WAREHOUSE_STOCKS {
        let control = find_descendant(root, tag, children, tags);
        commands.entity(control).insert((
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
    let labor = find_descendant(root, fourcc!("labo"), children, tags);
    let power = find_descendant(root, fourcc!("powe"), children, tags);
    for control in [labor, power] {
        commands.entity(control).insert((
            Text::new(""),
            value_font.clone(),
            value_layout,
            TextColor(text_color),
        ));
    }
    commands.entity(root).insert(WarehouseView {
        stocks,
        labor,
        power,
    });
    for tag in [fourcc!("oil "), fourcc!("fuel"), fourcc!("powe")] {
        let control = find_descendant(root, tag, children, tags);
        let mut control_commands = commands.entity(control);
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
    let dialog = find_descendant(root, fourcc!("DLOG"), children, tags);
    match assets.picture(picture) {
        Ok(handle) => {
            commands.entity(dialog).insert(ImageNode::new(handle));
        }
        Err(error) => warn!("could not load Warehouse picture {picture}: {error}"),
    }
    commands
        .entity(dialog)
        .entry::<Node>()
        .and_modify(|mut node| node.overflow = Overflow::clip());
    for tag in [fourcc!("WIND"), fourcc!("DLOG")] {
        let entity = find_descendant(root, tag, children, tags);
        commands
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
        let entity = find_descendant(root, tag, children, tags);
        commands
            .entity(entity)
            .entry::<Node>()
            .and_modify(|mut node| {
                let Val::Px(top) = node.top else {
                    panic!("generated Warehouse control has fixed retail coordinates");
                };
                node.top = px(top + 176.0);
            });
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn bind_rail_dialog(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    slot: CityFacilitySlot,
    building_name: String,
    binding: CityOrderBinding,
    step: i16,
) -> Entity {
    bind_city_dialog_root(commands, root, children, tags, slot);
    let name_control = find_descendant(root, fourcc!("name"), children, tags);
    commands
        .entity(name_control)
        .insert(Text::new(building_name));
    bind_city_order_control(
        commands,
        root,
        children,
        tags,
        binding,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        step,
    )
}

pub(in crate::ui::city) fn configure_food_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::FoodProcessing);
    let quantity = bind_rail_dialog(
        commands,
        root,
        children,
        tags,
        CityFacilitySlot::FoodProcessing,
        building_name,
        FOOD_ORDER,
        2,
    );
    let labor = find_descendant(root, fourcc!("labV"), children, tags);
    let grain = find_descendant(root, fourcc!("grai"), children, tags);
    let fruit = find_descendant(root, fourcc!("prod"), children, tags);
    let fish_and_livestock = find_descendant(root, fourcc!("fish"), children, tags);
    for entity in [labor, grain, fruit, fish_and_livestock] {
        commands.entity(entity).insert(Text::new("X"));
    }
    commands.entity(root).insert(FoodProcessingView {
        quantity,
        labor,
        grain,
        fruit,
        fish_and_livestock,
    });
}

pub(in crate::ui::city) fn configure_power_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::PowerPlant);
    let quantity = bind_rail_dialog(
        commands,
        root,
        children,
        tags,
        CityFacilitySlot::PowerPlant,
        building_name,
        POWER_ORDER,
        6,
    );
    commands.entity(root).insert(PowerPlantView { quantity });
    let fuel = find_descendant(root, fourcc!("fuel"), children, tags);
    commands
        .entity(fuel)
        .insert((Text::new("X"), Visibility::Hidden));
}

pub(in crate::ui::city) fn configure_transport_capacity_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::Transport);
    let quantity = bind_rail_dialog(
        commands,
        root,
        children,
        tags,
        CityFacilitySlot::Transport,
        building_name,
        TRANSPORT_CAPACITY_ORDER,
        1,
    );
    let labor = find_descendant(root, fourcc!("labV"), children, tags);
    let lumber = find_descendant(root, fourcc!("lumb"), children, tags);
    let steel = find_descendant(root, fourcc!("stee"), children, tags);
    for entity in [labor, lumber, steel] {
        commands.entity(entity).insert(Text::new("X"));
    }
    commands.entity(root).insert(TransportCapacityView {
        quantity,
        labor,
        lumber,
        steel,
    });
}

pub(in crate::ui::city) fn configure_population_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::RegionalPopulation);
    let capacity_template = city_string(assets, CITY_TEXT_STRING_GROUP, 0x10);
    let province_template = city_string(assets, CITY_TEXT_STRING_GROUP, 0x1d);
    let quantity = bind_rail_dialog(
        commands,
        root,
        children,
        tags,
        CityFacilitySlot::RegionalPopulation,
        building_name,
        POPULATION_ORDER,
        1,
    );
    let food = find_descendant(root, fourcc!("food"), children, tags);
    let clothing = find_descendant(root, fourcc!("clot"), children, tags);
    let furniture = find_descendant(root, fourcc!("furn"), children, tags);
    let capacity = find_descendant(root, fourcc!("capT"), children, tags);
    let provinces = find_descendant(root, fourcc!("prov"), children, tags);
    for entity in [food, clothing, furniture] {
        commands.entity(entity).insert(Text::new("X"));
    }
    for entity in [capacity, provinces] {
        commands.entity(entity).insert(Text::new(""));
    }
    commands.entity(root).insert(PopulationView {
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
        let quantity = session.0.city_order_quantity(nation, FOOD_ORDER.order);
        texts
            .get_mut(view.quantity)
            .expect("Food Processing order control belongs to its dialog")
            .0 = quantity.to_string();
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
        let quantity = session.0.city_order_quantity(nation, POWER_ORDER.order);
        texts
            .get_mut(view.quantity)
            .expect("Power Plant order control belongs to its dialog")
            .0 = quantity.to_string();
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
        let quantity = session
            .0
            .city_order_quantity(nation, TRANSPORT_CAPACITY_ORDER.order);
        texts
            .get_mut(view.quantity)
            .expect("Transport order control belongs to its dialog")
            .0 = quantity.to_string();
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
        let quantity = session
            .0
            .city_order_quantity(nation, POPULATION_ORDER.order);
        texts
            .get_mut(view.quantity)
            .expect("Population order control belongs to its dialog")
            .0 = quantity.to_string();
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
