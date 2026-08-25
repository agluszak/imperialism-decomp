use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct WarehouseDialogUi {
    pub(in crate::ui::city) stocks: Vec<(ResourceKind, Entity)>,
    pub(in crate::ui::city) labor: Entity,
    pub(in crate::ui::city) power: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct FoodDialogUi {
    pub(in crate::ui::city) order: RailOrderUi,
    pub(in crate::ui::city) labor: Entity,
    pub(in crate::ui::city) grain: Entity,
    pub(in crate::ui::city) fruit: Entity,
    pub(in crate::ui::city) fish_and_livestock: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct PowerDialogUi {
    pub(in crate::ui::city) order: RailOrderUi,
}

#[derive(Component)]
pub(in crate::ui::city) struct TransportCapacityDialogUi {
    pub(in crate::ui::city) order: RailOrderUi,
    pub(in crate::ui::city) labor: Entity,
    pub(in crate::ui::city) lumber: Entity,
    pub(in crate::ui::city) steel: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct PopulationDialogUi {
    pub(in crate::ui::city) order: RailOrderUi,
    pub(in crate::ui::city) food: Entity,
    pub(in crate::ui::city) clothing: Entity,
    pub(in crate::ui::city) furniture: Entity,
    pub(in crate::ui::city) capacity: Entity,
    pub(in crate::ui::city) capacity_template: String,
    pub(in crate::ui::city) provinces: Entity,
    pub(in crate::ui::city) province_template: String,
}

pub(in crate::ui::city) fn configure_warehouse_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    state: &GameState,
) {
    let advanced_production_unlocked = state.technology().advanced_production_unlocked();

    let mut stocks = Vec::new();
    for &(resource, tag) in &WAREHOUSE_STOCKS {
        let control = tree.find(root, tag);
        commands.entity(control).insert(Text::new(""));
        stocks.push((resource, control));
    }
    let labor = tree.find(root, fourcc!("labo"));
    let power = tree.find(root, fourcc!("powe"));
    commands.entity(labor).insert(Text::new(""));
    commands.entity(power).insert(Text::new(""));
    commands.entity(root).insert(WarehouseDialogUi {
        stocks,
        labor,
        power,
    });
    for tag in [fourcc!("oil "), fourcc!("fuel"), fourcc!("powe")] {
        let control = tree.find(root, tag);
        let mut control_commands = commands.entity(control);
        if advanced_production_unlocked {
            control_commands
                .insert(Visibility::Visible)
                .remove::<InteractionDisabled>();
        } else {
            control_commands.insert((Visibility::Hidden, InteractionDisabled));
        }
    }
    if !advanced_production_unlocked {
        return;
    }

    let picture = PictureId::new(9215);
    let dialog = tree.find(root, fourcc!("DLOG"));
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
        let entity = tree.find(root, tag);
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
        let entity = tree.find(root, tag);
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

pub(in crate::ui::city) fn bind_rail_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    building_name: String,
    binding: CityOrderBinding,
    step: i16,
) -> RailOrderUi {
    let name_control = tree.find(root, fourcc!("name"));
    commands
        .entity(name_control)
        .insert(Text::new(building_name));
    let counter = bind_city_order_row(
        commands,
        root,
        tree,
        binding,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        step,
        None,
    );
    let bar = bind_rail_amount_bar(commands, assets, counter.row, tree, binding.order, step);
    RailOrderUi {
        order: binding.order,
        quantity: counter.quantity,
        bar,
    }
}

pub(in crate::ui::city) fn configure_food_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::FoodProcessing);
    let order = bind_rail_dialog(commands, assets, root, tree, building_name, FOOD_ORDER, 2);
    let labor = tree.find(root, fourcc!("labV"));
    let grain = tree.find(root, fourcc!("grai"));
    let fruit = tree.find(root, fourcc!("prod"));
    let fish_and_livestock = tree.find(root, fourcc!("fish"));
    commands.entity(labor).insert(Text::new("X"));
    commands.entity(grain).insert(Text::new("X"));
    commands.entity(fruit).insert(Text::new("X"));
    commands.entity(fish_and_livestock).insert(Text::new("X"));
    commands.entity(root).insert(FoodDialogUi {
        order,
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
    tree: &RetailTree,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::PowerPlant);
    let order = bind_rail_dialog(commands, assets, root, tree, building_name, POWER_ORDER, 6);
    let fuel = tree.find(root, fourcc!("fuel"));
    commands
        .entity(fuel)
        .insert((Text::new("X"), Visibility::Hidden));
    commands.entity(root).insert(PowerDialogUi { order });
}

pub(in crate::ui::city) fn configure_transport_capacity_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::Transport);
    let order = bind_rail_dialog(
        commands,
        assets,
        root,
        tree,
        building_name,
        TRANSPORT_CAPACITY_ORDER,
        1,
    );
    let labor = tree.find(root, fourcc!("labV"));
    let lumber = tree.find(root, fourcc!("lumb"));
    let steel = tree.find(root, fourcc!("stee"));
    commands.entity(labor).insert(Text::new("X"));
    commands.entity(lumber).insert(Text::new("X"));
    commands.entity(steel).insert(Text::new("X"));
    commands.entity(root).insert(TransportCapacityDialogUi {
        order,
        labor,
        lumber,
        steel,
    });
}

pub(in crate::ui::city) fn configure_population_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::RegionalPopulation);
    let capacity_template = city_string(assets, CITY_TEXT_STRING_GROUP, 0x10);
    let province_template = city_string(assets, CITY_TEXT_STRING_GROUP, 0x1d);
    let order = bind_rail_dialog(
        commands,
        assets,
        root,
        tree,
        building_name,
        POPULATION_ORDER,
        1,
    );
    let food = tree.find(root, fourcc!("food"));
    let clothing = tree.find(root, fourcc!("clot"));
    let furniture = tree.find(root, fourcc!("furn"));
    let capacity = tree.find(root, fourcc!("capT"));
    let provinces = tree.find(root, fourcc!("prov"));
    commands.entity(food).insert(Text::new("X"));
    commands.entity(clothing).insert(Text::new("X"));
    commands.entity(furniture).insert(Text::new("X"));
    commands.entity(capacity).insert(Text::new(""));
    commands.entity(provinces).insert(Text::new(""));
    commands.entity(root).insert(PopulationDialogUi {
        order,
        food,
        clothing,
        furniture,
        capacity,
        capacity_template,
        provinces,
        province_template,
    });
}

pub(in crate::ui::city) fn refresh_warehouse_dialog(
    game: &GameState,
    nation: MajorNationId,
    ui: &WarehouseDialogUi,
    texts: &mut Query<&mut Text>,
) {
    let city = &game.nations().major(nation).city;
    for &(resource, entity) in &ui.stocks {
        let value = if resource == ResourceKind::Livestock {
            city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock]
        } else {
            city.stockpile[resource]
        };
        set_text(texts, entity, value.to_string());
    }
    set_text(texts, ui.labor, city.population.strength().to_string());
    set_text(texts, ui.power, city.power_available.to_string());
}

pub(in crate::ui::city) fn refresh_food_dialog(
    game: &GameState,
    nation: MajorNationId,
    ui: &FoodDialogUi,
    texts: &mut Query<&mut Text>,
    visibilities: &mut Query<&mut Visibility>,
    nodes: &mut Query<&mut Node>,
    images: &mut Query<&mut ImageNode>,
    assets: &mut RetailUiAssets,
) {
    let city = &game.nations().major(nation).city;
    refresh_rail_order(game, nation, &ui.order, texts, nodes, images, assets);
    set_visible(visibilities, ui.labor, city.population.strength() >= 2);
    set_visible(
        visibilities,
        ui.grain,
        city.stockpile[ResourceKind::Grain] >= 2,
    );
    set_visible(
        visibilities,
        ui.fruit,
        city.stockpile[ResourceKind::Fruit] >= 1,
    );
    set_visible(
        visibilities,
        ui.fish_and_livestock,
        city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock] >= 1,
    );
}

pub(in crate::ui::city) fn refresh_power_dialog(
    game: &GameState,
    nation: MajorNationId,
    ui: &PowerDialogUi,
    texts: &mut Query<&mut Text>,
    nodes: &mut Query<&mut Node>,
    images: &mut Query<&mut ImageNode>,
    assets: &mut RetailUiAssets,
) {
    refresh_rail_order(game, nation, &ui.order, texts, nodes, images, assets);
}

pub(in crate::ui::city) fn refresh_transport_capacity_dialog(
    game: &GameState,
    nation: MajorNationId,
    ui: &TransportCapacityDialogUi,
    texts: &mut Query<&mut Text>,
    visibilities: &mut Query<&mut Visibility>,
    nodes: &mut Query<&mut Node>,
    images: &mut Query<&mut ImageNode>,
    assets: &mut RetailUiAssets,
) {
    let city = &game.nations().major(nation).city;
    refresh_rail_order(game, nation, &ui.order, texts, nodes, images, assets);
    set_visible(visibilities, ui.labor, city.population.strength() >= 2);
    set_visible(
        visibilities,
        ui.lumber,
        city.stockpile[ResourceKind::Lumber] < 1,
    );
    set_visible(
        visibilities,
        ui.steel,
        city.stockpile[ResourceKind::Steel] < 1,
    );
}

pub(in crate::ui::city) fn refresh_population_dialog(
    game: &GameState,
    nation: MajorNationId,
    ui: &PopulationDialogUi,
    texts: &mut Query<&mut Text>,
    visibilities: &mut Query<&mut Visibility>,
    nodes: &mut Query<&mut Node>,
    images: &mut Query<&mut ImageNode>,
    assets: &mut RetailUiAssets,
) {
    let major = game.nations().major(nation);
    let city = &major.city;
    refresh_rail_order(game, nation, &ui.order, texts, nodes, images, assets);
    set_visible(
        visibilities,
        ui.food,
        city.stockpile[ResourceKind::Food] >= 1,
    );
    set_visible(
        visibilities,
        ui.clothing,
        city.stockpile[ResourceKind::Clothing] >= 1,
    );
    set_visible(
        visibilities,
        ui.furniture,
        city.stockpile[ResourceKind::Furniture] >= 1,
    );
    let owned_regions = major.common.owned_region_count();
    let building = city.building_type(
        CityFacilitySlot::RegionalPopulation,
        &major.economy,
        owned_regions,
    );
    set_text(
        texts,
        ui.capacity,
        format_retail_number(&ui.capacity_template, building),
    );
    set_text(
        texts,
        ui.provinces,
        format_retail_number(&ui.province_template, owned_regions as i16),
    );
}
