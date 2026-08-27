use super::*;

pub(crate) struct WarehouseUi {
    stocks: Vec<(Entity, ResourceKind)>,
    labor: Entity,
    power: Entity,
}

pub(crate) struct FoodUi {
    rail: RailUi,
    labor: Entity,
    grain: Entity,
    fruit: Entity,
    fish_and_livestock: Entity,
}

pub(crate) struct TransportUi {
    rail: RailUi,
    labor: Entity,
    lumber: Entity,
    steel: Entity,
}

pub(crate) struct PopulationUi {
    rail: RailUi,
    food: Entity,
    clothing: Entity,
    furniture: Entity,
    capacity: Entity,
    provinces: Entity,
}

pub(crate) fn bind_warehouse(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    state: &GameState,
) -> WarehouseUi {
    let advanced_production_unlocked = state.technology().advanced_production_unlocked();

    let stocks = (0..=ResourceKind::Livestock.retail())
        .filter_map(ResourceKind::from_index)
        .filter(|resource| *resource != ResourceKind::Fish)
        .zip(generated::WAREHOUSE_STOCK_TAGS)
        .map(|(resource, tag)| (tree.find(root, tag), resource))
        .collect();
    let labor = tree.find(root, fourcc!("labo"));
    let power = tree.find(root, fourcc!("powe"));
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
    if advanced_production_unlocked {
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
    WarehouseUi {
        stocks,
        labor,
        power,
    }
}

pub(crate) fn bind_food(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) -> FoodUi {
    let building_name = city_building_name(assets, CityFacilitySlot::FoodProcessing);
    let rail = bind_rail(
        commands,
        assets,
        root,
        tree,
        building_name,
        CityOrderId::FoodProcessing,
        generated::FOOD_ORDER_TAG,
        2,
    );
    FoodUi {
        rail,
        labor: tree.find(root, fourcc!("labV")),
        grain: tree.find(root, fourcc!("grai")),
        fruit: tree.find(root, fourcc!("prod")),
        fish_and_livestock: tree.find(root, fourcc!("fish")),
    }
}

pub(crate) fn bind_power(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) -> RailUi {
    let building_name = city_building_name(assets, CityFacilitySlot::PowerPlant);
    let rail = bind_rail(
        commands,
        assets,
        root,
        tree,
        building_name,
        CityOrderId::PowerPlant,
        generated::POWER_ORDER_TAG,
        6,
    );
    let fuel = tree.find(root, fourcc!("fuel"));
    commands
        .entity(fuel)
        .insert((Text::new("X"), Visibility::Hidden));
    rail
}

pub(crate) fn bind_transport(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) -> TransportUi {
    let building_name = city_building_name(assets, CityFacilitySlot::Transport);
    let rail = bind_rail(
        commands,
        assets,
        root,
        tree,
        building_name,
        CityOrderId::TransportCapacity,
        generated::TRANSPORT_ORDER_TAG,
        1,
    );
    TransportUi {
        rail,
        labor: tree.find(root, fourcc!("labV")),
        lumber: tree.find(root, fourcc!("lumb")),
        steel: tree.find(root, fourcc!("stee")),
    }
}

pub(crate) fn bind_population(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) -> PopulationUi {
    let building_name = city_building_name(assets, CityFacilitySlot::RegionalPopulation);
    let rail = bind_rail(
        commands,
        assets,
        root,
        tree,
        building_name,
        CityOrderId::PopulationGrowth,
        generated::POPULATION_ORDER_TAG,
        1,
    );
    PopulationUi {
        rail,
        food: tree.find(root, fourcc!("food")),
        clothing: tree.find(root, fourcc!("clot")),
        furniture: tree.find(root, fourcc!("furn")),
        capacity: tree.find(root, fourcc!("capT")),
        provinces: tree.find(root, fourcc!("prov")),
    }
}

pub(crate) fn render_warehouse(view: &WarehouseUi, session: &GameSession, ui: &mut CityUi) {
    let city = &session
        .game
        .nations()
        .major(session.active_major_nation())
        .city;
    for &(entity, resource) in &view.stocks {
        let value = if resource == ResourceKind::Livestock {
            city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock]
        } else {
            city.stockpile[resource]
        };
        ui.text(entity, value.to_string());
    }
    ui.text(view.labor, city.population.strength().to_string());
    ui.text(view.power, city.power_available.to_string());
}

pub(crate) fn render_food(
    view: &FoodUi,
    session: &GameSession,
    nation: MajorNationId,
    ui: &mut CityUi,
) {
    let city = &session.game.nations().major(nation).city;
    render_rail(session, nation, &view.rail, ui);
    ui.visible(view.labor, city.population.strength() >= 2);
    ui.visible(view.grain, city.stockpile[ResourceKind::Grain] >= 2);
    ui.visible(view.fruit, city.stockpile[ResourceKind::Fruit] >= 1);
    ui.visible(
        view.fish_and_livestock,
        city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock] >= 1,
    );
}

pub(crate) fn render_power(
    view: &RailUi,
    session: &GameSession,
    nation: MajorNationId,
    ui: &mut CityUi,
) {
    render_rail(session, nation, view, ui);
}

pub(crate) fn render_transport(
    view: &TransportUi,
    session: &GameSession,
    nation: MajorNationId,
    ui: &mut CityUi,
) {
    let city = &session.game.nations().major(nation).city;
    render_rail(session, nation, &view.rail, ui);
    ui.visible(view.labor, city.population.strength() >= 2);
    ui.visible(view.lumber, city.stockpile[ResourceKind::Lumber] < 1);
    ui.visible(view.steel, city.stockpile[ResourceKind::Steel] < 1);
}

pub(crate) fn render_population(
    view: &PopulationUi,
    session: &GameSession,
    nation: MajorNationId,
    assets: &RetailUiAssets,
    ui: &mut CityUi,
) {
    let major = session.game.nations().major(nation);
    let city = &major.city;
    let capacity_template = city_string(assets, CITY_TEXT_STRING_GROUP, 0x10);
    let province_template = city_string(assets, CITY_TEXT_STRING_GROUP, 0x1d);
    render_rail(session, nation, &view.rail, ui);
    ui.visible(view.food, city.stockpile[ResourceKind::Food] >= 1);
    ui.visible(view.clothing, city.stockpile[ResourceKind::Clothing] >= 1);
    ui.visible(view.furniture, city.stockpile[ResourceKind::Furniture] >= 1);
    let owned_regions = major.common.owned_region_count();
    let building = city.building_type(
        CityFacilitySlot::RegionalPopulation,
        &major.economy,
        owned_regions,
    );
    ui.text(
        view.capacity,
        format_retail_number(&capacity_template, building),
    );
    ui.text(
        view.provinces,
        format_retail_number(&province_template, owned_regions as i16),
    );
}
