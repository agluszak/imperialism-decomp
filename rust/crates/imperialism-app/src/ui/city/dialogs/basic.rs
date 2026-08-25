use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct WarehouseView {
    stocks: Vec<(ResourceKind, Entity)>,
    labor: Entity,
    power: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct FoodView {
    rail: RailOrderView,
    labor: Entity,
    grain: Entity,
    fruit: Entity,
    fish_and_livestock: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct PowerView {
    rail: RailOrderView,
}

#[derive(Component)]
pub(in crate::ui::city) struct TransportView {
    rail: RailOrderView,
    labor: Entity,
    lumber: Entity,
    steel: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct PopulationView {
    rail: RailOrderView,
    food: Entity,
    clothing: Entity,
    furniture: Entity,
    capacity: Entity,
    provinces: Entity,
    capacity_template: String,
    province_template: String,
}

pub(in crate::ui::city) fn configure_warehouse_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    state: &GameState,
) {
    let advanced_production_unlocked = state.technology().advanced_production_unlocked();

    let stocks = WAREHOUSE_STOCKS
        .iter()
        .map(|&(resource, tag)| {
            let entity = tree.find(root, tag);
            commands.entity(entity).insert(Text::new(""));
            (resource, entity)
        })
        .collect();
    let labor = tree.find(root, fourcc!("labo"));
    let power = tree.find(root, fourcc!("powe"));
    commands.entity(labor).insert(Text::new(""));
    commands.entity(power).insert(Text::new(""));
    commands.entity(root).insert(WarehouseView {
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
            control_commands.insert(Visibility::Hidden);
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

pub(in crate::ui::city) fn configure_food_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::FoodProcessing);
    let rail = bind_rail_order(commands, assets, root, tree, building_name, FOOD_ORDER, 2);
    let labor = tree.find(root, fourcc!("labV"));
    let grain = tree.find(root, fourcc!("grai"));
    let fruit = tree.find(root, fourcc!("prod"));
    let fish_and_livestock = tree.find(root, fourcc!("fish"));
    commands.entity(labor).insert(Text::new("X"));
    commands.entity(grain).insert(Text::new("X"));
    commands.entity(fruit).insert(Text::new("X"));
    commands.entity(fish_and_livestock).insert(Text::new("X"));
    commands.entity(root).insert(FoodView {
        rail,
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
    let rail = bind_rail_order(commands, assets, root, tree, building_name, POWER_ORDER, 6);
    let fuel = tree.find(root, fourcc!("fuel"));
    commands
        .entity(fuel)
        .insert((Text::new("X"), Visibility::Hidden));
    commands.entity(root).insert(PowerView { rail });
}

pub(in crate::ui::city) fn configure_transport_capacity_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::Transport);
    let rail = bind_rail_order(
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
    commands.entity(root).insert(TransportView {
        rail,
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
    let rail = bind_rail_order(
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
    commands.entity(root).insert(PopulationView {
        rail,
        food,
        clothing,
        furniture,
        capacity,
        provinces,
        capacity_template,
        province_template,
    });
}

pub(in crate::ui::city) fn sync_warehouse_dialog(
    session: Res<GameSession>,
    added: Query<(), Added<WarehouseView>>,
    views: Query<&WarehouseView>,
    mut texts: Query<&mut Text>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let city = &session
        .game
        .nations()
        .major(session.active_major_nation())
        .city;
    for view in &views {
        for &(resource, entity) in &view.stocks {
            let value = if resource == ResourceKind::Livestock {
                city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock]
            } else {
                city.stockpile[resource]
            };
            set_bound_text(
                &mut texts,
                entity,
                value.to_string(),
                "warehouse stock remains bound",
            );
        }
        set_bound_text(
            &mut texts,
            view.labor,
            city.population.strength().to_string(),
            "warehouse labor remains bound",
        );
        set_bound_text(
            &mut texts,
            view.power,
            city.power_available.to_string(),
            "warehouse power remains bound",
        );
    }
}

pub(in crate::ui::city) fn sync_food_dialog(
    session: Res<GameSession>,
    added: Query<(), Added<FoodView>>,
    views: Query<&FoodView>,
    retail: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
    mut nodes: Query<&mut Node>,
    pictures: Query<&ImageNode>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let city = &session
        .game
        .nations()
        .major(session.active_major_nation())
        .city;
    for view in &views {
        project_rail_order(
            &session,
            &retail,
            &mut images,
            &mut texts,
            &mut nodes,
            &pictures,
            view.rail,
            "food rail remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.labor,
            city.population.strength() >= 2,
            "food labor warning remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.grain,
            city.stockpile[ResourceKind::Grain] >= 2,
            "food grain warning remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.fruit,
            city.stockpile[ResourceKind::Fruit] >= 1,
            "food fruit warning remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.fish_and_livestock,
            city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock] >= 1,
            "food fish and livestock warning remains bound",
        );
    }
}

pub(in crate::ui::city) fn sync_power_dialog(
    session: Res<GameSession>,
    added: Query<(), Added<PowerView>>,
    views: Query<&PowerView>,
    retail: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut texts: Query<&mut Text>,
    mut nodes: Query<&mut Node>,
    pictures: Query<&ImageNode>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    for view in &views {
        project_rail_order(
            &session,
            &retail,
            &mut images,
            &mut texts,
            &mut nodes,
            &pictures,
            view.rail,
            "power rail remains bound",
        );
    }
}

pub(in crate::ui::city) fn sync_transport_capacity_dialog(
    session: Res<GameSession>,
    added: Query<(), Added<TransportView>>,
    views: Query<&TransportView>,
    retail: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
    mut nodes: Query<&mut Node>,
    pictures: Query<&ImageNode>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let city = &session
        .game
        .nations()
        .major(session.active_major_nation())
        .city;
    for view in &views {
        project_rail_order(
            &session,
            &retail,
            &mut images,
            &mut texts,
            &mut nodes,
            &pictures,
            view.rail,
            "transport rail remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.labor,
            city.population.strength() >= 2,
            "transport labor warning remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.lumber,
            city.stockpile[ResourceKind::Lumber] < 1,
            "transport lumber warning remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.steel,
            city.stockpile[ResourceKind::Steel] < 1,
            "transport steel warning remains bound",
        );
    }
}

pub(in crate::ui::city) fn sync_population_dialog(
    session: Res<GameSession>,
    added: Query<(), Added<PopulationView>>,
    views: Query<&PopulationView>,
    retail: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
    mut nodes: Query<&mut Node>,
    pictures: Query<&ImageNode>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let city = &major.city;
    let owned_regions = major.common.owned_region_count();
    let building = city.building_type(
        CityFacilitySlot::RegionalPopulation,
        &major.economy,
        owned_regions,
    );
    for view in &views {
        project_rail_order(
            &session,
            &retail,
            &mut images,
            &mut texts,
            &mut nodes,
            &pictures,
            view.rail,
            "population rail remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.food,
            city.stockpile[ResourceKind::Food] >= 1,
            "population food warning remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.clothing,
            city.stockpile[ResourceKind::Clothing] >= 1,
            "population clothing warning remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.furniture,
            city.stockpile[ResourceKind::Furniture] >= 1,
            "population furniture warning remains bound",
        );
        set_bound_text(
            &mut texts,
            view.capacity,
            format_retail_number(&view.capacity_template, building),
            "population capacity remains bound",
        );
        set_bound_text(
            &mut texts,
            view.provinces,
            format_retail_number(&view.province_template, owned_regions as i16),
            "population provinces remain bound",
        );
    }
}
