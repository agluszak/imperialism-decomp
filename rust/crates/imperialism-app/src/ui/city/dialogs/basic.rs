use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct WarehouseView {
    stocks: Vec<(Entity, ResourceKind)>,
    labor: Entity,
    power: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct FoodView {
    labor: Entity,
    grain: Entity,
    fruit: Entity,
    fish_and_livestock: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct TransportCapacityView {
    labor: Entity,
    lumber: Entity,
    steel: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct PopulationView {
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
    tree: &RetailTree,
    state: &GameState,
) {
    let advanced_production_unlocked = state.technology().advanced_production_unlocked();

    let stocks = WAREHOUSE_STOCKS
        .iter()
        .map(|&(resource, tag)| (tree.find(root, tag), resource))
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
    commands.entity(root).insert(WarehouseView {
        stocks,
        labor,
        power,
    });
}

pub(in crate::ui::city) fn bind_rail_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    building_name: String,
    binding: CityOrderBinding,
    step: i16,
) {
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
        false,
    );
    let (bar, fill, tick) = bind_rail_amount_bar(commands, assets, counter.row, tree);
    commands.entity(root).insert(RailView {
        order: binding.order,
        step,
        quantity: counter.quantity,
        bar,
        fill,
        tick,
    });
}

pub(in crate::ui::city) fn configure_food_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::FoodProcessing);
    bind_rail_dialog(commands, assets, root, tree, building_name, FOOD_ORDER, 2);
    commands.entity(root).insert(FoodView {
        labor: tree.find(root, fourcc!("labV")),
        grain: tree.find(root, fourcc!("grai")),
        fruit: tree.find(root, fourcc!("prod")),
        fish_and_livestock: tree.find(root, fourcc!("fish")),
    });
}

pub(in crate::ui::city) fn configure_power_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::PowerPlant);
    bind_rail_dialog(commands, assets, root, tree, building_name, POWER_ORDER, 6);
    let fuel = tree.find(root, fourcc!("fuel"));
    commands
        .entity(fuel)
        .insert((Text::new("X"), Visibility::Hidden));
}

pub(in crate::ui::city) fn configure_transport_capacity_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::Transport);
    bind_rail_dialog(
        commands,
        assets,
        root,
        tree,
        building_name,
        TRANSPORT_CAPACITY_ORDER,
        1,
    );
    commands.entity(root).insert(TransportCapacityView {
        labor: tree.find(root, fourcc!("labV")),
        lumber: tree.find(root, fourcc!("lumb")),
        steel: tree.find(root, fourcc!("stee")),
    });
}

pub(in crate::ui::city) fn configure_population_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::RegionalPopulation);
    bind_rail_dialog(
        commands,
        assets,
        root,
        tree,
        building_name,
        POPULATION_ORDER,
        1,
    );
    commands.entity(root).insert(PopulationView {
        food: tree.find(root, fourcc!("food")),
        clothing: tree.find(root, fourcc!("clot")),
        furniture: tree.find(root, fourcc!("furn")),
        capacity: tree.find(root, fourcc!("capT")),
        provinces: tree.find(root, fourcc!("prov")),
    });
}

pub(in crate::ui::city) fn render_warehouse_dialog(
    session: Res<GameSession>,
    views: Query<Ref<WarehouseView>>,
    mut texts: Query<&mut Text>,
) {
    let city = &session
        .game
        .nations()
        .major(session.active_major_nation())
        .city;
    for view in &views {
        if !session.is_changed() && !view.is_added() {
            continue;
        }
        for &(entity, resource) in &view.stocks {
            let value = if resource == ResourceKind::Livestock {
                city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock]
            } else {
                city.stockpile[resource]
            };
            texts
                .get_mut(entity)
                .expect("bound warehouse stock text must exist")
                .0 = value.to_string();
        }
        texts
            .get_mut(view.labor)
            .expect("bound warehouse labor text must exist")
            .0 = city.population.strength().to_string();
        texts
            .get_mut(view.power)
            .expect("bound warehouse power text must exist")
            .0 = city.power_available.to_string();
    }
}

pub(in crate::ui::city) fn render_food_dialog(
    session: Res<GameSession>,
    views: Query<Ref<FoodView>>,
    mut commands: Commands,
) {
    let city = &session
        .game
        .nations()
        .major(session.active_major_nation())
        .city;
    for view in &views {
        if !session.is_changed() && !view.is_added() {
            continue;
        }
        let mut set = |entity, visible| {
            commands.entity(entity).insert(if visible {
                Visibility::Visible
            } else {
                Visibility::Hidden
            });
        };
        set(view.labor, city.population.strength() >= 2);
        set(view.grain, city.stockpile[ResourceKind::Grain] >= 2);
        set(view.fruit, city.stockpile[ResourceKind::Fruit] >= 1);
        set(
            view.fish_and_livestock,
            city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock] >= 1,
        );
    }
}

pub(in crate::ui::city) fn render_transport_capacity_dialog(
    session: Res<GameSession>,
    views: Query<Ref<TransportCapacityView>>,
    mut commands: Commands,
) {
    let city = &session
        .game
        .nations()
        .major(session.active_major_nation())
        .city;
    for view in &views {
        if !session.is_changed() && !view.is_added() {
            continue;
        }
        let mut set = |entity, visible| {
            commands.entity(entity).insert(if visible {
                Visibility::Visible
            } else {
                Visibility::Hidden
            });
        };
        set(view.labor, city.population.strength() >= 2);
        set(view.lumber, city.stockpile[ResourceKind::Lumber] < 1);
        set(view.steel, city.stockpile[ResourceKind::Steel] < 1);
    }
}

pub(in crate::ui::city) fn render_population_dialog(
    session: Res<GameSession>,
    views: Query<Ref<PopulationView>>,
    assets: RetailUiAssets,
    mut commands: Commands,
    mut texts: Query<&mut Text>,
) {
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let city = &major.city;
    let capacity_template = city_string(&assets, CITY_TEXT_STRING_GROUP, 0x10);
    let province_template = city_string(&assets, CITY_TEXT_STRING_GROUP, 0x1d);
    for view in &views {
        if !session.is_changed() && !view.is_added() {
            continue;
        }
        let mut set = |entity, visible| {
            commands.entity(entity).insert(if visible {
                Visibility::Visible
            } else {
                Visibility::Hidden
            });
        };
        set(view.food, city.stockpile[ResourceKind::Food] >= 1);
        set(view.clothing, city.stockpile[ResourceKind::Clothing] >= 1);
        set(view.furniture, city.stockpile[ResourceKind::Furniture] >= 1);
        let owned_regions = major.common.owned_region_count();
        let building = city.building_type(
            CityFacilitySlot::RegionalPopulation,
            &major.economy,
            owned_regions,
        );
        texts
            .get_mut(view.capacity)
            .expect("bound population capacity text must exist")
            .0 = format_retail_number(&capacity_template, building);
        texts
            .get_mut(view.provinces)
            .expect("bound population provinces text must exist")
            .0 = format_retail_number(&province_template, owned_regions as i16);
    }
}
