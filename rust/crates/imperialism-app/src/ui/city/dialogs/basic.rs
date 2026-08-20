use super::*;

#[derive(Component)]
pub(in crate::ui::city) enum WarehouseDisplay {
    Stock(ResourceKind),
    Labor,
    Power,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) enum FoodIndicator {
    Labor,
    Grain,
    Fruit,
    FishAndLivestock,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) enum TransportCapacityIndicator {
    Labor,
    Lumber,
    Steel,
}

#[derive(Component)]
pub(in crate::ui::city) struct PopulationGood(ResourceKind);

#[derive(Component)]
pub(in crate::ui::city) enum PopulationText {
    Capacity(String),
    Provinces(String),
}

pub(in crate::ui::city) fn configure_warehouse_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    state: &GameState,
) {
    let oil_drilling_available = state.technology().oil_drilling_available();

    for &(resource, tag) in &WAREHOUSE_STOCKS {
        let control = tree.find(root, tag);
        commands
            .entity(control)
            .insert((Text::new(""), WarehouseDisplay::Stock(resource)));
    }
    let labor = tree.find(root, fourcc!("labo"));
    let power = tree.find(root, fourcc!("powe"));
    commands
        .entity(labor)
        .insert((Text::new(""), WarehouseDisplay::Labor));
    commands
        .entity(power)
        .insert((Text::new(""), WarehouseDisplay::Power));
    for tag in [fourcc!("oil "), fourcc!("fuel"), fourcc!("powe")] {
        let control = tree.find(root, tag);
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

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn bind_rail_dialog(
    commands: &mut Commands,
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
    bind_city_order_row(
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
}

pub(in crate::ui::city) fn configure_food_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::FoodProcessing);
    bind_rail_dialog(commands, root, tree, building_name, FOOD_ORDER, 2);
    let labor = tree.find(root, fourcc!("labV"));
    let grain = tree.find(root, fourcc!("grai"));
    let fruit = tree.find(root, fourcc!("prod"));
    let fish_and_livestock = tree.find(root, fourcc!("fish"));
    commands
        .entity(labor)
        .insert((Text::new("X"), FoodIndicator::Labor));
    commands
        .entity(grain)
        .insert((Text::new("X"), FoodIndicator::Grain));
    commands
        .entity(fruit)
        .insert((Text::new("X"), FoodIndicator::Fruit));
    commands
        .entity(fish_and_livestock)
        .insert((Text::new("X"), FoodIndicator::FishAndLivestock));
}

pub(in crate::ui::city) fn configure_power_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::PowerPlant);
    bind_rail_dialog(commands, root, tree, building_name, POWER_ORDER, 6);
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
        root,
        tree,
        building_name,
        TRANSPORT_CAPACITY_ORDER,
        1,
    );
    let labor = tree.find(root, fourcc!("labV"));
    let lumber = tree.find(root, fourcc!("lumb"));
    let steel = tree.find(root, fourcc!("stee"));
    commands
        .entity(labor)
        .insert((Text::new("X"), TransportCapacityIndicator::Labor));
    commands
        .entity(lumber)
        .insert((Text::new("X"), TransportCapacityIndicator::Lumber));
    commands
        .entity(steel)
        .insert((Text::new("X"), TransportCapacityIndicator::Steel));
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
    bind_rail_dialog(commands, root, tree, building_name, POPULATION_ORDER, 1);
    let food = tree.find(root, fourcc!("food"));
    let clothing = tree.find(root, fourcc!("clot"));
    let furniture = tree.find(root, fourcc!("furn"));
    let capacity = tree.find(root, fourcc!("capT"));
    let provinces = tree.find(root, fourcc!("prov"));
    commands
        .entity(food)
        .insert((Text::new("X"), PopulationGood(ResourceKind::Food)));
    commands
        .entity(clothing)
        .insert((Text::new("X"), PopulationGood(ResourceKind::Clothing)));
    commands
        .entity(furniture)
        .insert((Text::new("X"), PopulationGood(ResourceKind::Furniture)));
    commands
        .entity(capacity)
        .insert((Text::new(""), PopulationText::Capacity(capacity_template)));
    commands
        .entity(provinces)
        .insert((Text::new(""), PopulationText::Provinces(province_template)));
}

pub(in crate::ui::city) fn sync_warehouse_dialog(
    session: Res<GameSession>,
    added: Query<(), Added<WarehouseDisplay>>,
    mut displays: Query<(&WarehouseDisplay, &mut Text)>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let city = &session
        .game
        .nations()
        .major(session.active_major_nation())
        .city;
    for (display, mut text) in &mut displays {
        text.0 = match *display {
            WarehouseDisplay::Stock(resource) => {
                let value = if resource == ResourceKind::Livestock {
                    city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock]
                } else {
                    city.stockpile[resource]
                };
                value.to_string()
            }
            WarehouseDisplay::Labor => city.population.strength().to_string(),
            WarehouseDisplay::Power => city.power_available.to_string(),
        };
    }
}

pub(in crate::ui::city) fn sync_food_dialog(
    session: Res<GameSession>,
    added: Query<(), Added<FoodIndicator>>,
    mut indicators: Query<(&FoodIndicator, &mut Visibility)>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let city = &session
        .game
        .nations()
        .major(session.active_major_nation())
        .city;
    for (indicator, mut visibility) in &mut indicators {
        let visible = match indicator {
            FoodIndicator::Labor => city.population.strength() >= 2,
            FoodIndicator::Grain => city.stockpile[ResourceKind::Grain] >= 2,
            FoodIndicator::Fruit => city.stockpile[ResourceKind::Fruit] >= 1,
            FoodIndicator::FishAndLivestock => {
                city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock] >= 1
            }
        };
        *visibility = if visible {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
}

pub(in crate::ui::city) fn sync_transport_capacity_dialog(
    session: Res<GameSession>,
    added: Query<(), Added<TransportCapacityIndicator>>,
    mut indicators: Query<(&TransportCapacityIndicator, &mut Visibility)>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let city = &session
        .game
        .nations()
        .major(session.active_major_nation())
        .city;
    for (indicator, mut visibility) in &mut indicators {
        let visible = match indicator {
            TransportCapacityIndicator::Labor => city.population.strength() >= 2,
            TransportCapacityIndicator::Lumber => city.stockpile[ResourceKind::Lumber] < 1,
            TransportCapacityIndicator::Steel => city.stockpile[ResourceKind::Steel] < 1,
        };
        *visibility = if visible {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
}

pub(in crate::ui::city) fn sync_population_dialog(
    session: Res<GameSession>,
    added: Query<(), Added<PopulationGood>>,
    mut goods: Query<(&PopulationGood, &mut Visibility)>,
    mut texts: Query<(&PopulationText, &mut Text)>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let city = &major.city;
    for (PopulationGood(resource), mut visibility) in &mut goods {
        *visibility = if city.stockpile[*resource] >= 1 {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
    let owned_regions = major.common.owned_region_count();
    let building = city.building_type(
        CityFacilitySlot::RegionalPopulation,
        &major.economy,
        owned_regions,
    );
    for (text_kind, mut text) in &mut texts {
        text.0 = match text_kind {
            PopulationText::Capacity(template) => format_retail_number(template, building),
            PopulationText::Provinces(template) => {
                format_retail_number(template, owned_regions as i16)
            }
        };
    }
}
