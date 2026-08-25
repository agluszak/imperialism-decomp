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
    ui: &generated::Citydlog9213,
    state: &GameState,
) {
    let advanced_production_unlocked = state.technology().advanced_production_unlocked();
    let stocks = [
        (ResourceKind::Cotton, ui.cott),
        (ResourceKind::Wool, ui.wool),
        (ResourceKind::Timber, ui.timb),
        (ResourceKind::Coal, ui.coal),
        (ResourceKind::Iron, ui.iron),
        (ResourceKind::Horses, ui.hors),
        (ResourceKind::Oil, ui.oil),
        (ResourceKind::Food, ui.food),
        (ResourceKind::Fabric, ui.fabr),
        (ResourceKind::Lumber, ui.lumb),
        (ResourceKind::Paper, ui.pape),
        (ResourceKind::Steel, ui.stee),
        (ResourceKind::Fuel, ui.fuel),
        (ResourceKind::Clothing, ui.clot),
        (ResourceKind::Furniture, ui.furn),
        (ResourceKind::Hardware, ui.hard),
        (ResourceKind::Arms, ui.arma),
        (ResourceKind::Grain, ui.grai),
        (ResourceKind::Fruit, ui.prod),
        (ResourceKind::Livestock, ui.live),
    ];
    for (resource, control) in stocks {
        commands
            .entity(control)
            .insert((Text::new(""), WarehouseDisplay::Stock(resource)));
    }
    commands
        .entity(ui.labo)
        .insert((Text::new(""), WarehouseDisplay::Labor));
    commands
        .entity(ui.powe)
        .insert((Text::new(""), WarehouseDisplay::Power));
    for control in [ui.oil, ui.fuel, ui.powe] {
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
    match assets.picture(picture) {
        Ok(handle) => {
            commands.entity(ui.dlog).insert(ImageNode::new(handle));
        }
        Err(error) => warn!("could not load Warehouse picture {picture}: {error}"),
    }
    commands
        .entity(ui.dlog)
        .entry::<Node>()
        .and_modify(|mut node| node.overflow = Overflow::clip());
    for entity in [ui.wind, ui.dlog] {
        commands
            .entity(entity)
            .entry::<Node>()
            .and_modify(|mut node| {
                node.width = px(176);
                node.height = px(335);
            });
    }
    for entity in [ui.hors, ui.food, ui.labo, ui.grai, ui.prod, ui.live] {
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
    name: Entity,
    order: CityOrderId,
    row: Entity,
    decrease: Entity,
    increase: Entity,
    quantity: Entity,
    bar: Entity,
    building_name: String,
    step: i16,
) {
    commands.entity(name).insert(Text::new(building_name));
    let counter = bind_city_order_row(
        commands, order, row, decrease, increase, quantity, step, None,
    );
    commands
        .entity(counter.quantity)
        .insert(RailBarCounter { order });
    bind_rail_amount_bar(commands, assets, bar, order, step);
}

pub(in crate::ui::city) fn configure_food_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    ui: &generated::Citydlog9212,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::FoodProcessing);
    bind_rail_dialog(
        commands,
        assets,
        ui.name,
        CityOrderId::FoodProcessing,
        ui.food,
        ui.left,
        ui.rght,
        ui.move_,
        ui.bar,
        building_name,
        2,
    );
    commands
        .entity(ui.labv)
        .insert((Text::new("X"), FoodIndicator::Labor));
    commands
        .entity(ui.grai)
        .insert((Text::new("X"), FoodIndicator::Grain));
    commands
        .entity(ui.prod)
        .insert((Text::new("X"), FoodIndicator::Fruit));
    commands
        .entity(ui.fish)
        .insert((Text::new("X"), FoodIndicator::FishAndLivestock));
}

pub(in crate::ui::city) fn configure_power_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    ui: &generated::Citydlog9211,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::PowerPlant);
    bind_rail_dialog(
        commands,
        assets,
        ui.name,
        CityOrderId::PowerPlant,
        ui.powe,
        ui.left,
        ui.rght,
        ui.move_,
        ui.bar,
        building_name,
        6,
    );
    commands
        .entity(ui.fuel)
        .insert((Text::new("X"), Visibility::Hidden));
}

pub(in crate::ui::city) fn configure_transport_capacity_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    ui: &generated::Citydlog9214,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::Transport);
    bind_rail_dialog(
        commands,
        assets,
        ui.name,
        CityOrderId::TransportCapacity,
        ui.rail,
        ui.left,
        ui.rght,
        ui.move_,
        ui.bar,
        building_name,
        1,
    );
    commands
        .entity(ui.labv)
        .insert((Text::new("X"), TransportCapacityIndicator::Labor));
    commands
        .entity(ui.lumb)
        .insert((Text::new("X"), TransportCapacityIndicator::Lumber));
    commands
        .entity(ui.stee)
        .insert((Text::new("X"), TransportCapacityIndicator::Steel));
}

pub(in crate::ui::city) fn configure_population_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    ui: &generated::Citydlog9215,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::RegionalPopulation);
    let capacity_template = city_string(assets, CITY_TEXT_STRING_GROUP, 0x10);
    let province_template = city_string(assets, CITY_TEXT_STRING_GROUP, 0x1d);
    bind_rail_dialog(
        commands,
        assets,
        ui.name,
        CityOrderId::PopulationGrowth,
        ui.popu,
        ui.left,
        ui.rght,
        ui.move_,
        ui.bar,
        building_name,
        1,
    );
    commands
        .entity(ui.food)
        .insert((Text::new("X"), PopulationGood(ResourceKind::Food)));
    commands
        .entity(ui.clot)
        .insert((Text::new("X"), PopulationGood(ResourceKind::Clothing)));
    commands
        .entity(ui.furn)
        .insert((Text::new("X"), PopulationGood(ResourceKind::Furniture)));
    commands
        .entity(ui.capt)
        .insert((Text::new(""), PopulationText::Capacity(capacity_template)));
    commands
        .entity(ui.prov)
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
