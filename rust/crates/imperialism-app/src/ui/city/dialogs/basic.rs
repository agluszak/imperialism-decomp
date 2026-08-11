use super::*;

struct WarehouseStockControl {
    resource: ResourceKind,
    entity: Entity,
}

struct WarehouseDialogControls {
    stocks: Vec<WarehouseStockControl>,
    labor: Entity,
    power: Entity,
}

struct FoodDialogControls {
    orders: Vec<CityOrderControl>,
    labor: Entity,
    grain: Entity,
    fruit: Entity,
    fish_and_livestock: Entity,
}

struct PowerDialogControls {
    orders: Vec<CityOrderControl>,
}

struct TransportDialogControls {
    orders: Vec<CityOrderControl>,
    labor: Entity,
    lumber: Entity,
    steel: Entity,
}

struct PopulationDialogControls {
    orders: Vec<CityOrderControl>,
    food: Entity,
    clothing: Entity,
    furniture: Entity,
    capacity: Entity,
    capacity_template: String,
    provinces: Entity,
    province_template: String,
}

#[derive(Component)]
pub(in crate::ui::city) struct BasicDialogControls(BasicDialogKind);

enum BasicDialogKind {
    Warehouse(WarehouseDialogControls),
    Food(FoodDialogControls),
    Power(PowerDialogControls),
    Transport(TransportDialogControls),
    Population(PopulationDialogControls),
}

pub(in crate::ui::city) fn bind_warehouse_dialog(
    ui: &mut UiSpawner,
    spawned: &SpawnedView,
    nation: MajorNationId,
    building_name: String,
    oil_drilling_available: bool,
) {
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
    let root = bind_city_dialog_root(
        &mut ui.commands,
        spawned,
        nation,
        CityFacilitySlot::Warehouse,
    );
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
    ui.commands
        .entity(root)
        .insert(BasicDialogControls(BasicDialogKind::Warehouse(
            WarehouseDialogControls {
                stocks,
                labor,
                power,
            },
        )));

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

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn bind_rail_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    slot: CityFacilitySlot,
    building_name: String,
    bindings: &[CityOrderBinding],
    step: i16,
) -> (Entity, Vec<CityOrderControl>) {
    let root = bind_city_dialog_root(commands, spawned, nation, slot);
    let name_control = spawned.unique(fourcc!("name"));
    commands
        .entity(name_control)
        .insert(Text::new(building_name));
    let orders = bind_city_order_controls(
        commands,
        catalog,
        spawned,
        root,
        nation,
        bindings,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        step,
    );
    (root, orders)
}

pub(in crate::ui::city) fn bind_food_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    building_name: String,
) {
    let (root, orders) = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        CityFacilitySlot::FoodProcessing,
        building_name,
        &FOOD_ORDERS,
        2,
    );
    let labor = spawned.unique(fourcc!("labV"));
    let grain = spawned.unique(fourcc!("grai"));
    let fruit = spawned.unique(fourcc!("prod"));
    let fish_and_livestock = spawned.unique(fourcc!("fish"));
    for entity in [labor, grain, fruit, fish_and_livestock] {
        commands.entity(entity).insert(Text::new("X"));
    }
    commands
        .entity(root)
        .insert(BasicDialogControls(BasicDialogKind::Food(
            FoodDialogControls {
                orders,
                labor,
                grain,
                fruit,
                fish_and_livestock,
            },
        )));
}

pub(in crate::ui::city) fn bind_power_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    building_name: String,
) {
    let (root, orders) = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        CityFacilitySlot::PowerPlant,
        building_name,
        &POWER_ORDERS,
        6,
    );
    commands
        .entity(root)
        .insert(BasicDialogControls(BasicDialogKind::Power(
            PowerDialogControls { orders },
        )));
    let fuel = spawned.unique(fourcc!("fuel"));
    commands
        .entity(fuel)
        .insert((Text::new("X"), Visibility::Hidden));
}

pub(in crate::ui::city) fn bind_transport_capacity_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    building_name: String,
) {
    let (root, orders) = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        CityFacilitySlot::Transport,
        building_name,
        &TRANSPORT_CAPACITY_ORDERS,
        1,
    );
    let labor = spawned.unique(fourcc!("labV"));
    let lumber = spawned.unique(fourcc!("lumb"));
    let steel = spawned.unique(fourcc!("stee"));
    for entity in [labor, lumber, steel] {
        commands.entity(entity).insert(Text::new("X"));
    }
    commands
        .entity(root)
        .insert(BasicDialogControls(BasicDialogKind::Transport(
            TransportDialogControls {
                orders,
                labor,
                lumber,
                steel,
            },
        )));
}

pub(in crate::ui::city) fn bind_population_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    building_name: String,
    capacity_template: String,
    province_template: String,
) {
    let (root, orders) = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        CityFacilitySlot::RegionalPopulation,
        building_name,
        &POPULATION_ORDERS,
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
    commands
        .entity(root)
        .insert(BasicDialogControls(BasicDialogKind::Population(
            PopulationDialogControls {
                orders,
                food,
                clothing,
                furniture,
                capacity,
                capacity_template,
                provinces,
                province_template,
            },
        )));
}

pub(in crate::ui::city) fn sync_basic_dialog(
    session: Res<GameSession>,
    dialogs: Query<(Ref<CityBuildingDialog>, &BasicDialogControls)>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
) {
    for (dialog, controls) in &dialogs {
        if !session.is_changed() && !dialog.is_added() {
            continue;
        }
        let major = session.0.nations().major(dialog.nation);
        let city = &major.city;
        match &controls.0 {
            BasicDialogKind::Warehouse(controls) => {
                for stock in &controls.stocks {
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
                    .get_mut(controls.labor)
                    .expect("Warehouse labor control belongs to its dialog")
                    .0 = city.population.strength().to_string();
                texts
                    .get_mut(controls.power)
                    .expect("Warehouse power control belongs to its dialog")
                    .0 = city.power_available.to_string();
            }
            BasicDialogKind::Food(controls) => {
                for order in &controls.orders {
                    let status = session.0.city_order_status(dialog.nation, order.order);
                    texts
                        .get_mut(order.quantity)
                        .expect("Food Processing order control belongs to its dialog")
                        .0 = status.quantity.to_string();
                }
                *visibilities
                    .get_mut(controls.labor)
                    .expect("Food Processing labor indicator belongs to its dialog") =
                    if city.population.strength() >= 2 {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
                *visibilities
                    .get_mut(controls.grain)
                    .expect("Food Processing grain indicator belongs to its dialog") =
                    if city.stockpile[ResourceKind::Grain] >= 2 {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
                *visibilities
                    .get_mut(controls.fruit)
                    .expect("Food Processing fruit indicator belongs to its dialog") =
                    if city.stockpile[ResourceKind::Fruit] >= 1 {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
                *visibilities
                    .get_mut(controls.fish_and_livestock)
                    .expect("Food Processing livestock indicator belongs to its dialog") =
                    if city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock]
                        >= 1
                    {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
            }
            BasicDialogKind::Power(controls) => {
                for order in &controls.orders {
                    let status = session.0.city_order_status(dialog.nation, order.order);
                    texts
                        .get_mut(order.quantity)
                        .expect("Power Plant order control belongs to its dialog")
                        .0 = status.quantity.to_string();
                }
            }
            BasicDialogKind::Transport(controls) => {
                for order in &controls.orders {
                    let status = session.0.city_order_status(dialog.nation, order.order);
                    texts
                        .get_mut(order.quantity)
                        .expect("Transport order control belongs to its dialog")
                        .0 = status.quantity.to_string();
                }
                *visibilities
                    .get_mut(controls.labor)
                    .expect("Transport labor indicator belongs to its dialog") =
                    if city.population.strength() >= 2 {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
                *visibilities
                    .get_mut(controls.lumber)
                    .expect("Transport lumber indicator belongs to its dialog") =
                    if city.stockpile[ResourceKind::Lumber] < 1 {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
                *visibilities
                    .get_mut(controls.steel)
                    .expect("Transport steel indicator belongs to its dialog") =
                    if city.stockpile[ResourceKind::Steel] < 1 {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
            }
            BasicDialogKind::Population(controls) => {
                for order in &controls.orders {
                    let status = session.0.city_order_status(dialog.nation, order.order);
                    texts
                        .get_mut(order.quantity)
                        .expect("Population order control belongs to its dialog")
                        .0 = status.quantity.to_string();
                }
                for (entity, resource) in [
                    (controls.food, ResourceKind::Food),
                    (controls.clothing, ResourceKind::Clothing),
                    (controls.furniture, ResourceKind::Furniture),
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
                let capacity = format_retail_number(
                    &controls.capacity_template,
                    city.building_type(
                        CityFacilitySlot::RegionalPopulation,
                        &major.economy,
                        owned_regions as i32,
                    ),
                );
                texts
                    .get_mut(controls.capacity)
                    .expect("Population capacity control belongs to its dialog")
                    .0 = capacity;
                texts
                    .get_mut(controls.provinces)
                    .expect("Population province control belongs to its dialog")
                    .0 = format_retail_number(&controls.province_template, owned_regions as i16);
            }
        }
    }
}
