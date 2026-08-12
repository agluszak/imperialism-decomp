use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct PopulationDialogTemplates {
    capacity_template: String,
    province_template: String,
}

pub(in crate::ui::city) fn bind_warehouse_dialog(
    ui: &mut UiSpawner,
    spawned: &SpawnedView,
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
    bind_city_dialog_root(&mut ui.commands, spawned, CityFacilitySlot::Warehouse);
    let name = spawned.unique(fourcc!("name"));
    ui.commands.entity(name).insert((
        Text::new(building_name),
        title_font,
        title_layout,
        TextColor(text_color),
    ));

    for &(_, tag) in &WAREHOUSE_STOCKS {
        let control = spawned.unique(tag);
        ui.commands.entity(control).insert((
            Text::new(""),
            value_font.clone(),
            value_layout,
            TextColor(text_color),
        ));
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
) {
    bind_city_dialog_root(commands, spawned, slot);
    let name_control = spawned.unique(fourcc!("name"));
    commands
        .entity(name_control)
        .insert(Text::new(building_name));
    let left = spawned.under(catalog, binding.tag, fourcc!("left"));
    let right = spawned.under(catalog, binding.tag, fourcc!("rght"));
    commands.entity(left).insert(CityOrderAdjust {
        order: binding.order,
        delta: -step,
    });
    commands.entity(right).insert(CityOrderAdjust {
        order: binding.order,
        delta: step,
    });
    let quantity = spawned.under(catalog, binding.tag, fourcc!("move"));
    commands.entity(quantity).insert(Text::new(""));
}

pub(in crate::ui::city) fn bind_food_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    building_name: String,
) {
    bind_rail_dialog(
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
}

pub(in crate::ui::city) fn bind_power_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    building_name: String,
) {
    bind_rail_dialog(
        commands,
        catalog,
        spawned,
        CityFacilitySlot::PowerPlant,
        building_name,
        POWER_ORDER,
        6,
    );
    let fuel = spawned.unique(fourcc!("fuel"));
    commands
        .entity(fuel)
        .insert((Text::new("X"), Visibility::Hidden));
}

pub(in crate::ui::city) fn bind_transport_capacity_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    building_name: String,
) {
    bind_rail_dialog(
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
}

pub(in crate::ui::city) fn bind_population_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    building_name: String,
    capacity_template: String,
    province_template: String,
) {
    bind_rail_dialog(
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
    commands
        .entity(spawned.root)
        .insert(PopulationDialogTemplates {
            capacity_template,
            province_template,
        });
}

pub(in crate::ui::city) fn sync_basic_dialog(
    session: Res<GameSession>,
    catalog: Res<UiCatalogResource>,
    dialogs: Query<(
        &SpawnedView,
        Ref<CityBuildingDialog>,
        Option<&PopulationDialogTemplates>,
    )>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City active nation is a major nation");
    for (spawned, dialog, templates) in &dialogs {
        if !session.is_changed() && !dialog.is_added() {
            continue;
        }
        let major = session.0.nations().major(nation);
        let city = &major.city;
        match dialog.slot {
            CityFacilitySlot::Warehouse => {
                for &(resource, tag) in &WAREHOUSE_STOCKS {
                    let value = if resource == ResourceKind::Livestock {
                        city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock]
                    } else {
                        city.stockpile[resource]
                    };
                    texts
                        .get_mut(spawned.unique(tag))
                        .expect("Warehouse stock control belongs to its dialog")
                        .0 = value.to_string();
                }
                texts
                    .get_mut(spawned.unique(fourcc!("labo")))
                    .expect("Warehouse labor control belongs to its dialog")
                    .0 = city.population.strength().to_string();
                texts
                    .get_mut(spawned.unique(fourcc!("powe")))
                    .expect("Warehouse power control belongs to its dialog")
                    .0 = city.power_available.to_string();
            }
            CityFacilitySlot::FoodProcessing => {
                let status = session.0.city_order_status(nation, FOOD_ORDER.order);
                texts
                    .get_mut(spawned.under(&catalog, FOOD_ORDER.tag, fourcc!("move")))
                    .expect("Food Processing order control belongs to its dialog")
                    .0 = status.quantity.to_string();
                *visibilities
                    .get_mut(spawned.unique(fourcc!("labV")))
                    .expect("Food Processing labor indicator belongs to its dialog") =
                    if city.population.strength() >= 2 {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
                *visibilities
                    .get_mut(spawned.unique(fourcc!("grai")))
                    .expect("Food Processing grain indicator belongs to its dialog") =
                    if city.stockpile[ResourceKind::Grain] >= 2 {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
                *visibilities
                    .get_mut(spawned.unique(fourcc!("prod")))
                    .expect("Food Processing fruit indicator belongs to its dialog") =
                    if city.stockpile[ResourceKind::Fruit] >= 1 {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
                *visibilities
                    .get_mut(spawned.unique(fourcc!("fish")))
                    .expect("Food Processing livestock indicator belongs to its dialog") =
                    if city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock]
                        >= 1
                    {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
            }
            CityFacilitySlot::PowerPlant => {
                let status = session.0.city_order_status(nation, POWER_ORDER.order);
                texts
                    .get_mut(spawned.under(&catalog, POWER_ORDER.tag, fourcc!("move")))
                    .expect("Power Plant order control belongs to its dialog")
                    .0 = status.quantity.to_string();
            }
            CityFacilitySlot::Transport => {
                let status = session
                    .0
                    .city_order_status(nation, TRANSPORT_CAPACITY_ORDER.order);
                texts
                    .get_mut(spawned.under(&catalog, TRANSPORT_CAPACITY_ORDER.tag, fourcc!("move")))
                    .expect("Transport order control belongs to its dialog")
                    .0 = status.quantity.to_string();
                *visibilities
                    .get_mut(spawned.unique(fourcc!("labV")))
                    .expect("Transport labor indicator belongs to its dialog") =
                    if city.population.strength() >= 2 {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
                *visibilities
                    .get_mut(spawned.unique(fourcc!("lumb")))
                    .expect("Transport lumber indicator belongs to its dialog") =
                    if city.stockpile[ResourceKind::Lumber] < 1 {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
                *visibilities
                    .get_mut(spawned.unique(fourcc!("stee")))
                    .expect("Transport steel indicator belongs to its dialog") =
                    if city.stockpile[ResourceKind::Steel] < 1 {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
            }
            CityFacilitySlot::RegionalPopulation => {
                let status = session.0.city_order_status(nation, POPULATION_ORDER.order);
                texts
                    .get_mut(spawned.under(&catalog, POPULATION_ORDER.tag, fourcc!("move")))
                    .expect("Population order control belongs to its dialog")
                    .0 = status.quantity.to_string();
                for (tag, resource) in [
                    (fourcc!("food"), ResourceKind::Food),
                    (fourcc!("clot"), ResourceKind::Clothing),
                    (fourcc!("furn"), ResourceKind::Furniture),
                ] {
                    *visibilities
                        .get_mut(spawned.unique(tag))
                        .expect("Population stock indicator belongs to its dialog") =
                        if city.stockpile[resource] >= 1 {
                            Visibility::Visible
                        } else {
                            Visibility::Hidden
                        };
                }
                let templates = templates.expect("Population dialog has number templates");
                let owned_regions = major.common.owned_region_count();
                let capacity = format_retail_number(
                    &templates.capacity_template,
                    city.building_type(
                        CityFacilitySlot::RegionalPopulation,
                        &major.economy,
                        owned_regions as i32,
                    ),
                );
                texts
                    .get_mut(spawned.unique(fourcc!("capT")))
                    .expect("Population capacity control belongs to its dialog")
                    .0 = capacity;
                texts
                    .get_mut(spawned.unique(fourcc!("prov")))
                    .expect("Population province control belongs to its dialog")
                    .0 = format_retail_number(&templates.province_template, owned_regions as i16);
            }
            _ => continue,
        }
    }
}
