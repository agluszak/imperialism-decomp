use super::*;

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

    for &(resource, tag) in &WAREHOUSE_STOCKS {
        let value = if resource == ResourceKind::Livestock {
            CityValue::WarehouseFishAndLivestock
        } else {
            CityValue::Stock(resource)
        };
        let control = spawned.unique(tag);
        ui.commands.entity(control).insert((
            Text::new(""),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
            value_font.clone(),
            value_layout,
            TextColor(text_color),
        ));
    }
    for (tag, value) in [
        (fourcc!("labo"), CityValue::LaborAvailable),
        (fourcc!("powe"), CityValue::PowerAvailable),
    ] {
        let control = spawned.unique(tag);
        ui.commands.entity(control).insert((
            Text::new(""),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
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
) -> Entity {
    let root = bind_city_dialog_root(commands, spawned, nation, slot);
    let name_control = spawned.unique(fourcc!("name"));
    commands
        .entity(name_control)
        .insert(Text::new(building_name));
    bind_city_order_controls(
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
    root
}

pub(in crate::ui::city) fn bind_food_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    building_name: String,
) {
    let root = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        CityFacilitySlot::FoodProcessing,
        building_name,
        &FOOD_ORDERS,
        2,
    );
    for (tag, value) in [
        (fourcc!("labV"), CityValue::LaborIndicator),
        (
            fourcc!("grai"),
            CityValue::AvailableStockIndicator(ResourceKind::Grain, 2),
        ),
        (
            fourcc!("prod"),
            CityValue::AvailableStockIndicator(ResourceKind::Fruit, 1),
        ),
        (
            fourcc!("fish"),
            CityValue::AvailableCombinedStockIndicator(
                ResourceKind::Fish,
                ResourceKind::Livestock,
                1,
            ),
        ),
    ] {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert((
            Text::new("X"),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
        ));
    }
}

pub(in crate::ui::city) fn bind_power_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    building_name: String,
) {
    bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        CityFacilitySlot::PowerPlant,
        building_name,
        &POWER_ORDERS,
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
    nation: MajorNationId,
    building_name: String,
) {
    let root = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        CityFacilitySlot::Transport,
        building_name,
        &TRANSPORT_CAPACITY_ORDERS,
        1,
    );
    for (tag, value) in [
        (fourcc!("labV"), CityValue::LaborIndicator),
        (
            fourcc!("lumb"),
            CityValue::StockIndicator(ResourceKind::Lumber, 1),
        ),
        (
            fourcc!("stee"),
            CityValue::StockIndicator(ResourceKind::Steel, 1),
        ),
    ] {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert((
            Text::new("X"),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
        ));
    }
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
    let root = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        CityFacilitySlot::RegionalPopulation,
        building_name,
        &POPULATION_ORDERS,
        1,
    );
    for (tag, value) in [
        (
            fourcc!("food"),
            CityValue::AvailableStockIndicator(ResourceKind::Food, 1),
        ),
        (
            fourcc!("clot"),
            CityValue::AvailableStockIndicator(ResourceKind::Clothing, 1),
        ),
        (
            fourcc!("furn"),
            CityValue::AvailableStockIndicator(ResourceKind::Furniture, 1),
        ),
        (fourcc!("capT"), CityValue::RegionalCapacity),
        (fourcc!("prov"), CityValue::OwnedRegionCount),
    ] {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert((
            Text::new(""),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
        ));
    }
    let capacity = spawned.unique(fourcc!("capT"));
    commands
        .entity(capacity)
        .insert(RetailNumberTemplate(capacity_template));
    let provinces = spawned.unique(fourcc!("prov"));
    commands
        .entity(provinces)
        .insert(RetailNumberTemplate(province_template));
}
