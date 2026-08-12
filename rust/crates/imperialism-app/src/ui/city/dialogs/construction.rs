use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct CityExpansionOpen {
    pub(in crate::ui::city) slot: CityFacilitySlot,
}

#[derive(Component)]
pub(in crate::ui::city) struct CityBuildingChangeChoice {
    pub(in crate::ui::city) slot: CityFacilitySlot,
    pub(in crate::ui::city) accept: bool,
}

pub(in crate::ui::city) fn construction_dialog_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "Citydlog.rsrc".to_owned(),
        resource_id: 9220,
    }
}

pub(in crate::ui::city) fn expansion_dialog_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "Citydlog.rsrc".to_owned(),
        resource_id: 9221,
    }
}

pub(in crate::ui::city) fn open_city_construction_dialog(
    ui: &mut UiSpawner,
    session: &mut GameSession,
    slot: CityFacilitySlot,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City screen requires an active major nation");
    let (capacity_value, can_reserve) = match slot {
        CityFacilitySlot::PowerPlant => {
            session.0.set_power_plant_upgrade(nation, false);
            let major = session.0.nations().major(nation);
            let can_reserve = major
                .economy
                .available_diplomacy_budget(major.common.treasury)
                >= 5_000;
            (city_string(ui, CITY_TEXT_STRING_GROUP, 0x15), can_reserve)
        }
        _ => {
            let (next_capacity, needed) = {
                let major = session.0.nations().major(nation);
                let city = &major.city;
                let owned_regions = major.common.owned_region_count() as i32;
                let current = city.building_type(slot, &major.economy, owned_regions);
                let next_capacity = city.max_building_capacity(slot, &major.economy, owned_regions);
                (next_capacity, next_capacity - current)
            };
            let order = CityOrderId::Expansion(
                ExpandableFacility::try_from_slot(slot)
                    .expect("ordinary capacity center is expandable"),
            );
            let can_reserve = session.0.can_set_city_order_quantity(nation, order, needed);
            (next_capacity.to_string(), can_reserve)
        }
    };
    let spawned = ui.spawn_modal(construction_dialog_view_id());
    bind_construction_dialog(ui, &spawned, slot, &capacity_value, can_reserve);
}

pub(in crate::ui::city) fn bind_construction_dialog(
    ui: &mut UiSpawner,
    spawned: &SpawnedView,
    slot: CityFacilitySlot,
    capacity_value: &str,
    can_reserve: bool,
) {
    ui.commands
        .entity(spawned.root)
        .insert(DespawnOnExit(AppState::City));

    let picture = PictureId::new(9250 + i16::from(slot as u8) * 5);
    match ui.picture(picture) {
        Ok(handle) => {
            let dialog = spawned.unique(fourcc!("DLOG"));
            ui.commands.entity(dialog).insert(ImageNode::new(handle));
        }
        Err(error) => warn!("could not load construction-dialog picture {picture}: {error}"),
    }

    let capacity = format_retail_value(
        &city_string(ui, CITY_TEXT_STRING_GROUP, 0x10),
        capacity_value,
    );
    let text_group = 0x2422 + i16::from(slot as u8);
    let text = [
        (
            fourcc!("tex1"),
            ui.string(text_group, 1)
                .expect("retail English construction headline"),
        ),
        (
            fourcc!("name"),
            city_string(ui, CITY_BUILDING_STRING_GROUP, slot as i16),
        ),
        (fourcc!("capT"), capacity),
        (
            fourcc!("cost"),
            city_string(ui, CITY_TEXT_STRING_GROUP, 0x14),
        ),
    ];
    for (tag, value) in text {
        let entity = spawned.unique(tag);
        ui.commands.entity(entity).insert(Text::new(value));
    }

    let text2 = spawned.unique(fourcc!("tex2"));
    if slot == CityFacilitySlot::PowerPlant {
        ui.commands
            .entity(text2)
            .entry::<Node>()
            .and_modify(|mut node| {
                let Val::Px(top) = node.top else {
                    panic!("catalog construction detail has fixed retail coordinates");
                };
                node.top = px(top + 5.0);
            });
    }

    let connective = spawned.unique(fourcc!("or  "));
    let connective_left = match slot {
        CityFacilitySlot::TextileMill => Some(0x98),
        CityFacilitySlot::Metalworks => Some(0xcd),
        CityFacilitySlot::LumberMill => Some(0xd0),
        _ => None,
    };
    if let Some(left) = connective_left {
        let connective_text = city_string(ui, CITY_TEXT_STRING_GROUP, 0x11);
        let mut connective_commands = ui.commands.entity(connective);
        connective_commands.insert((Text::new(connective_text), Visibility::Visible));
        connective_commands
            .entry::<Node>()
            .and_modify(move |mut node| node.left = px(left as f32));
    } else {
        ui.commands.entity(connective).insert(Visibility::Hidden);
    }

    let buck = spawned.unique(fourcc!("buck"));
    ui.commands.entity(buck).insert((
        Text::new(if slot == CityFacilitySlot::PowerPlant {
            format_currency(5_000)
        } else {
            String::new()
        }),
        if slot == CityFacilitySlot::PowerPlant {
            Visibility::Visible
        } else {
            Visibility::Hidden
        },
    ));

    let warning = spawned.unique(fourcc!("warn"));
    let warning_text = city_string(
        ui,
        CITY_TEXT_STRING_GROUP,
        if slot == CityFacilitySlot::PowerPlant {
            0x16
        } else {
            0x17
        },
    );
    let warning_color = ui.palette_color(0xcb);
    ui.commands.entity(warning).insert((
        Text::new(warning_text),
        TextColor(warning_color),
        if can_reserve {
            Visibility::Hidden
        } else {
            Visibility::Visible
        },
    ));

    let okay = spawned.unique(fourcc!("okay"));
    let mut okay_commands = ui.commands.entity(okay);
    okay_commands.insert(CityBuildingChangeChoice { slot, accept: true });
    if !can_reserve {
        okay_commands.insert((InteractionDisabled, Visibility::Hidden));
    }

    let cancel = spawned.unique(fourcc!("cncl"));
    ui.commands.entity(cancel).insert(CityBuildingChangeChoice {
        slot,
        accept: false,
    });
}

pub(in crate::ui::city) fn bind_expansion_dialog(
    ui: &mut UiSpawner,
    spawned: &SpawnedView,
    slot: CityFacilitySlot,
    building_name: String,
    next_capacity: i16,
    next_level: u8,
    can_reserve: bool,
) {
    ui.commands
        .entity(spawned.root)
        .insert(DespawnOnExit(AppState::City));

    let picture = PictureId::new(9250 + i16::from(slot as u8) * 5 + i16::from(next_level));
    match ui.picture(picture) {
        Ok(handle) => {
            let dialog = spawned.unique(fourcc!("DLOG"));
            ui.commands.entity(dialog).insert(ImageNode::new(handle));
        }
        Err(error) => warn!("could not load expansion-dialog picture {picture}: {error}"),
    }

    let capacity = format_retail_number(
        &city_string(ui, CITY_TEXT_STRING_GROUP, 0x10),
        next_capacity,
    );
    let cost = city_string(ui, CITY_TEXT_STRING_GROUP, 0x14);
    for (tag, text) in [
        (fourcc!("name"), building_name),
        (fourcc!("capT"), capacity),
        (fourcc!("cost"), cost),
    ] {
        let entity = spawned.unique(tag);
        ui.commands.entity(entity).insert(Text::new(text));
    }

    let warning = spawned.unique(fourcc!("warn"));
    let warning_color = ui.palette_color(0xcb);
    let warning_text = city_string(ui, CITY_TEXT_STRING_GROUP, 0x17);
    ui.commands.entity(warning).insert((
        Text::new(warning_text),
        TextColor(warning_color),
        if can_reserve {
            Visibility::Hidden
        } else {
            Visibility::Visible
        },
    ));

    let okay = spawned.unique(fourcc!("okay"));
    let mut okay_commands = ui.commands.entity(okay);
    okay_commands.insert(CityBuildingChangeChoice { slot, accept: true });
    if !can_reserve {
        okay_commands.insert((InteractionDisabled, Visibility::Hidden));
    }

    let cancel = spawned.unique(fourcc!("cncl"));
    ui.commands.entity(cancel).insert(CityBuildingChangeChoice {
        slot,
        accept: false,
    });
}

pub(in crate::ui::city) fn on_city_expansion_open(
    activate: On<Activate>,
    openers: Query<&CityExpansionOpen>,
    session: Res<GameSession>,
    mut ui: UiSpawner,
) {
    let Ok(open) = openers.get(activate.entity) else {
        return;
    };
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City screen requires an active major nation");
    let (next_capacity, needed, next_level) = {
        let major = session.0.nations().major(nation);
        let city = &major.city;
        let owned_regions = major.common.owned_region_count() as i32;
        let current = city.building_type(open.slot, &major.economy, owned_regions);
        let next_capacity = city.max_building_capacity(open.slot, &major.economy, owned_regions);
        (
            next_capacity,
            next_capacity - current,
            city.next_building_level(open.slot, &major.economy, owned_regions),
        )
    };
    let order = CityOrderId::Expansion(
        ExpandableFacility::try_from_slot(open.slot).expect("ordinary industry is expandable"),
    );
    let can_reserve = session.0.can_set_city_order_quantity(nation, order, needed);
    let spawned = ui.spawn_modal(expansion_dialog_view_id());
    let building_name = city_string(&ui, CITY_BUILDING_STRING_GROUP, open.slot as i16);
    bind_expansion_dialog(
        &mut ui,
        &spawned,
        open.slot,
        building_name,
        next_capacity,
        next_level,
        can_reserve,
    );
}

pub(in crate::ui::city) fn on_city_building_change_choice(
    activate: On<Activate>,
    choices: Query<&CityBuildingChangeChoice>,
    parents: Query<&ChildOf>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
    let Ok(choice) = choices.get(activate.entity) else {
        return;
    };
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City screen requires an active major nation");
    if choice.slot == CityFacilitySlot::PowerPlant {
        if choice.accept {
            session.0.set_power_plant_upgrade(nation, true);
        }
    } else {
        let order = CityOrderId::Expansion(
            ExpandableFacility::try_from_slot(choice.slot)
                .expect("ordinary industry is expandable"),
        );
        let quantity = if choice.accept {
            let major = session.0.nations().major(nation);
            let city = &major.city;
            let owned_regions = major.common.owned_region_count() as i32;
            city.max_building_capacity(choice.slot, &major.economy, owned_regions)
                - city.building_type(choice.slot, &major.economy, owned_regions)
        } else {
            0
        };
        let _ = session.0.set_city_order_quantity(nation, order, quantity);
    }

    let mut dialog = activate.entity;
    while let Ok(parent) = parents.get(dialog) {
        dialog = parent.parent();
    }
    commands.entity(dialog).despawn();
}
