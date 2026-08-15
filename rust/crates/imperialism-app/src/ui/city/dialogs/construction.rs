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

#[derive(Component)]
pub(in crate::ui::city) struct ConstructionDialog {
    slot: CityFacilitySlot,
    capacity_value: String,
    can_reserve: bool,
}

#[derive(Component)]
pub(in crate::ui::city) struct ExpansionDialog {
    slot: CityFacilitySlot,
    building_name: String,
    next_capacity: i16,
    next_level: u8,
    can_reserve: bool,
}

pub(in crate::ui::city) fn open_city_construction_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    session: &mut GameSession,
    slot: CityFacilitySlot,
) {
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("City screen requires an active major nation");
    let (capacity_value, can_reserve) = match slot {
        CityFacilitySlot::PowerPlant => {
            session.game.set_power_plant_upgrade(nation, false);
            let major = session.game.nations().major(nation);
            let can_reserve = major
                .economy
                .available_diplomacy_budget(major.common.treasury)
                >= 5_000;
            (
                city_string(assets, CITY_TEXT_STRING_GROUP, 0x15),
                can_reserve,
            )
        }
        _ => {
            let (next_capacity, needed) = {
                let major = session.game.nations().major(nation);
                let city = &major.city;
                let owned_regions = major.common.owned_region_count();
                let current = city.building_type(slot, &major.economy, owned_regions);
                let next_capacity = city.max_building_capacity(slot, &major.economy, owned_regions);
                (next_capacity, next_capacity - current)
            };
            let order = CityOrderId::Expansion(
                ExpandableFacility::try_from_slot(slot)
                    .expect("ordinary capacity center is expandable"),
            );
            let can_reserve = needed <= session.game.city_order_limit(nation, order).maximum;
            (next_capacity.to_string(), can_reserve)
        }
    };
    let root = commands.spawn_scene(generated::citydlog_9220()).id();
    commands.entity(root).insert((
        ConstructionDialog {
            slot,
            capacity_value,
            can_reserve,
        },
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        Pickable::default(),
        DespawnOnExit(AppState::City),
    ));
}

struct BuildingChangePresentation {
    slot: CityFacilitySlot,
    picture: PictureId,
    name: String,
    capacity: String,
    cost: String,
    warning_text: String,
    warning_color: Color,
    can_reserve: bool,
}

fn bind_building_change_common(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    presentation: BuildingChangePresentation,
) {
    let BuildingChangePresentation {
        slot,
        picture,
        name,
        capacity,
        cost,
        warning_text,
        warning_color,
        can_reserve,
    } = presentation;
    match assets.picture(picture) {
        Ok(handle) => {
            let dialog = find_descendant(root, fourcc!("DLOG"), children, tags);
            commands.entity(dialog).insert(ImageNode::new(handle));
        }
        Err(error) => warn!("could not load building-change picture {picture}: {error}"),
    }
    for (tag, text) in [
        (fourcc!("name"), name),
        (fourcc!("capT"), capacity),
        (fourcc!("cost"), cost),
    ] {
        let entity = find_descendant(root, tag, children, tags);
        commands.entity(entity).insert(Text::new(text));
    }
    let warning = find_descendant(root, fourcc!("warn"), children, tags);
    commands.entity(warning).insert((
        Text::new(warning_text),
        TextColor(warning_color),
        if can_reserve {
            Visibility::Hidden
        } else {
            Visibility::Visible
        },
    ));
    let okay = find_descendant(root, fourcc!("okay"), children, tags);
    let mut okay_commands = commands.entity(okay);
    okay_commands.insert(CityBuildingChangeChoice { slot, accept: true });
    if !can_reserve {
        okay_commands.insert((InteractionDisabled, Visibility::Hidden));
    }
    let cancel = find_descendant(root, fourcc!("cncl"), children, tags);
    commands.entity(cancel).insert(CityBuildingChangeChoice {
        slot,
        accept: false,
    });
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn bind_construction_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    slot: CityFacilitySlot,
    capacity_value: &str,
    can_reserve: bool,
) {
    let capacity = format_retail_value(
        &city_string(assets, CITY_TEXT_STRING_GROUP, 0x10),
        capacity_value,
    );
    let headline = assets
        .string(0x2422 + i16::from(slot as u8), 1)
        .expect("retail English construction headline");
    let tex1 = find_descendant(root, fourcc!("tex1"), children, tags);
    commands.entity(tex1).insert(Text::new(headline));

    let text2 = find_descendant(root, fourcc!("tex2"), children, tags);
    if slot == CityFacilitySlot::PowerPlant {
        commands
            .entity(text2)
            .entry::<Node>()
            .and_modify(|mut node| {
                let Val::Px(top) = node.top else {
                    panic!("generated construction detail has fixed retail coordinates");
                };
                node.top = px(top + 5.0);
            });
    }

    let connective = find_descendant(root, fourcc!("or  "), children, tags);
    let connective_left = match slot {
        CityFacilitySlot::TextileMill => Some(0x98),
        CityFacilitySlot::Metalworks => Some(0xcd),
        CityFacilitySlot::LumberMill => Some(0xd0),
        _ => None,
    };
    if let Some(left) = connective_left {
        let connective_text = city_string(assets, CITY_TEXT_STRING_GROUP, 0x11);
        let mut connective_commands = commands.entity(connective);
        connective_commands.insert((Text::new(connective_text), Visibility::Visible));
        connective_commands
            .entry::<Node>()
            .and_modify(move |mut node| node.left = px(left as f32));
    } else {
        commands.entity(connective).insert(Visibility::Hidden);
    }

    let buck = find_descendant(root, fourcc!("buck"), children, tags);
    commands.entity(buck).insert((
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

    bind_building_change_common(
        commands,
        assets,
        root,
        children,
        tags,
        BuildingChangePresentation {
            slot,
            picture: PictureId::new(9250 + i16::from(slot as u8) * 5),
            name: city_string(assets, CITY_BUILDING_STRING_GROUP, slot as i16),
            capacity,
            cost: city_string(assets, CITY_TEXT_STRING_GROUP, 0x14),
            warning_text: city_string(
                assets,
                CITY_TEXT_STRING_GROUP,
                if slot == CityFacilitySlot::PowerPlant {
                    0x16
                } else {
                    0x17
                },
            ),
            warning_color: assets.palette_color(0xcb),
            can_reserve,
        },
    );
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn bind_expansion_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    slot: CityFacilitySlot,
    building_name: String,
    next_capacity: i16,
    next_level: u8,
    can_reserve: bool,
) {
    bind_building_change_common(
        commands,
        assets,
        root,
        children,
        tags,
        BuildingChangePresentation {
            slot,
            picture: PictureId::new(9250 + i16::from(slot as u8) * 5 + i16::from(next_level)),
            name: building_name,
            capacity: format_retail_number(
                &city_string(assets, CITY_TEXT_STRING_GROUP, 0x10),
                next_capacity,
            ),
            cost: city_string(assets, CITY_TEXT_STRING_GROUP, 0x14),
            warning_text: city_string(assets, CITY_TEXT_STRING_GROUP, 0x17),
            warning_color: assets.palette_color(0xcb),
            can_reserve,
        },
    );
}

pub(in crate::ui::city) fn on_city_expansion_open(
    activate: On<Activate>,
    openers: Query<&CityExpansionOpen>,
    session: Res<GameSession>,
    mut commands: Commands,
    assets: RetailUiAssets,
) {
    let Ok(open) = openers.get(activate.entity) else {
        return;
    };
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("City screen requires an active major nation");
    let (next_capacity, needed, next_level) = {
        let major = session.game.nations().major(nation);
        let city = &major.city;
        let owned_regions = major.common.owned_region_count();
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
    let can_reserve = needed <= session.game.city_order_limit(nation, order).maximum;
    let root = commands.spawn_scene(generated::citydlog_9221()).id();
    let building_name = city_string(&assets, CITY_BUILDING_STRING_GROUP, open.slot as i16);
    commands.entity(root).insert((
        ExpansionDialog {
            slot: open.slot,
            building_name,
            next_capacity,
            next_level,
            can_reserve,
        },
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        Pickable::default(),
        DespawnOnExit(AppState::City),
    ));
}

pub(in crate::ui::city) fn bind_building_change_dialogs(
    mut commands: Commands,
    constructions: Query<(Entity, &ConstructionDialog), Added<ConstructionDialog>>,
    expansions: Query<(Entity, &ExpansionDialog), Added<ExpansionDialog>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
) {
    for (root, dialog) in &constructions {
        bind_construction_dialog(
            &mut commands,
            &mut assets,
            root,
            &children,
            &tags,
            dialog.slot,
            &dialog.capacity_value,
            dialog.can_reserve,
        );
    }
    for (root, dialog) in &expansions {
        bind_expansion_dialog(
            &mut commands,
            &mut assets,
            root,
            &children,
            &tags,
            dialog.slot,
            dialog.building_name.clone(),
            dialog.next_capacity,
            dialog.next_level,
            dialog.can_reserve,
        );
    }
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
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("City screen requires an active major nation");
    if choice.slot == CityFacilitySlot::PowerPlant {
        if choice.accept {
            session.game.set_power_plant_upgrade(nation, true);
        }
    } else {
        let order = CityOrderId::Expansion(
            ExpandableFacility::try_from_slot(choice.slot)
                .expect("ordinary industry is expandable"),
        );
        let quantity = if choice.accept {
            let major = session.game.nations().major(nation);
            let city = &major.city;
            let owned_regions = major.common.owned_region_count();
            city.max_building_capacity(choice.slot, &major.economy, owned_regions)
                - city.building_type(choice.slot, &major.economy, owned_regions)
        } else {
            0
        };
        session
            .game
            .set_city_order_quantity(nation, order, quantity);
    }

    let mut dialog = activate.entity;
    while let Ok(parent) = parents.get(dialog) {
        dialog = parent.parent();
    }
    commands.entity(dialog).despawn();
}
