use super::*;

#[derive(Component)]
pub(in crate::ui::city) enum BuildingChangeDialog {
    Construction {
        slot: CityFacilitySlot,
        capacity: String,
        can_reserve: bool,
    },
    Expansion {
        slot: CityFacilitySlot,
        next_capacity: i16,
        next_level: u8,
        can_reserve: bool,
    },
}

pub(in crate::ui::city) fn open_city_construction_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    session: &mut GameSession,
    slot: CityFacilitySlot,
) {
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("City screen requires an active major nation");
    let (capacity, can_reserve) = match slot {
        CityFacilitySlot::PowerPlant => {
            session.game.set_power_plant_upgrade(nation, false);
            let major = session.game.nations().major(nation);
            let can_reserve = major
                .economy
                .available_diplomacy_budget(major.common.treasury)
                >= 5_000;
            (city_text(assets, 0x15), can_reserve)
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
    let (modal, _window) = spawn_modal_window(commands, generated::citydlog_9220());
    commands.entity(modal).insert((
        BuildingChangeDialog::Construction {
            slot,
            capacity,
            can_reserve,
        },
        DespawnOnExit(AppState::City),
    ));
}

pub(in crate::ui::city) fn open_city_expansion_dialog(
    commands: &mut Commands,
    session: &GameSession,
    slot: CityFacilitySlot,
) {
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("City screen requires an active major nation");
    let (next_capacity, needed, next_level) = {
        let major = session.game.nations().major(nation);
        let city = &major.city;
        let owned_regions = major.common.owned_region_count();
        let current = city.building_type(slot, &major.economy, owned_regions);
        let next_capacity = city.max_building_capacity(slot, &major.economy, owned_regions);
        (
            next_capacity,
            next_capacity - current,
            city.next_building_level(slot, &major.economy, owned_regions),
        )
    };
    let order = CityOrderId::Expansion(
        ExpandableFacility::try_from_slot(slot).expect("ordinary industry is expandable"),
    );
    let can_reserve = needed <= session.game.city_order_limit(nation, order).maximum;
    let (modal, _window) = spawn_modal_window(commands, generated::citydlog_9221());
    commands.entity(modal).insert((
        BuildingChangeDialog::Expansion {
            slot,
            next_capacity,
            next_level,
            can_reserve,
        },
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

fn apply_building_change(session: &mut GameSession, slot: CityFacilitySlot, accept: bool) {
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("City screen requires an active major nation");
    if slot == CityFacilitySlot::PowerPlant {
        if accept {
            session.game.set_power_plant_upgrade(nation, true);
        }
    } else {
        let order = CityOrderId::Expansion(
            ExpandableFacility::try_from_slot(slot).expect("ordinary industry is expandable"),
        );
        let quantity = if accept {
            let major = session.game.nations().major(nation);
            let city = &major.city;
            let owned_regions = major.common.owned_region_count();
            city.max_building_capacity(slot, &major.economy, owned_regions)
                - city.building_type(slot, &major.economy, owned_regions)
        } else {
            0
        };
        session
            .game
            .set_city_order_quantity(nation, order, quantity);
    }
}

fn bind_building_change_common(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
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
    commands
        .entity(tree.find(root, fourcc!("DLOG")))
        .insert(ImageNode::new(assets.picture(picture)));
    for (tag, text) in [
        (fourcc!("name"), name),
        (fourcc!("capT"), capacity),
        (fourcc!("cost"), cost),
    ] {
        let entity = tree.find(root, tag);
        commands.entity(entity).insert(Text::new(text));
    }
    let warning = tree.find(root, fourcc!("warn"));
    commands.entity(warning).insert((
        Text::new(warning_text),
        TextColor(warning_color),
        if can_reserve {
            Visibility::Hidden
        } else {
            Visibility::Visible
        },
    ));
    let okay = tree.find(root, fourcc!("okay"));
    let cancel = tree.find(root, fourcc!("cncl"));
    for (button, accept) in [(okay, true), (cancel, false)] {
        commands.entity(button).observe(
            move |_: On<Activate>, mut session: ResMut<GameSession>| {
                apply_building_change(&mut session, slot, accept);
            },
        );
    }
    if !can_reserve {
        commands
            .entity(okay)
            .insert((InteractionDisabled, Visibility::Hidden));
    }
    dismiss_on_activate(commands, okay, root);
    dismiss_on_activate(commands, cancel, root);
    bind_modal_keys(commands, root, Some(okay), Some(cancel));
}

fn bind_construction_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    slot: CityFacilitySlot,
    capacity_value: &str,
    can_reserve: bool,
) {
    let capacity = fill_brackets(&city_text(assets, 0x10), &[capacity_value]);
    let headline = assets.string(slot.construction_headline_string());
    commands
        .entity(tree.find(root, fourcc!("tex1")))
        .insert(Text::new(headline));

    if slot == CityFacilitySlot::PowerPlant {
        commands
            .entity(tree.find(root, fourcc!("tex2")))
            .entry::<Node>()
            .and_modify(|mut node| {
                let Val::Px(top) = node.top else {
                    panic!("fixed construction coords");
                };
                node.top = px(top + 5.0);
            });
    }

    let connective = tree.find(root, fourcc!("or  "));
    let connective_left = match slot {
        CityFacilitySlot::TextileMill => Some(0x98),
        CityFacilitySlot::Metalworks => Some(0xcd),
        CityFacilitySlot::LumberMill => Some(0xd0),
        _ => None,
    };
    if let Some(left) = connective_left {
        let connective_text = city_text(assets, 0x11);
        let mut connective_commands = commands.entity(connective);
        connective_commands.insert((Text::new(connective_text), Visibility::Visible));
        connective_commands
            .entry::<Node>()
            .and_modify(move |mut node| node.left = px(left as f32));
    } else {
        commands.entity(connective).insert(Visibility::Hidden);
    }

    let buck = tree.find(root, fourcc!("buck"));
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
        tree,
        BuildingChangePresentation {
            slot,
            picture: slot.construction_picture(0),
            name: assets.string(slot.name_string()),
            capacity,
            cost: city_text(assets, 0x14),
            warning_text: city_text(
                assets,
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

fn bind_expansion_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    slot: CityFacilitySlot,
    next_capacity: i16,
    next_level: u8,
    can_reserve: bool,
) {
    bind_building_change_common(
        commands,
        assets,
        root,
        tree,
        BuildingChangePresentation {
            slot,
            picture: slot.construction_picture(next_level),
            name: assets.string(slot.name_string()),
            capacity: format_retail_number(&city_text(assets, 0x10), next_capacity),
            cost: city_text(assets, 0x14),
            warning_text: city_text(assets, 0x17),
            warning_color: assets.palette_color(0xcb),
            can_reserve,
        },
    );
}

pub(in crate::ui::city) fn bind_building_change_dialogs(
    mut commands: Commands,
    dialogs: Query<(Entity, &BuildingChangeDialog), Added<BuildingChangeDialog>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
) {
    for (root, dialog) in &dialogs {
        match dialog {
            BuildingChangeDialog::Construction {
                slot,
                capacity,
                can_reserve,
            } => bind_construction_dialog(
                &mut commands,
                &mut assets,
                root,
                &tree,
                *slot,
                capacity,
                *can_reserve,
            ),
            BuildingChangeDialog::Expansion {
                slot,
                next_capacity,
                next_level,
                can_reserve,
            } => bind_expansion_dialog(
                &mut commands,
                &mut assets,
                root,
                &tree,
                *slot,
                *next_capacity,
                *next_level,
                *can_reserve,
            ),
        }
    }
}
