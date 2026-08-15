use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct CityBuildingDialog {
    pub(in crate::ui::city) slot: CityFacilitySlot,
    saved_position: Option<IVec2>,
}

#[derive(Component)]
pub(in crate::ui::city) struct CityDialogWindow(CityFacilitySlot);

#[derive(Component)]
pub(in crate::ui::city) struct CityDialogCaption;

#[derive(Component)]
pub(in crate::ui::city) struct CityDialogClose;

pub(in crate::ui::city) const CITY_DIALOG_CAPTION_HEIGHT: f32 = 18.0;
pub(in crate::ui::city) const CITY_DIALOG_CLOSE_SIZE: f32 = 14.0;

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn on_city_canvas_click(
    click: On<Pointer<Click>>,
    canvases: Query<(&RelativeCursorPosition, &CityCanvas)>,
    dialogs: Query<(&CityBuildingDialog, &GlobalZIndex)>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
    mut assets: RetailUiAssets,
) {
    let Ok((cursor, canvas)) = canvases.get(click.entity) else {
        return;
    };
    let Some(normalized) = cursor.normalized.filter(|_| cursor.cursor_over()) else {
        return;
    };
    let point = IVec2::new(
        ((normalized.x + 0.5) * CITY_WIDTH).floor() as i32,
        ((normalized.y + 0.5) * CITY_HEIGHT).floor() as i32,
    );
    let Some(building) = canvas
        .buildings
        .iter()
        .rev()
        .find(|building| building.mask.contains(point - building.origin))
    else {
        return;
    };
    let nation = session.active_major_nation();
    if dialogs
        .iter()
        .any(|(dialog, _)| dialog.slot == building.slot)
    {
        return;
    }
    match city_building_click(&session.game, nation, building.slot) {
        Some(CityBuildingClick::Construction) => {
            open_city_construction_dialog(&mut commands, &mut assets, &mut session, building.slot);
        }
        Some(CityBuildingClick::Production) => {
            let z_index = dialogs.iter().map(|(_, z)| z.0).max().unwrap_or(0) + 1;
            open_city_dialog(&mut commands, building.slot, None, z_index);
        }
        None => {}
    }
}

pub(in crate::ui::city) fn open_city_dialog(
    commands: &mut Commands,
    slot: CityFacilitySlot,
    saved_position: Option<IVec2>,
    z_index: i32,
) {
    let root = match slot {
        CityFacilitySlot::TextileMill => commands.spawn_scene(generated::citydlog_9200()).id(),
        CityFacilitySlot::ClothingFactory => commands.spawn_scene(generated::citydlog_9201()).id(),
        CityFacilitySlot::SteelMill => commands.spawn_scene(generated::citydlog_9202()).id(),
        CityFacilitySlot::Metalworks => commands.spawn_scene(generated::citydlog_9203()).id(),
        CityFacilitySlot::LumberMill => commands.spawn_scene(generated::citydlog_9204()).id(),
        CityFacilitySlot::FurnitureFactory => commands.spawn_scene(generated::citydlog_9205()).id(),
        CityFacilitySlot::OilRefinery => commands.spawn_scene(generated::citydlog_9206()).id(),
        CityFacilitySlot::Shipyard => commands.spawn_scene(generated::shipyard_9207()).id(),
        CityFacilitySlot::Armory => commands.spawn_scene(generated::armory_9208()).id(),
        CityFacilitySlot::TradeSchool => commands.spawn_scene(generated::citydlog_9209()).id(),
        CityFacilitySlot::University => commands.spawn_scene(generated::univ_9210()).id(),
        CityFacilitySlot::PowerPlant => commands.spawn_scene(generated::citydlog_9211()).id(),
        CityFacilitySlot::FoodProcessing => commands.spawn_scene(generated::citydlog_9212()).id(),
        CityFacilitySlot::Warehouse => commands.spawn_scene(generated::citydlog_9213()).id(),
        CityFacilitySlot::Transport => commands.spawn_scene(generated::citydlog_9214()).id(),
        CityFacilitySlot::RegionalPopulation => {
            commands.spawn_scene(generated::citydlog_9215()).id()
        }
    };
    commands.entity(root).insert((
        CityBuildingDialog {
            slot,
            saved_position,
        },
        GlobalZIndex(z_index),
        Pickable::IGNORE,
        DespawnOnExit(AppState::City),
    ));
}

pub(in crate::ui::city) fn bind_city_dialog_root(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    slot: CityFacilitySlot,
) {
    let window = tree.find(root, fourcc!("WIND"));
    commands
        .entity(window)
        .insert((Pickable::default(), CityDialogWindow(slot)));
    commands.entity(window).with_children(|parent| {
        parent
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0),
                    top: px(-CITY_DIALOG_CAPTION_HEIGHT),
                    width: percent(100),
                    height: px(CITY_DIALOG_CAPTION_HEIGHT),
                    ..default()
                },
                BackgroundColor(Color::srgb_u8(0, 0, 128)),
                CityDialogCaption,
                Pickable::default(),
                Name::new("city-dialog-caption"),
            ))
            .observe(on_city_dialog_dragged);
        parent
            .spawn((
                UiButton,
                Node {
                    position_type: PositionType::Absolute,
                    right: px(2),
                    top: px(-CITY_DIALOG_CAPTION_HEIGHT + 2.0),
                    width: px(CITY_DIALOG_CLOSE_SIZE),
                    height: px(CITY_DIALOG_CLOSE_SIZE),
                    align_items: AlignItems::Center,
                    justify_content: JustifyContent::Center,
                    ..default()
                },
                BackgroundColor(Color::srgb_u8(192, 192, 192)),
                CityDialogClose,
                ZIndex(1),
                Name::new("city-dialog-close"),
            ))
            .observe(on_city_dialog_close)
            .with_child((
                Text::new("×"),
                TextFont {
                    font_size: FontSize::Px(12.0),
                    ..default()
                },
                TextColor(Color::BLACK),
                Pickable::IGNORE,
            ));
    });
}

pub(in crate::ui::city) fn bind_city_dialogs(
    mut commands: Commands,
    dialogs: Query<(Entity, &CityBuildingDialog), Added<CityBuildingDialog>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    for (root, dialog) in &dialogs {
        let window = tree.find(root, fourcc!("WIND"));
        if let Some(position) = dialog.saved_position {
            commands
                .entity(window)
                .entry::<Node>()
                .and_modify(move |mut node| {
                    node.left = px(position.x as f32);
                    node.top = px(position.y as f32);
                });
        }
        match city_dialog_kind(dialog.slot) {
            CityDialogKind::Industry(page) => {
                configure_industry_dialog(&mut commands, &mut assets, root, &tree, page);
            }
            CityDialogKind::Training => {
                configure_training_dialog(&mut commands, &assets, root, &tree)
            }
            CityDialogKind::Armory => {
                configure_armory_dialog(&mut commands, &mut assets, root, &tree, &session.game)
            }
            CityDialogKind::University => {
                configure_university_dialog(&mut commands, &mut assets, root, &tree, &session.game)
            }
            CityDialogKind::Shipyard => {
                configure_shipyard_dialog(&mut commands, &mut assets, root, &tree, &session.game)
            }
            CityDialogKind::Warehouse => {
                configure_warehouse_dialog(&mut commands, &mut assets, root, &tree, &session.game)
            }
            CityDialogKind::FoodProcessing => {
                configure_food_dialog(&mut commands, &mut assets, root, &tree)
            }
            CityDialogKind::PowerPlant => {
                configure_power_dialog(&mut commands, &mut assets, root, &tree)
            }
            CityDialogKind::Transport => {
                configure_transport_capacity_dialog(&mut commands, &mut assets, root, &tree)
            }
            CityDialogKind::Population => {
                configure_population_dialog(&mut commands, &mut assets, root, &tree)
            }
        }
    }
}

pub(in crate::ui::city) fn restore_city_dialogs(
    roots: Query<(), Added<CityScreenRoot>>,
    session: Res<GameSession>,
    mut commands: Commands,
) {
    if roots.is_empty() {
        return;
    }
    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    let mut next_z = 1;
    for slot in (0..enum_map::enum_len::<CityFacilitySlot>()).map(CityFacilitySlot::from_usize) {
        let state = city.building_windows[slot];
        let Some(position) = state else {
            continue;
        };
        open_city_dialog(
            &mut commands,
            slot,
            Some(IVec2::new(
                i32::from(position.left),
                i32::from(position.top),
            )),
            next_z,
        );
        next_z += 1;
    }
}

pub(in crate::ui::city) fn node_position(node: &Node) -> (f32, f32) {
    let Val::Px(left) = node.left else {
        panic!("generated City window has a non-pixel left position");
    };
    let Val::Px(top) = node.top else {
        panic!("generated City window has a non-pixel top position");
    };
    (left, top)
}

pub(in crate::ui::city) fn leave_city_screen(
    mut session: ResMut<GameSession>,
    windows: Query<(&CityDialogWindow, &Node)>,
) {
    let nation = session.active_major_nation();
    let mut positions = ProductionTable::default();
    for (window, node) in &windows {
        let (left, top) = node_position(node);
        positions[window.0] = Some(CityWindowPosition {
            left: i16::try_from(left.round() as i32)
                .expect("City window coordinate fits retail short storage"),
            top: i16::try_from(top.round() as i32)
                .expect("City window coordinate fits retail short storage"),
        });
    }
    session.game.set_city_building_windows(nation, positions);
}

pub(in crate::ui::city) fn on_city_dialog_pressed(
    press: On<Pointer<Press>>,
    parents: Query<&ChildOf>,
    mut dialogs: Query<(Entity, &mut GlobalZIndex), With<CityBuildingDialog>>,
) {
    if press.event.button != PointerButton::Primary {
        return;
    }
    let mut target = press.original_event_target();
    let dialog = loop {
        if dialogs.contains(target) {
            break target;
        }
        let Ok(parent) = parents.get(target) else {
            return;
        };
        target = parent.parent();
    };
    let mut order = dialogs
        .iter()
        .map(|(entity, z)| (entity, z.0))
        .collect::<Vec<_>>();
    order.sort_by_key(|(entity, z)| (*entity == dialog, *z, entity.to_bits()));
    for (index, (entity, _)) in order.into_iter().enumerate() {
        dialogs
            .get_mut(entity)
            .expect("City dialog remained present while raising it")
            .1
            .0 = i32::try_from(index + 1).expect("City dialog count fits z order");
    }
}

pub(in crate::ui::city) fn on_city_dialog_dragged(
    drag: On<Pointer<Drag>>,
    parents: Query<&ChildOf>,
    mut windows: Query<&mut Node>,
) {
    if drag.event.button != PointerButton::Primary {
        return;
    }
    let mut node = windows
        .get_mut(
            parents
                .get(drag.entity)
                .expect("City dialog caption belongs to its generated window")
                .parent(),
        )
        .expect("City dialog caption owns its generated window");
    let (left, top) = node_position(&node);
    node.left = px(left + drag.event.delta.x);
    node.top = px(top + drag.event.delta.y);
}

pub(in crate::ui::city) fn on_city_dialog_close(
    activate: On<Activate>,
    parents: Query<&ChildOf>,
    dialogs: Query<(), With<CityBuildingDialog>>,
    mut commands: Commands,
) {
    let mut entity = activate.entity;
    loop {
        if dialogs.contains(entity) {
            commands.entity(entity).despawn();
            return;
        }
        entity = parents
            .get(entity)
            .expect("City close button belongs to its dialog")
            .parent();
    }
}
