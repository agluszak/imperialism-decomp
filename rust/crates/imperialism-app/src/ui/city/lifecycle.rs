use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct CityBuildingDialog {
    pub(in crate::ui::city) slot: CityFacilitySlot,
}

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
    catalog: Res<UiCatalogResource>,
    mut ui: UiSpawner,
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
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City screen requires an active major nation");
    if dialogs
        .iter()
        .any(|(dialog, _)| dialog.slot == building.slot)
    {
        return;
    }
    let unbuilt_capacity_center = {
        let major = session.0.nations().major(nation);
        CityState::is_capacity_center(building.slot)
            && major.city.building_type(
                building.slot,
                &major.economy,
                major.common.owned_region_count() as i32,
            ) == 0
    };
    if unbuilt_capacity_center {
        let available = !matches!(
            building.slot,
            CityFacilitySlot::OilRefinery | CityFacilitySlot::PowerPlant
        ) || session.0.technology().city_capabilities_by_nation[nation]
            .oil_drilling;
        if available {
            open_city_construction_dialog(&mut ui, &mut session, building.slot);
            return;
        }
    }
    let z_index = dialogs.iter().map(|(_, z)| z.0).max().unwrap_or(0) + 1;
    open_city_dialog(
        &mut ui,
        &catalog,
        &session.0,
        building.slot,
        building.dialog.clone(),
        None,
        z_index,
    );
}

pub(in crate::ui::city) fn open_city_dialog(
    ui: &mut UiSpawner,
    catalog: &UiCatalogResource,
    state: &GameState,
    slot: CityFacilitySlot,
    view_id: ScopedViewId,
    saved_position: Option<IVec2>,
    z_index: i32,
) {
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("City screen requires an active major nation");
    let building_name = city_string(ui, CITY_BUILDING_STRING_GROUP, slot as i16);
    let capacity_template = city_string(ui, CITY_TEXT_STRING_GROUP, 0x10);
    let province_template = city_string(ui, CITY_TEXT_STRING_GROUP, 0x1d);
    let spawned = ui.spawn(view_id);
    if let Some(page) = industry_page(slot) {
        let bar_color = ui.palette_color(0x16);
        bind_industry_dialog(
            &mut ui.commands,
            catalog,
            &spawned,
            page,
            building_name,
            capacity_template,
            bar_color,
        );
    } else {
        match slot {
            CityFacilitySlot::TradeSchool => {
                bind_training_dialog(&mut ui.commands, catalog, &spawned, building_name)
            }
            CityFacilitySlot::Armory => {
                let title = ui
                    .string(0x271c, 0x20)
                    .expect("retail English Armory title");
                bind_armory_dialog(&mut ui.commands, catalog, &spawned, title);
            }
            CityFacilitySlot::University => {
                let data = university_dialog_data(ui, state, nation);
                bind_university_dialog(&mut ui.commands, catalog, &spawned, data);
            }
            CityFacilitySlot::Shipyard => {
                bind_shipyard_dialog(ui, catalog, &spawned, state, nation)
            }
            CityFacilitySlot::Warehouse => bind_warehouse_dialog(
                ui,
                &spawned,
                building_name,
                state.technology().oil_drilling_available(),
            ),
            CityFacilitySlot::FoodProcessing => {
                bind_food_dialog(&mut ui.commands, catalog, &spawned, building_name)
            }
            CityFacilitySlot::PowerPlant => {
                bind_power_dialog(&mut ui.commands, catalog, &spawned, building_name)
            }
            CityFacilitySlot::Transport => {
                bind_transport_capacity_dialog(&mut ui.commands, catalog, &spawned, building_name)
            }
            CityFacilitySlot::RegionalPopulation => bind_population_dialog(
                &mut ui.commands,
                catalog,
                &spawned,
                building_name,
                capacity_template,
                province_template,
            ),
            _ => unreachable!("catalog City building has no dialog binder"),
        }
    }
    if let Some(position) = saved_position {
        let window = spawned.unique(fourcc!("WIND"));
        ui.commands
            .entity(window)
            .entry::<Node>()
            .and_modify(move |mut node| {
                node.left = px(position.x as f32);
                node.top = px(position.y as f32);
            });
    }
    ui.commands
        .entity(spawned.root)
        .insert((GlobalZIndex(z_index), spawned));
}

pub(in crate::ui::city) fn bind_city_dialog_root(
    commands: &mut Commands,
    spawned: &SpawnedView,
    slot: CityFacilitySlot,
) -> Entity {
    let root = spawned.root;
    let window = spawned.unique(fourcc!("WIND"));
    commands
        .entity(root)
        .insert((CityBuildingDialog { slot }, Pickable::IGNORE));
    commands.entity(window).insert(Pickable::default());
    commands.entity(window).with_children(|parent| {
        parent.spawn((
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
        ));
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
    root
}

pub(in crate::ui::city) fn restore_city_dialogs(
    roots: Query<(), Added<CityScreenRoot>>,
    session: Res<GameSession>,
    catalog: Res<UiCatalogResource>,
    mut ui: UiSpawner,
) {
    if roots.is_empty() {
        return;
    }
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City screen requires an active major nation");
    let city = &session.0.nations().major(nation).city;
    let mut next_z = 1;
    for building in &catalog.required_view(&city_view_id()).city_buildings {
        let state = city.building_window_state(building.slot);
        if state.flag == 0 {
            continue;
        }
        open_city_dialog(
            &mut ui,
            &catalog,
            &session.0,
            building.slot,
            building.dialog.clone(),
            Some(IVec2::new(
                i32::from(state.current),
                i32::from(state.accumulated),
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
    mut commands: Commands,
    mut session: ResMut<GameSession>,
    catalog: Res<UiCatalogResource>,
    dialogs: Query<(Entity, &CityBuildingDialog, &SpawnedView)>,
    windows: Query<&Node>,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City screen requires an active major nation");
    for building in &catalog.required_view(&city_view_id()).city_buildings {
        let open = dialogs
            .iter()
            .find(|(_, dialog, _)| dialog.slot == building.slot);
        let state = if let Some((_, _, spawned)) = open {
            let (left, top) = node_position(
                windows
                    .get(spawned.unique(fourcc!("WIND")))
                    .expect("open City dialog has its generated window"),
            );
            BuildingWindowState {
                flag: 1,
                current: i16::try_from(left.round() as i32)
                    .expect("City window coordinate fits retail short storage"),
                accumulated: i16::try_from(top.round() as i32)
                    .expect("City window coordinate fits retail short storage"),
            }
        } else {
            BuildingWindowState {
                flag: 0,
                current: 0,
                accumulated: 0,
            }
        };
        session
            .0
            .set_city_building_window_state(nation, building.slot, state);
    }
    for (root, _, _) in &dialogs {
        commands.entity(root).despawn();
    }
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
    captions: Query<(), With<CityDialogCaption>>,
    parents: Query<&ChildOf>,
    mut windows: Query<&mut Node>,
) {
    if drag.event.button != PointerButton::Primary {
        return;
    }
    if captions.get(drag.entity).is_err() {
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
    closes: Query<(), With<CityDialogClose>>,
    parents: Query<&ChildOf>,
    dialogs: Query<(), With<CityBuildingDialog>>,
    mut commands: Commands,
) {
    if closes.get(activate.entity).is_err() {
        return;
    }
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
