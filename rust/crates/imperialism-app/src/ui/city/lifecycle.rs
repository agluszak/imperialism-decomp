use super::*;

pub(in crate::ui::city) const CITY_DIALOG_CAPTION_HEIGHT: f32 = 18.0;
pub(in crate::ui::city) const CITY_DIALOG_CLOSE_SIZE: f32 = 14.0;

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn on_city_canvas_click(
    click: On<Pointer<Click>>,
    canvases: Query<(&RelativeCursorPosition, &CityCanvas)>,
    dialogs: Query<(Entity, &CityBuildingDialog, &GlobalZIndex)>,
    screen_roots: Query<Entity, With<CityScreenRoot>>,
    modal_dialogs: Query<(), With<ModalDialog>>,
    session: Option<ResMut<GameSession>>,
    catalog: Res<UiCatalogResource>,
    mut ui: UiSpawner,
) {
    if !modal_dialogs.is_empty() {
        return;
    }
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
    let mut session = session.expect("city canvas activated without an authoritative game session");
    let Some(nation) = MajorNationId::from_nation(session.0.turn().active_nation) else {
        return;
    };
    if dialogs
        .iter()
        .any(|(_, dialog, _)| dialog.nation == nation && dialog.slot == building.slot)
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
            open_city_construction_dialog(&mut ui, &mut session, nation, building.slot);
            for (entity, _, _) in &dialogs {
                ui.commands.entity(entity).insert(CityDialogNeedsSync);
            }
            for root in &screen_roots {
                ui.commands.entity(root).insert(CityScreenNeedsSync);
            }
            return;
        }
    }
    let z_index = dialogs.iter().map(|(_, _, z)| z.0).max().unwrap_or(0) + 1;
    assert!(z_index < 20, "modeless City dialogs remain below modals");
    open_city_dialog(
        &mut ui,
        &catalog,
        &session.0,
        nation,
        building.slot,
        building.dialog.clone(),
        None,
        z_index,
    );
}

pub(in crate::ui::city) fn supports_city_dialog(slot: CityFacilitySlot) -> bool {
    industry_page(slot).is_some()
        || matches!(
            slot,
            CityFacilitySlot::TradeSchool
                | CityFacilitySlot::Armory
                | CityFacilitySlot::University
                | CityFacilitySlot::Shipyard
                | CityFacilitySlot::Warehouse
                | CityFacilitySlot::FoodProcessing
                | CityFacilitySlot::PowerPlant
                | CityFacilitySlot::Transport
                | CityFacilitySlot::RegionalPopulation
        )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn open_city_dialog(
    ui: &mut UiSpawner,
    catalog: &UiCatalogResource,
    state: &GameState,
    nation: MajorNationId,
    slot: CityFacilitySlot,
    view_id: ScopedViewId,
    saved_position: Option<IVec2>,
    z_index: i32,
) {
    if !supports_city_dialog(slot) {
        return;
    }
    let bar_color = ui.palette_color(0x16);
    let building_name = city_string(ui, CITY_BUILDING_STRING_GROUP, slot as i16);
    let capacity_template = city_string(ui, CITY_TEXT_STRING_GROUP, 0x10);
    let province_template = city_string(ui, CITY_TEXT_STRING_GROUP, 0x1d);
    let armory_title = (slot == CityFacilitySlot::Armory).then(|| {
        ui.string(0x271c, 0x20)
            .expect("validated English retail Armory title")
    });
    let university_data = (slot == CityFacilitySlot::University).then(|| {
        let (detail_font, _, _) = ui
            .text_style(RetailTextStylePreset {
                font_family: 3,
                face_flags: 0,
                point_size: 10,
                alignment: -2,
            })
            .expect("retail University detail text style");
        let (title_font, _, _) = ui
            .text_style(RetailTextStylePreset {
                font_family: 3,
                face_flags: 0,
                point_size: 24,
                alignment: 1,
            })
            .expect("retail University title fallback text style");
        let (unit_font, _, _) = ui
            .text_style(RetailTextStylePreset {
                font_family: 3,
                face_flags: 0,
                point_size: 12,
                alignment: 1,
            })
            .expect("retail University unit-name fallback text style");
        UniversityDialogData {
            available: state.technology().city_capabilities_by_nation[nation]
                .university
                .available,
            rows: UNIVERSITY_ORDERS.map(|binding| {
                let CityOrderId::CivilianRecruit(kind) = binding.order else {
                    unreachable!("University binding has a civilian recruitment order");
                };
                UniversityRowText {
                    unit_name: ui
                        .string(0x2718, i16::from(kind as u8) + 1)
                        .expect("validated English retail civilian name"),
                    description: ui
                        .string(0x2751, i16::from(kind as u8))
                        .expect("validated English retail civilian description"),
                    preview: transparent_picture(
                        ui,
                        PictureId::new(university_preview_picture(kind)),
                    ),
                }
            }),
            resource_icons: transparent_picture(ui, PictureId::new(750)),
            tier_labels: std::array::from_fn(|level| {
                ui.string(0x2723, 0x0e + level as i16)
                    .expect("validated English retail University tier label")
            }),
            title_font,
            unit_font,
            detail_font,
            normal_color: ui.palette_color(0xd2),
            warning_color: ui.palette_color(0xcb),
        }
    });
    let shipyard_data = (slot == CityFacilitySlot::Shipyard).then(|| {
        let city = &state.nations().major(nation).city;
        let material_pictures = SHIPYARD_MATERIALS
            .map(|resource| transparent_picture(ui, PictureId::new(700 + resource as i16)));
        let (detail_font, _, _) = ui
            .text_style(RetailTextStylePreset {
                font_family: 3,
                face_flags: 0,
                point_size: 10,
                alignment: -2,
            })
            .expect("retail Shipyard detail text style");
        let (title_font, _, _) = ui
            .text_style(RetailTextStylePreset {
                font_family: 1,
                face_flags: 0,
                point_size: 24,
                alignment: 1,
            })
            .expect("retail Shipyard title text style");
        let (name_font, _, _) = ui
            .text_style(RetailTextStylePreset {
                font_family: 1,
                face_flags: 0,
                point_size: 12,
                alignment: 1,
            })
            .expect("retail Shipyard name text style");
        ShipyardDialogData {
            rows: SHIP_ORDERS.map(|binding| {
                let CityOrderId::Ship(slot) = binding.order else {
                    unreachable!("Shipyard binding has a ship order");
                };
                let ship_type = city.orders.ships[slot].ship_type;
                if ship_type == ShipType::NoShip {
                    return None;
                }
                let costs = ship_order_costs(ship_type);
                Some(ShipyardRowData {
                    ship_type,
                    ship_name: ui
                        .string(0x2716, ship_type as i16 + 1)
                        .expect("validated English retail ship name"),
                    description: ui
                        .string(0x2752, ship_type as i16)
                        .expect("validated English retail ship description"),
                    picture: ui
                        .picture(PictureId::new(9834 + ship_type as i16))
                        .expect("validated retail Shipyard detail picture"),
                    materials: SHIPYARD_MATERIALS
                        .iter()
                        .zip(&material_pictures)
                        .filter_map(|(&resource, picture)| {
                            let required = costs[resource];
                            (required != 0).then(|| ShipyardMaterialData {
                                resource,
                                required,
                                picture: picture.clone(),
                            })
                        })
                        .collect(),
                    stats: ship_display_stats(ship_type),
                })
            }),
            queue_icons: transparent_picture(ui, PictureId::new(9807)),
            stat_labels: std::array::from_fn(|index| city_string(ui, 0x2736, 0x10 + index as i16)),
            title_font,
            name_font,
            detail_font,
            normal_color: ui.palette_color(0xd2),
            warning_color: ui.palette_color(0xcb),
        }
    });
    let spawned = ui.spawn(view_id);
    if let Some(page) = industry_page(slot) {
        bind_industry_dialog(
            &mut ui.commands,
            catalog,
            &spawned,
            nation,
            page,
            building_name,
            capacity_template,
            bar_color,
        );
    } else {
        match slot {
            CityFacilitySlot::TradeSchool => {
                bind_training_dialog(&mut ui.commands, catalog, &spawned, nation, building_name)
            }
            CityFacilitySlot::Armory => bind_armory_dialog(
                &mut ui.commands,
                catalog,
                &spawned,
                nation,
                armory_title.expect("Armory branch has its retail title"),
            ),
            CityFacilitySlot::University => bind_university_dialog(
                &mut ui.commands,
                catalog,
                &spawned,
                nation,
                university_data.expect("University branch has retail text and technology"),
            ),
            CityFacilitySlot::Shipyard => bind_shipyard_dialog(
                &mut ui.commands,
                catalog,
                &spawned,
                nation,
                shipyard_data.expect("Shipyard branch has retail ship data"),
            ),
            CityFacilitySlot::Warehouse => bind_warehouse_dialog(
                ui,
                &spawned,
                nation,
                building_name,
                state.technology().oil_drilling_available(),
            ),
            CityFacilitySlot::FoodProcessing => {
                bind_food_dialog(&mut ui.commands, catalog, &spawned, nation, building_name)
            }
            CityFacilitySlot::PowerPlant => {
                bind_power_dialog(&mut ui.commands, catalog, &spawned, nation, building_name)
            }
            CityFacilitySlot::Transport => bind_transport_capacity_dialog(
                &mut ui.commands,
                catalog,
                &spawned,
                nation,
                building_name,
            ),
            CityFacilitySlot::RegionalPopulation => bind_population_dialog(
                &mut ui.commands,
                catalog,
                &spawned,
                nation,
                building_name,
                capacity_template,
                province_template,
            ),
            _ => unreachable!("supported ordinary city dialog handled above"),
        }
    }
    if let Some(position) = saved_position {
        let window = spawned
            .require_unique(fourcc!("WIND"))
            .expect("validated city window binding");
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
        .insert(GlobalZIndex(z_index));
}

pub(in crate::ui::city) fn bind_city_dialog_root(
    commands: &mut Commands,
    spawned: &SpawnedView,
    nation: MajorNationId,
    slot: CityFacilitySlot,
) -> Entity {
    let root = spawned.root;
    let window = spawned
        .require_unique(fourcc!("WIND"))
        .expect("validated city window binding");
    commands.entity(root).insert((
        CityBuildingDialog {
            nation,
            slot,
            window,
        },
        CityDialogNeedsSync,
        GlobalZIndex(19),
        Pickable::IGNORE,
    ));
    commands
        .entity(window)
        .insert((CityDialogWindow { dialog: root }, Pickable::default()));
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
            CityDialogCaption { window },
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
                CityDialogClose { dialog: root },
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
    roots: Query<Entity, With<CityDialogsNeedRestore>>,
    session: Option<Res<GameSession>>,
    catalog: Res<UiCatalogResource>,
    dialogs: Query<(&CityBuildingDialog, &GlobalZIndex)>,
    mut ui: UiSpawner,
) {
    if roots.is_empty() {
        return;
    }
    let Some(session) = session else {
        for root in &roots {
            ui.commands.entity(root).remove::<CityDialogsNeedRestore>();
        }
        return;
    };
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City screen requires an active major nation");
    let buildings = catalog
        .view(&city_view_id())
        .expect("validated City screen catalog view")
        .city_buildings
        .clone();
    let city = &session.0.nations().major(nation).city;
    let mut next_z = dialogs.iter().map(|(_, z)| z.0).max().unwrap_or(0) + 1;
    for building in buildings {
        if !supports_city_dialog(building.slot) {
            continue;
        }
        if dialogs
            .iter()
            .any(|(dialog, _)| dialog.nation == nation && dialog.slot == building.slot)
        {
            continue;
        }
        let state = city.building_window_state(building.slot);
        if state.flag == 0 {
            continue;
        }
        open_city_dialog(
            &mut ui,
            &catalog,
            &session.0,
            nation,
            building.slot,
            building.dialog,
            Some(IVec2::new(
                i32::from(state.current),
                i32::from(state.accumulated),
            )),
            next_z,
        );
        next_z += 1;
    }
    assert!(next_z <= 20, "modeless City dialogs remain below modals");
    for root in &roots {
        ui.commands.entity(root).remove::<CityDialogsNeedRestore>();
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

pub(in crate::ui::city) fn saved_window_coordinate(value: f32) -> i16 {
    i16::try_from(value.round() as i32).expect("City window coordinate fits retail short storage")
}

pub(in crate::ui::city) fn leave_city_screen(
    mut commands: Commands,
    mut session: Option<ResMut<GameSession>>,
    catalog: Res<UiCatalogResource>,
    dialogs: Query<(Entity, &CityBuildingDialog)>,
    windows: Query<&Node, With<CityDialogWindow>>,
) {
    if let Some(session) = session.as_mut() {
        let nation = MajorNationId::from_nation(session.0.turn().active_nation)
            .expect("City screen requires an active major nation");
        let slots = catalog
            .view(&city_view_id())
            .expect("validated City screen catalog view")
            .city_buildings
            .iter()
            .map(|building| building.slot)
            .filter(|slot| supports_city_dialog(*slot))
            .collect::<Vec<_>>();
        for slot in slots {
            let open = dialogs
                .iter()
                .find(|(_, dialog)| dialog.nation == nation && dialog.slot == slot);
            let state = if let Some((_, dialog)) = open {
                let (left, top) = node_position(
                    windows
                        .get(dialog.window)
                        .expect("open City dialog has its generated window"),
                );
                BuildingWindowState {
                    flag: 1,
                    current: saved_window_coordinate(left),
                    accumulated: saved_window_coordinate(top),
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
                .set_city_building_window_state(nation, slot, state);
        }
    }
    for (root, _) in &dialogs {
        commands.entity(root).despawn();
    }
}

pub(in crate::ui::city) fn on_city_dialog_pressed(
    press: On<Pointer<Press>>,
    windows: Query<&CityDialogWindow>,
    parents: Query<&ChildOf>,
    mut dialogs: Query<(Entity, &mut GlobalZIndex), With<CityBuildingDialog>>,
    modals: Query<(), With<ModalDialog>>,
) {
    if press.event.button != PointerButton::Primary || !modals.is_empty() {
        return;
    }
    let mut target = press.original_event_target();
    let dialog = loop {
        if let Ok(window) = windows.get(target) {
            break window.dialog;
        }
        let Ok(parent) = parents.get(target) else {
            return;
        };
        target = parent.parent();
    };
    if dialogs.get(dialog).is_err() {
        return;
    }
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
    captions: Query<&CityDialogCaption>,
    mut windows: Query<&mut Node, With<CityDialogWindow>>,
    modals: Query<(), With<ModalDialog>>,
) {
    if drag.event.button != PointerButton::Primary || !modals.is_empty() {
        return;
    }
    let Ok(caption) = captions.get(drag.entity) else {
        return;
    };
    let mut node = windows
        .get_mut(caption.window)
        .expect("City dialog caption owns its generated window");
    let (left, top) = node_position(&node);
    node.left = px(left + drag.event.delta.x);
    node.top = px(top + drag.event.delta.y);
}

pub(in crate::ui::city) fn on_city_dialog_close(
    activate: On<Activate>,
    closes: Query<&CityDialogClose>,
    modals: Query<(), With<ModalDialog>>,
    mut commands: Commands,
) {
    if !modals.is_empty() {
        return;
    }
    let Ok(close) = closes.get(activate.entity) else {
        return;
    };
    commands.entity(close.dialog).despawn();
}
