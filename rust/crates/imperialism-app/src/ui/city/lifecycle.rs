use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct CityBuildingDialog {
    pub(in crate::ui::city) slot: CityFacilitySlot,
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn on_city_canvas_click(
    click: On<Pointer<Click>>,
    canvases: Query<(&RelativeCursorPosition, &CityCanvas)>,
    dialogs: Query<&CityBuildingDialog>,
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
    if dialogs.iter().any(|dialog| dialog.slot == building.slot) {
        return;
    }
    match city_building_click(&session.game, nation, building.slot) {
        Some(CityBuildingClick::Construction) => {
            open_city_construction_dialog(&mut commands, &mut assets, &mut session, building.slot);
        }
        Some(CityBuildingClick::Production) => {
            open_city_dialog(&mut commands, building.slot, None);
        }
        None => {}
    }
}

pub(in crate::ui::city) fn open_city_dialog(
    commands: &mut Commands,
    slot: CityFacilitySlot,
    saved_position: Option<IVec2>,
) {
    let root = generated::spawn_city_dialog(commands, slot);
    commands.entity(root).insert((
        CityBuildingDialog { slot },
        FloatingWindow,
        DespawnOnExit(AppState::City),
    ));
    if let Some(position) = saved_position {
        commands.entity(root).insert(WindowPosition(position));
    }
}

pub(in crate::ui::city) fn bind_city_dialogs(
    mut commands: Commands,
    dialogs: Query<(Entity, &CityBuildingDialog), Added<CityBuildingDialog>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    for (root, dialog) in &dialogs {
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
    windows: Res<CityWindows>,
    mut commands: Commands,
) {
    if roots.is_empty() {
        return;
    }
    let nation = session.active_major_nation();
    for slot in (0..enum_map::enum_len::<CityFacilitySlot>()).map(CityFacilitySlot::from_usize) {
        let state = windows.0[nation][slot];
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
        );
    }
}

pub(in crate::ui::city) fn leave_city_screen(
    session: Res<GameSession>,
    mut windows: ResMut<CityWindows>,
    dialogs: Query<(&CityBuildingDialog, &WindowPosition)>,
) {
    let nation = session.active_major_nation();
    let mut positions = ProductionTable::default();
    for (window, position) in &dialogs {
        positions[window.slot] = Some(CityWindowPosition {
            left: i16::try_from(position.0.x)
                .expect("City window coordinate fits retail short storage"),
            top: i16::try_from(position.0.y)
                .expect("City window coordinate fits retail short storage"),
        });
    }
    windows.0[nation] = positions;
}
