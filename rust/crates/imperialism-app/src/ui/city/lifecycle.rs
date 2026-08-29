use super::*;
use crate::ui::retail::AmountBarParts;

#[derive(Component)]
pub(in crate::ui::city) struct CityBuildingDialog {
    pub(in crate::ui::city) slot: CityFacilitySlot,
    saved_position: Option<IVec2>,
}

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
    let root = spawn_city_dialog(commands, slot);
    commands.entity(root).insert((
        CityBuildingDialog {
            slot,
            saved_position,
        },
        DespawnOnExit(AppState::City),
    ));
}

pub(in crate::ui::city) fn bind_city_dialogs(
    mut commands: Commands,
    dialogs: Query<(Entity, &CityBuildingDialog), Added<CityBuildingDialog>>,
    tree: RetailTree,
    amount_bars: Query<&AmountBarParts>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    for (root, dialog) in &dialogs {
        if let Some(position) = dialog.saved_position {
            commands
                .entity(root)
                .entry::<Node>()
                .and_modify(move |mut node| set_window_position(&mut node, position));
        }

        let view = if ExpandableFacility::try_from_slot(dialog.slot).is_some() {
            CityDialogView::Industry(bind_industry(
                &mut commands,
                &mut assets,
                root,
                &tree,
                &amount_bars,
                dialog.slot,
            ))
        } else {
            match dialog.slot {
                CityFacilitySlot::TradeSchool => CityDialogView::Training(bind_training(
                    &mut commands,
                    &assets,
                    root,
                    &tree,
                    &amount_bars,
                )),
                CityFacilitySlot::Armory => CityDialogView::Armory(bind_armory(
                    &mut commands,
                    &mut assets,
                    root,
                    &tree,
                    &session.game,
                )),
                CityFacilitySlot::University => CityDialogView::University(bind_university(
                    &mut commands,
                    &mut assets,
                    root,
                    &tree,
                    &session.game,
                )),
                CityFacilitySlot::Shipyard => CityDialogView::Shipyard(bind_shipyard(
                    &mut commands,
                    &mut assets,
                    root,
                    &tree,
                    &session.game,
                )),
                CityFacilitySlot::Warehouse => CityDialogView::Warehouse(bind_warehouse(
                    &mut commands,
                    &mut assets,
                    root,
                    &tree,
                    &session.game,
                )),
                CityFacilitySlot::FoodProcessing => CityDialogView::Food(bind_food(
                    &mut commands,
                    &mut assets,
                    root,
                    &tree,
                    &amount_bars,
                )),
                CityFacilitySlot::PowerPlant => CityDialogView::Power(bind_power(
                    &mut commands,
                    &mut assets,
                    root,
                    &tree,
                    &amount_bars,
                )),
                CityFacilitySlot::Transport => CityDialogView::Transport(bind_transport(
                    &mut commands,
                    &mut assets,
                    root,
                    &tree,
                    &amount_bars,
                )),
                CityFacilitySlot::RegionalPopulation => CityDialogView::Population(
                    bind_population(&mut commands, &mut assets, root, &tree, &amount_bars),
                ),
                _ => unreachable!("ordinary industry is classified by ExpandableFacility"),
            }
        };
        commands.entity(root).insert(view);
    }
}

pub(in crate::ui::city) fn restore_city_dialogs(
    roots: Query<(), Added<CityScreenView>>,
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
    dialogs: Query<(&CityBuildingDialog, &Node), With<CaptionedWindow>>,
) {
    let nation = session.active_major_nation();
    let mut positions = ProductionTable::default();
    for (dialog, node) in &dialogs {
        let position = window_position(node);
        positions[dialog.slot] = Some(CityWindowPosition {
            left: i16::try_from(position.x).expect("window x"),
            top: i16::try_from(position.y).expect("window y"),
        });
    }
    windows.0[nation] = positions;
}
