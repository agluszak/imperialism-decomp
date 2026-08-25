use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct CityBuildingDialog {
    pub(in crate::ui::city) slot: CityFacilitySlot,
    saved_position: Option<IVec2>,
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
        CityBuildingDialog {
            slot,
            saved_position,
        },
        DespawnOnExit(AppState::City),
    ));
}

fn restore_city_dialog_window(
    commands: &mut Commands,
    window: Entity,
    saved_position: Option<IVec2>,
) {
    if let Some(position) = saved_position {
        commands
            .entity(window)
            .entry::<Node>()
            .and_modify(move |mut node| set_window_position(&mut node, position));
    }
}

pub(in crate::ui::city) fn bind_city_dialogs(
    mut commands: Commands,
    dialogs: Query<(&CityBuildingDialog, EntityRef), Added<CityBuildingDialog>>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    for (dialog, entity) in &dialogs {
        match city_dialog_kind(dialog.slot) {
            CityDialogKind::Industry(CityFacilitySlot::TextileMill) => {
                let ui = entity
                    .get::<generated::Citydlog9200>()
                    .expect("textile mill dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                let orders = [IndustryOrderControls {
                    order: CityOrderId::Item(ManufacturedItem::Fabric),
                    row: ui.fabr,
                    decrease: ui.left,
                    increase: ui.rght,
                    quantity: ui.move_,
                    bar: ui.bar,
                }];
                let stocks = [
                    (ResourceKind::Cotton, ui.cott, 1),
                    (ResourceKind::Wool, ui.wool, 1),
                ];
                configure_industry_dialog(
                    &mut commands,
                    &mut assets,
                    IndustryDialogControls {
                        slot: dialog.slot,
                        name: ui.name,
                        capacity: ui.capt,
                        labor: ui.labv,
                        expansion: ui.expa,
                        flag: ui.flag,
                        orders: &orders,
                        stocks: &stocks,
                    },
                );
            }
            CityDialogKind::Industry(CityFacilitySlot::ClothingFactory) => {
                let ui = entity
                    .get::<generated::Citydlog9201>()
                    .expect("clothing factory dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                let orders = [IndustryOrderControls {
                    order: CityOrderId::Item(ManufacturedItem::Clothing),
                    row: ui.clot,
                    decrease: ui.left,
                    increase: ui.rght,
                    quantity: ui.move_,
                    bar: ui.bar,
                }];
                let stocks = [(ResourceKind::Fabric, ui.fabr, 2)];
                configure_industry_dialog(
                    &mut commands,
                    &mut assets,
                    IndustryDialogControls {
                        slot: dialog.slot,
                        name: ui.name,
                        capacity: ui.capt,
                        labor: ui.labv,
                        expansion: ui.expa,
                        flag: ui.flag,
                        orders: &orders,
                        stocks: &stocks,
                    },
                );
            }
            CityDialogKind::Industry(CityFacilitySlot::SteelMill) => {
                let ui = entity
                    .get::<generated::Citydlog9202>()
                    .expect("steel mill dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                let orders = [IndustryOrderControls {
                    order: CityOrderId::Item(ManufacturedItem::Steel),
                    row: ui.stee,
                    decrease: ui.left,
                    increase: ui.rght,
                    quantity: ui.move_,
                    bar: ui.bar,
                }];
                let stocks = [
                    (ResourceKind::Coal, ui.coal, 1),
                    (ResourceKind::Iron, ui.iron, 1),
                ];
                configure_industry_dialog(
                    &mut commands,
                    &mut assets,
                    IndustryDialogControls {
                        slot: dialog.slot,
                        name: ui.name,
                        capacity: ui.capt,
                        labor: ui.labv,
                        expansion: ui.expa,
                        flag: ui.flag,
                        orders: &orders,
                        stocks: &stocks,
                    },
                );
            }
            CityDialogKind::Industry(CityFacilitySlot::Metalworks) => {
                let ui = entity
                    .get::<generated::Citydlog9203>()
                    .expect("metalworks dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                let orders = [
                    IndustryOrderControls {
                        order: CityOrderId::Item(ManufacturedItem::Hardware),
                        row: ui.hard,
                        decrease: ui.hard_left,
                        increase: ui.hard_rght,
                        quantity: ui.hard_move_,
                        bar: ui.hard_bar,
                    },
                    IndustryOrderControls {
                        order: CityOrderId::Item(ManufacturedItem::Arms),
                        row: ui.arma,
                        decrease: ui.arma_left,
                        increase: ui.arma_rght,
                        quantity: ui.arma_move_,
                        bar: ui.arma_bar,
                    },
                ];
                let stocks = [(ResourceKind::Steel, ui.stee, 2)];
                configure_industry_dialog(
                    &mut commands,
                    &mut assets,
                    IndustryDialogControls {
                        slot: dialog.slot,
                        name: ui.name,
                        capacity: ui.capt,
                        labor: ui.labv,
                        expansion: ui.expa,
                        flag: ui.flag,
                        orders: &orders,
                        stocks: &stocks,
                    },
                );
            }
            CityDialogKind::Industry(CityFacilitySlot::LumberMill) => {
                let ui = entity
                    .get::<generated::Citydlog9204>()
                    .expect("lumber mill dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                let orders = [
                    IndustryOrderControls {
                        order: CityOrderId::Item(ManufacturedItem::Lumber),
                        row: ui.lumb,
                        decrease: ui.lumb_left,
                        increase: ui.lumb_rght,
                        quantity: ui.lumb_move_,
                        bar: ui.lumb_bar,
                    },
                    IndustryOrderControls {
                        order: CityOrderId::Item(ManufacturedItem::Paper),
                        row: ui.pape,
                        decrease: ui.pape_left,
                        increase: ui.pape_rght,
                        quantity: ui.pape_move_,
                        bar: ui.pape_bar,
                    },
                ];
                let stocks = [(ResourceKind::Timber, ui.timb, 2)];
                configure_industry_dialog(
                    &mut commands,
                    &mut assets,
                    IndustryDialogControls {
                        slot: dialog.slot,
                        name: ui.name,
                        capacity: ui.capt,
                        labor: ui.labv,
                        expansion: ui.expa,
                        flag: ui.flag,
                        orders: &orders,
                        stocks: &stocks,
                    },
                );
            }
            CityDialogKind::Industry(CityFacilitySlot::FurnitureFactory) => {
                let ui = entity
                    .get::<generated::Citydlog9205>()
                    .expect("furniture factory dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                let orders = [IndustryOrderControls {
                    order: CityOrderId::Item(ManufacturedItem::Furniture),
                    row: ui.furn,
                    decrease: ui.left,
                    increase: ui.rght,
                    quantity: ui.move_,
                    bar: ui.bar,
                }];
                let stocks = [(ResourceKind::Lumber, ui.lumb, 2)];
                configure_industry_dialog(
                    &mut commands,
                    &mut assets,
                    IndustryDialogControls {
                        slot: dialog.slot,
                        name: ui.name,
                        capacity: ui.capt,
                        labor: ui.labv,
                        expansion: ui.expa,
                        flag: ui.flag,
                        orders: &orders,
                        stocks: &stocks,
                    },
                );
            }
            CityDialogKind::Industry(CityFacilitySlot::OilRefinery) => {
                let ui = entity
                    .get::<generated::Citydlog9206>()
                    .expect("oil refinery dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                let orders = [IndustryOrderControls {
                    order: CityOrderId::Item(ManufacturedItem::Fuel),
                    row: ui.fuel,
                    decrease: ui.left,
                    increase: ui.rght,
                    quantity: ui.move_,
                    bar: ui.bar,
                }];
                let stocks = [(ResourceKind::Oil, ui.oil, 2)];
                configure_industry_dialog(
                    &mut commands,
                    &mut assets,
                    IndustryDialogControls {
                        slot: dialog.slot,
                        name: ui.name,
                        capacity: ui.capt,
                        labor: ui.labv,
                        expansion: ui.expa,
                        flag: ui.flag,
                        orders: &orders,
                        stocks: &stocks,
                    },
                );
            }
            CityDialogKind::Industry(_) => {
                unreachable!("industry dialog slots are enumerated above")
            }
            CityDialogKind::Training => {
                let ui = entity
                    .get::<generated::Citydlog9209>()
                    .expect("training dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                configure_training_dialog(&mut commands, &assets, ui);
            }
            CityDialogKind::Armory => {
                let ui = entity
                    .get::<generated::Armory9208>()
                    .expect("armory dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                configure_armory_dialog(&mut commands, &mut assets, ui, &session.game);
            }
            CityDialogKind::University => {
                let ui = entity
                    .get::<generated::Univ9210>()
                    .expect("university dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                configure_university_dialog(&mut commands, &mut assets, ui, &session.game);
            }
            CityDialogKind::Shipyard => {
                let ui = entity
                    .get::<generated::Shipyard9207>()
                    .expect("shipyard dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                configure_shipyard_dialog(&mut commands, &mut assets, ui, &session.game);
            }
            CityDialogKind::Warehouse => {
                let ui = entity
                    .get::<generated::Citydlog9213>()
                    .expect("warehouse dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                configure_warehouse_dialog(&mut commands, &mut assets, ui, &session.game);
            }
            CityDialogKind::FoodProcessing => {
                let ui = entity
                    .get::<generated::Citydlog9212>()
                    .expect("food processing dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                configure_food_dialog(&mut commands, &mut assets, ui);
            }
            CityDialogKind::PowerPlant => {
                let ui = entity
                    .get::<generated::Citydlog9211>()
                    .expect("power plant dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                configure_power_dialog(&mut commands, &mut assets, ui);
            }
            CityDialogKind::Transport => {
                let ui = entity
                    .get::<generated::Citydlog9214>()
                    .expect("transport dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                configure_transport_capacity_dialog(&mut commands, &mut assets, ui);
            }
            CityDialogKind::Population => {
                let ui = entity
                    .get::<generated::Citydlog9215>()
                    .expect("population dialog has generated identities");
                restore_city_dialog_window(&mut commands, ui.wind, dialog.saved_position);
                configure_population_dialog(&mut commands, &mut assets, ui);
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
    dialogs: Query<(&CityBuildingDialog, &Children)>,
    nodes: Query<&Node, With<CaptionedWindow>>,
) {
    let nation = session.active_major_nation();
    let mut positions = ProductionTable::default();
    for (dialog, children) in &dialogs {
        let node = children
            .iter()
            .find_map(|child| nodes.get(child).ok())
            .expect("city building dialog has a captioned window");
        let position = window_position(node);
        positions[dialog.slot] = Some(CityWindowPosition {
            left: i16::try_from(position.x)
                .expect("City window coordinate fits retail short storage"),
            top: i16::try_from(position.y)
                .expect("City window coordinate fits retail short storage"),
        });
    }
    windows.0[nation] = positions;
}
