//! Map-triggered recovered report/roster/garrison dialogs.

use super::map_interaction::{
    MapInteractionMode, MapTransition, StrategicInteraction, StrategicViewport,
    apply_map_transition, cycle_map_interaction_selection,
};
use crate::AppState;
use crate::media::RetailAudioAssets;
use crate::ui::GameSession;
use crate::ui::generated;
use crate::ui::linger::{bind_linger_dialog, spawn_linger_dialog};
use crate::ui::retail::RetailTree;
use crate::ui::window::{DismissWindow, ModalCancel, ModalDefault, ModalWindow};
use crate::ui::{RetailUiAssets, fill_brackets, format_currency};
use bevy::prelude::*;
use bevy::ui::{Checked, InteractionDisabled};
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::{PictureId, RetailTextStylePreset, SoundId, fourcc};

#[derive(Component)]
struct MapModal;

const CIVILIANS_PER_COLUMN: usize = 4;
const CIVILIAN_LEDGER_VISIBLE_COLUMNS: usize = 2;
const SHIPS_PER_COLUMN: usize = 6;
const NAVY_ROSTER_VISIBLE_COLUMNS: usize = 2;
const SHIP_ROW_WIDTH: f32 = 229.0;
const SHIP_ROW_HEIGHT: f32 = 49.0;
const SHIP_CHECK_WIDTH: f32 = 80.0;
const SHIP_CHECK_HEIGHT: f32 = 45.0;
const SHIP_ROSTER_ATLAS: i16 = 0xdba;
const SHIP_ROSTER_TRANSPARENT: u8 = 0x10;
const SHIP_ROSTER_ATLAS_OFFSET: [i16; 14] =
    [0, 0, 0, 0, 160, 0, 0, 320, 480, 640, 0, 800, 960, 1120];
const SHIP_STATUS_STRING_INDEX: [i16; 14] = [-1, -1, -1, 0, 1, -1, -1, 2, 3, 4, -1, 5, 6, 7];

#[derive(Component)]
struct CivilianLedger {
    current_column: usize,
    last_column: usize,
}

#[derive(Component)]
struct CivilianLedgerRow {
    column: usize,
    row: usize,
}

#[derive(Clone, Copy, Component)]
enum CivilianLedgerAction {
    Previous,
    Next,
    Select(TileId),
}

#[derive(Component)]
struct NavyRoster {
    force: TaskForceId,
    current_column: usize,
    last_column: usize,
}

#[derive(Component)]
struct NavyRosterRow {
    column: usize,
    row: usize,
}

#[derive(Clone, Copy, Component)]
struct NavyRosterShip {
    force: TaskForceId,
    ship: ShipId,
}

#[derive(Clone, Copy, Component)]
enum NavyRosterAction {
    Previous,
    Next,
}

#[derive(Component)]
enum CivilianModal {
    Engineer(CivilianUnitId),
    Purchase(CivilianUnitId, TileId),
    Report(CivilianUnitId),
    Disband(CivilianUnitId),
    Notice { title: String, body: String },
}

#[derive(Clone, Copy, Component)]
enum CivilianModalAction {
    Engineer(CivilianUnitId, EngineerConstructionChoice),
    ConfirmPurchase(CivilianUnitId, TileId),
    ConfirmDisband(CivilianUnitId),
}

#[derive(Clone, Copy, Component)]
struct CancelCivilianOrder(CivilianUnitId);

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        (
            bind_added_map_modals,
            bind_added_civilian_ledgers,
            bind_added_navy_rosters,
            bind_added_civilian_modals,
            project_civilian_ledger,
            project_navy_roster,
        )
            .run_if(in_state(AppState::StrategicMap)),
    );
}

pub(crate) fn spawn_garrison(commands: &mut Commands, _province: ProvinceId) {
    let root = commands.spawn_scene(generated::mapview_3500()).id();
    spawn_modal(commands, root);
}

pub(crate) fn spawn_army_report(commands: &mut Commands, _province: ProvinceId) {
    let root = commands.spawn_scene(generated::mapview_3100()).id();
    spawn_modal(commands, root);
}

pub(crate) fn spawn_fleet_report(commands: &mut Commands, friendly: bool) {
    let root = if friendly {
        commands.spawn_scene(generated::mapview_9474()).id()
    } else {
        commands.spawn_scene(generated::mapview_9475()).id()
    };
    spawn_modal(commands, root);
}

pub(crate) fn spawn_navy_roster(commands: &mut Commands, force: TaskForceId) {
    let root = commands.spawn_scene(generated::mapview_9478()).id();
    spawn_modal(commands, root);
    commands.entity(root).insert(NavyRoster {
        force,
        current_column: 0,
        last_column: 0,
    });
}

pub(crate) fn spawn_army_roster(commands: &mut Commands) {
    let root = commands.spawn_scene(generated::mapview_9460()).id();
    spawn_modal(commands, root);
}

pub(crate) fn spawn_civilian_roster(commands: &mut Commands) {
    let root = commands.spawn_scene(generated::mapview_3500()).id();
    spawn_modal(commands, root);
    commands.entity(root).insert(CivilianLedger {
        current_column: 0,
        last_column: 0,
    });
}

pub(crate) fn spawn_engineer_construction(commands: &mut Commands, unit: CivilianUnitId) {
    let root = commands.spawn_scene(generated::mapview_7200()).id();
    spawn_modal(commands, root);
    commands.entity(root).insert(CivilianModal::Engineer(unit));
}

pub(crate) fn spawn_developer_purchase(
    commands: &mut Commands,
    unit: CivilianUnitId,
    tile: TileId,
) {
    spawn_linger_dialog(
        commands,
        CivilianModal::Purchase(unit, tile),
        AppState::StrategicMap,
    );
}

pub(crate) fn spawn_civilian_report(commands: &mut Commands, unit: CivilianUnitId) {
    let root = commands.spawn_scene(generated::mapview_3012()).id();
    spawn_modal(commands, root);
    commands.entity(root).insert(CivilianModal::Report(unit));
}

pub(crate) fn spawn_civilian_disband(commands: &mut Commands, unit: CivilianUnitId) {
    spawn_linger_dialog(
        commands,
        CivilianModal::Disband(unit),
        AppState::StrategicMap,
    );
}

fn spawn_modal(commands: &mut Commands, root: Entity) {
    commands
        .entity(root)
        .insert((MapModal, ModalWindow, DespawnOnExit(AppState::StrategicMap)));
}

fn bind_added_map_modals(
    mut commands: Commands,
    added: Query<Entity, (Added<MapModal>, Without<CivilianModal>)>,
    tree: RetailTree,
) {
    for root in &added {
        for tag in [fourcc!("okay"), fourcc!("end ")] {
            if let Some(entity) = tree.try_find(root, tag) {
                commands
                    .entity(entity)
                    .insert((ActivateOnPress, ModalDefault, DismissWindow));
                break;
            }
        }
    }
}

fn bind_added_civilian_ledgers(
    mut commands: Commands,
    added: Query<Entity, Added<CivilianLedger>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    for root in &added {
        let view = tree.view(root);
        let page = view.find(fourcc!("page"));
        let active_nation = session.game.turn().active_nation;
        let civilians = session
            .game
            .civilian_units()
            .filter(|(_, unit)| unit.owner_nation() == active_nation)
            .filter_map(|(_, unit)| unit.location().tile().map(|tile| (unit.unit_type(), tile)))
            .collect::<Vec<_>>();
        let last_column = civilians.len().saturating_sub(1) / CIVILIANS_PER_COLUMN;
        commands.entity(root).insert(CivilianLedger {
            current_column: 0,
            last_column,
        });

        let (font, layout, line_height, _) = assets
            .text_style(RetailTextStylePreset {
                font_family: 3,
                face_flags: 0,
                point_size: 12,
                alignment: -2,
            })
            .expect("retail civilian-ledger text style");
        let title = commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(77.0),
                    top: Val::Px(17.0),
                    width: Val::Px(128.0),
                    height: Val::Px(18.0),
                    ..default()
                },
                Text::new(
                    assets
                        .string(0x2746, 11)
                        .expect("retail civilian-ledger title"),
                ),
                font.clone(),
                layout,
                line_height,
                TextColor(Color::BLACK),
                Pickable::IGNORE,
            ))
            .id();
        commands.entity(view.find(fourcc!("DLOG"))).add_child(title);

        for (index, (kind, tile)) in civilians.into_iter().enumerate() {
            let column = index / CIVILIANS_PER_COLUMN;
            let row_in_column = index % CIVILIANS_PER_COLUMN;
            let name = assets
                .string(0x2718, i16::from(kind.retail()) + 1)
                .expect("retail civilian class name");
            let location = city_name(&session.game, tile);
            let row = commands
                .spawn((
                    CivilianLedgerRow {
                        column,
                        row: row_in_column,
                    },
                    CivilianLedgerAction::Select(tile),
                    Button,
                    ActivateOnPress,
                    Node {
                        position_type: PositionType::Absolute,
                        left: Val::Px(column as f32 * 229.0),
                        top: Val::Px(row_in_column as f32 * 64.0),
                        width: Val::Px(229.0),
                        height: Val::Px(64.0),
                        padding: UiRect::all(Val::Px(4.0)),
                        ..default()
                    },
                    Text::new(format!("{name}\n{location}")),
                    font.clone(),
                    layout,
                    line_height,
                    TextColor(Color::BLACK),
                    if column < CIVILIAN_LEDGER_VISIBLE_COLUMNS {
                        Visibility::Inherited
                    } else {
                        Visibility::Hidden
                    },
                ))
                .observe(on_civilian_ledger_action)
                .id();
            commands.entity(page).add_child(row);
        }
        for (tag, action) in [
            (fourcc!("lcor"), CivilianLedgerAction::Previous),
            (fourcc!("rcor"), CivilianLedgerAction::Next),
        ] {
            commands
                .entity(view.find(tag))
                .insert((
                    Button,
                    ActivateOnPress,
                    action,
                    match action {
                        CivilianLedgerAction::Previous => Visibility::Hidden,
                        CivilianLedgerAction::Next
                            if CIVILIAN_LEDGER_VISIBLE_COLUMNS <= last_column =>
                        {
                            Visibility::Inherited
                        }
                        CivilianLedgerAction::Next | CivilianLedgerAction::Select(_) => {
                            Visibility::Hidden
                        }
                    },
                ))
                .observe(on_civilian_ledger_action);
        }
    }
}

fn project_civilian_ledger(
    ledgers: Query<&CivilianLedger, Changed<CivilianLedger>>,
    mut rows: Query<(&CivilianLedgerRow, &mut Node, &mut Visibility)>,
    mut arrows: Query<(&CivilianLedgerAction, &mut Visibility), Without<CivilianLedgerRow>>,
) {
    let Ok(ledger) = ledgers.single() else {
        return;
    };
    for (row, mut node, mut visibility) in &mut rows {
        let visible = (ledger.current_column
            ..ledger.current_column + CIVILIAN_LEDGER_VISIBLE_COLUMNS)
            .contains(&row.column);
        *visibility = if visible {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        };
        if visible {
            node.left = Val::Px((row.column - ledger.current_column) as f32 * 229.0);
            node.top = Val::Px(row.row as f32 * 64.0);
        }
    }
    for (action, mut visibility) in &mut arrows {
        let visible = match action {
            CivilianLedgerAction::Previous => ledger.current_column > 0,
            CivilianLedgerAction::Next => {
                ledger.current_column + CIVILIAN_LEDGER_VISIBLE_COLUMNS <= ledger.last_column
            }
            CivilianLedgerAction::Select(_) => continue,
        };
        *visibility = if visible {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        };
    }
}

#[allow(clippy::too_many_arguments)]
fn on_civilian_ledger_action(
    activate: On<Activate>,
    actions: Query<&CivilianLedgerAction>,
    parents: Query<&ChildOf>,
    roots: Query<(), With<CivilianLedger>>,
    mut ledgers: Query<&mut CivilianLedger>,
    mut interactions: Query<(&mut StrategicInteraction, &mut StrategicViewport)>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
    mut audio: RetailAudioAssets,
) {
    let Ok(action) = actions.get(activate.entity).copied() else {
        return;
    };
    let Some(root) = ancestor_with_component(activate.entity, &parents, &roots) else {
        return;
    };
    match action {
        CivilianLedgerAction::Previous => {
            let mut ledger = ledgers.get_mut(root).expect("civilian ledger action root");
            ledger.current_column = ledger
                .current_column
                .saturating_sub(CIVILIAN_LEDGER_VISIBLE_COLUMNS);
        }
        CivilianLedgerAction::Next => {
            let mut ledger = ledgers.get_mut(root).expect("civilian ledger action root");
            ledger.current_column =
                (ledger.current_column + CIVILIAN_LEDGER_VISIBLE_COLUMNS).min(ledger.last_column);
        }
        CivilianLedgerAction::Select(tile) => {
            if let Ok((mut interaction, mut viewport)) = interactions.single_mut() {
                apply_map_transition(
                    &mut session,
                    &mut interaction,
                    &mut viewport,
                    MapTransition::Center(tile),
                );
            }
            let nation = session.game.turn().active_nation;
            let selectable = session
                .game
                .civilian_on_tile_for_nation(tile, nation)
                .and_then(|(unit, state)| {
                    matches!(
                        state.order(),
                        CivilianWorkOrder::Idle
                            | CivilianWorkOrder::Sleep
                            | CivilianWorkOrder::Later
                    )
                    .then_some(unit)
                });
            if let Some(unit) = selectable
                && let Ok((mut interaction, mut viewport)) = interactions.single_mut()
            {
                apply_map_transition(
                    &mut session,
                    &mut interaction,
                    &mut viewport,
                    MapTransition::SetMode(MapInteractionMode::Civilian),
                );
                interaction.civilian = Some(unit);
                session.game.activate_civilian_selection(unit);
                audio.play(&mut commands, SoundId::new(0x2338));
            }
            commands.entity(root).try_despawn();
        }
    }
}

fn ancestor_with_component<T: Component>(
    mut entity: Entity,
    parents: &Query<&ChildOf>,
    components: &Query<(), With<T>>,
) -> Option<Entity> {
    for _ in 0..10 {
        if components.contains(entity) {
            return Some(entity);
        }
        entity = parents.get(entity).ok()?.parent();
    }
    None
}

fn bind_added_navy_rosters(
    mut commands: Commands,
    added: Query<(Entity, &NavyRoster), Added<NavyRoster>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    for (root, roster) in &added {
        let view = tree.view(root);
        let page = view.find(fourcc!("page"));
        let force = roster.force;
        let ships = session
            .game
            .task_force(force)
            .map(|entry| entry.ships().collect::<Vec<_>>())
            .unwrap_or_default();
        let last_column = ships.len().saturating_sub(1) / SHIPS_PER_COLUMN;
        commands.entity(root).insert(NavyRoster {
            force,
            current_column: 0,
            last_column,
        });

        let (font, layout, line_height, _) = assets
            .text_style(RetailTextStylePreset {
                font_family: 3,
                face_flags: 0,
                point_size: 12,
                alignment: -2,
            })
            .expect("retail navy-roster text style");
        let atlas = assets
            .transparent_picture(PictureId::new(SHIP_ROSTER_ATLAS), SHIP_ROSTER_TRANSPARENT)
            .expect("retail navy roster atlas 3514 must load");

        for (index, (ship, _)) in ships.into_iter().enumerate() {
            let column = index / SHIPS_PER_COLUMN;
            let row_in_column = index % SHIPS_PER_COLUMN;
            let Some(state) = session.game.ship(ship) else {
                continue;
            };
            let caption = ship_roster_caption(&assets, state);
            let row = commands
                .spawn((
                    NavyRosterRow {
                        column,
                        row: row_in_column,
                    },
                    Node {
                        position_type: PositionType::Absolute,
                        left: Val::Px(column as f32 * SHIP_ROW_WIDTH),
                        top: Val::Px(row_in_column as f32 * SHIP_ROW_HEIGHT),
                        width: Val::Px(SHIP_ROW_WIDTH),
                        height: Val::Px(SHIP_ROW_HEIGHT),
                        overflow: Overflow::clip(),
                        ..default()
                    },
                    if column < NAVY_ROSTER_VISIBLE_COLUMNS {
                        Visibility::Inherited
                    } else {
                        Visibility::Hidden
                    },
                ))
                .id();
            let checkbox = commands
                .spawn((
                    NavyRosterShip { force, ship },
                    Button,
                    ActivateOnPress,
                    Node {
                        position_type: PositionType::Absolute,
                        left: Val::Px(0.0),
                        top: Val::Px(0.0),
                        width: Val::Px(SHIP_CHECK_WIDTH),
                        height: Val::Px(SHIP_CHECK_HEIGHT),
                        ..default()
                    },
                    ImageNode {
                        image: atlas.clone(),
                        ..default()
                    },
                ))
                .observe(on_navy_roster_toggle)
                .id();
            let name = commands
                .spawn((
                    Node {
                        position_type: PositionType::Absolute,
                        left: Val::Px(64.0),
                        top: Val::Px(0.0),
                        width: Val::Px(SHIP_ROW_WIDTH - 64.0),
                        height: Val::Px(SHIP_ROW_HEIGHT),
                        ..default()
                    },
                    Text::new(caption),
                    font.clone(),
                    layout,
                    line_height,
                    TextColor(Color::BLACK),
                    Pickable::IGNORE,
                ))
                .id();
            commands.entity(row).add_child(checkbox);
            commands.entity(row).add_child(name);
            commands.entity(page).add_child(row);
        }
        for (tag, action) in [
            (fourcc!("lcor"), NavyRosterAction::Previous),
            (fourcc!("rcor"), NavyRosterAction::Next),
        ] {
            commands
                .entity(view.find(tag))
                .insert((
                    Button,
                    ActivateOnPress,
                    action,
                    match action {
                        NavyRosterAction::Previous => Visibility::Hidden,
                        NavyRosterAction::Next if NAVY_ROSTER_VISIBLE_COLUMNS <= last_column => {
                            Visibility::Inherited
                        }
                        NavyRosterAction::Next => Visibility::Hidden,
                    },
                ))
                .observe(on_navy_roster_page);
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn project_navy_roster(
    session: Res<GameSession>,
    mut commands: Commands,
    rosters: Query<&NavyRoster, Changed<NavyRoster>>,
    mut rows: Query<(&NavyRosterRow, &mut Node, &mut Visibility)>,
    mut arrows: Query<(&NavyRosterAction, &mut Visibility), Without<NavyRosterRow>>,
    added_ships: Query<(), Added<NavyRosterShip>>,
    mut ships: Query<(Entity, &NavyRosterShip, &mut ImageNode, Has<Checked>)>,
) {
    if let Ok(roster) = rosters.single() {
        for (row, mut node, mut visibility) in &mut rows {
            let visible = (roster.current_column
                ..roster.current_column + NAVY_ROSTER_VISIBLE_COLUMNS)
                .contains(&row.column);
            *visibility = if visible {
                Visibility::Inherited
            } else {
                Visibility::Hidden
            };
            if visible {
                node.left = Val::Px((row.column - roster.current_column) as f32 * SHIP_ROW_WIDTH);
                node.top = Val::Px(row.row as f32 * SHIP_ROW_HEIGHT);
            }
        }
        for (action, mut visibility) in &mut arrows {
            let visible = match *action {
                NavyRosterAction::Previous => roster.current_column > 0,
                NavyRosterAction::Next => {
                    roster.current_column + NAVY_ROSTER_VISIBLE_COLUMNS <= roster.last_column
                }
            };
            *visibility = if visible {
                Visibility::Inherited
            } else {
                Visibility::Hidden
            };
        }
    }

    if crate::ui::projection_idle(&session, !added_ships.is_empty()) {
        return;
    }
    for (entity, toggle, mut image, checked) in &mut ships {
        let selected = ship_selected_in_force(&session.game, toggle.force, toggle.ship);
        if selected != checked {
            if selected {
                commands.entity(entity).insert(Checked);
            } else {
                commands.entity(entity).remove::<Checked>();
            }
        }
        let Some(ship) = session.game.ship(toggle.ship) else {
            continue;
        };
        image.rect = Some(ship_check_rect(ship.ship_type, selected));
    }
}

fn on_navy_roster_toggle(
    activate: On<Activate>,
    ships: Query<&NavyRosterShip>,
    mut session: ResMut<GameSession>,
) {
    let Ok(toggle) = ships.get(activate.entity) else {
        return;
    };
    let selected = ship_selected_in_force(&session.game, toggle.force, toggle.ship);
    session
        .game
        .set_task_force_ship_selected(toggle.force, toggle.ship, !selected);
}

fn on_navy_roster_page(
    activate: On<Activate>,
    actions: Query<&NavyRosterAction>,
    parents: Query<&ChildOf>,
    roots: Query<(), With<NavyRoster>>,
    mut rosters: Query<&mut NavyRoster>,
) {
    let Ok(action) = actions.get(activate.entity).copied() else {
        return;
    };
    let Some(root) = ancestor_with_component(activate.entity, &parents, &roots) else {
        return;
    };
    let mut roster = rosters.get_mut(root).expect("navy roster page action root");
    match action {
        NavyRosterAction::Previous => {
            roster.current_column = roster
                .current_column
                .saturating_sub(NAVY_ROSTER_VISIBLE_COLUMNS);
        }
        NavyRosterAction::Next => {
            roster.current_column =
                (roster.current_column + NAVY_ROSTER_VISIBLE_COLUMNS).min(roster.last_column);
        }
    }
}

fn ship_roster_caption(assets: &RetailUiAssets, ship: &ShipState) -> String {
    let index = SHIP_STATUS_STRING_INDEX[usize::from(ship.ship_type.retail())];
    if index < 0 {
        ship.name.clone()
    } else {
        format!("{} {}", get_string(assets, 0x2760, index), ship.name)
    }
}

fn ship_selected_in_force(game: &GameState, force: TaskForceId, ship: ShipId) -> bool {
    game.task_force(force)
        .and_then(|entry| {
            entry
                .ships()
                .find(|(id, _)| *id == ship)
                .map(|(_, selected)| selected)
        })
        .unwrap_or(false)
}

fn ship_check_rect(ship_type: ShipType, selected: bool) -> Rect {
    let x = f32::from(SHIP_ROSTER_ATLAS_OFFSET[usize::from(ship_type.retail())])
        + if selected { SHIP_CHECK_WIDTH } else { 0.0 };
    Rect::from_corners(
        Vec2::new(x, 0.0),
        Vec2::new(x + SHIP_CHECK_WIDTH, SHIP_CHECK_HEIGHT),
    )
}

fn bind_added_civilian_modals(
    mut commands: Commands,
    added: Query<(Entity, &CivilianModal), Added<CivilianModal>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    for (root, modal) in &added {
        match modal {
            CivilianModal::Engineer(unit) => bind_engineer_dialog(
                &mut commands,
                root,
                *unit,
                &tree,
                &mut assets,
                &session.game,
            ),
            CivilianModal::Purchase(unit, tile) => bind_purchase_dialog(
                &mut commands,
                root,
                *unit,
                *tile,
                &tree,
                &mut assets,
                &session.game,
            ),
            CivilianModal::Report(unit) => bind_civilian_report(
                &mut commands,
                root,
                *unit,
                &tree,
                &mut assets,
                &session.game,
            ),
            CivilianModal::Disband(unit) => {
                let linger = bind_linger_dialog(&mut commands, root, &tree);
                let kind = session
                    .game
                    .civilian_unit(*unit)
                    .expect("disband dialog retains its civilian")
                    .unit_type();
                let title = get_string(&assets, 0x274d, 3);
                let body = get_string(
                    &assets,
                    0x274d,
                    if kind == CivilianUnitKind::Developer {
                        5
                    } else {
                        4
                    },
                );
                linger.set_title(&mut commands, &mut assets, title);
                linger.set_body(&mut commands, &mut assets, body);
                commands
                    .entity(linger.okay)
                    .insert((
                        ActivateOnPress,
                        CivilianModalAction::ConfirmDisband(*unit),
                        DismissWindow,
                    ))
                    .observe(on_civilian_modal_action);
                commands
                    .entity(linger.cancel)
                    .insert(ActivateOnPress)
                    .remove::<InteractionDisabled>();
            }
            CivilianModal::Notice { title, body } => {
                let linger = bind_linger_dialog(&mut commands, root, &tree);
                linger.set_title(&mut commands, &mut assets, title);
                linger.set_body(&mut commands, &mut assets, body);
                commands.entity(linger.okay).insert(ActivateOnPress);
                commands.entity(linger.cancel).insert(Visibility::Hidden);
            }
        }
    }
}

fn bind_engineer_dialog(
    commands: &mut Commands,
    root: Entity,
    unit: CivilianUnitId,
    tree: &RetailTree,
    assets: &mut RetailUiAssets,
    state: &GameState,
) {
    let dialog = tree.find(root, fourcc!("DLOG"));
    let title = tree.find(root, fourcc!("titl"));
    insert_retail_text(commands, assets, title, &get_string(assets, 0x1c20, 6), 14);
    let options = state.engineer_construction_options(unit);
    let tile = state
        .civilian_unit(unit)
        .and_then(|unit| unit.location().tile())
        .expect("engineer dialog retains its map unit");
    let fort_level = state.map()[tile]
        .province
        .map(|province| state.map().provinces[province].fort_level().retail())
        .unwrap_or(0);
    let mut y = 40.0;
    for option in options {
        let (picture, label_offset) = match option.choice {
            EngineerConstructionChoice::Fort => (0x1c2a, i16::from(fort_level) + 3),
            EngineerConstructionChoice::Rail => (0x1c2c, 1),
            EngineerConstructionChoice::Port => (0x1c2e, 2),
        };
        commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: px(17),
                    top: px(y + 1.0),
                    width: px(38),
                    height: px(32),
                    ..default()
                },
                Button,
                ImageNode::new(
                    assets
                        .picture(PictureId::new(picture))
                        .expect("retail engineer option picture"),
                ),
                ActivateOnPress,
                CivilianModalAction::Engineer(unit, option.choice),
                DismissWindow,
                ChildOf(dialog),
            ))
            .observe(on_civilian_modal_action);
        let label = commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: px(84),
                    top: px(y),
                    width: px(236),
                    height: px(38),
                    ..default()
                },
                ChildOf(dialog),
            ))
            .id();
        insert_retail_text(
            commands,
            assets,
            label,
            &get_string(assets, 0x1c20, label_offset),
            10,
        );
        y += 42.0;
    }
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(17),
            top: px(y - 2.0),
            width: px(61),
            height: px(24),
            ..default()
        },
        Button,
        ImageNode::new(
            assets
                .picture(PictureId::new(0x24c4))
                .expect("retail cancel picture"),
        ),
        ActivateOnPress,
        ModalCancel,
        DismissWindow,
        ChildOf(dialog),
    ));
    let height = y + 30.0;
    let window = tree.find(root, fourcc!("WIND"));
    commands.entity(window).insert(Node {
        position_type: PositionType::Absolute,
        left: px(94),
        top: px(99),
        width: px(328),
        height: px(height + 1.0),
        ..default()
    });
    commands.entity(dialog).insert(Node {
        position_type: PositionType::Absolute,
        left: px(0),
        top: px(1),
        width: px(328),
        height: px(height),
        ..default()
    });
    spawn_engineer_background(commands, assets, dialog, 0.0, 56.0, 0x1c30);
    let mut background_y = 56.0;
    while background_y < height - 14.0 {
        spawn_engineer_background(commands, assets, dialog, background_y, 14.0, 0x1c32);
        background_y += 14.0;
    }
    spawn_engineer_background(commands, assets, dialog, height - 14.0, 14.0, 0x1c31);
}

fn spawn_engineer_background(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    parent: Entity,
    top: f32,
    height: f32,
    picture: i16,
) {
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(0),
            top: px(top),
            width: px(328),
            height: px(height),
            ..default()
        },
        ImageNode::new(
            assets
                .picture(PictureId::new(picture))
                .expect("retail engineer dialog strip"),
        ),
        ZIndex(-1),
        Pickable::IGNORE,
        ChildOf(parent),
    ));
}

fn bind_purchase_dialog(
    commands: &mut Commands,
    root: Entity,
    unit: CivilianUnitId,
    tile: TileId,
    tree: &RetailTree,
    assets: &mut RetailUiAssets,
    state: &GameState,
) {
    let linger = bind_linger_dialog(commands, root, tree);
    let title = get_string(assets, 0x274d, 0);
    let city = city_name(state, tile);
    let cost = format_currency(state.developer_tile_purchase_cost(tile));
    let affordable = state.can_afford_developer_tile_purchase(unit, tile);
    let body = fill_brackets(
        &get_string(assets, 0x274d, if affordable { 1 } else { 2 }),
        &[&city, &cost],
    );
    linger.set_title(commands, assets, title);
    linger.set_body(commands, assets, body);
    commands
        .entity(linger.okay)
        .insert((ActivateOnPress, DismissWindow));
    if affordable {
        commands
            .entity(linger.okay)
            .insert(CivilianModalAction::ConfirmPurchase(unit, tile))
            .observe(on_civilian_modal_action);
    }
    if affordable {
        commands.entity(linger.cancel).insert(ActivateOnPress);
    } else {
        commands.entity(linger.cancel).insert(Visibility::Hidden);
    }
}

fn bind_civilian_report(
    commands: &mut Commands,
    root: Entity,
    unit: CivilianUnitId,
    tree: &RetailTree,
    assets: &mut RetailUiAssets,
    state: &GameState,
) {
    for (tag, offset, point_size) in [
        (fourcc!("ttl0"), 12, 14),
        (fourcc!("ttl1"), 13, 12),
        (fourcc!("ttl2"), 14, 12),
    ] {
        insert_retail_text(
            commands,
            assets,
            tree.find(root, tag),
            &assets
                .string(0x2724, offset)
                .expect("retail civilian report title string"),
            point_size,
        );
    }
    insert_retail_text(
        commands,
        assets,
        tree.find(root, fourcc!("info")),
        &civilian_report_text(assets, state, unit),
        12,
    );
    commands.entity(tree.find(root, fourcc!("okay"))).insert((
        ActivateOnPress,
        ModalDefault,
        DismissWindow,
    ));
    commands
        .entity(tree.find(root, fourcc!("canc")))
        .insert((
            ActivateOnPress,
            CancelCivilianOrder(unit),
            ModalCancel,
            DismissWindow,
        ))
        .observe(on_cancel_civilian_order);
}

fn civilian_report_text(
    assets: &RetailUiAssets,
    state: &GameState,
    unit: CivilianUnitId,
) -> String {
    let civilian = state
        .civilian_unit(unit)
        .expect("civilian report retains its order");
    let tile = civilian
        .location()
        .tile()
        .expect("reported civilian is on the strategic map");
    let kind = get_string(assets, 0x2718, i16::from(civilian.unit_type().retail()));
    let city = city_name(state, tile);
    let mut report = fill_brackets(&get_string(assets, 0x2724, 0), &[&kind, &city]);
    report.push('\n');
    let (line, turns) = match civilian.order() {
        CivilianWorkOrder::Redeploy { .. } => (get_string(assets, 0x2724, 8), None),
        CivilianWorkOrder::LayRail { turns, .. } => (get_string(assets, 0x2724, 1), Some(*turns)),
        CivilianWorkOrder::BuildDepot { turns, .. } => {
            (get_string(assets, 0x2724, 2), Some(*turns))
        }
        CivilianWorkOrder::BuildPort { turns, .. } => (get_string(assets, 0x2724, 3), Some(*turns)),
        CivilianWorkOrder::Prospect { turns, .. } => (get_string(assets, 0x2724, 4), Some(*turns)),
        CivilianWorkOrder::DevelopResource { turns, .. } => {
            if civilian.unit_type() == CivilianUnitKind::Miner
                && state.map()[tile].development.extractive.get() == 0
            {
                let mut primary = String::new();
                let mut secondary = String::new();
                let mut count = 0;
                for (edge, resource) in state.map()[tile].edge_resources.into_iter().enumerate() {
                    let Some(resource) = resource else {
                        continue;
                    };
                    if !matches!(
                        resource,
                        ResourceKind::Coal
                            | ResourceKind::Iron
                            | ResourceKind::Oil
                            | ResourceKind::Gems
                            | ResourceKind::Gold
                    ) {
                        continue;
                    }
                    let name = get_string(assets, 0x2711, i16::from(resource.retail()));
                    if edge == 0 {
                        primary = name;
                    } else {
                        secondary = name;
                    }
                    count += 1;
                }
                let template = get_string(assets, 0x2724, if count > 1 { 6 } else { 10 });
                let line = if count > 1 {
                    fill_brackets(&template, &[&primary, &secondary])
                } else {
                    fill_brackets(&template, &[&primary])
                };
                (line, Some(*turns))
            } else {
                let action = get_string(assets, 0x2725, i16::from(civilian.unit_type().retail()));
                let template = get_string(
                    assets,
                    0x2724,
                    if civilian.unit_type() == CivilianUnitKind::Developer {
                        5
                    } else {
                        7
                    },
                );
                (fill_brackets(&template, &[&action]), Some(*turns))
            }
        }
        CivilianWorkOrder::BuildFort { turns, .. }
        | CivilianWorkOrder::PurchaseLand { turns, .. } => (String::new(), Some(*turns)),
        CivilianWorkOrder::Idle
        | CivilianWorkOrder::Sleep
        | CivilianWorkOrder::Later
        | CivilianWorkOrder::Done => (String::new(), None),
    };
    report.push_str(&line);
    if let Some(turns) = turns {
        report.push('\n');
        report.push_str(&fill_brackets(
            &get_string(assets, 0x2724, 9),
            &[&(turns * 3).to_string()],
        ));
    }
    report
}

fn city_name(state: &GameState, tile: TileId) -> String {
    state.map()[tile]
        .province
        .map(|province| state.map().provinces[province].name.clone())
        .unwrap_or_default()
}

fn get_string(assets: &RetailUiAssets, group: i16, offset: i16) -> String {
    assets
        .string(group, offset + 1)
        .unwrap_or_else(|_| panic!("retail string {group:#x}:{offset} must load"))
}

fn insert_retail_text(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    entity: Entity,
    text: &str,
    point_size: i32,
) {
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size,
            alignment: 1,
        })
        .expect("retail civilian modal text style");
    commands.entity(entity).insert((
        Text::new(text.to_owned()),
        font,
        layout,
        line_height,
        TextColor(Color::BLACK),
    ));
}

#[allow(clippy::too_many_arguments)]
fn on_civilian_modal_action(
    activate: On<Activate>,
    actions: Query<&CivilianModalAction>,
    mut interactions: Query<(&mut StrategicInteraction, &mut StrategicViewport)>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
    assets: RetailUiAssets,
    mut audio: RetailAudioAssets,
) {
    let Ok(action) = actions.get(activate.entity).copied() else {
        return;
    };
    let mut completed = false;
    match action {
        CivilianModalAction::Engineer(unit, choice) => {
            match session.game.queue_engineer_construction(unit, choice) {
                Ok(()) => {
                    audio.play(
                        &mut commands,
                        SoundId::new(match choice {
                            EngineerConstructionChoice::Fort => 0x232c,
                            EngineerConstructionChoice::Rail => 0x232a,
                            EngineerConstructionChoice::Port => 0x232b,
                        }),
                    );
                    completed = true;
                }
                Err(CivilianOrderRejection::InsufficientFunds) => {
                    let cost = session
                        .game
                        .engineer_construction_options(unit)
                        .into_iter()
                        .find(|option| option.choice == choice)
                        .map(|option| option.cost)
                        .unwrap_or(0);
                    let body =
                        fill_brackets(&get_string(&assets, 0x2745, 8), &[&format_currency(cost)]);
                    spawn_notice(&mut commands, String::new(), body);
                }
                Err(_) => {}
            }
        }
        CivilianModalAction::ConfirmPurchase(unit, tile) => {
            completed = session
                .game
                .confirm_developer_tile_purchase(unit, tile)
                .is_ok();
            if completed {
                audio.play(&mut commands, SoundId::new(0x2335));
            }
        }
        CivilianModalAction::ConfirmDisband(unit) => {
            completed = session.game.disband_civilian(unit);
        }
    }
    if completed && let Ok((mut interaction, mut viewport)) = interactions.single_mut() {
        cycle_map_interaction_selection(&mut session, &mut interaction, &mut viewport);
    }
}

fn on_cancel_civilian_order(
    activate: On<Activate>,
    actions: Query<&CancelCivilianOrder>,
    mut interactions: Query<(&mut StrategicInteraction, &mut StrategicViewport)>,
    mut session: ResMut<GameSession>,
) {
    let Ok(CancelCivilianOrder(unit)) = actions.get(activate.entity) else {
        return;
    };
    if session.game.cancel_civilian_work_order(*unit).is_ok()
        && let Ok((mut interaction, mut viewport)) = interactions.single_mut()
    {
        apply_map_transition(
            &mut session,
            &mut interaction,
            &mut viewport,
            MapTransition::SetMode(MapInteractionMode::Civilian),
        );
        interaction.civilian = Some(*unit);
    }
}

fn spawn_notice(commands: &mut Commands, title: String, body: String) {
    spawn_linger_dialog(
        commands,
        CivilianModal::Notice { title, body },
        AppState::StrategicMap,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_support::beginning_of_game_parts;
    use crate::ui::window::UiWindowPlugin;
    use bevy::state::app::StatesPlugin;
    use indexmap::IndexMap;

    fn two_frigate_force() -> (GameState, TaskForceId, ShipId, ShipId) {
        let mut parts = beginning_of_game_parts();
        let nation = parts.turn.active_nation;
        let location = OceanZoneId::new(0);
        let first = parts.object_ids.ship();
        let second = parts.object_ids.ship();
        let force = parts.object_ids.task_force();
        let ship = |name: &str| ShipState {
            ship_type: ShipType::Frigate,
            location,
            aggression: NavalAggression::Balanced,
            nation,
            name: name.to_string(),
            strength: 900,
            experience: 0,
            selection: ShipSelection::Available,
        };
        parts.ships.insert(first, ship("Alpha"));
        parts.ships.insert(second, ship("Beta"));
        parts.task_forces.insert(
            force,
            TaskForceState::from_parts(
                NavalAggression::Balanced,
                TaskForceOrder::None,
                TaskForceTarget::None,
                location,
                nation,
                false,
                -1,
                [(first, true), (second, true)]
                    .into_iter()
                    .collect::<IndexMap<_, _>>(),
            ),
        );
        (GameState::from_parts(parts), force, first, second)
    }

    #[test]
    fn navy_roster_checkbox_toggles_core_selection_and_keeps_navy_mode() {
        let (state, force, first, second) = two_frigate_force();
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(StatesPlugin)
            .add_plugins(UiWindowPlugin)
            .insert_state(AppState::StrategicMap)
            .insert_resource(GameSession::new(state))
            .add_systems(Update, project_navy_roster);

        let mut interaction = StrategicInteraction {
            mode: MapInteractionMode::Navy,
            ..default()
        };
        interaction.navy.zone = Some(OceanZoneId::new(0));
        interaction.navy.force = Some(force);
        let interaction_entity = app.world_mut().spawn(interaction).id();

        let root = app
            .world_mut()
            .spawn((
                NavyRoster {
                    force,
                    current_column: 0,
                    last_column: 0,
                },
                ModalWindow,
            ))
            .id();
        let first_row = app
            .world_mut()
            .spawn((NavyRosterRow { column: 0, row: 0 }, ChildOf(root)))
            .id();
        let second_row = app
            .world_mut()
            .spawn((NavyRosterRow { column: 0, row: 1 }, ChildOf(root)))
            .id();
        let first_check = app
            .world_mut()
            .spawn((
                NavyRosterShip { force, ship: first },
                Button,
                ImageNode::default(),
                ChildOf(first_row),
            ))
            .observe(on_navy_roster_toggle)
            .id();
        let second_check = app
            .world_mut()
            .spawn((
                NavyRosterShip {
                    force,
                    ship: second,
                },
                Button,
                ImageNode::default(),
                ChildOf(second_row),
            ))
            .observe(on_navy_roster_toggle)
            .id();
        let okay = app.world_mut().spawn((DismissWindow, ChildOf(root))).id();

        app.update();

        let row_count = app
            .world_mut()
            .query::<&NavyRosterRow>()
            .iter(app.world())
            .count();
        assert_eq!(row_count, 2);
        assert!(app.world().entity(first_check).contains::<Checked>());
        assert!(app.world().entity(second_check).contains::<Checked>());
        assert_eq!(
            app.world()
                .resource::<GameSession>()
                .game
                .navy_toolbar_counts(Some(force))
                .selected[NavyToolbarClass::Class1],
            2
        );

        app.world_mut().commands().trigger(Activate {
            entity: first_check,
        });
        app.world_mut().flush();
        app.update();

        let session = app.world().resource::<GameSession>();
        assert!(!ship_selected_in_force(&session.game, force, first));
        assert!(ship_selected_in_force(&session.game, force, second));
        assert_eq!(
            session.game.navy_toolbar_counts(Some(force)).selected[NavyToolbarClass::Class1],
            1
        );
        assert_eq!(
            session.game.navy_toolbar_counts(Some(force)).available[NavyToolbarClass::Class1],
            2
        );
        assert_eq!(
            session.game.task_force(force).map(|entry| entry.order),
            Some(TaskForceOrder::None)
        );
        assert!(!app.world().entity(first_check).contains::<Checked>());
        assert!(app.world().entity(second_check).contains::<Checked>());

        app.world_mut()
            .commands()
            .trigger(Activate { entity: okay });
        app.world_mut().flush();
        app.update();

        assert!(app.world().get_entity(root).is_err());
        let interaction = app
            .world()
            .get::<StrategicInteraction>(interaction_entity)
            .expect("navy selection survives roster close");
        assert_eq!(interaction.mode, MapInteractionMode::Navy);
        assert_eq!(interaction.navy.force, Some(force));
    }
}
