//! Map-triggered recovered report/roster/garrison dialogs.

use super::map_interaction::{MapAction, StrategicMapSession, StrategicSelection};
use crate::AppState;
use crate::media::RetailAudioAssets;
use crate::ui::GameSession;
use crate::ui::generated;
use crate::ui::linger::{bind_linger_dialog, spawn_linger_dialog};
use crate::ui::retail::{RetailTree, ancestor_with};
use crate::ui::window::{ModalWindow, bind_modal_keys, dismiss_on_activate};
use crate::ui::{RetailUiAssets, fill_brackets, format_currency};
use bevy::ecs::system::EntityCommands;
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use enum_map::Enum;
use imperialism_core::*;
use imperialism_formats::{PictureId, RetailTextStylePreset, SoundId, fourcc};

#[derive(Component)]
struct MapModal;

const CIVILIANS_PER_COLUMN: usize = 4;
const CIVILIAN_LEDGER_VISIBLE_COLUMNS: usize = 2;
const ROSTER_VISIBLE_COLUMNS: usize = 2;
const GARRISON_PER_COLUMN: usize = 6;
const MINI_ROSTER_PER_COLUMN: usize = 8;
const ROSTER_ROW_WIDTH: f32 = 229.0;
const GARRISON_ROW_HEIGHT: f32 = 49.0;
const MINI_ROSTER_ROW_HEIGHT: f32 = 36.0;

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

#[derive(Component)]
struct ArmyReportDialog(ProvinceId);

#[derive(Component)]
struct GarrisonDialog(ProvinceId);

#[derive(Component)]
struct ArmyRosterDialog;

#[derive(Component)]
struct FleetReportDialog(FleetReportKind);

#[derive(Clone, Copy, Component)]
struct CancelFleetOrders(TaskForceId);

#[derive(Component)]
struct NavyRosterDialog(NavyRosterKind);

#[derive(Component)]
struct RosterPage {
    current_column: usize,
    last_column: usize,
    row_height: f32,
}

#[derive(Clone, Copy, Component)]
struct RosterRow {
    column: usize,
    row: usize,
}

#[derive(Clone, Copy, Component)]
enum RosterPageAction {
    Previous,
    Next,
}

#[derive(Clone, Copy, Component)]
enum GarrisonRowAction {
    Toggle(MilitaryUnitId),
}

#[derive(Clone, Copy, Component)]
enum ArmyRosterRowAction {
    Select(ProvinceId),
}

#[derive(Clone, Copy, Component)]
enum NavyRosterRowAction {
    Select {
        zone: OceanZoneId,
        force: Option<TaskForceId>,
    },
    Toggle {
        force: TaskForceId,
        ship: ShipId,
        selected: bool,
    },
}

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        (
            bind_added_map_modals,
            bind_added_civilian_ledgers,
            bind_added_civilian_modals,
            bind_added_army_reports,
            bind_added_garrisons,
            bind_added_army_rosters,
            bind_added_fleet_reports,
            bind_added_navy_rosters,
            project_civilian_ledger,
            project_roster_pages,
        )
            .run_if(in_state(AppState::StrategicMap)),
    );
}

pub(crate) fn spawn_garrison(commands: &mut Commands, province: ProvinceId) {
    let root = commands.spawn_scene(generated::mapview_3500()).id();
    spawn_modal(commands, root);
    commands.entity(root).insert(GarrisonDialog(province));
}

pub(crate) fn spawn_army_report(commands: &mut Commands, province: ProvinceId) {
    let root = commands.spawn_scene(generated::mapview_3100()).id();
    spawn_modal(commands, root);
    commands.entity(root).insert(ArmyReportDialog(province));
}

pub(crate) fn spawn_fleet_report(commands: &mut Commands, kind: FleetReportKind) {
    let root = match kind {
        FleetReportKind::Friendly(_) => commands.spawn_scene(generated::mapview_9474()).id(),
        FleetReportKind::Intelligence { .. } => {
            commands.spawn_scene(generated::mapview_9475()).id()
        }
    };
    spawn_modal(commands, root);
    commands.entity(root).insert(FleetReportDialog(kind));
}

pub(crate) fn spawn_navy_roster(commands: &mut Commands, kind: NavyRosterKind) {
    let root = commands.spawn_scene(generated::mapview_9478()).id();
    spawn_modal(commands, root);
    commands.entity(root).insert(NavyRosterDialog(kind));
}

pub(crate) fn spawn_army_roster(commands: &mut Commands) {
    let root = commands.spawn_scene(generated::mapview_3500()).id();
    spawn_modal(commands, root);
    commands.entity(root).insert(ArmyRosterDialog);
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
                commands.entity(entity).insert(ActivateOnPress);
                dismiss_on_activate(&mut commands, entity, root);
                bind_modal_keys(&mut commands, root, Some(entity), None);
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
    mut map: ResMut<StrategicMapSession>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
    mut audio: RetailAudioAssets,
) {
    let Ok(action) = actions.get(activate.entity).copied() else {
        return;
    };
    let Some(root) = ancestor_with(activate.entity, &parents, &roots) else {
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
            map.apply(&mut session.game, MapAction::Center(tile));
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
            if let Some(unit) = selectable {
                map.apply(
                    &mut session.game,
                    MapAction::Select(StrategicSelection::Civilian(Some(unit))),
                );
                session.game.activate_civilian_selection(unit);
                audio.play(&mut commands, SoundId::new(0x2338));
            }
            commands.entity(root).try_despawn();
        }
    }
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
                    .insert((ActivateOnPress, CivilianModalAction::ConfirmDisband(*unit)))
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
        let option_button = commands
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
                ChildOf(dialog),
            ))
            .observe(on_civilian_modal_action)
            .id();
        dismiss_on_activate(commands, option_button, root);
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
    let cancel = commands
        .spawn((
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
            ChildOf(dialog),
        ))
        .id();
    dismiss_on_activate(commands, cancel, root);
    bind_modal_keys(commands, root, None, Some(cancel));
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
    commands.entity(linger.okay).insert(ActivateOnPress);
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
    let okay = tree.find(root, fourcc!("okay"));
    commands.entity(okay).insert(ActivateOnPress);
    dismiss_on_activate(commands, okay, root);
    let cancel = tree.find(root, fourcc!("canc"));
    commands
        .entity(cancel)
        .insert((ActivateOnPress, CancelCivilianOrder(unit)))
        .observe(on_cancel_civilian_order);
    dismiss_on_activate(commands, cancel, root);
    bind_modal_keys(commands, root, Some(okay), Some(cancel));
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
    mut map: ResMut<StrategicMapSession>,
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
    if completed {
        map.cycle_selection(&mut session.game);
    }
}

fn on_cancel_civilian_order(
    activate: On<Activate>,
    actions: Query<&CancelCivilianOrder>,
    mut map: ResMut<StrategicMapSession>,
    mut session: ResMut<GameSession>,
) {
    let Ok(CancelCivilianOrder(unit)) = actions.get(activate.entity) else {
        return;
    };
    if session.game.cancel_civilian_work_order(*unit).is_ok() {
        map.apply(
            &mut session.game,
            MapAction::Select(StrategicSelection::Civilian(Some(*unit))),
        );
    }
}

fn spawn_notice(commands: &mut Commands, title: String, body: String) {
    spawn_linger_dialog(
        commands,
        CivilianModal::Notice { title, body },
        AppState::StrategicMap,
    );
}

fn bind_added_army_reports(
    mut commands: Commands,
    added: Query<(Entity, &ArmyReportDialog), Added<ArmyReportDialog>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    for (root, ArmyReportDialog(province)) in &added {
        let report = session.game.army_report_model(*province);
        let view = tree.view(root);
        let title = get_string(&assets, 0x2744, 0xb);
        let lab2 = get_string(&assets, 0x2744, 0xc);
        let lab3 = get_string(&assets, 0x2744, 0xd);
        let composition = army_composition_text(&assets, &report.composition);
        let order_template = get_string(
            &assets,
            0x2744,
            if report.owned_by_viewer { 0xa } else { 0xe },
        );
        let orders = fill_brackets(&order_template, &[&report.city_name]);
        insert_styled_text(
            &mut commands,
            &mut assets,
            view.find(fourcc!("titl")),
            &title,
            14,
            1,
        );
        insert_styled_text(
            &mut commands,
            &mut assets,
            view.find(fourcc!("lab2")),
            &lab2,
            12,
            0,
        );
        insert_styled_text(
            &mut commands,
            &mut assets,
            view.find(fourcc!("lab3")),
            &lab3,
            12,
            0,
        );
        insert_styled_text(
            &mut commands,
            &mut assets,
            view.find(fourcc!("whom")),
            &composition,
            10,
            3,
        );
        insert_styled_text(
            &mut commands,
            &mut assets,
            view.find(fourcc!("gene")),
            "",
            10,
            3,
        );
        insert_styled_text(
            &mut commands,
            &mut assets,
            view.find(fourcc!("ords")),
            &orders,
            10,
            3,
        );
        let cancel = view.find(fourcc!("canc"));
        commands.entity(cancel).insert(ActivateOnPress);
        dismiss_on_activate(&mut commands, cancel, root);
        bind_modal_keys(&mut commands, root, None, Some(cancel));
    }
}

fn bind_added_garrisons(
    mut commands: Commands,
    added: Query<(Entity, &GarrisonDialog), Added<GarrisonDialog>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    for (root, GarrisonDialog(province)) in &added {
        let model = session.game.garrison_model(*province);
        bind_roster_page(
            &mut commands,
            root,
            &tree,
            &mut assets,
            None,
            model.units.len(),
            GARRISON_PER_COLUMN,
            GARRISON_ROW_HEIGHT,
        );
        let page = tree.find(root, fourcc!("page"));
        let (font, layout, line_height) = roster_text_style(&mut assets, 12);
        for (index, row) in model.units.iter().enumerate() {
            let column = index / GARRISON_PER_COLUMN;
            let row_in_column = index % GARRISON_PER_COLUMN;
            let kind = garrison_order_text(&assets, row.order);
            let mut entity = spawn_roster_row(
                &mut commands,
                page,
                RosterRow {
                    column,
                    row: row_in_column,
                },
                column < ROSTER_VISIBLE_COLUMNS,
                GARRISON_ROW_HEIGHT,
                format!("{}\n{kind}", row.name),
                font.clone(),
                layout,
                line_height,
            );
            if !row.militia {
                entity
                    .insert((Button, ActivateOnPress, GarrisonRowAction::Toggle(row.unit)))
                    .observe(on_garrison_row_action);
            }
        }
    }
}

fn bind_added_army_rosters(
    mut commands: Commands,
    added: Query<Entity, Added<ArmyRosterDialog>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    for root in &added {
        let model = session.game.army_roster_model();
        bind_roster_page(
            &mut commands,
            root,
            &tree,
            &mut assets,
            Some((0x2746, 0xb)),
            model.units.len(),
            MINI_ROSTER_PER_COLUMN,
            MINI_ROSTER_ROW_HEIGHT,
        );
        let page = tree.find(root, fourcc!("page"));
        let (font, layout, line_height) = roster_text_style(&mut assets, 12);
        for (index, row) in model.units.iter().enumerate() {
            let column = index / MINI_ROSTER_PER_COLUMN;
            let row_in_column = index % MINI_ROSTER_PER_COLUMN;
            spawn_roster_row(
                &mut commands,
                page,
                RosterRow {
                    column,
                    row: row_in_column,
                },
                column < ROSTER_VISIBLE_COLUMNS,
                MINI_ROSTER_ROW_HEIGHT,
                format!("{}\n{}", row.name, row.city_name),
                font.clone(),
                layout,
                line_height,
            )
            .insert((
                Button,
                ActivateOnPress,
                ArmyRosterRowAction::Select(row.province),
            ))
            .observe(on_army_roster_row_action);
        }
    }
}

fn bind_added_fleet_reports(
    mut commands: Commands,
    added: Query<(Entity, &FleetReportDialog), Added<FleetReportDialog>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    for (root, FleetReportDialog(kind)) in &added {
        let Some(model) = session.game.fleet_report_model(*kind) else {
            commands.entity(root).try_despawn();
            continue;
        };
        match model {
            FleetReportModel::Friendly(report) => {
                bind_friendly_fleet_report(&mut commands, root, &tree, &mut assets, &report);
            }
            FleetReportModel::Intelligence(report) => {
                bind_enemy_fleet_report(&mut commands, root, &tree, &mut assets, &report);
            }
        }
    }
}

fn bind_friendly_fleet_report(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    assets: &mut RetailUiAssets,
    report: &FriendlyFleetReport,
) {
    let view = tree.view(root);
    let title = get_string(assets, 0x2762, 7);
    let lab1 = get_string(assets, 0x2762, 8);
    let lab2 = get_string(assets, 0x2762, 9);
    let lab3 = get_string(assets, 0x2762, 0xa);
    let composition = ship_composition_text(assets, &report.composition);
    let orders = friendly_orders_text(assets, report);
    let agro = get_string(assets, 0x2762, report.aggression.retail() as i16 + 4);
    let authority = fill_brackets(
        &get_string(assets, 0x2762, 0),
        &[&fleet_authority_text(assets, &report.authority)],
    );
    insert_styled_text(commands, assets, view.find(fourcc!("titl")), &title, 14, 1);
    insert_styled_text(commands, assets, view.find(fourcc!("lab1")), &lab1, 10, 3);
    insert_styled_text(
        commands,
        assets,
        view.find(fourcc!("zone")),
        &report.zone_name,
        12,
        1,
    );
    insert_styled_text(commands, assets, view.find(fourcc!("lab2")), &lab2, 12, 0);
    insert_styled_text(commands, assets, view.find(fourcc!("lab3")), &lab3, 12, 0);
    insert_styled_text(
        commands,
        assets,
        view.find(fourcc!("whom")),
        &composition,
        10,
        3,
    );
    insert_styled_text(commands, assets, view.find(fourcc!("ords")), &orders, 10, 3);
    insert_styled_text(commands, assets, view.find(fourcc!("agro")), &agro, 10, 0);
    insert_styled_text(
        commands,
        assets,
        view.find(fourcc!("adam")),
        &authority,
        10,
        3,
    );
    let cancel = view.find(fourcc!("canc"));
    commands
        .entity(cancel)
        .insert((ActivateOnPress, CancelFleetOrders(report.force)))
        .observe(on_cancel_fleet_orders);
    dismiss_on_activate(commands, cancel, root);
    bind_modal_keys(commands, root, None, Some(cancel));
}

fn bind_enemy_fleet_report(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    assets: &mut RetailUiAssets,
    report: &EnemyFleetReport,
) {
    let view = tree.view(root);
    let mut string_index = 0x29;
    let title = get_string(assets, 0x2762, string_index);
    string_index += 1;
    let lab1 = get_string(assets, 0x2762, string_index);
    string_index += 1;
    let lab2 = get_string(assets, 0x2762, string_index);
    string_index += 1;
    let lab3 = get_string(assets, 0x2762, string_index);
    string_index += 1;
    let lab4 = get_string(assets, 0x2762, string_index);
    let composition = ship_composition_text(assets, &report.composition);
    let source = intelligence_source_text(assets, &report.authority);
    insert_styled_text(commands, assets, view.find(fourcc!("titl")), &title, 14, 1);
    insert_styled_text(commands, assets, view.find(fourcc!("lab1")), &lab1, 10, 3);
    insert_styled_text(commands, assets, view.find(fourcc!("lab2")), &lab2, 10, 3);
    insert_styled_text(commands, assets, view.find(fourcc!("lab3")), &lab3, 12, 0);
    insert_styled_text(commands, assets, view.find(fourcc!("lab4")), &lab4, 10, 3);
    insert_styled_text(
        commands,
        assets,
        view.find(fourcc!("gpee")),
        &report.nation_name,
        12,
        1,
    );
    insert_styled_text(
        commands,
        assets,
        view.find(fourcc!("zone")),
        &report.zone_name,
        12,
        1,
    );
    insert_styled_text(
        commands,
        assets,
        view.find(fourcc!("ship")),
        &composition,
        10,
        3,
    );
    insert_styled_text(commands, assets, view.find(fourcc!("adam")), &source, 10, 3);
}

fn bind_added_navy_rosters(
    mut commands: Commands,
    added: Query<(Entity, &NavyRosterDialog), Added<NavyRosterDialog>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    for (root, NavyRosterDialog(kind)) in &added {
        let model = session.game.navy_roster_model(*kind);
        let title = match kind {
            NavyRosterKind::Nation => Some((0x2746, 0xc)),
            NavyRosterKind::TaskForce(_) => None,
        };
        bind_roster_page(
            &mut commands,
            root,
            &tree,
            &mut assets,
            title,
            model.ships.len(),
            MINI_ROSTER_PER_COLUMN,
            MINI_ROSTER_ROW_HEIGHT,
        );
        let page = tree.find(root, fourcc!("page"));
        let (font, layout, line_height) = roster_text_style(&mut assets, 12);
        for (index, row) in model.ships.iter().enumerate() {
            let column = index / MINI_ROSTER_PER_COLUMN;
            let row_in_column = index % MINI_ROSTER_PER_COLUMN;
            let kind_name = navy_roster_type_label(&assets, row.ship_type);
            let selected = if row.selected { "* " } else { "" };
            let mut entity = spawn_roster_row(
                &mut commands,
                page,
                RosterRow {
                    column,
                    row: row_in_column,
                },
                column < ROSTER_VISIBLE_COLUMNS,
                MINI_ROSTER_ROW_HEIGHT,
                format!("{selected}{kind_name}{}\n{}", row.name, row.zone_name),
                font.clone(),
                layout,
                line_height,
            );
            match kind {
                NavyRosterKind::Nation => {
                    entity.insert((
                        Button,
                        ActivateOnPress,
                        NavyRosterRowAction::Select {
                            zone: row.location,
                            force: row.force,
                        },
                    ));
                }
                NavyRosterKind::TaskForce(force) => {
                    entity.insert((
                        Button,
                        ActivateOnPress,
                        NavyRosterRowAction::Toggle {
                            force: *force,
                            ship: row.ship,
                            selected: row.selected,
                        },
                    ));
                }
            }
            entity.observe(on_navy_roster_row_action);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn bind_roster_page(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    assets: &mut RetailUiAssets,
    title: Option<(i16, i16)>,
    count: usize,
    rows_per_column: usize,
    row_height: f32,
) {
    let last_column = if count == 0 {
        0
    } else {
        count.saturating_sub(1) / rows_per_column
    };
    commands.entity(root).insert(RosterPage {
        current_column: 0,
        last_column,
        row_height,
    });
    if let Some((group, offset)) = title {
        spawn_roster_title(
            commands,
            tree.view(root).find(fourcc!("DLOG")),
            assets,
            group,
            offset,
        );
    }
    let view = tree.view(root);
    for (tag, action) in [
        (fourcc!("lcor"), RosterPageAction::Previous),
        (fourcc!("rcor"), RosterPageAction::Next),
    ] {
        commands
            .entity(view.find(tag))
            .insert((
                Button,
                ActivateOnPress,
                action,
                match action {
                    RosterPageAction::Previous => Visibility::Hidden,
                    RosterPageAction::Next if ROSTER_VISIBLE_COLUMNS <= last_column => {
                        Visibility::Inherited
                    }
                    RosterPageAction::Next => Visibility::Hidden,
                },
            ))
            .observe(on_roster_page_action);
    }
}

fn spawn_roster_title(
    commands: &mut Commands,
    dialog: Entity,
    assets: &mut RetailUiAssets,
    group: i16,
    offset: i16,
) {
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 12,
            alignment: -2,
        })
        .expect("retail roster title text style");
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
            Text::new(get_string(assets, group, offset)),
            font,
            layout,
            line_height,
            TextColor(Color::BLACK),
            Pickable::IGNORE,
        ))
        .id();
    commands.entity(dialog).add_child(title);
}

#[allow(clippy::too_many_arguments)]
fn spawn_roster_row<'a>(
    commands: &'a mut Commands,
    page: Entity,
    row: RosterRow,
    visible: bool,
    height: f32,
    text: String,
    font: TextFont,
    layout: TextLayout,
    line_height: LineHeight,
) -> EntityCommands<'a> {
    let mut entity = commands.spawn((
        row,
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(row.column as f32 * ROSTER_ROW_WIDTH),
            top: Val::Px(row.row as f32 * height),
            width: Val::Px(ROSTER_ROW_WIDTH),
            height: Val::Px(height),
            padding: UiRect::all(Val::Px(2.0)),
            ..default()
        },
        Text::new(text),
        font,
        layout,
        line_height,
        TextColor(Color::BLACK),
        if visible {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        },
    ));
    entity.insert(ChildOf(page));
    entity
}

fn roster_text_style(
    assets: &mut RetailUiAssets,
    point_size: i32,
) -> (TextFont, TextLayout, LineHeight) {
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size,
            alignment: -2,
        })
        .expect("retail roster row text style");
    (font, layout, line_height)
}

fn project_roster_pages(
    pages: Query<&RosterPage, Changed<RosterPage>>,
    mut rows: Query<(&RosterRow, &mut Node, &mut Visibility)>,
    mut arrows: Query<(&RosterPageAction, &mut Visibility), Without<RosterRow>>,
) {
    let Ok(page) = pages.single() else {
        return;
    };
    for (row, mut node, mut visibility) in &mut rows {
        let visible = (page.current_column..page.current_column + ROSTER_VISIBLE_COLUMNS)
            .contains(&row.column);
        *visibility = if visible {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        };
        if visible {
            node.left = Val::Px((row.column - page.current_column) as f32 * ROSTER_ROW_WIDTH);
            node.top = Val::Px(row.row as f32 * page.row_height);
        }
    }
    for (action, mut visibility) in &mut arrows {
        let visible = match action {
            RosterPageAction::Previous => page.current_column > 0,
            RosterPageAction::Next => {
                page.current_column + ROSTER_VISIBLE_COLUMNS <= page.last_column
            }
        };
        *visibility = if visible {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        };
    }
}

fn on_roster_page_action(
    activate: On<Activate>,
    actions: Query<&RosterPageAction>,
    parents: Query<&ChildOf>,
    roots: Query<(), With<RosterPage>>,
    mut pages: Query<&mut RosterPage>,
) {
    let Ok(action) = actions.get(activate.entity).copied() else {
        return;
    };
    let Some(root) = ancestor_with(activate.entity, &parents, &roots) else {
        return;
    };
    let mut page = pages.get_mut(root).expect("roster page action root");
    match action {
        RosterPageAction::Previous => {
            page.current_column = page.current_column.saturating_sub(ROSTER_VISIBLE_COLUMNS);
        }
        RosterPageAction::Next => {
            page.current_column =
                (page.current_column + ROSTER_VISIBLE_COLUMNS).min(page.last_column);
        }
    }
}

fn on_garrison_row_action(
    activate: On<Activate>,
    actions: Query<&GarrisonRowAction>,
    mut texts: Query<&mut Text>,
    mut session: ResMut<GameSession>,
    assets: RetailUiAssets,
) {
    let Ok(GarrisonRowAction::Toggle(unit)) = actions.get(activate.entity).copied() else {
        return;
    };
    session.game.toggle_garrison_unit_ready(unit);
    let Some(state) = session.game.military_unit(unit) else {
        return;
    };
    let kind = garrison_order_text(&assets, state.order().code());
    if let Ok(mut text) = texts.get_mut(activate.entity) {
        text.0 = format!("{}\n{kind}", state.name());
    }
}

fn on_army_roster_row_action(
    activate: On<Activate>,
    actions: Query<&ArmyRosterRowAction>,
    parents: Query<&ChildOf>,
    roots: Query<(), With<ArmyRosterDialog>>,
    mut map: ResMut<StrategicMapSession>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
    let Ok(ArmyRosterRowAction::Select(province)) = actions.get(activate.entity).copied() else {
        return;
    };
    let Some(root) = ancestor_with(activate.entity, &parents, &roots) else {
        return;
    };
    map.apply(
        &mut session.game,
        MapAction::Select(StrategicSelection::Army(Some(province))),
    );
    session.game.apply_army_province_selection(Some(province));
    if let Some(tile) = session.game.map().provinces[province].city_tile() {
        map.apply(&mut session.game, MapAction::Center(tile));
    }
    commands.entity(root).try_despawn();
}

fn on_navy_roster_row_action(
    activate: On<Activate>,
    actions: Query<&NavyRosterRowAction>,
    parents: Query<&ChildOf>,
    roots: Query<(), With<NavyRosterDialog>>,
    mut map: ResMut<StrategicMapSession>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
    let Ok(action) = actions.get(activate.entity).copied() else {
        return;
    };
    let Some(root) = ancestor_with(activate.entity, &parents, &roots) else {
        return;
    };
    match action {
        NavyRosterRowAction::Select { zone, force } => {
            map.select_navy(&mut session.game, zone, force);
            commands.entity(root).try_despawn();
        }
        NavyRosterRowAction::Toggle {
            force,
            ship,
            selected,
        } => {
            session
                .game
                .set_task_force_ship_selected(force, ship, !selected);
            commands.entity(root).try_despawn();
            spawn_navy_roster(&mut commands, NavyRosterKind::TaskForce(force));
        }
    }
}

fn on_cancel_fleet_orders(
    activate: On<Activate>,
    actions: Query<&CancelFleetOrders>,
    mut map: ResMut<StrategicMapSession>,
    mut session: ResMut<GameSession>,
) {
    let Ok(CancelFleetOrders(force)) = actions.get(activate.entity).copied() else {
        return;
    };
    let zone = session.game.task_force(force).map(|entry| entry.location);
    session.game.cancel_task_force(force);
    map.apply(
        &mut session.game,
        MapAction::Select(StrategicSelection::Navy { zone, force: None }),
    );
}

fn garrison_order_text(assets: &RetailUiAssets, order: MilitaryOrderCode) -> String {
    get_string(assets, 0x272c, order.get() as i16)
}

fn navy_roster_type_label(assets: &RetailUiAssets, ship_type: ShipType) -> String {
    const STATUS_INDEX: [i16; 14] = [-1, -1, -1, 0, 1, -1, -1, 2, 3, 4, -1, 5, 6, 7];
    let index = STATUS_INDEX[usize::from(ship_type.retail())];
    if index < 0 {
        String::new()
    } else {
        format!("{} ", get_string(assets, 0x2760, index))
    }
}

fn army_composition_text(
    assets: &RetailUiAssets,
    composition: &[(ArmyUnitCategory, i32)],
) -> String {
    join_counted_labels(composition.iter().map(|(category, count)| {
        let name = get_string(assets, 0x2726, category.into_usize() as i16);
        (*count, name)
    }))
}

fn ship_composition_text(assets: &RetailUiAssets, composition: &[(ShipType, i32)]) -> String {
    join_counted_labels(composition.iter().map(|(kind, count)| {
        let group = if *count < 2 { 0x2716 } else { 0x271a };
        let name = get_string(assets, group, i16::from(kind.retail()));
        (*count, name)
    }))
}

fn join_counted_labels(items: impl Iterator<Item = (i32, String)>) -> String {
    let mut text = String::new();
    for (count, name) in items {
        if !text.is_empty() {
            text.push_str(", ");
        }
        text.push_str(&count.to_string());
        text.push(' ');
        text.push_str(&name);
    }
    text
}

fn friendly_orders_text(assets: &RetailUiAssets, report: &FriendlyFleetReport) -> String {
    match report.order {
        TaskForceOrder::Sail => fill_brackets(
            &get_string(assets, 0x2762, 0xb),
            &[report.target_name.as_deref().unwrap_or("")],
        ),
        TaskForceOrder::Patrol => fill_brackets(
            &get_string(assets, 0x2762, 1),
            &[report.target_name.as_deref().unwrap_or(&report.zone_name)],
        ),
        TaskForceOrder::Marines => get_string(assets, 0x2762, 2),
        TaskForceOrder::Blockade => fill_brackets(
            &get_string(assets, 0x2762, 0x39),
            &[report.target_name.as_deref().unwrap_or("")],
        ),
        _ => get_string(assets, 0x2762, 3),
    }
}

fn fleet_authority_text(assets: &RetailUiAssets, authority: &FleetAuthority) -> String {
    match (&authority.admiral, &authority.ship) {
        (None, None) => get_string(assets, 0x2762, 0xd),
        (Some(admiral), Some(ship)) => fill_brackets(
            &get_string(assets, 0x2762, 0xe),
            &[&format!("Adm. {admiral}"), ship],
        ),
        (None, Some(ship)) => fill_brackets(&get_string(assets, 0x2762, 0xf), &[ship]),
        (Some(admiral), None) => format!("Adm. {admiral}"),
    }
}

fn intelligence_source_text(assets: &RetailUiAssets, authority: &FleetAuthority) -> String {
    match (&authority.admiral, &authority.ship) {
        (None, None) => get_string(assets, 0x2762, 0x10),
        _ => fleet_authority_text(assets, authority),
    }
}

fn insert_styled_text(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    entity: Entity,
    text: &str,
    point_size: i32,
    alignment: i32,
) {
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size,
            alignment,
        })
        .expect("retail army/navy report text style");
    commands.entity(entity).insert((
        Text::new(text.to_owned()),
        font,
        layout,
        line_height,
        TextColor(Color::BLACK),
    ));
}
