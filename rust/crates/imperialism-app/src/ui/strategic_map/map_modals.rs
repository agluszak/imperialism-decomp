//! Map-triggered recovered report/roster/garrison dialogs.

use super::map_interaction::{MapAction, StrategicMapSession, StrategicSelection};
use crate::AppState;
use crate::media::RetailAudioAssets;
use crate::ui::GameSession;
use crate::ui::generated;
use crate::ui::linger::{bind_linger_dialog, spawn_linger_dialog};
use crate::ui::retail::RetailTree;
use crate::ui::retail_resources::CivilianUnitKindRetailResources;
use crate::ui::retail_resources::EngineerConstructionChoiceRetailResources;
use crate::ui::retail_resources::ResourceKindRetailResources;
use crate::ui::retail_resources::ShipTypeRetailResources;
use crate::ui::window::{bind_modal_keys, dismiss_on_activate, spawn_modal_window};
use crate::ui::{RetailUiAssets, fill_brackets, format_currency};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, Button};
use enum_map::Enum;
use imperialism_core::*;
use imperialism_formats::{PictureId, RetailTextStylePreset, SoundId, fourcc};

#[derive(Component)]
struct MapModal;

const CIVILIANS_PER_COLUMN: usize = 4;
const PAGED_VISIBLE_COLUMNS: usize = 2;
const GARRISON_PER_COLUMN: usize = 6;
const MINI_ROSTER_PER_COLUMN: usize = 8;
const ROSTER_ROW_WIDTH: f32 = 229.0;
const GARRISON_ROW_HEIGHT: f32 = 49.0;
const MINI_ROSTER_ROW_HEIGHT: f32 = 36.0;

#[derive(Component)]
struct CivilianLedger;

struct PageRow {
    entity: Entity,
    column: usize,
}

#[derive(Component)]
struct PagedRows {
    current_column: usize,
    last_column: usize,
    rows: Vec<PageRow>,
    previous: Entity,
    next: Entity,
}

#[derive(Component)]
enum CivilianModal {
    Engineer(CivilianUnitId),
    Purchase(CivilianUnitId, TileId),
    Report(CivilianUnitId),
    Disband(CivilianUnitId),
    Notice { title: String, body: String },
}

#[derive(Component)]
struct ArmyReportDialog(ProvinceId);

#[derive(Component)]
struct GarrisonDialog(ProvinceId);

#[derive(Component)]
struct ArmyRosterDialog;

#[derive(Component)]
struct FleetReportDialog(FleetReportKind);

#[derive(Component)]
struct NavyRosterDialog(NavyRosterKind);

pub(super) fn register(app: &mut App) {
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
            project_paged_rows,
        )
            .run_if(in_state(AppState::StrategicMap)),
    );
}

pub(crate) fn spawn_garrison(commands: &mut Commands, province: ProvinceId) {
    let modal = spawn_modal(commands, generated::mapview_3500());
    commands.entity(modal).insert(GarrisonDialog(province));
}

pub(crate) fn spawn_army_report(commands: &mut Commands, province: ProvinceId) {
    let modal = spawn_modal(commands, generated::mapview_3100());
    commands.entity(modal).insert(ArmyReportDialog(province));
}

pub(crate) fn spawn_fleet_report(commands: &mut Commands, kind: FleetReportKind) {
    let modal = match kind {
        FleetReportKind::Friendly(_) => spawn_modal(commands, generated::mapview_9474()),
        FleetReportKind::Intelligence { .. } => spawn_modal(commands, generated::mapview_9475()),
    };
    commands.entity(modal).insert(FleetReportDialog(kind));
}

pub(crate) fn spawn_navy_roster(commands: &mut Commands, kind: NavyRosterKind) {
    let modal = spawn_modal(commands, generated::mapview_9478());
    commands.entity(modal).insert(NavyRosterDialog(kind));
}

pub(crate) fn spawn_army_roster(commands: &mut Commands) {
    let modal = spawn_modal(commands, generated::mapview_3500());
    commands.entity(modal).insert(ArmyRosterDialog);
}

pub(crate) fn spawn_civilian_roster(commands: &mut Commands) {
    let modal = spawn_modal(commands, generated::mapview_3500());
    commands.entity(modal).insert(CivilianLedger);
}

pub(crate) fn spawn_engineer_construction(commands: &mut Commands, unit: CivilianUnitId) {
    let modal = spawn_modal(commands, generated::mapview_7200());
    commands.entity(modal).insert(CivilianModal::Engineer(unit));
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
    let modal = spawn_modal(commands, generated::mapview_3012());
    commands.entity(modal).insert(CivilianModal::Report(unit));
}

pub(crate) fn spawn_civilian_disband(commands: &mut Commands, unit: CivilianUnitId) {
    spawn_linger_dialog(
        commands,
        CivilianModal::Disband(unit),
        AppState::StrategicMap,
    );
}

fn spawn_modal(commands: &mut Commands, scene: impl Scene) -> Entity {
    let (modal, _window) = spawn_modal_window(commands, scene);
    commands
        .entity(modal)
        .insert((MapModal, DespawnOnExit(AppState::StrategicMap)));
    modal
}

fn bind_added_map_modals(
    mut commands: Commands,
    added: Query<Entity, (Added<MapModal>, Without<CivilianModal>)>,
    tree: RetailTree,
) {
    for root in &added {
        for tag in [fourcc!("okay"), fourcc!("end ")] {
            if let Some(entity) = tree.try_find(root, tag) {
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
    assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    for root in &added {
        let view = tree.view(root);
        let page = view.find(fourcc!("page"));
        let previous = view.find(fourcc!("lcor"));
        let next = view.find(fourcc!("rcor"));
        let active_nation = session.game.turn().active_nation;
        let civilians = session
            .game
            .civilian_units()
            .filter(|(_, unit)| unit.owner_nation() == active_nation)
            .filter_map(|(_, unit)| unit.location().tile().map(|tile| (unit.unit_type(), tile)))
            .collect::<Vec<_>>();
        let last_column = civilians.len().saturating_sub(1) / CIVILIANS_PER_COLUMN;

        let (font, layout, line_height, _) =
            assets.text_style(RetailTextStylePreset::explicit(3, 0, 12, -2));
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
                Text::new(assets.ui_string(0x2746, 11)),
                font.clone(),
                layout,
                line_height,
                TextColor(Color::BLACK),
                Pickable::IGNORE,
            ))
            .id();
        commands.entity(view.find(fourcc!("DLOG"))).add_child(title);

        let row_height = 64.0;
        let mut rows = Vec::new();
        for (index, (kind, tile)) in civilians.into_iter().enumerate() {
            let column = index / CIVILIANS_PER_COLUMN;
            let row_in_column = index % CIVILIANS_PER_COLUMN;
            let name = assets.string(kind.name_string());
            let location = city_name(&session.game, tile);
            let row_entity = commands
                .spawn((
                    Button,
                    Node {
                        position_type: PositionType::Absolute,
                        left: Val::Px(column as f32 * ROSTER_ROW_WIDTH),
                        top: Val::Px(row_in_column as f32 * row_height),
                        width: Val::Px(ROSTER_ROW_WIDTH),
                        height: Val::Px(row_height),
                        padding: UiRect::all(Val::Px(4.0)),
                        ..default()
                    },
                    Text::new(format!("{name}\n{location}")),
                    font.clone(),
                    layout,
                    line_height,
                    TextColor(Color::BLACK),
                    if column < PAGED_VISIBLE_COLUMNS {
                        Visibility::Inherited
                    } else {
                        Visibility::Hidden
                    },
                ))
                .observe(
                    move |_: On<Activate>,
                          mut map: ResMut<StrategicMapSession>,
                          mut session: ResMut<GameSession>,
                          mut commands: Commands,
                          mut audio: RetailAudioAssets| {
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
                    },
                )
                .id();
            commands.entity(page).add_child(row_entity);
            rows.push(PageRow {
                entity: row_entity,
                column,
            });
        }
        let paged = PagedRows {
            current_column: 0,
            last_column,
            rows,
            previous,
            next,
        };
        bind_page_arrows(&mut commands, root, &paged);
        commands
            .entity(root)
            .remove::<CivilianLedger>()
            .insert(paged);
    }
}

fn bind_page_arrows(commands: &mut Commands, root: Entity, page: &PagedRows) {
    let prev_visible = page.current_column > 0;
    let next_visible = page.current_column + PAGED_VISIBLE_COLUMNS <= page.last_column;
    commands
        .entity(page.previous)
        .insert((
            Button,
            if prev_visible {
                Visibility::Inherited
            } else {
                Visibility::Hidden
            },
        ))
        .observe(move |_: On<Activate>, mut pages: Query<&mut PagedRows>| {
            let mut page = pages
                .get_mut(root)
                .expect("paged row arrow root retains PagedRows");
            page.current_column = page.current_column.saturating_sub(PAGED_VISIBLE_COLUMNS);
        });
    commands
        .entity(page.next)
        .insert((
            Button,
            if next_visible {
                Visibility::Inherited
            } else {
                Visibility::Hidden
            },
        ))
        .observe(move |_: On<Activate>, mut pages: Query<&mut PagedRows>| {
            let mut page = pages
                .get_mut(root)
                .expect("paged row arrow root retains PagedRows");
            page.current_column =
                (page.current_column + PAGED_VISIBLE_COLUMNS).min(page.last_column);
        });
}

fn project_paged_rows(
    pages: Query<&PagedRows, Changed<PagedRows>>,
    mut nodes: Query<&mut Node>,
    mut visibilities: Query<&mut Visibility>,
) {
    for page in &pages {
        for row in &page.rows {
            let visible = (page.current_column..page.current_column + PAGED_VISIBLE_COLUMNS)
                .contains(&row.column);
            *visibilities.get_mut(row.entity).expect("bound paged row") = if visible {
                Visibility::Inherited
            } else {
                Visibility::Hidden
            };
            if visible {
                nodes.get_mut(row.entity).expect("bound paged row").left =
                    Val::Px((row.column - page.current_column) as f32 * ROSTER_ROW_WIDTH);
            }
        }
        let prev_visible = page.current_column > 0;
        let next_visible = page.current_column + PAGED_VISIBLE_COLUMNS <= page.last_column;
        *visibilities
            .get_mut(page.previous)
            .expect("bound paged row previous arrow") = if prev_visible {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        };
        *visibilities
            .get_mut(page.next)
            .expect("bound paged row next arrow") = if next_visible {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        };
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
                let unit = *unit;
                let linger = bind_linger_dialog(&mut commands, root, &tree);
                let kind = session
                    .game
                    .civilian_unit(unit)
                    .expect("disband dialog retains its civilian")
                    .unit_type();
                let title = assets.get_string(0x274d, 3);
                let body = assets.string(kind.disband_confirmation_string());
                linger.set_title(&mut commands, &mut assets, title);
                linger.set_body(&mut commands, &mut assets, body);
                commands.entity(linger.okay).observe(
                    move |_: On<Activate>,
                          mut map: ResMut<StrategicMapSession>,
                          mut session: ResMut<GameSession>| {
                        if session.game.disband_civilian(unit) {
                            map.cycle_selection(&mut session.game);
                        }
                    },
                );
                commands
                    .entity(linger.cancel)
                    .remove::<InteractionDisabled>();
            }
            CivilianModal::Notice { title, body } => {
                let linger = bind_linger_dialog(&mut commands, root, &tree);
                linger.set_title(&mut commands, &mut assets, title);
                linger.set_body(&mut commands, &mut assets, body);
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
    insert_retail_text(commands, assets, title, &assets.get_string(0x1c20, 6), 14);
    let options = state.engineer_construction_options(unit);
    let tile = state
        .civilian_unit(unit)
        .and_then(|unit| unit.location().tile())
        .expect("engineer dialog retains its map unit");
    let fort_level = state.map()[tile]
        .province
        .map(|province| state.map().provinces[province].fort_level())
        .unwrap_or(FortLevel::None);
    let mut y = 40.0;
    for option in options {
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
                ImageNode::new(assets.picture(option.choice.picture())),
                ChildOf(dialog),
            ))
            .observe(
                move |_: On<Activate>,
                      mut map: ResMut<StrategicMapSession>,
                      mut session: ResMut<GameSession>,
                      mut commands: Commands,
                      assets: RetailUiAssets,
                      mut audio: RetailAudioAssets| {
                    match session
                        .game
                        .queue_engineer_construction(unit, option.choice)
                    {
                        Ok(()) => {
                            audio.play(&mut commands, option.choice.confirm_sound());
                            map.cycle_selection(&mut session.game);
                        }
                        Err(CivilianOrderRejection::InsufficientFunds) => {
                            let cost = session
                                .game
                                .engineer_construction_options(unit)
                                .into_iter()
                                .find(|entry| entry.choice == option.choice)
                                .map(|entry| entry.cost)
                                .unwrap_or(0);
                            let body = fill_brackets(
                                &assets.get_string(0x2745, 8),
                                &[&format_currency(cost)],
                            );
                            spawn_notice(&mut commands, String::new(), body);
                        }
                        Err(_) => {}
                    }
                },
            )
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
            &assets.string(option.choice.label_string(fort_level)),
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
            ImageNode::new(assets.picture(PictureId::new(0x24c4))),
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
    spawn_engineer_background(commands, assets, dialog, 0.0, 56.0, PictureId::new(0x1c30));
    let mut background_y = 56.0;
    while background_y < height - 14.0 {
        spawn_engineer_background(
            commands,
            assets,
            dialog,
            background_y,
            14.0,
            PictureId::new(0x1c32),
        );
        background_y += 14.0;
    }
    spawn_engineer_background(
        commands,
        assets,
        dialog,
        height - 14.0,
        14.0,
        PictureId::new(0x1c31),
    );
}

fn spawn_engineer_background(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    parent: Entity,
    top: f32,
    height: f32,
    picture: PictureId,
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
        ImageNode::new(assets.picture(picture)),
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
    let title = assets.get_string(0x274d, 0);
    let city = city_name(state, tile);
    let cost = format_currency(state.developer_tile_purchase_cost(tile));
    let affordable = state.can_afford_developer_tile_purchase(unit, tile);
    let body = fill_brackets(
        &assets.get_string(0x274d, if affordable { 1 } else { 2 }),
        &[&city, &cost],
    );
    linger.set_title(commands, assets, title);
    linger.set_body(commands, assets, body);
    if affordable {
        commands.entity(linger.okay).observe(
            move |_: On<Activate>,
                  mut map: ResMut<StrategicMapSession>,
                  mut session: ResMut<GameSession>,
                  mut audio: RetailAudioAssets,
                  mut commands: Commands| {
                if session
                    .game
                    .confirm_developer_tile_purchase(unit, tile)
                    .is_ok()
                {
                    audio.play(&mut commands, SoundId::new(0x2335));
                    map.cycle_selection(&mut session.game);
                }
            },
        );
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
            &assets.ui_string(0x2724, offset),
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
    dismiss_on_activate(commands, okay, root);
    let cancel = tree.find(root, fourcc!("canc"));
    commands.entity(cancel).observe(
        move |_: On<Activate>,
              mut map: ResMut<StrategicMapSession>,
              mut session: ResMut<GameSession>| {
            if session.game.cancel_civilian_work_order(unit).is_ok() {
                map.apply(
                    &mut session.game,
                    MapAction::Select(StrategicSelection::Civilian(Some(unit))),
                );
            }
        },
    );
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
    let kind = assets.string(civilian.unit_type().name_string());
    let city = city_name(state, tile);
    let mut report = fill_brackets(&assets.get_string(0x2724, 0), &[&kind, &city]);
    report.push('\n');
    let (line, turns) = match civilian.order() {
        CivilianWorkOrder::Redeploy { .. } => (assets.get_string(0x2724, 8), None),
        CivilianWorkOrder::LayRail { turns, .. } => (assets.get_string(0x2724, 1), Some(*turns)),
        CivilianWorkOrder::BuildDepot { turns, .. } => (assets.get_string(0x2724, 2), Some(*turns)),
        CivilianWorkOrder::BuildPort { turns, .. } => (assets.get_string(0x2724, 3), Some(*turns)),
        CivilianWorkOrder::Prospect { turns, .. } => (assets.get_string(0x2724, 4), Some(*turns)),
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
                    let name = assets.string(resource.name_string());
                    if edge == 0 {
                        primary = name;
                    } else {
                        secondary = name;
                    }
                    count += 1;
                }
                let template = assets.get_string(0x2724, if count > 1 { 6 } else { 10 });
                let line = if count > 1 {
                    fill_brackets(&template, &[&primary, &secondary])
                } else {
                    fill_brackets(&template, &[&primary])
                };
                (line, Some(*turns))
            } else {
                let action = assets.string(civilian.unit_type().work_action_string());
                let template = assets.string(civilian.unit_type().work_report_template_string());
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
            &assets.get_string(0x2724, 9),
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

fn insert_retail_text(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    entity: Entity,
    text: &str,
    point_size: i32,
) {
    let (font, layout, line_height, _) =
        assets.text_style(RetailTextStylePreset::explicit(3, 0, point_size, 1));
    commands.entity(entity).insert((
        Text::new(text.to_owned()),
        font,
        layout,
        line_height,
        TextColor(Color::BLACK),
    ));
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
        let title = assets.get_string(0x2744, 0xb);
        let lab2 = assets.get_string(0x2744, 0xc);
        let lab3 = assets.get_string(0x2744, 0xd);
        let composition = army_composition_text(&assets, &report.composition);
        let order_template =
            assets.get_string(0x2744, if report.owned_by_viewer { 0xa } else { 0xe });
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
        let (page, previous, next, last_column) =
            roster_paging_entities(&tree, root, model.units.len(), GARRISON_PER_COLUMN);
        let (font, layout, line_height) = roster_text_style(&mut assets, 12);
        let mut rows = Vec::new();
        for (index, row) in model.units.iter().enumerate() {
            let column = index / GARRISON_PER_COLUMN;
            let row_in_column = index % GARRISON_PER_COLUMN;
            let kind = garrison_order_text(&assets, row.order);
            let row_entity = spawn_paged_row(
                &mut commands,
                page,
                column,
                row_in_column,
                column < PAGED_VISIBLE_COLUMNS,
                GARRISON_ROW_HEIGHT,
                format!("{}\n{kind}", row.name),
                font.clone(),
                layout,
                line_height,
            );
            rows.push(PageRow {
                entity: row_entity,
                column,
            });
            if !row.militia {
                let unit = row.unit;
                commands.entity(row_entity).insert(Button).observe(
                    move |activate: On<Activate>,
                          mut texts: Query<&mut Text>,
                          mut session: ResMut<GameSession>,
                          assets: RetailUiAssets| {
                        session.game.toggle_garrison_unit_ready(unit);
                        let Some(state) = session.game.military_unit(unit) else {
                            return;
                        };
                        let kind = garrison_order_text(&assets, state.order().code());
                        if let Ok(mut text) = texts.get_mut(activate.entity) {
                            text.0 = format!("{}\n{kind}", state.name());
                        }
                    },
                );
            }
        }
        insert_paged_rows(&mut commands, root, rows, previous, next, last_column);
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
        let (page, previous, next, last_column) =
            roster_paging_entities(&tree, root, model.units.len(), MINI_ROSTER_PER_COLUMN);
        spawn_roster_title(
            &mut commands,
            tree.view(root).find(fourcc!("DLOG")),
            &mut assets,
            0x2746,
            0xb,
        );
        let (font, layout, line_height) = roster_text_style(&mut assets, 12);
        let mut rows = Vec::new();
        for (index, row) in model.units.iter().enumerate() {
            let column = index / MINI_ROSTER_PER_COLUMN;
            let row_in_column = index % MINI_ROSTER_PER_COLUMN;
            let province = row.province;
            let row_entity = spawn_paged_row(
                &mut commands,
                page,
                column,
                row_in_column,
                column < PAGED_VISIBLE_COLUMNS,
                MINI_ROSTER_ROW_HEIGHT,
                format!("{}\n{}", row.name, row.city_name),
                font.clone(),
                layout,
                line_height,
            );
            rows.push(PageRow {
                entity: row_entity,
                column,
            });
            commands.entity(row_entity).insert(Button).observe(
                move |_: On<Activate>,
                      mut map: ResMut<StrategicMapSession>,
                      mut session: ResMut<GameSession>,
                      mut commands: Commands| {
                    map.apply(
                        &mut session.game,
                        MapAction::Select(StrategicSelection::Army(Some(province))),
                    );
                    session.game.apply_army_province_selection(Some(province));
                    if let Some(tile) = session.game.map().provinces[province].city_tile() {
                        map.apply(&mut session.game, MapAction::Center(tile));
                    }
                    commands.entity(root).try_despawn();
                },
            );
        }
        insert_paged_rows(&mut commands, root, rows, previous, next, last_column);
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
    let title = assets.get_string(0x2762, 7);
    let lab1 = assets.get_string(0x2762, 8);
    let lab2 = assets.get_string(0x2762, 9);
    let lab3 = assets.get_string(0x2762, 0xa);
    let composition = ship_composition_text(assets, &report.composition);
    let orders = friendly_orders_text(assets, report);
    let agro = assets.get_string(0x2762, report.aggression.retail() as u16 + 4);
    let authority = fill_brackets(
        &assets.get_string(0x2762, 0),
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
    let force = report.force;
    commands.entity(cancel).observe(
        move |_: On<Activate>,
              mut map: ResMut<StrategicMapSession>,
              mut session: ResMut<GameSession>| {
            let zone = session.game.task_force(force).map(|entry| entry.location);
            session.game.cancel_task_force(force);
            map.apply(
                &mut session.game,
                MapAction::Select(StrategicSelection::Navy { zone, force: None }),
            );
        },
    );
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
    let title = assets.get_string(0x2762, string_index);
    string_index += 1;
    let lab1 = assets.get_string(0x2762, string_index);
    string_index += 1;
    let lab2 = assets.get_string(0x2762, string_index);
    string_index += 1;
    let lab3 = assets.get_string(0x2762, string_index);
    string_index += 1;
    let lab4 = assets.get_string(0x2762, string_index);
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
        let (page, previous, next, last_column) =
            roster_paging_entities(&tree, root, model.ships.len(), MINI_ROSTER_PER_COLUMN);
        if let NavyRosterKind::Nation = kind {
            spawn_roster_title(
                &mut commands,
                tree.view(root).find(fourcc!("DLOG")),
                &mut assets,
                0x2746,
                0xc,
            );
        }
        let (font, layout, line_height) = roster_text_style(&mut assets, 12);
        let mut rows = Vec::new();
        for (index, row) in model.ships.iter().enumerate() {
            let column = index / MINI_ROSTER_PER_COLUMN;
            let row_in_column = index % MINI_ROSTER_PER_COLUMN;
            let kind_name = navy_roster_type_label(&assets, row.ship_type);
            let selected = if row.selected { "* " } else { "" };
            let row_entity = spawn_paged_row(
                &mut commands,
                page,
                column,
                row_in_column,
                column < PAGED_VISIBLE_COLUMNS,
                MINI_ROSTER_ROW_HEIGHT,
                format!("{selected}{kind_name}{}\n{}", row.name, row.zone_name),
                font.clone(),
                layout,
                line_height,
            );
            rows.push(PageRow {
                entity: row_entity,
                column,
            });
            match kind {
                NavyRosterKind::Nation => {
                    let zone = row.location;
                    let force = row.force;
                    commands.entity(row_entity).insert(Button).observe(
                        move |_: On<Activate>,
                              mut map: ResMut<StrategicMapSession>,
                              mut session: ResMut<GameSession>,
                              mut commands: Commands| {
                            map.select_navy(&mut session.game, zone, force);
                            commands.entity(root).try_despawn();
                        },
                    );
                }
                NavyRosterKind::TaskForce(force) => {
                    let force = *force;
                    let ship = row.ship;
                    let selected = row.selected;
                    commands.entity(row_entity).insert(Button).observe(
                        move |_: On<Activate>,
                              mut session: ResMut<GameSession>,
                              mut commands: Commands| {
                            session
                                .game
                                .set_task_force_ship_selected(force, ship, !selected);
                            commands.entity(root).try_despawn();
                            spawn_navy_roster(&mut commands, NavyRosterKind::TaskForce(force));
                        },
                    );
                }
            }
        }
        insert_paged_rows(&mut commands, root, rows, previous, next, last_column);
    }
}

fn roster_paging_entities(
    tree: &RetailTree,
    root: Entity,
    count: usize,
    rows_per_column: usize,
) -> (Entity, Entity, Entity, usize) {
    let view = tree.view(root);
    let page = view.find(fourcc!("page"));
    let previous = view.find(fourcc!("lcor"));
    let next = view.find(fourcc!("rcor"));
    let last_column = if count == 0 {
        0
    } else {
        count.saturating_sub(1) / rows_per_column
    };
    (page, previous, next, last_column)
}

fn insert_paged_rows(
    commands: &mut Commands,
    root: Entity,
    rows: Vec<PageRow>,
    previous: Entity,
    next: Entity,
    last_column: usize,
) {
    let paged = PagedRows {
        current_column: 0,
        last_column,
        rows,
        previous,
        next,
    };
    bind_page_arrows(commands, root, &paged);
    commands.entity(root).insert(paged);
}

fn spawn_roster_title(
    commands: &mut Commands,
    dialog: Entity,
    assets: &mut RetailUiAssets,
    group: u16,
    offset: u16,
) {
    let (font, layout, line_height, _) =
        assets.text_style(RetailTextStylePreset::explicit(3, 0, 12, -2));
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
            Text::new(assets.get_string(group, offset)),
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
fn spawn_paged_row(
    commands: &mut Commands,
    page: Entity,
    column: usize,
    row: usize,
    visible: bool,
    height: f32,
    text: String,
    font: TextFont,
    layout: TextLayout,
    line_height: LineHeight,
) -> Entity {
    let row_entity = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(column as f32 * ROSTER_ROW_WIDTH),
                top: Val::Px(row as f32 * height),
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
        ))
        .id();
    commands.entity(page).add_child(row_entity);
    row_entity
}

fn roster_text_style(
    assets: &mut RetailUiAssets,
    point_size: i32,
) -> (TextFont, TextLayout, LineHeight) {
    let (font, layout, line_height, _) =
        assets.text_style(RetailTextStylePreset::explicit(3, 0, point_size, -2));
    (font, layout, line_height)
}

fn garrison_order_text(assets: &RetailUiAssets, order: MilitaryOrderCode) -> String {
    assets.get_string(0x272c, order.get() as u16)
}

fn navy_roster_type_label(assets: &RetailUiAssets, ship_type: ShipType) -> String {
    match ship_type.navy_roster_status_string() {
        Some(id) => format!("{} ", assets.string(id)),
        None => String::new(),
    }
}

fn army_composition_text(
    assets: &RetailUiAssets,
    composition: &[(ArmyUnitCategory, i32)],
) -> String {
    join_counted_labels(composition.iter().map(|(category, count)| {
        let name = assets.get_string(0x2726, category.into_usize() as u16);
        (*count, name)
    }))
}

fn ship_composition_text(assets: &RetailUiAssets, composition: &[(ShipType, i32)]) -> String {
    join_counted_labels(composition.iter().map(|(kind, count)| {
        let name = assets.string(if *count < 2 {
            kind.name_string()
        } else {
            kind.plural_name_string()
        });
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
            &assets.get_string(0x2762, 0xb),
            &[report.target_name.as_deref().unwrap_or("")],
        ),
        TaskForceOrder::Patrol => fill_brackets(
            &assets.get_string(0x2762, 1),
            &[report.target_name.as_deref().unwrap_or(&report.zone_name)],
        ),
        TaskForceOrder::Marines => assets.get_string(0x2762, 2),
        TaskForceOrder::Blockade => fill_brackets(
            &assets.get_string(0x2762, 0x39),
            &[report.target_name.as_deref().unwrap_or("")],
        ),
        _ => assets.get_string(0x2762, 3),
    }
}

fn fleet_authority_text(assets: &RetailUiAssets, authority: &FleetAuthority) -> String {
    match (&authority.admiral, &authority.ship) {
        (None, None) => assets.get_string(0x2762, 0xd),
        (Some(admiral), Some(ship)) => fill_brackets(
            &assets.get_string(0x2762, 0xe),
            &[&format!("Adm. {admiral}"), ship],
        ),
        (None, Some(ship)) => fill_brackets(&assets.get_string(0x2762, 0xf), &[ship]),
        (Some(admiral), None) => format!("Adm. {admiral}"),
    }
}

fn intelligence_source_text(assets: &RetailUiAssets, authority: &FleetAuthority) -> String {
    match (&authority.admiral, &authority.ship) {
        (None, None) => assets.get_string(0x2762, 0x10),
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
    let (font, layout, line_height, _) =
        assets.text_style(RetailTextStylePreset::explicit(3, 0, point_size, alignment));
    commands.entity(entity).insert((
        Text::new(text.to_owned()),
        font,
        layout,
        line_height,
        TextColor(Color::BLACK),
    ));
}
