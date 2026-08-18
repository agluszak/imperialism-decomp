//! Map-triggered recovered report/roster/garrison dialogs.

use super::map_interaction::{
    MapInteractionMode, StrategicInteraction, cycle_map_interaction_selection,
    set_map_interaction_mode,
};
use crate::AppState;
use crate::media::RetailAudioAssets;
use crate::ui::GameSession;
use crate::ui::generated;
use crate::ui::linger::{bind_linger_dialog, spawn_linger_dialog};
use crate::ui::retail::{ModalDialog, RetailTree};
use crate::ui::{RetailUiAssets, fill_brackets, format_currency};
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::prelude::*;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::{PictureId, RetailTextStylePreset, SoundId, fourcc};

#[derive(Component)]
struct MapModal;

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
    Close,
    CancelOrder(CivilianUnitId),
    Engineer(CivilianUnitId, EngineerConstructionChoice),
    ConfirmPurchase(CivilianUnitId, TileId),
    ConfirmDisband(CivilianUnitId),
}

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        (bind_added_map_modals, bind_added_civilian_modals)
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

pub(crate) fn spawn_navy_roster(commands: &mut Commands) {
    let root = commands.spawn_scene(generated::mapview_9478()).id();
    spawn_modal(commands, root);
}

pub(crate) fn spawn_army_roster(commands: &mut Commands) {
    let root = commands.spawn_scene(generated::mapview_9460()).id();
    spawn_modal(commands, root);
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
        30,
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
        31,
    );
}

fn spawn_modal(commands: &mut Commands, root: Entity) {
    commands
        .entity(root)
        .insert((MapModal, ModalDialog, TabGroup::modal(), GlobalZIndex(30)));
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
                    .insert(ActivateOnPress)
                    .observe(on_map_modal_close);
            }
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
                let linger = bind_linger_dialog(root, &tree);
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
                    .insert((ActivateOnPress, CivilianModalAction::Close))
                    .observe(on_civilian_modal_action);
            }
            CivilianModal::Notice { title, body } => {
                let linger = bind_linger_dialog(root, &tree);
                linger.set_title(&mut commands, &mut assets, title);
                linger.set_body(&mut commands, &mut assets, body);
                commands
                    .entity(linger.okay)
                    .insert((ActivateOnPress, CivilianModalAction::Close))
                    .observe(on_civilian_modal_action);
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
    commands
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
            CivilianModalAction::Close,
            ChildOf(dialog),
        ))
        .observe(on_civilian_modal_action);
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
    let linger = bind_linger_dialog(root, tree);
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
        .insert((
            ActivateOnPress,
            if affordable {
                CivilianModalAction::ConfirmPurchase(unit, tile)
            } else {
                CivilianModalAction::Close
            },
        ))
        .observe(on_civilian_modal_action);
    if affordable {
        commands
            .entity(linger.cancel)
            .insert((ActivateOnPress, CivilianModalAction::Close))
            .observe(on_civilian_modal_action);
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
    commands
        .entity(tree.find(root, fourcc!("okay")))
        .insert((ActivateOnPress, CivilianModalAction::Close))
        .observe(on_civilian_modal_action);
    commands
        .entity(tree.find(root, fourcc!("canc")))
        .insert((ActivateOnPress, CivilianModalAction::CancelOrder(unit)))
        .observe(on_civilian_modal_action);
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
    child_of: Query<&ChildOf>,
    roots: Query<(), With<CivilianModal>>,
    mut interactions: Query<&mut StrategicInteraction>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
    assets: RetailUiAssets,
    mut audio: RetailAudioAssets,
) {
    let Ok(action) = actions.get(activate.entity).copied() else {
        return;
    };
    let Some(root) = modal_root(activate.entity, &child_of, &roots) else {
        return;
    };
    let mut completed = false;
    match action {
        CivilianModalAction::Close => {}
        CivilianModalAction::CancelOrder(unit) => {
            if session.game.cancel_civilian_work_order(unit).is_ok()
                && let Ok(mut interaction) = interactions.single_mut()
            {
                set_map_interaction_mode(&mut interaction, MapInteractionMode::Civilian);
                interaction.civilian = Some(unit);
            }
        }
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
    commands.entity(root).despawn();
    if completed && let Ok(mut interaction) = interactions.single_mut() {
        cycle_map_interaction_selection(&mut session, &mut interaction);
    }
}

fn spawn_notice(commands: &mut Commands, title: String, body: String) {
    spawn_linger_dialog(
        commands,
        CivilianModal::Notice { title, body },
        AppState::StrategicMap,
        31,
    );
}

fn modal_root(
    mut entity: Entity,
    child_of: &Query<&ChildOf>,
    roots: &Query<(), With<CivilianModal>>,
) -> Option<Entity> {
    for _ in 0..10 {
        if roots.contains(entity) {
            return Some(entity);
        }
        entity = child_of.get(entity).ok()?.parent();
    }
    None
}

fn on_map_modal_close(
    activate: On<Activate>,
    mut commands: Commands,
    child_of: Query<&ChildOf>,
    modals: Query<Entity, With<MapModal>>,
) {
    let mut entity = activate.entity;
    for _ in 0..8 {
        if modals.contains(entity) {
            commands.entity(entity).despawn();
            return;
        }
        let Ok(parent) = child_of.get(entity) else {
            return;
        };
        entity = parent.parent();
    }
}
