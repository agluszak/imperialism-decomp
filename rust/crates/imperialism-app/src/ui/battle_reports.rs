//! Post-combat `TBattleReportView` / `TBattleDetailBook`.

use super::generated;
use super::retail::{ModalDialog, RetailTree};
use super::session::{GameSession, apply_turn_stop};
use crate::AppState;
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::prelude::*;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::fourcc;

#[derive(Component)]
struct BattleReportRoot {
    selected: usize,
}

#[derive(Component, Clone, Copy)]
enum BattleReportStep {
    Prev,
    Next,
}

#[derive(Component)]
enum BattleReportField {
    Result,
    Location,
    FriendlyAdmiral,
    EnemyAdmiral,
    FriendlyShips,
    EnemyShips,
}

#[derive(Component)]
struct DetailRoot;

pub(crate) struct BattleReportPlugin;

impl Plugin for BattleReportPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::BattleReport),
            (spawn_battle_report, bind_battle_report).chain(),
        )
        .add_systems(
            Update,
            (project_battle_report, bind_detail, project_detail)
                .run_if(in_state(AppState::BattleReport).and_then(resource_exists::<GameSession>)),
        );
    }
}

fn spawn_battle_report(mut commands: Commands) {
    let root = commands.spawn_scene(generated::diplo_1351()).id();
    commands.entity(root).insert((
        BattleReportRoot { selected: 0 },
        DespawnOnExit(AppState::BattleReport),
    ));
}

fn bind_battle_report(
    mut commands: Commands,
    root: Single<Entity, Added<BattleReportRoot>>,
    tree: RetailTree,
) {
    commands
        .entity(tree.find(*root, fourcc!("okay")))
        .insert(ActivateOnPress)
        .observe(on_battle_report_close);
    commands
        .entity(tree.find(*root, fourcc!("info")))
        .insert(ActivateOnPress)
        .observe(on_battle_report_detail);
    commands
        .entity(tree.find(*root, fourcc!("prev")))
        .insert((BattleReportStep::Prev, ActivateOnPress))
        .observe(on_battle_report_step);
    commands
        .entity(tree.find(*root, fourcc!("next")))
        .insert((BattleReportStep::Next, ActivateOnPress))
        .observe(on_battle_report_step);
    for (tag, field) in [
        (fourcc!("resu"), BattleReportField::Result),
        (fourcc!("loca"), BattleReportField::Location),
        (fourcc!("fadm"), BattleReportField::FriendlyAdmiral),
        (fourcc!("eadm"), BattleReportField::EnemyAdmiral),
        (fourcc!("fshp"), BattleReportField::FriendlyShips),
        (fourcc!("eshp"), BattleReportField::EnemyShips),
    ] {
        commands.entity(tree.find(*root, tag)).insert(field);
    }
}

fn project_battle_report(
    session: Res<GameSession>,
    roots: Query<Ref<BattleReportRoot>>,
    added: Query<(), Added<BattleReportField>>,
    mut fields: Query<(&BattleReportField, &mut Text)>,
) {
    let Ok(root) = roots.single() else {
        return;
    };
    if super::projection_idle(&session, !added.is_empty()) && !root.is_changed() {
        return;
    }
    let reports = session.game.battle_reports();
    let Some(report) = reports.get(root.selected) else {
        for (_, mut text) in &mut fields {
            text.0.clear();
        }
        return;
    };
    let location = match report.location {
        BattleReportLocation::Province(id) => session.game.map().provinces[id].name.clone(),
        BattleReportLocation::Zone(id) => format!("zone {}", id.get()),
    };
    for (field, mut text) in &mut fields {
        text.0 = match field {
            BattleReportField::Result => report.sides[BattleReportSideSlot::Left].overlay.clone(),
            BattleReportField::Location => location.clone(),
            BattleReportField::FriendlyAdmiral => {
                report.sides[BattleReportSideSlot::Left].name.clone()
            }
            BattleReportField::EnemyAdmiral => {
                report.sides[BattleReportSideSlot::Right].name.clone()
            }
            BattleReportField::FriendlyShips => report.sides[BattleReportSideSlot::Left]
                .children
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            BattleReportField::EnemyShips => report.sides[BattleReportSideSlot::Right]
                .children
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        };
    }
}

fn on_battle_report_close(
    _activate: On<Activate>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    assets: Option<Res<crate::RetailAssetsResource>>,
) {
    apply_turn_stop(
        session
            .game
            .close_post_combat_reports(super::session::news_story_ids(assets.as_deref())),
        &mut next_state,
    );
}

fn on_battle_report_detail(
    _activate: On<Activate>,
    mut commands: Commands,
    session: Res<GameSession>,
    details: Query<(), With<DetailRoot>>,
) {
    if details.is_empty() && !session.game.battle_reports().is_empty() {
        spawn_detail(&mut commands);
    }
}

fn on_battle_report_step(
    activate: On<Activate>,
    step: Query<&BattleReportStep>,
    session: Res<GameSession>,
    mut roots: Query<&mut BattleReportRoot>,
) {
    let Ok(step) = step.get(activate.entity) else {
        return;
    };
    let count = session.game.battle_reports().len();
    if count == 0 {
        return;
    }
    let Ok(mut root) = roots.single_mut() else {
        return;
    };
    root.selected = match *step {
        BattleReportStep::Prev => (root.selected + count - 1) % count,
        BattleReportStep::Next => (root.selected + 1) % count,
    };
}

fn spawn_detail(commands: &mut Commands) {
    let root = commands.spawn_scene(generated::diplo_1352()).id();
    commands.entity(root).insert((
        DetailRoot,
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        DespawnOnExit(AppState::BattleReport),
    ));
}

fn bind_detail(mut commands: Commands, root: Single<Entity, Added<DetailRoot>>, tree: RetailTree) {
    commands
        .entity(tree.find(*root, fourcc!("okay")))
        .insert(ActivateOnPress)
        .observe(on_detail_close);
}

fn project_detail(
    session: Res<GameSession>,
    selected: Single<&BattleReportRoot>,
    added: Query<(), Added<DetailRoot>>,
    tree: RetailTree,
    root: Query<Entity, With<DetailRoot>>,
    mut texts: Query<&mut Text>,
) {
    if added.is_empty() {
        return;
    }
    let Ok(root) = root.single() else {
        return;
    };
    let Some(report) = session.game.battle_reports().get(selected.selected) else {
        return;
    };
    let left = tree.find(root, fourcc!("natL"));
    let right = tree.find(root, fourcc!("natR"));
    if let Ok(mut text) = texts.get_mut(left) {
        text.0 = report.sides[BattleReportSideSlot::Left].name.clone();
    }
    if let Ok(mut text) = texts.get_mut(right) {
        text.0 = report.sides[BattleReportSideSlot::Right].name.clone();
    }
}

fn on_detail_close(
    _activate: On<Activate>,
    details: Query<Entity, With<DetailRoot>>,
    mut commands: Commands,
) {
    for detail in &details {
        commands.entity(detail).despawn();
    }
}
