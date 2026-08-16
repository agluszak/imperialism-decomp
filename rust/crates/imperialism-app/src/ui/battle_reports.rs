//! Post-combat `TBattleReportView` / `TBattleDetailBook`.

use super::generated;
use super::retail::RetailTree;
use super::session::{GameSession, apply_turn_stop};
use crate::AppState;
use bevy::prelude::*;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::fourcc;

#[derive(Component)]
struct BattleReportRoot;

#[derive(Component)]
struct BattleReportClose;

#[derive(Component)]
struct BattleReportDetailButton;

#[derive(Component, Clone, Copy)]
enum BattleReportStep {
    Prev,
    Next,
}

#[derive(Resource, Default)]
struct SelectedBattleReport(usize);

#[derive(Component)]
struct BattleReportField(&'static str);

#[derive(Component)]
struct DetailRoot;

#[derive(Component)]
struct DetailClose;

pub(crate) struct BattleReportPlugin;

impl Plugin for BattleReportPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<SelectedBattleReport>()
            .add_systems(
                OnEnter(AppState::BattleReport),
                (
                    reset_selected_report,
                    spawn_battle_report,
                    bind_battle_report,
                )
                    .chain(),
            )
            .add_systems(
                Update,
                project_battle_report.run_if(
                    in_state(AppState::BattleReport).and_then(resource_exists::<GameSession>),
                ),
            )
            .add_observer(on_battle_report_activate.run_if(in_state(AppState::BattleReport)))
            .add_systems(
                OnEnter(AppState::BattleReportDetail),
                (spawn_detail, bind_detail).chain(),
            )
            .add_systems(
                Update,
                project_detail.run_if(
                    in_state(AppState::BattleReportDetail).and_then(resource_exists::<GameSession>),
                ),
            )
            .add_observer(on_detail_close.run_if(in_state(AppState::BattleReportDetail)));
    }
}

fn reset_selected_report(mut selected: ResMut<SelectedBattleReport>) {
    selected.0 = 0;
}

fn spawn_battle_report(mut commands: Commands) {
    let root = commands.spawn_scene(generated::diplo_1351()).id();
    commands
        .entity(root)
        .insert((BattleReportRoot, DespawnOnExit(AppState::BattleReport)));
}

fn bind_battle_report(
    mut commands: Commands,
    root: Single<Entity, Added<BattleReportRoot>>,
    tree: RetailTree,
) {
    commands
        .entity(tree.find(*root, fourcc!("okay")))
        .insert((BattleReportClose, ActivateOnPress));
    commands
        .entity(tree.find(*root, fourcc!("info")))
        .insert((BattleReportDetailButton, ActivateOnPress));
    commands
        .entity(tree.find(*root, fourcc!("prev")))
        .insert((BattleReportStep::Prev, ActivateOnPress));
    commands
        .entity(tree.find(*root, fourcc!("next")))
        .insert((BattleReportStep::Next, ActivateOnPress));
    for (tag, field) in [
        (fourcc!("resu"), "resu"),
        (fourcc!("loca"), "loca"),
        (fourcc!("fadm"), "fadm"),
        (fourcc!("eadm"), "eadm"),
        (fourcc!("fshp"), "fshp"),
        (fourcc!("eshp"), "eshp"),
    ] {
        commands
            .entity(tree.find(*root, tag))
            .insert(BattleReportField(field));
    }
}

fn project_battle_report(
    session: Res<GameSession>,
    selected: Res<SelectedBattleReport>,
    added: Query<(), Added<BattleReportField>>,
    mut fields: Query<(&BattleReportField, &mut Text)>,
) {
    if super::projection_idle(&session, !added.is_empty()) && !selected.is_changed() {
        return;
    }
    let reports = session.game.battle_reports();
    let Some(report) = reports.get(selected.0) else {
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
        text.0 = match field.0 {
            "resu" => report.sides[0].overlay.clone(),
            "loca" => location.clone(),
            "fadm" => report.sides[0].name.clone(),
            "eadm" => report.sides[1].name.clone(),
            "fshp" => report.sides[0]
                .children
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            "eshp" => report.sides[1]
                .children
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            _ => continue,
        };
    }
}

fn on_battle_report_activate(
    activate: On<Activate>,
    close: Query<(), With<BattleReportClose>>,
    detail: Query<(), With<BattleReportDetailButton>>,
    step: Query<&BattleReportStep>,
    mut session: ResMut<GameSession>,
    mut selected: ResMut<SelectedBattleReport>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if close.get(activate.entity).is_ok() {
        apply_turn_stop(session.game.close_post_combat_reports(), &mut next_state);
        return;
    }
    if detail.get(activate.entity).is_ok() && !session.game.battle_reports().is_empty() {
        next_state.set(AppState::BattleReportDetail);
        return;
    }
    let Ok(step) = step.get(activate.entity) else {
        return;
    };
    let count = session.game.battle_reports().len();
    if count == 0 {
        return;
    }
    selected.0 = match *step {
        BattleReportStep::Prev => (selected.0 + count - 1) % count,
        BattleReportStep::Next => (selected.0 + 1) % count,
    };
}

fn spawn_detail(mut commands: Commands) {
    let root = commands.spawn_scene(generated::diplo_1352()).id();
    commands
        .entity(root)
        .insert((DetailRoot, DespawnOnExit(AppState::BattleReportDetail)));
}

fn bind_detail(
    mut commands: Commands,
    root: Single<Entity, Added<DetailRoot>>,
    tree: RetailTree,
) {
    commands
        .entity(tree.find(*root, fourcc!("okay")))
        .insert((DetailClose, ActivateOnPress));
}

fn project_detail(
    session: Res<GameSession>,
    selected: Res<SelectedBattleReport>,
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
    let Some(report) = session.game.battle_reports().get(selected.0) else {
        return;
    };
    let left = tree.find(root, fourcc!("natL"));
    let right = tree.find(root, fourcc!("natR"));
    if let Ok(mut text) = texts.get_mut(left) {
        text.0 = report.sides[0].name.clone();
    }
    if let Ok(mut text) = texts.get_mut(right) {
        text.0 = report.sides[1].name.clone();
    }
}

fn on_detail_close(
    activate: On<Activate>,
    actions: Query<(), With<DetailClose>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if actions.get(activate.entity).is_err() {
        return;
    }
    next_state.set(AppState::BattleReport);
}
