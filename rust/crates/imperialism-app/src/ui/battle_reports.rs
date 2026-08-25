//! Post-combat `TBattleReportView` / `TBattleDetailBook`.

use super::generated;
use super::retail::RetailTree;
use super::session::{BattleReportPresentation, GameSession, apply_turn_stop};
use super::window::{DismissWindow, ModalDefault, ModalWindow};
use crate::AppState;
use bevy::prelude::*;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::{BattleReportSideText, BattleReportText, fourcc};

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
        .insert((ActivateOnPress, ModalDefault, DismissWindow))
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
    reports: Res<BattleReportPresentation>,
    roots: Query<Ref<BattleReportRoot>>,
    added: Query<(), Added<BattleReportField>>,
    mut fields: Query<(&BattleReportField, &mut Text)>,
) {
    let Ok(root) = roots.single() else {
        return;
    };
    if super::projection_idle(&session, !added.is_empty())
        && !root.is_changed()
        && !reports.is_changed()
    {
        return;
    }
    let reports_game = session.game.battle_reports();
    let Some(report) = reports_game.get(root.selected) else {
        for (_, mut text) in &mut fields {
            text.0.clear();
        }
        return;
    };
    let report_text = battle_report_text(&session, &reports.0, root.selected);
    let location = match report.location {
        BattleReportLocation::Province(id) => session.game.map().provinces[id].name.clone(),
        BattleReportLocation::Zone(id) => format!("zone {}", id.get()),
    };
    for (field, mut text) in &mut fields {
        text.0 = match field {
            BattleReportField::Result => report_text[BattleReportSideSlot::Left].overlay.clone(),
            BattleReportField::Location => location.clone(),
            BattleReportField::FriendlyAdmiral => {
                report_text[BattleReportSideSlot::Left].name.clone()
            }
            BattleReportField::EnemyAdmiral => {
                report_text[BattleReportSideSlot::Right].name.clone()
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
    mut reports: ResMut<BattleReportPresentation>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    reports.0.clear();
    apply_turn_stop(session.game.close_post_combat_reports(), &mut next_state);
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
        ModalWindow,
        DespawnOnExit(AppState::BattleReport),
    ));
}

fn bind_detail(mut commands: Commands, root: Single<Entity, Added<DetailRoot>>, tree: RetailTree) {
    commands.entity(tree.find(*root, fourcc!("okay"))).insert((
        ActivateOnPress,
        ModalDefault,
        DismissWindow,
    ));
}

fn project_detail(
    session: Res<GameSession>,
    reports: Res<BattleReportPresentation>,
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
    let Some(_) = session.game.battle_reports().get(selected.selected) else {
        return;
    };
    let report_text = battle_report_text(&session, &reports.0, selected.selected);
    let left = tree.find(root, fourcc!("natL"));
    let right = tree.find(root, fourcc!("natR"));
    if let Ok(mut text) = texts.get_mut(left) {
        text.0 = report_text[BattleReportSideSlot::Left].name.clone();
    }
    if let Ok(mut text) = texts.get_mut(right) {
        text.0 = report_text[BattleReportSideSlot::Right].name.clone();
    }
}

pub(crate) fn battle_report_texts_for_save(
    session: &GameSession,
    captured: &[BattleReportText],
) -> Vec<BattleReportText> {
    session
        .game
        .battle_reports()
        .iter()
        .enumerate()
        .map(|(index, _)| battle_report_text(session, captured, index))
        .collect()
}

fn battle_report_text(
    session: &GameSession,
    captured: &[BattleReportText],
    index: usize,
) -> BattleReportText {
    if let Some(text) = captured.get(index) {
        return text.clone();
    }
    let report = &session.game.battle_reports()[index];
    BattleReportText::from_array([
        generated_battle_report_side_text(&session.game, report, BattleReportSideSlot::Left),
        generated_battle_report_side_text(&session.game, report, BattleReportSideSlot::Right),
    ])
}

fn generated_battle_report_side_text(
    state: &GameState,
    report: &BattleReport,
    slot: BattleReportSideSlot,
) -> BattleReportSideText {
    let side = &report.sides[slot];
    let nation_name = state
        .nation(side.nation)
        .map(|nation| nation.display_name.as_str())
        .unwrap_or("");
    let role = match (report.kind.is_land(), slot) {
        (true, BattleReportSideSlot::Left) => "Units Attacking",
        (true, BattleReportSideSlot::Right) => "Defensive Muster",
        (false, _) => "",
    };
    let name = if role.is_empty() {
        nation_name.to_owned()
    } else {
        format!("{nation_name}: {role}")
    };
    let mut overlay = String::new();
    for kind_index in 0..MilitaryUnitKind::LENGTH {
        let kind = MilitaryUnitKind::from_index(kind_index as u8).expect("military kind index");
        let matching = side
            .children
            .iter()
            .filter(|row| row.kind == BattleReportUnitKind::Military(kind))
            .collect::<Vec<_>>();
        if matching.is_empty() {
            continue;
        }
        if !overlay.is_empty() {
            overlay.push_str(", ");
        }
        let unit_name = match kind {
            MilitaryUnitKind::Minutemen => "Minutemen",
            MilitaryUnitKind::Skirmishers => "Skirmishers",
            MilitaryUnitKind::Regulars => "Regulars",
            MilitaryUnitKind::Grenadiers => "Grenadiers",
            MilitaryUnitKind::Hussars => "Hussars",
            MilitaryUnitKind::Cuirassiers => "Cuirassiers",
            MilitaryUnitKind::LightArtillery => "Light Artillery",
            MilitaryUnitKind::Artillery => "Artillery",
            _ => &matching[0].name,
        };
        overlay.push_str(&format!("{} {unit_name}", matching.len()));
        let inactive = matching
            .iter()
            .filter(|row| row.stock_or_required <= 0)
            .count();
        if inactive != 0 {
            overlay.push_str(&format!(" ({inactive} Inactive)"));
        }
    }
    BattleReportSideText { name, overlay }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_support::beginning_of_game;

    #[test]
    fn generated_land_report_text_preserves_retail_caption_and_summary_order() {
        let state = beginning_of_game();
        let nation = state.turn().active_nation;
        let report = BattleReport {
            participant: Some(BattleReportSideSlot::Left),
            kind: BattleReportKind::LandBattle,
            location: BattleReportLocation::Province(ProvinceId::new(0)),
            sides: BattleReportSideTable::from_array([
                BattleReportSide {
                    nation,
                    children: vec![
                        BattleReportUnit {
                            kind: BattleReportUnitKind::Military(MilitaryUnitKind::Regulars),
                            stock_or_required: 100,
                            name: "1st Regulars".to_owned(),
                            strength_bucket: 1,
                            detail_identity: BATTLE_REPORT_ARMY_IDENTITY,
                        },
                        BattleReportUnit {
                            kind: BattleReportUnitKind::Military(MilitaryUnitKind::Regulars),
                            stock_or_required: 0,
                            name: "2nd Regulars".to_owned(),
                            strength_bucket: 1,
                            detail_identity: BATTLE_REPORT_ARMY_IDENTITY,
                        },
                    ],
                },
                BattleReportSide {
                    nation: NationId::new(1),
                    children: Vec::new(),
                },
            ]),
        };

        let text = generated_battle_report_side_text(&state, &report, BattleReportSideSlot::Left);

        assert_eq!(
            text.name,
            format!(
                "{}: Units Attacking",
                state.nation(nation).unwrap().display_name
            )
        );
        assert_eq!(text.overlay, "2 Regulars (1 Inactive)");
    }
}
