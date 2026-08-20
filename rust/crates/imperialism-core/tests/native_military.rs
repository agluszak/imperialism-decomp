//! Native transition differentials for recruitment, maintenance, and civilian work.

use imperialism_core::differential;
use imperialism_core::*;
use imperialism_testkit::{
    assert_game_state_eq, compare_native, load_save_backed_state, run_native,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NationCase {
    nation: MajorNationId,
}

#[derive(Debug, Deserialize)]
struct AiDevelopmentCase {
    nation: MajorNationId,
    average_allocation: i32,
}

#[derive(Debug, Deserialize)]
struct SpecialistRecruitmentCase {
    nation: MajorNationId,
    unit_kind: MilitaryUnitKind,
    quantity: i16,
}

#[derive(Debug, Deserialize)]
struct ResourceDevelopmentCase {
    extractive_worker: CivilianUnitId,
    surface_worker: CivilianUnitId,
}

#[derive(Debug, Deserialize)]
struct RailConstructionCase {
    civilian: CivilianUnitId,
}

#[derive(Debug, Deserialize)]
struct IssuedRailSectionCase {
    civilian: CivilianUnitId,
    destination: TileId,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn specialist_recruitment() {
    compare_native(
        "specialist_recruitment",
        |state, case: SpecialistRecruitmentCase| {
            state.produce_military_recruits(case.nation, case.unit_kind, case.quantity);
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn military_maintenance() {
    compare_native("military_maintenance", |state, case: NationCase| {
        state.pay_for_military(case.nation);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn completed_resource_development() {
    compare_native(
        "completed_resource_development",
        |state, case: ResourceDevelopmentCase| {
            state.advance_civilian_work(case.extractive_worker);
            state.advance_civilian_work(case.surface_worker);
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn completed_rail_section() {
    compare_native(
        "completed_rail_section",
        |state, case: RailConstructionCase| {
            state.advance_civilian_work(case.civilian);
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn issued_rail_section() {
    compare_native(
        "issued_rail_section",
        |state, case: IssuedRailSectionCase| {
            state
                .order_rail_construction(case.civilian, case.destination)
                .unwrap();
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn civilians_phase() {
    compare_native("civilians_phase", |state, (): ()| {
        state.do_civilians();
    })
    .unwrap();
}

#[derive(Debug, Deserialize)]
struct EmptyCase {}

#[derive(Debug, Deserialize)]
struct InteractiveMoveResult {
    targets: Vec<i32>,
    actuals: Vec<i32>,
    snapshots: Vec<differential::ArmyBattleSnapshot>,
}

#[derive(Debug, Deserialize)]
struct InteractiveAttackResult {
    kinds: Vec<i32>,
    targets: Vec<i32>,
    actuals: Vec<i32>,
    snapshots: Vec<differential::ArmyBattleSnapshot>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct NavalBattleResult {
    attacker: usize,
    defender: usize,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn military_phase() {
    compare_native("military_phase", |state, _: EmptyCase| state.do_military()).unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn second_turn_military_cleanup() {
    compare_native("second_turn_military_cleanup", |state, (): ()| {
        state.do_military_cleanup();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn ai_naval_industry_development() {
    compare_native(
        "ai_naval_industry_development",
        |state, case: AiDevelopmentCase| {
            let before = state
                .nations()
                .major(case.nation)
                .economy
                .interior_civilian
                .pending_development_actions()
                .len();
            differential::plan_ai_military_development(state, case.nation, case.average_allocation);
            let actions = state
                .nations()
                .major(case.nation)
                .economy
                .interior_civilian
                .pending_development_actions();
            assert!(actions.len() >= before + 2);
            assert!(
                actions[before..]
                    .iter()
                    .all(|action| matches!(action, PendingDevelopmentAction::Industry { .. }))
            );
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn military_phase_ships_without_orders() {
    compare_native(
        "military_phase_ships_without_orders",
        |state, _: EmptyCase| state.do_military(),
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn military_phase_naval_encounter() {
    compare_native("military_phase_naval_encounter", |state, _: EmptyCase| {
        differential::do_military_with_tactical_battles(state).map(|continuation| {
            let attacker = state
                .task_forces_in_retail_order()
                .position(|(id, _)| id == continuation.battle.attacker)
                .expect("attacking task force remains queued");
            let defender = state
                .task_forces_in_retail_order()
                .position(|(id, _)| id == continuation.battle.defender)
                .expect("defending task force remains queued");
            NavalBattleResult { attacker, defender }
        })
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn advisory_map_missions_case16() {
    compare_native("advisory_map_missions_case16", |state, _: EmptyCase| {
        differential::select_and_queue_advisory_map_missions(state);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn army_movement_give_orders() {
    compare_native("army_movement_give_orders", |state, _: EmptyCase| {
        for index in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(index);
            if !state.nations().major(nation).is_auto() {
                continue;
            }
            if matches!(
                state.nations().country_status(nation.nation()),
                Some(CountryStatus::ProtectorateOf(_))
            ) {
                continue;
            }
            differential::do_army_movement(state, nation);
        }
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn combat_moves_uncontested() {
    compare_native("combat_moves_uncontested", |state, _: EmptyCase| {
        state
            .do_combat_moves()
            .map(|continuation| continuation.battle)
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn combat_moves_creates_battle() {
    compare_native("combat_moves_creates_battle", |state, _: EmptyCase| {
        state
            .do_combat_moves()
            .map(|continuation| continuation.battle)
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn auto_resolve_land_battle() {
    compare_native("auto_resolve_land_battle", |state, _: EmptyCase| {
        let continuation = state
            .do_combat_moves()
            .expect("hostile stack creates a battle");
        state.enter_land_battle(continuation);
        let _ = state.auto_resolve_land_battle(&[]);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn interactive_army_battle_done() {
    let native = run_native::<EmptyCase, Vec<differential::ArmyBattleSnapshot>>(
        "interactive_army_battle_done",
    )
    .unwrap();
    let mut state = load_save_backed_state(native.before).unwrap();
    let expected = load_save_backed_state(native.after).unwrap();
    let continuation = state
        .do_combat_moves()
        .expect("hostile stack creates a battle");
    state.enter_land_battle(continuation);
    differential::auto_deploy_army_battle(&mut state);
    let mut snapshots = vec![differential::army_battle_snapshot(&state).unwrap()];
    assert_eq!(state.finish_selected_army_unit_action(&[]), Ok(None));
    snapshots.push(differential::army_battle_snapshot(&state).unwrap());
    let _ = state.auto_resolve_land_battle(&[]);

    assert_eq!(snapshots, native.result);
    assert_game_state_eq(&expected, &state).unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn interactive_army_battle_move() {
    let native =
        run_native::<EmptyCase, InteractiveMoveResult>("interactive_army_battle_move").unwrap();
    let mut state = load_save_backed_state(native.before).unwrap();
    let expected = load_save_backed_state(native.after).unwrap();
    let continuation = state
        .do_combat_moves()
        .expect("hostile stack creates a battle");
    state.enter_land_battle(continuation);
    differential::auto_deploy_army_battle(&mut state);
    let mut snapshots = vec![differential::army_battle_snapshot(&state).unwrap()];
    assert_eq!(native.result.targets.len(), native.result.actuals.len());
    for (&target, &actual) in native.result.targets.iter().zip(&native.result.actuals) {
        let target = TacticalHex::from_index(target).unwrap();
        let (action, _) = state.army_action_at(target, &[]).unwrap();
        let ArmyAction::Move(moved) = action else {
            panic!("native move target must classify as Move");
        };
        assert_eq!(moved.to.index(), actual);
        snapshots.push(differential::army_battle_snapshot(&state).unwrap());
    }
    assert_ne!(native.result.targets.last(), native.result.actuals.last());
    let _ = state.auto_resolve_land_battle(&[]);

    assert_eq!(snapshots, native.result.snapshots);
    assert_game_state_eq(&expected, &state).unwrap();
}

fn compare_interactive_army_battle_attack(case_name: &str) {
    let native = run_native::<EmptyCase, InteractiveAttackResult>(case_name).unwrap();
    let mut state = load_save_backed_state(native.before).unwrap();
    let expected = load_save_backed_state(native.after).unwrap();
    let continuation = state
        .do_combat_moves()
        .expect("hostile stack creates a battle");
    state.enter_land_battle(continuation);
    differential::auto_deploy_army_battle(&mut state);
    let mut snapshots = vec![differential::army_battle_snapshot(&state).unwrap()];
    for ((&kind, &target), &actual) in native
        .result
        .kinds
        .iter()
        .zip(&native.result.targets)
        .zip(&native.result.actuals)
    {
        match kind {
            0 => assert_eq!(state.finish_selected_army_unit_action(&[]), Ok(None)),
            1 => {
                let target = TacticalHex::from_index(target).unwrap();
                let (action, _) = state.army_action_at(target, &[]).unwrap();
                let ArmyAction::Move(moved) = action else {
                    panic!("native move target must classify as Move");
                };
                assert_eq!(moved.to.index(), actual);
            }
            2 => {
                let target = TacticalHex::from_index(target).unwrap();
                let (action, _) = state.army_action_at(target, &[]).unwrap();
                assert!(matches!(action, ArmyAction::Attack { .. }));
            }
            _ => panic!("unknown native tactical input kind {kind}"),
        }
        if let Some(snapshot) = differential::army_battle_snapshot(&state) {
            snapshots.push(snapshot);
        }
    }
    if state.pending_land_battle().is_some() {
        let _ = state.auto_resolve_land_battle(&[]);
    }
    assert_eq!(snapshots, native.result.snapshots);
    assert_game_state_eq(&expected, &state).unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn interactive_army_battle_melee() {
    compare_interactive_army_battle_attack("interactive_army_battle_melee");
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn interactive_army_battle_ranged() {
    compare_interactive_army_battle_attack("interactive_army_battle_ranged");
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn interactive_army_battle_retreat() {
    let native = run_native::<EmptyCase, differential::ArmyBattleSnapshot>(
        "interactive_army_battle_retreat",
    )
    .unwrap();
    let mut state = load_save_backed_state(native.before).unwrap();
    let expected = load_save_backed_state(native.after).unwrap();
    let continuation = state
        .do_combat_moves()
        .expect("hostile stack creates a battle");
    state.enter_land_battle(continuation);
    differential::auto_deploy_army_battle(&mut state);
    assert_eq!(
        differential::army_battle_snapshot(&state),
        Some(native.result)
    );
    assert!(state.retreat_from_army_battle(&[]).unwrap().is_some());
    assert_game_state_eq(&expected, &state).unwrap();
}

#[derive(Debug, Deserialize, PartialEq)]
struct TwoLandBattles {
    first: PendingLandBattle,
    second: PendingLandBattle,
}

#[derive(Debug, Deserialize, PartialEq)]
struct CombatMovesResumeResult {
    first: PendingLandBattle,
    second: Option<PendingLandBattle>,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn combat_moves_resumes_after_battle() {
    compare_native(
        "combat_moves_resumes_after_battle",
        |state, _: EmptyCase| {
            let first = state
                .do_combat_moves()
                .expect("first hostile stack creates a battle");
            let second = differential::resume_combat_moves(state, first.clone())
                .expect("remaining stack creates a second battle");
            TwoLandBattles {
                first: first.battle,
                second: second.battle,
            }
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn combat_moves_battle_then_later_movement() {
    compare_native(
        "combat_moves_battle_then_later_movement",
        |state, _: EmptyCase| {
            let continuation = state
                .do_combat_moves()
                .expect("hostile stack creates a battle");
            let first = continuation.battle.clone();
            let second = differential::resume_combat_moves(state, continuation)
                .map(|continuation| continuation.battle);
            CombatMovesResumeResult { first, second }
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn reassess_control_sea_missions() {
    compare_native("reassess_control_sea_missions", |state, _: EmptyCase| {
        differential::reassess_control_sea_missions(state);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn recompute_nation_order_priority_metrics() {
    compare_native(
        "recompute_nation_order_priority_metrics",
        |state, _: EmptyCase| differential::recompute_nation_order_priority_metrics(state),
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn reassess_control_sea_missions_damaged_ship() {
    compare_native(
        "reassess_control_sea_missions_damaged_ship",
        |state, _: EmptyCase| {
            differential::reassess_control_sea_missions(state);
        },
    )
    .unwrap();
}

#[derive(Debug, Deserialize)]
struct ArmyProvinceCase {
    province: ProvinceId,
}

#[derive(Debug, Deserialize, PartialEq)]
struct ArmyToolbarResult {
    #[serde(deserialize_with = "deserialize_army_category_table")]
    totals: ArmyCategoryTable<i32>,
    #[serde(deserialize_with = "deserialize_army_category_table")]
    available: ArmyCategoryTable<i32>,
    can_upgrade: bool,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn army_toolbar_counts() {
    compare_native("army_toolbar_counts", |state, case: ArmyProvinceCase| {
        let counts = state.army_toolbar_counts(case.province);
        ArmyToolbarResult {
            totals: counts.totals,
            available: counts.available,
            can_upgrade: counts.can_upgrade,
        }
    })
    .unwrap();
}

#[derive(Debug, Deserialize)]
struct ArmyCategoryCase {
    province: ProvinceId,
    #[serde(deserialize_with = "deserialize_army_unit_category")]
    category: ArmyUnitCategory,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn army_select_category() {
    compare_native("army_select_category", |state, case: ArmyCategoryCase| {
        i32::from(state.activate_first_idle_unit_by_category(case.province, case.category))
    })
    .unwrap();
}

#[derive(Debug, Deserialize)]
struct ArmyOrderModeCase {
    province: ProvinceId,
    mode: i32,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn army_set_order_mode() {
    compare_native("army_set_order_mode", |state, case: ArmyOrderModeCase| {
        let mode = match case.mode {
            2 => ArmyIdleOrderMode::Sleep,
            3 => ArmyIdleOrderMode::Latr,
            4 => ArmyIdleOrderMode::Done,
            other => panic!("unproven army idle order mode {other}"),
        };
        state.set_idle_unit_orders_on_province(case.province, mode);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn army_select_province() {
    compare_native("army_select_province", |state, case: ArmyProvinceCase| {
        state.apply_army_province_selection(Some(case.province));
    })
    .unwrap();
}

#[derive(Debug, Deserialize)]
struct ArmyTileCase {
    province: ProvinceId,
    tile: TileId,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn army_click_blocked() {
    compare_native("army_click_blocked", |state, case: ArmyTileCase| {
        state
            .army_map_cursor_state(
                state.turn().active_nation,
                Some(case.province),
                case.tile,
                0,
                true,
            )
            .retail()
    })
    .unwrap();
}

#[derive(Debug, Deserialize)]
struct ArmyTargetCase {
    province: ProvinceId,
    target: ProvinceId,
}

fn army_click_target_friendly(state: &mut GameState, from: ProvinceId, to: ProvinceId) {
    state.issue_army_redeploy(from, to);
}

fn army_click_target_hostile(state: &mut GameState, from: ProvinceId, to: ProvinceId) {
    let nation = state.turn().active_nation;
    state.issue_army_hostile_order(nation, from, to);
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn army_click_friendly() {
    compare_native("army_click_friendly", |state, case: ArmyTargetCase| {
        army_click_target_friendly(state, case.province, case.target);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn army_click_hostile() {
    compare_native("army_click_hostile", |state, case: ArmyTargetCase| {
        army_click_target_hostile(state, case.province, case.target);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn army_selection_cycling() {
    compare_native("army_selection_cycling", |state, case: ArmyProvinceCase| {
        state
            .find_next_selectable_army_province(state.turn().active_nation, Some(case.province))
            .map(|province| i32::from(province.get()))
            .unwrap_or(-1)
    })
    .unwrap();
}

#[derive(Debug, Deserialize)]
struct NavyZoneCase {
    zone: OceanZoneId,
}

#[derive(Debug, Deserialize)]
struct NavySelectCase {
    class: i16,
    selecting: bool,
}

#[derive(Debug, Deserialize)]
struct NavyAggressionCase {
    aggression: i32,
}

#[derive(Debug, Deserialize, PartialEq)]
struct NavyToolbarResult {
    available: [i16; 4],
    selected: [i16; 4],
}

#[derive(Debug, Deserialize)]
struct NavyZoneTargetCase {
    zone: OceanZoneId,
    other: OceanZoneId,
}

#[derive(Debug, Deserialize, PartialEq)]
struct NavyZoneTargetResult {
    legal: bool,
    illegal: bool,
}

#[derive(Debug, Deserialize)]
struct NavyProvinceTargetCase {
    province: ProvinceId,
}

fn first_task_force(state: &GameState) -> TaskForceId {
    state
        .task_forces()
        .next()
        .map(|(id, _)| id)
        .expect("native navy case expected a committed task force")
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn navy_create_force() {
    compare_native("navy_create_force", |state, case: NavyZoneCase| {
        let nation = state.turn().active_nation;
        let force = state
            .demand_task_force_for_zone(case.zone, nation)
            .expect("loose ships must create a task force");
        assert!(state.submit_navy_order(force, NavyOrder::Evade, TaskForceTarget::None));
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn navy_toolbar_counts() {
    compare_native("navy_toolbar_counts", |state, _: NavyZoneCase| {
        let counts = state.navy_toolbar_counts(Some(first_task_force(state)));
        NavyToolbarResult {
            available: counts.available.into_array(),
            selected: counts.selected.into_array(),
        }
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn navy_select_ship() {
    compare_native("navy_select_ship", |state, case: NavySelectCase| {
        state.select_task_force_toolbar_class(
            first_task_force(state),
            NavyToolbarClass::from_retail(case.class)
                .expect("native navy toolbar fixture class is in 0..=3"),
            case.selecting,
        );
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn navy_set_aggression() {
    compare_native("navy_set_aggression", |state, case: NavyAggressionCase| {
        state.set_task_force_aggression(
            first_task_force(state),
            NavalAggression::from_retail(case.aggression)
                .expect("native navy aggression fixture is in 0..=2"),
        );
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn navy_submit_order() {
    compare_native("navy_submit_order", |state, case: NavyZoneCase| {
        let nation = state.turn().active_nation;
        let force = state
            .demand_task_force_for_zone(case.zone, nation)
            .expect("loose ships must create a task force");
        assert!(state.submit_navy_order(force, NavyOrder::Evade, TaskForceTarget::None));
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn navy_cancel_order() {
    compare_native("navy_cancel_order", |state, _: NavyZoneCase| {
        state.cancel_task_force(first_task_force(state));
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn navy_zone_target() {
    compare_native("navy_zone_target", |state, case: NavyZoneTargetCase| {
        let force = first_task_force(state);
        NavyZoneTargetResult {
            legal: state.navy_zone_is_valid_target(force, case.zone),
            illegal: state.navy_zone_is_valid_target(force, case.other),
        }
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn navy_province_target() {
    compare_native(
        "navy_province_target",
        |state, case: NavyProvinceTargetCase| {
            state.navy_province_is_valid_target(first_task_force(state), case.province)
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn navy_selection_cycling() {
    compare_native("navy_selection_cycling", |state, case: NavyZoneCase| {
        state
            .next_navy_order_zone(state.turn().active_nation, Some(case.zone))
            .map(|zone| i32::from(zone.get()))
            .unwrap_or(-1)
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn navy_empty_toolbar() {
    compare_native("navy_empty_toolbar", |state, _: EmptyCase| {
        let counts = state.navy_toolbar_counts(None);
        NavyToolbarResult {
            available: counts.available.into_array(),
            selected: counts.selected.into_array(),
        }
    })
    .unwrap();
}

fn two_ship_force(state: &GameState, nation: NationId, order: TaskForceOrder) -> TaskForceId {
    state
        .task_forces_in_retail_order()
        .find_map(|(id, force)| {
            (force.nation == nation && force.order == order && force.ships().len() >= 2)
                .then_some(id)
        })
        .expect("native navy tactical fixture force")
}

fn other_two_ship_force(state: &GameState, active: NationId, order: TaskForceOrder) -> TaskForceId {
    state
        .task_forces_in_retail_order()
        .find_map(|(id, force)| {
            (force.nation != active && force.order == order && force.ships().len() >= 2)
                .then_some(id)
        })
        .expect("native navy tactical opposing force")
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn navy_battle_accepted_deploy_tiles() {
    compare_native(
        "navy_battle_accepted_deploy_tiles",
        |state, _: EmptyCase| {
            let active = state.turn().active_nation;
            let our = two_ship_force(state, active, TaskForceOrder::Patrol);
            let enemy = other_two_ship_force(state, active, TaskForceOrder::Blockade);
            differential::navy_tactical_init_snapshot(state, our, enemy)
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn navy_battle_player_as_defender() {
    compare_native("navy_battle_player_as_defender", |state, _: EmptyCase| {
        let active = state.turn().active_nation;
        let our = two_ship_force(state, active, TaskForceOrder::Blockade);
        let enemy = other_two_ship_force(state, active, TaskForceOrder::Patrol);
        differential::navy_tactical_init_snapshot(state, our, enemy)
    })
    .unwrap();
}
