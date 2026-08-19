//! Native transition differentials for the non-military turn tail.

use imperialism_core::*;
use imperialism_testkit::compare_native;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NationCase {
    nation: MajorNationId,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn great_power_pressure_human_debt() {
    compare_native("great_power_pressure_human_debt", |state, (): ()| {
        state.do_great_power_pressure_phase()
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn great_power_pressure_ai_noop() {
    compare_native("great_power_pressure_ai_noop", |state, case: NationCase| {
        state.update_great_power_pressure(case.nation)
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn season_advance_clears_status_flags() {
    compare_native("season_advance_clears_status_flags", |state, (): ()| {
        state.advance_season_phase();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn turn_alerts_skip_first_economic_turn() {
    compare_native("turn_alerts_skip_first_economic_turn", |state, (): ()| {
        state.show_turn_alerts(true)
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn diplomacy_offer_gate() {
    compare_native("diplomacy_offer_gate", |state, (): ()| {
        state.diplomacy_offer_gate()
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn quarter_gate_off_decade() {
    compare_native("quarter_gate_off_decade", |state, (): ()| {
        state.quarter_gate() == QuarterGateResult::DecadeCinematic
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn return_to_map_clears_notice_queues() {
    compare_native("return_to_map_clears_notice_queues", |state, (): ()| {
        state.return_to_map();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn newspaper_navy_growth_reward_levels() {
    compare_native("newspaper_navy_growth_reward_levels", |state, (): ()| {
        state.mark_all_pending_status_flags_handled();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn opening_civilian_grant() {
    compare_native("opening_civilian_grant", |state, (): ()| {
        let nation =
            NationId::as_major(state.turn().active_nation).expect("active nation is a great power");
        state.grant_opening_civilians_for_nation(nation);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn opening_home_city_setup() {
    compare_native("opening_home_city_setup", |state, (): ()| {
        for index in 0..MajorNationId::COUNT {
            state.finalize_home_city_setup(MajorNationId::new(index));
        }
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn newspaper_pending_status() {
    compare_native("newspaper_pending_status", |state, (): ()| {
        state.mark_all_pending_status_flags_handled();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn elimination_phase_with_landed_great_powers() {
    compare_native(
        "elimination_phase_with_landed_great_powers",
        |state, (): ()| state.do_elimination_phase(),
    )
    .unwrap();
}
