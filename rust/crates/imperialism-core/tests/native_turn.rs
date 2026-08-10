//! Native transition differentials for turn-phase advances.

use imperialism_core::*;
use imperialism_testkit::compare_native;

#[test]
#[ignore = "requires the native C++ oracle"]
fn first_turn_alert_phase() {
    compare_native("first_turn_alert_phase", |state, (): ()| {
        let _ = state.advance_turn_step();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn first_turn_diplomacy_phase() {
    compare_native("first_turn_diplomacy_phase", |state, (): ()| {
        let _ = state.advance_turn_step();
    })
    .unwrap();
}
