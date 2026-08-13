//! Native transition differentials for diplomacy grants and aid.

use imperialism_core::*;
use imperialism_testkit::compare_native;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NationCase {
    nation: MajorNationId,
}

#[derive(Debug, Deserialize)]
struct DiplomacyGrantCase {
    nation: MajorNationId,
    target: NationId,
    amount: i32,
}

#[derive(Debug, Deserialize)]
struct AidAllocationCase {
    nation: MajorNationId,
    minor_nation: MinorNationId,
    resource: ResourceKind,
    amount: i32,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn diplomacy_grant_entry_updates_treasury() {
    compare_native(
        "diplomacy_grant_entry_updates_treasury",
        |state, case: DiplomacyGrantCase| {
            state.set_diplomacy_grant(
                case.nation,
                case.target,
                Some(DiplomacyGrant {
                    amount: case.amount,
                    recurring: false,
                }),
            )
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn diplomacy_reset_preserves_recurring_grants() {
    compare_native(
        "diplomacy_reset_preserves_recurring_grants",
        |state, case: NationCase| {
            state.reset_diplomacy_commitments(case.nation);
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn aid_allocation() {
    compare_native("aid_allocation", |state, case: AidAllocationCase| {
        state.add_aid_allocation(case.nation, case.minor_nation, case.resource, case.amount);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn diplomacy_phase_applies_grant_and_consulate() {
    compare_native(
        "diplomacy_phase_applies_grant_and_consulate",
        |state, (): ()| state.do_diplomacy(),
    )
    .unwrap();
}
