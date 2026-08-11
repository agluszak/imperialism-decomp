//! Native transition differentials for nation resource yield rebuild.

use imperialism_core::*;
use imperialism_testkit::compare_native;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NationCase {
    nation: MajorNationId,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn nation_resource_yield_rebuild() {
    compare_native(
        "nation_resource_yield_rebuild",
        |state, case: NationCase| {
            state.rebuild_nation_resource_yields(case.nation);
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn ai_nation_resource_yield_rebuild_clamps_targets() {
    compare_native(
        "ai_nation_resource_yield_rebuild_clamps_targets",
        |state, case: NationCase| {
            state.rebuild_nation_resource_yields(case.nation);
        },
    )
    .unwrap();
}
