//! Native transition differentials for city/transport phase orchestration.

use imperialism_core::*;
use imperialism_testkit::compare_native;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NationCase {
    nation: MajorNationId,
}

#[derive(Debug, Deserialize)]
struct EmptyCase {}

#[test]
#[ignore = "requires the native C++ oracle"]
fn owned_region_development() {
    compare_native("owned_region_development", |state, case: NationCase| {
        state.advance_owned_region_development_counters_and_handle_events(case.nation);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn city_and_transport_phase() {
    compare_native("city_and_transport_phase", |state, _: EmptyCase| {
        state.do_city_and_transport();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn navy_growth_pending() {
    compare_native("navy_growth_pending", |state, _: EmptyCase| {
        state.do_city_and_transport();
    })
    .unwrap();
}
