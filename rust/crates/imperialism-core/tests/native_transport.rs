//! Native transition differentials for transport capacity and needs.

use imperialism_core::*;
use imperialism_testkit::compare_native;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NationCase {
    nation: MajorNationId,
}

#[derive(Debug, Deserialize)]
struct DirectTransportCase {
    nation: MajorNationId,
    resource: ResourceKind,
    requested: i32,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn direct_transport() {
    compare_native("direct_transport", |state, case: DirectTransportCase| {
        state.direct_transport(case.nation, case.resource, case.requested)
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn transport_need_allocation() {
    compare_native("transport_need_allocation", |state, case: NationCase| {
        state.allocate_transport_needs(case.nation);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn transported_items_phase() {
    compare_native("transported_items_phase", |state, case: NationCase| {
        state.settle_transported_items(case.nation);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn rolling_stock() {
    compare_native("rolling_stock", |state, case: NationCase| {
        state.increase_rolling_stock(case.nation)
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn rolling_stock_insufficient_resources() {
    compare_native(
        "rolling_stock_insufficient_resources",
        |state, case: NationCase| state.increase_rolling_stock(case.nation),
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn merchant_marine() {
    compare_native("merchant_marine", |state, case: NationCase| {
        state.increase_merchant_marine(case.nation)
    })
    .unwrap();
}
