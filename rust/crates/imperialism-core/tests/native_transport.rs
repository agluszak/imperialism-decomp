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
    requested: i16,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn direct_transport() {
    compare_native("direct_transport", |state, case: DirectTransportCase| {
        state
            .nations_mut()
            .major_mut(case.nation)
            .unwrap()
            .direct_transport(case.resource, case.requested)
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn transport_need_allocation() {
    compare_native("transport_need_allocation", |state, case: NationCase| {
        state
            .nations_mut()
            .major_mut(case.nation)
            .unwrap()
            .allocate_transport_needs();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn transported_items_phase() {
    compare_native("transported_items_phase", |state, case: NationCase| {
        state
            .nations_mut()
            .major_mut(case.nation)
            .unwrap()
            .settle_transported_items();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn rolling_stock() {
    compare_native("rolling_stock", |state, case: NationCase| {
        state
            .nations_mut()
            .major_mut(case.nation)
            .unwrap()
            .increase_rolling_stock()
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn rolling_stock_insufficient_resources() {
    compare_native(
        "rolling_stock_insufficient_resources",
        |state, case: NationCase| {
            state
                .nations_mut()
                .major_mut(case.nation)
                .unwrap()
                .increase_rolling_stock()
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn merchant_marine() {
    compare_native("merchant_marine", |state, case: NationCase| {
        state
            .nations_mut()
            .major_mut(case.nation)
            .unwrap()
            .increase_merchant_marine()
    })
    .unwrap();
}
