//! Native transition differentials for civilian and ownership phase boundaries.

use imperialism_core::*;
use imperialism_testkit::compare_native;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct EmptyCase {}

#[derive(Debug, Deserialize)]
struct ProvinceOwnerCase {
    province: ProvinceId,
    new_owner: NationId,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn civilians_phase() {
    compare_native("civilians_phase", |state, _: EmptyCase| {
        state.do_civilians();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn province_loss_with_stationed_unit() {
    compare_native(
        "province_loss_with_stationed_unit",
        |state, case: ProvinceOwnerCase| {
            state.change_province_owner(case.province, case.new_owner);
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn province_owner_ocean_context() {
    compare_native(
        "province_owner_ocean_context",
        |state, case: ProvinceOwnerCase| {
            state.change_province_owner(case.province, case.new_owner);
        },
    )
    .unwrap();
}
