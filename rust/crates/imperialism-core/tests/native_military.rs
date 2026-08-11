//! Native transition differentials for recruitment, maintenance, and civilian work.

use imperialism_core::*;
use imperialism_testkit::compare_native;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NationCase {
    nation: MajorNationId,
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
