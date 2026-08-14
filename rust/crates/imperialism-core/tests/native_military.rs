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

#[test]
#[ignore = "requires the native C++ oracle"]
fn military_phase_supported_subset() {
    compare_native("military_phase_supported_subset", |state, _: EmptyCase| {
        state.do_military();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn advisory_map_missions_case16() {
    compare_native("advisory_map_missions_case16", |state, _: EmptyCase| {
        for index in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(index);
            if state.nations().major(nation).kind != MajorNationKind::AutoGreatPower {
                continue;
            }
            if matches!(
                state.nations().country_status(nation.nation()),
                Some(CountryStatus::ProtectorateOf(_))
            ) {
                continue;
            }
            state.select_and_queue_advisory_map_missions_case16(nation);
        }
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn combat_moves_uncontested() {
    compare_native("combat_moves_uncontested", |state, _: EmptyCase| {
        state.do_combat_moves()
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn combat_moves_creates_battle() {
    compare_native("combat_moves_creates_battle", |state, _: EmptyCase| {
        state.do_combat_moves()
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn military_cleanup_supported_subset() {
    compare_native(
        "military_cleanup_supported_subset",
        |state, _: EmptyCase| {
            state.do_military_cleanup();
        },
    )
    .unwrap();
}
