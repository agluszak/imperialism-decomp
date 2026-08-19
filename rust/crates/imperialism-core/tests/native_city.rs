//! Native transition differentials for city production rules.

use imperialism_core::*;
use imperialism_testkit::compare_native;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CityItemOrderCase {
    nation: MajorNationId,
    output: ManufacturedItem,
    quantity: i32,
}

#[derive(Debug, Deserialize)]
struct PowerPlantUpgradeCase {
    nation: MajorNationId,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct NationCase {
    nation: MajorNationId,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn city_item_order_increase() {
    compare_native(
        "city_item_order_increase",
        |state, case: CityItemOrderCase| {
            matches!(
                state.set_city_order_quantity(
                    case.nation,
                    CityOrderId::Item(case.output),
                    case.quantity,
                ),
                CityOrderUpdate::Applied
            )
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn city_item_order_decrease() {
    compare_native(
        "city_item_order_decrease",
        |state, case: CityItemOrderCase| {
            matches!(
                state.set_city_order_quantity(
                    case.nation,
                    CityOrderId::Item(case.output),
                    case.quantity,
                ),
                CityOrderUpdate::Applied
            )
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn power_plant_upgrade() {
    compare_native(
        "power_plant_upgrade",
        |state, case: PowerPlantUpgradeCase| {
            state.set_power_plant_upgrade(case.nation, case.enabled);
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn created_items_phase() {
    compare_native("created_items_phase", |state, case: NationCase| {
        state.add_created_items(case.nation);
    })
    .unwrap();
}
