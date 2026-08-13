#![cfg(test)]

use super::*;
use crate::*;

fn set_item_quantity(
    order: &mut RequestedCityOrderState,
    city: &mut CityState,
    item: ManufacturedItem,
    quantity: i16,
) -> bool {
    let limit = item_limit(order, city, item);
    super::set_item_quantity(
        order,
        &mut city.stockpile,
        &mut city.population,
        &mut city.production_accum,
        item,
        limit,
        quantity,
    )
}

fn set_food_processing_quantity(
    progress: &mut ProductionProgress,
    city: &mut CityState,
    quantity: i16,
) -> bool {
    let maximum = food_processing_max_order(progress, city);
    super::set_food_processing_quantity(
        progress,
        &mut city.stockpile,
        &mut city.population,
        maximum,
        quantity,
    )
}

fn set_population_growth_quantity(
    progress: &mut ProductionProgress,
    city: &mut CityState,
    quantity: i16,
) -> bool {
    let limit = population_growth_limit(progress, city);
    super::set_population_growth_quantity(
        progress,
        &mut city.stockpile,
        &mut city.production_accum,
        limit,
        quantity,
    )
}

fn set_expansion_quantity(
    order: &mut RequestedCityOrderState,
    city: &mut CityState,
    primary: ResourceKind,
    secondary: ResourceKind,
    quantity: i16,
) -> bool {
    let maximum = expansion_max_order(order, city, primary, secondary);
    super::set_expansion_quantity(
        order,
        &mut city.stockpile,
        primary,
        secondary,
        maximum,
        quantity,
    )
}

fn set_power_plant_quantity(
    order: &mut PowerPlantOrderState,
    city: &mut CityState,
    quantity: i16,
) -> bool {
    let maximum = power_plant_max_order(order, city);
    super::set_power_plant_quantity(
        order,
        &mut city.stockpile,
        &mut city.population,
        &mut city.power_available,
        maximum,
        quantity,
    )
}

fn set_training_quantity(
    level: TrainingLevel,
    progress: &mut ProductionProgress,
    city: &mut CityState,
    owner: &GreatPowerState,
    treasury: &mut i32,
    quantity: i16,
) -> bool {
    let limit = training_limit(level, progress, city, owner, *treasury);
    super::set_training_quantity(
        level,
        progress,
        &mut city.stockpile,
        &mut city.population,
        treasury,
        limit,
        quantity,
    )
}

fn set_recruit_quantity(
    progress: &mut ProductionProgress,
    spec: RecruitmentOrderSpec,
    city: &mut CityState,
    owner: &GreatPowerState,
    treasury: &mut i32,
    quantity: i16,
) -> bool {
    let limit = recruit_limit(progress, spec, city, owner, *treasury);
    super::set_recruit_quantity(
        progress,
        spec,
        &mut city.stockpile,
        &mut city.population,
        treasury,
        limit,
        quantity,
    )
}

fn slot(value: u8) -> CityFacilitySlot {
    CityFacilitySlot::from_index(value).unwrap()
}

fn city() -> CityState {
    let mut city = crate::test_support::city();
    city.population.strength = 10;
    city
}

fn nation() -> GreatPowerState {
    crate::test_support::great_power_state()
}

fn item_state() -> RequestedCityOrderState {
    RequestedCityOrderState::default()
}

#[test]
fn max_order_records_capacity_workforce_and_resource_constraints() {
    let mut state = city();
    let production = item_state();
    let lumber = ManufacturedItem::Lumber;
    state.production_accum[CityFacilitySlot::LumberMill] = 4;
    state.stockpile[ResourceKind::Timber] = 20;
    assert_eq!(
        item_limit(&production, &state, lumber),
        OrderLimit {
            maximum: 4,
            constraint: ProductionConstraint::Capacity,
        }
    );

    state.production_accum[CityFacilitySlot::LumberMill] = 20;
    assert_eq!(
        item_limit(&production, &state, lumber),
        OrderLimit {
            maximum: 5,
            constraint: ProductionConstraint::Workforce,
        }
    );

    state.population.strength = 30;
    state.stockpile[ResourceKind::Timber] = 8;
    assert_eq!(
        item_limit(&production, &state, lumber),
        OrderLimit {
            maximum: 4,
            constraint: ProductionConstraint::Resources,
        }
    );

    let two_input = item_state();
    let steel = ManufacturedItem::Steel;
    state.production_accum[CityFacilitySlot::SteelMill] = 20;
    state.stockpile[ResourceKind::Iron] = 9;
    state.stockpile[ResourceKind::Coal] = 3;
    assert_eq!(
        item_limit(&two_input, &state, steel),
        OrderLimit {
            maximum: 3,
            constraint: ProductionConstraint::Resources,
        }
    );
}

#[test]
fn game_state_adjusts_the_authoritative_steel_order_and_releases_it() {
    let mut game = crate::test_support::game_state();
    let nation = MajorNationId::new(6);
    {
        let city = &mut game.nations.major_mut(nation).city;
        city.production_accum[CityFacilitySlot::SteelMill] = 1;
        city.stockpile[ResourceKind::Iron] = 1;
        city.stockpile[ResourceKind::Coal] = 1;
    }

    assert!(game.adjust_city_order(nation, CityOrderId::Item(ManufacturedItem::Steel), 1));
    let city = game.nations.city(nation);
    let steel = &city.orders.items[ManufacturedItem::Steel];
    assert_eq!(steel.progress.quantity, 1);
    assert_eq!(steel.requested_quantity, 1);
    assert_eq!(steel.tracking_by_resource[ResourceKind::Iron], 1);
    assert_eq!(steel.tracking_by_resource[ResourceKind::Coal], 1);
    assert_eq!(city.stockpile[ResourceKind::Iron], 0);
    assert_eq!(city.stockpile[ResourceKind::Coal], 0);
    assert_eq!(city.population.strength, 10);
    assert_eq!(city.production_accum[CityFacilitySlot::SteelMill], 0);

    assert!(game.adjust_city_order(nation, CityOrderId::Item(ManufacturedItem::Steel), -1));
    let city = game.nations.city(nation);
    let steel = &city.orders.items[ManufacturedItem::Steel];
    assert_eq!(steel.progress.quantity, 0);
    assert_eq!(steel.requested_quantity, 0);
    assert_eq!(steel.tracking_by_resource[ResourceKind::Iron], 0);
    assert_eq!(steel.tracking_by_resource[ResourceKind::Coal], 0);
    assert_eq!(city.stockpile[ResourceKind::Iron], 1);
    assert_eq!(city.stockpile[ResourceKind::Coal], 1);
    assert_eq!(city.population.strength, 12);
    assert_eq!(city.production_accum[CityFacilitySlot::SteelMill], 1);
}

#[test]
fn rejected_quantity_keeps_reservations_unchanged() {
    let mut state = city();
    let mut production = item_state();
    let lumber = ManufacturedItem::Lumber;
    state.production_accum[CityFacilitySlot::LumberMill] = 1;
    state.stockpile[ResourceKind::Timber] = 20;
    assert!(!set_item_quantity(&mut production, &mut state, lumber, 2));
    assert_eq!(production.progress.quantity, 0);
    assert_eq!(state.stockpile[ResourceKind::Timber], 20);
    assert_eq!(state.population.strength, 10);
    assert_eq!(state.production_accum[CityFacilitySlot::LumberMill], 1);
    assert_eq!(
        production.progress.limiting_constraint,
        ProductionConstraint::Capacity
    );
}

#[test]
fn produce_restores_capacity_creates_output_and_clears_reservations() {
    let mut state = city();
    let mut production = item_state();
    let steel = ManufacturedItem::Steel;
    state.production_accum[CityFacilitySlot::SteelMill] = 10;
    state.stockpile[ResourceKind::Iron] = 5;
    state.stockpile[ResourceKind::Coal] = 4;
    set_item_quantity(&mut production, &mut state, steel, 1);

    produce_item(
        &mut production,
        &mut state.stockpile,
        &mut state.production_accum,
        &mut state.rolling_item_production_score,
        steel,
    );
    assert_eq!(state.production_accum[CityFacilitySlot::SteelMill], 10);
    assert_eq!(state.stockpile[ResourceKind::Steel], 1);
    assert_eq!(state.rolling_item_production_score, 1);
    assert_eq!(production.tracking_by_resource[ResourceKind::Iron], 0);
    assert_eq!(production.tracking_by_resource[ResourceKind::Coal], 0);
    assert_eq!(production.accumulated_value, 1);
}

#[test]
fn resource_limited_restock_preserves_the_requested_quantity() {
    let mut state = city();
    let mut production = item_state();
    let lumber = ManufacturedItem::Lumber;
    production.progress.quantity = 5;
    production.requested_quantity = 5;
    state.population.strength = 20;
    state.production_accum[CityFacilitySlot::LumberMill] = 5;
    state.stockpile[ResourceKind::Timber] = 4;

    assert!(restock_item(
        &mut production,
        &mut state.stockpile,
        &mut state.population,
        &mut state.production_accum,
        lumber,
    ));
    assert_eq!(production.progress.quantity, 2);
    assert_eq!(production.requested_quantity, 5);
    assert_eq!(state.stockpile[ResourceKind::Timber], 0);
    assert_eq!(state.population.strength, 16);
    assert_eq!(state.production_accum[CityFacilitySlot::LumberMill], 3);
    assert_eq!(
        production.progress.limiting_constraint,
        ProductionConstraint::Resources
    );
}

#[test]
fn either_inputs_shift_shortfalls_and_reverse_the_tracked_split() {
    let mut state = city();
    let mut production = item_state();
    let fabric = ManufacturedItem::Fabric;
    state.population.strength = 20;
    state.production_accum[CityFacilitySlot::TextileMill] = 10;
    state.stockpile[ResourceKind::Wool] = 1;
    state.stockpile[ResourceKind::Cotton] = 10;

    assert_eq!(item_limit(&production, &state, fabric).maximum, 5);
    assert!(set_item_quantity(&mut production, &mut state, fabric, 3));
    assert_eq!(state.stockpile[ResourceKind::Wool], 0);
    assert_eq!(state.stockpile[ResourceKind::Cotton], 5);
    assert_eq!(production.tracking_by_resource[ResourceKind::Wool], 1);
    assert_eq!(production.tracking_by_resource[ResourceKind::Cotton], 5);

    assert!(set_item_quantity(&mut production, &mut state, fabric, 1));
    assert_eq!(state.stockpile[ResourceKind::Wool], 1);
    assert_eq!(state.stockpile[ResourceKind::Cotton], 8);
    assert_eq!(production.tracking_by_resource[ResourceKind::Wool], 0);
    assert_eq!(production.tracking_by_resource[ResourceKind::Cotton], 2);
    assert_eq!(state.population.strength, 18);
    assert_eq!(state.production_accum[CityFacilitySlot::TextileMill], 9);

    produce_item(
        &mut production,
        &mut state.stockpile,
        &mut state.production_accum,
        &mut state.rolling_item_production_score,
        fabric,
    );
    assert_eq!(production.tracking_by_resource[ResourceKind::Cotton], 0);
}

#[test]
fn either_inputs_shift_a_secondary_shortfall_to_the_primary_input() {
    let mut state = city();
    let mut production = item_state();
    let fabric = ManufacturedItem::Fabric;
    state.population.strength = 20;
    state.production_accum[CityFacilitySlot::TextileMill] = 10;
    state.stockpile[ResourceKind::Wool] = 10;
    state.stockpile[ResourceKind::Cotton] = 1;

    assert!(set_item_quantity(&mut production, &mut state, fabric, 3));
    assert_eq!(state.stockpile[ResourceKind::Wool], 5);
    assert_eq!(state.stockpile[ResourceKind::Cotton], 0);
    assert_eq!(production.tracking_by_resource[ResourceKind::Wool], 5);
    assert_eq!(production.tracking_by_resource[ResourceKind::Cotton], 1);
}

#[test]
fn food_processing_limit_uses_grain_fruit_animals_and_workforce() {
    let mut state = city();
    let production = ProductionProgress::default();
    state.stockpile[ResourceKind::Grain] = 10;
    state.stockpile[ResourceKind::Fruit] = 4;
    state.stockpile[ResourceKind::Fish] = 1;
    state.stockpile[ResourceKind::Livestock] = 2;
    state.population.strength = 10;
    assert_eq!(food_processing_max_order(&production, &state), 6);
}

#[test]
fn food_processing_rounds_even_and_consumes_livestock_before_fish() {
    let mut state = city();
    let mut production = ProductionProgress::default();
    state.stockpile[ResourceKind::Grain] = 10;
    state.stockpile[ResourceKind::Fruit] = 5;
    state.stockpile[ResourceKind::Fish] = 3;
    state.stockpile[ResourceKind::Livestock] = 1;
    state.population.strength = 10;

    assert!(set_food_processing_quantity(&mut production, &mut state, 3));
    assert_eq!(production.quantity, 4);
    assert_eq!(state.stockpile[ResourceKind::Grain], 6);
    assert_eq!(state.stockpile[ResourceKind::Fruit], 3);
    assert_eq!(state.stockpile[ResourceKind::Livestock], 0);
    assert_eq!(state.stockpile[ResourceKind::Fish], 2);
    assert_eq!(state.population.strength, 6);

    assert!(set_food_processing_quantity(&mut production, &mut state, 1));
    assert_eq!(production.quantity, 2);
    assert_eq!(state.stockpile[ResourceKind::Grain], 8);
    assert_eq!(state.stockpile[ResourceKind::Fruit], 4);
    assert_eq!(state.stockpile[ResourceKind::Livestock], 1);
    assert_eq!(state.stockpile[ResourceKind::Fish], 2);
    assert_eq!(state.population.strength, 8);
}

#[test]
fn food_processing_accepts_minus_one_as_zero_after_retail_rounding() {
    let mut state = city();
    let mut production = ProductionProgress::default();
    assert!(set_food_processing_quantity(
        &mut production,
        &mut state,
        -1
    ));
    assert_eq!(production.quantity, 0);
    assert_eq!(state.population.strength, 10);
}

#[test]
fn food_processing_produces_canned_food_and_clears_the_order() {
    let mut state = city();
    let mut production = ProductionProgress {
        quantity: 4,
        limiting_constraint: ProductionConstraint::Resources,
    };
    produce_food_processing(&mut production, &mut state.stockpile);
    assert_eq!(state.stockpile[ResourceKind::Food], 4);
    assert_eq!(production.quantity, 0);
}

#[test]
fn population_growth_selects_resource_then_capacity_limits() {
    let mut state = city();
    let production = ProductionProgress::default();
    state.stockpile[ResourceKind::Furniture] = 3;
    state.stockpile[ResourceKind::Clothing] = 2;
    state.stockpile[ResourceKind::Food] = 4;
    state.production_accum[slot(15)] = 10;
    assert_eq!(
        population_growth_limit(&production, &state),
        OrderLimit {
            maximum: 2,
            constraint: ProductionConstraint::Resources,
        }
    );

    state.production_accum[slot(15)] = 1;
    assert_eq!(
        population_growth_limit(&production, &state),
        OrderLimit {
            maximum: 1,
            constraint: ProductionConstraint::Capacity,
        }
    );
}

#[test]
fn population_growth_quantity_reserves_and_refunds_all_inputs() {
    let mut state = city();
    let mut production = ProductionProgress::default();
    state.stockpile[ResourceKind::Furniture] = 3;
    state.stockpile[ResourceKind::Clothing] = 3;
    state.stockpile[ResourceKind::Food] = 3;
    state.production_accum[slot(15)] = 3;

    assert!(set_population_growth_quantity(
        &mut production,
        &mut state,
        2
    ));
    assert_eq!(state.stockpile[ResourceKind::Furniture], 1);
    assert_eq!(state.stockpile[ResourceKind::Clothing], 1);
    assert_eq!(state.stockpile[ResourceKind::Food], 1);
    assert_eq!(state.production_accum[slot(15)], 1);

    assert!(set_population_growth_quantity(
        &mut production,
        &mut state,
        1
    ));
    assert_eq!(state.stockpile[ResourceKind::Furniture], 2);
    assert_eq!(state.stockpile[ResourceKind::Clothing], 2);
    assert_eq!(state.stockpile[ResourceKind::Food], 2);
    assert_eq!(state.production_accum[slot(15)], 2);
}

#[test]
fn population_growth_produces_low_skill_population_and_refreshes_capacity() {
    let mut state = city();
    let mut owner = nation();
    let mut production = ProductionProgress {
        quantity: 2,
        limiting_constraint: ProductionConstraint::Resources,
    };
    owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
        crate::PendingActionState::new(crate::PendingActionStatus::Level3, None);
    let float_count = state.population.accumulator;

    produce_population_growth(
        &mut production,
        &mut state.population,
        &mut state.production_accum,
        &owner,
        12,
    );
    assert_eq!(state.population.baseline_labor.low, 6);
    assert_eq!(state.population.production_labor.low, 6);
    assert_eq!(state.population.count, 9);
    assert_eq!(state.population.accumulator, float_count);
    assert_eq!(state.production_accum[slot(15)], 4);
    assert_eq!(production.quantity, 0);
}

fn capacity_order() -> RequestedCityOrderState {
    RequestedCityOrderState::default()
}

fn expansion_order() -> RequestedCityOrderState {
    RequestedCityOrderState::default()
}

#[test]
fn capacity_order_transport_target_increases_the_nation_capacity() {
    let mut owner = nation();
    let mut production = capacity_order();
    production.progress.quantity = 3;
    production.requested_quantity = 3;
    production.tracking_by_resource[ResourceKind::Lumber] = 3;
    production.tracking_by_resource[ResourceKind::Steel] = 3;
    owner.capacities.transport = 4;

    produce_transport_capacity(
        &mut production,
        &mut owner,
        ResourceKind::Lumber,
        ResourceKind::Steel,
    );
    assert_eq!(owner.capacities.transport, 7);
    assert_eq!(production.progress.quantity, 0);
}

#[test]
fn expansion_order_reserves_only_its_two_material_inputs() {
    let mut state = city();
    let mut production = expansion_order();
    state.stockpile[ResourceKind::Lumber] = 3;
    state.stockpile[ResourceKind::Steel] = 2;
    state.production_accum[slot(14)] = 9;

    assert_eq!(
        expansion_max_order(
            &production,
            &state,
            ResourceKind::Lumber,
            ResourceKind::Steel,
        ),
        2
    );
    assert!(set_expansion_quantity(
        &mut production,
        &mut state,
        ResourceKind::Lumber,
        ResourceKind::Steel,
        2,
    ));
    assert_eq!(state.stockpile[ResourceKind::Lumber], 1);
    assert_eq!(state.stockpile[ResourceKind::Steel], 0);
    assert_eq!(state.population.strength, 10);
    assert_eq!(state.production_accum[slot(14)], 9);

    assert!(set_expansion_quantity(
        &mut production,
        &mut state,
        ResourceKind::Lumber,
        ResourceKind::Steel,
        1,
    ));
    assert_eq!(state.stockpile[ResourceKind::Lumber], 2);
    assert_eq!(state.stockpile[ResourceKind::Steel], 1);
}

#[test]
fn expansion_production_increases_facility_capacity() {
    let mut state = city();
    let mut production = expansion_order();
    state.production_orders[slot(2)] = 4;
    state.production_accum[slot(2)] = 7;
    production.progress.quantity = 2;
    production.requested_quantity = 2;
    production.tracking_by_resource[ResourceKind::Lumber] = 2;
    production.tracking_by_resource[ResourceKind::Steel] = 2;

    produce_expansion(
        &mut production,
        &mut state.production_orders,
        &mut state.production_accum,
        ExpandableFacility::SteelMill,
        ResourceKind::Lumber,
        ResourceKind::Steel,
    );
    assert_eq!(state.production_orders[slot(2)], 6);
    assert_eq!(state.production_accum[slot(2)], 9);
    assert_eq!(production.progress.quantity, 0);
    assert_eq!(production.requested_quantity, 0);
    assert_eq!(production.tracking_by_resource[ResourceKind::Lumber], 0);
    assert_eq!(production.tracking_by_resource[ResourceKind::Steel], 0);
}

#[test]
fn power_plant_limit_counts_each_fuel_unit_as_six_power() {
    let mut state = city();
    let production = PowerPlantOrderState {
        progress: ProductionProgress {
            quantity: 5,
            limiting_constraint: ProductionConstraint::Resources,
        },
        desired_quantity: 0,
    };
    state.stockpile[ResourceKind::Fuel] = 3;
    assert_eq!(power_plant_max_order(&production, &state), 23);
}

#[test]
fn power_plant_quantity_reserves_and_refunds_fuel_with_truncating_division() {
    let mut state = city();
    let mut production = PowerPlantOrderState::default();
    state.stockpile[ResourceKind::Fuel] = 3;

    assert!(set_power_plant_quantity(&mut production, &mut state, 13));
    assert_eq!(state.stockpile[ResourceKind::Fuel], 1);
    assert_eq!(production.desired_quantity, 13);
    assert_eq!(state.power_available, 13);
    assert_eq!(state.population.extra, 13);
    assert_eq!(state.population.strength, 23);

    assert!(set_power_plant_quantity(&mut production, &mut state, 6));
    assert_eq!(state.stockpile[ResourceKind::Fuel], 2);
    assert_eq!(production.desired_quantity, 6);
    assert_eq!(state.power_available, 6);
    assert_eq!(state.population.extra, 6);
    assert_eq!(state.population.strength, 16);
}

#[test]
fn power_plant_rejects_a_reduction_that_exceeds_available_strength() {
    let mut state = city();
    let mut production = PowerPlantOrderState {
        progress: ProductionProgress {
            quantity: 6,
            limiting_constraint: ProductionConstraint::Resources,
        },
        desired_quantity: 6,
    };
    state.stockpile[ResourceKind::Fuel] = 2;
    state.population.strength = 2;
    state.population.extra = 6;
    state.power_available = 6;
    let expected_state = state.clone();

    assert!(!set_power_plant_quantity(&mut production, &mut state, 0));
    assert_eq!(production.progress.quantity, 6);
    assert_eq!(production.desired_quantity, 6);
    assert_eq!(state, expected_state);
}

#[test]
fn power_plant_restock_clamps_but_preserves_the_desired_quantity() {
    let mut state = city();
    let mut production = PowerPlantOrderState {
        progress: ProductionProgress::default(),
        desired_quantity: 15,
    };
    state.stockpile[ResourceKind::Fuel] = 2;

    assert!(restock_power_plant(
        &mut production,
        &mut state.stockpile,
        &mut state.population,
        &mut state.power_available,
    ));
    assert_eq!(production.progress.quantity, 12);
    assert_eq!(production.desired_quantity, 15);
    assert_eq!(state.stockpile[ResourceKind::Fuel], 0);
    assert_eq!(state.power_available, 12);
    assert_eq!(state.population.extra, 12);
    assert_eq!(state.population.strength, 22);
}

#[test]
fn training_limits_record_workforce_treasury_resources_and_the_global_cap() {
    let mut state = city();
    let mut owner = nation();
    let mut medium = ProductionProgress::default();
    state.stockpile[ResourceKind::Paper] = 10;
    assert_eq!(
        training_limit(TrainingLevel::Medium, &medium, &state, &owner, 10_000),
        OrderLimit {
            maximum: 4,
            constraint: ProductionConstraint::Workforce,
        }
    );
    assert_eq!(
        training_limit(TrainingLevel::Medium, &medium, &state, &owner, i32::MAX).maximum,
        4
    );

    assert_eq!(
        training_limit(TrainingLevel::Medium, &medium, &state, &owner, 150),
        OrderLimit {
            maximum: 1,
            constraint: ProductionConstraint::Treasury,
        }
    );

    state.stockpile[ResourceKind::Paper] = 0;
    assert_eq!(
        training_limit(TrainingLevel::Medium, &medium, &state, &owner, 10_000),
        OrderLimit {
            maximum: 0,
            constraint: ProductionConstraint::Resources,
        }
    );

    owner.controller = crate::MajorNationController::Computer;
    state.stockpile[ResourceKind::Paper] = 100;
    medium.quantity = 98;
    assert_eq!(
        training_limit(TrainingLevel::Medium, &medium, &state, &owner, -50_000).maximum,
        99
    );

    let high = ProductionProgress::default();
    assert_eq!(
        training_limit(TrainingLevel::High, &high, &state, &owner, 0),
        OrderLimit {
            maximum: 2,
            constraint: ProductionConstraint::Workforce,
        }
    );
}

#[test]
fn training_quantity_reserves_and_refunds_paper_cash_and_workers() {
    let mut state = city();
    let owner = nation();
    let mut treasury = 1_000;
    let mut production = ProductionProgress::default();
    state.stockpile[ResourceKind::Paper] = 10;

    assert!(set_training_quantity(
        TrainingLevel::Medium,
        &mut production,
        &mut state,
        &owner,
        &mut treasury,
        2,
    ));
    assert_eq!(state.stockpile[ResourceKind::Paper], 8);
    assert_eq!(treasury, 800);
    assert_eq!(state.population.production_labor.low, 2);
    assert_eq!(state.population.strength, 8);

    assert!(set_training_quantity(
        TrainingLevel::Medium,
        &mut production,
        &mut state,
        &owner,
        &mut treasury,
        1,
    ));
    assert_eq!(state.stockpile[ResourceKind::Paper], 9);
    assert_eq!(treasury, 900);
    assert_eq!(state.population.production_labor.low, 3);
    assert_eq!(state.population.strength, 9);
}

#[test]
fn high_training_uses_two_paper_and_one_thousand_cash_per_worker() {
    let mut state = city();
    let owner = nation();
    let mut treasury = 3_000;
    let mut production = ProductionProgress::default();
    state.stockpile[ResourceKind::Paper] = 6;

    assert!(set_training_quantity(
        TrainingLevel::High,
        &mut production,
        &mut state,
        &owner,
        &mut treasury,
        2,
    ));
    assert_eq!(state.stockpile[ResourceKind::Paper], 2);
    assert_eq!(treasury, 1_000);
    assert_eq!(state.population.production_labor.medium, 0);
    assert_eq!(state.population.strength, 6);
}

#[test]
fn training_production_promotes_the_requested_baseline_workers() {
    let mut state = city();
    let mut owner = nation();
    let mut medium = ProductionProgress {
        quantity: 2,
        limiting_constraint: ProductionConstraint::Resources,
    };

    produce_training(
        TrainingLevel::Medium,
        &mut medium,
        &mut state.population,
        &mut owner,
    );
    assert_eq!(state.population.baseline_labor.low, 2);
    assert_eq!(state.population.baseline_labor.medium, 4);
    assert_eq!(medium.quantity, 0);

    owner.pending_actions[PendingActionKind::UniversityExpansion] =
        crate::PendingActionState::new(crate::PendingActionStatus::Level3, None);
    state.population.baseline_labor.high = 29;
    let mut high = ProductionProgress {
        quantity: 1,
        limiting_constraint: ProductionConstraint::Resources,
    };
    produce_training(
        TrainingLevel::High,
        &mut high,
        &mut state.population,
        &mut owner,
    );
    assert_eq!(state.population.baseline_labor.medium, 3);
    assert_eq!(state.population.baseline_labor.high, 30);
    assert_eq!(
        owner.pending_actions[PendingActionKind::UniversityExpansion].status(),
        crate::PendingActionStatus::Queued
    );
    assert_eq!(
        owner.pending_actions[PendingActionKind::UniversityExpansion].payload(),
        Some(3)
    );
    assert_eq!(high.quantity, 0);
}

#[test]
fn high_training_preserves_the_retail_pending_action_threshold_order() {
    let mut state = city();
    let mut owner = nation();
    state.population.baseline_labor.high = 29;
    let mut production = ProductionProgress {
        quantity: 1,
        limiting_constraint: ProductionConstraint::Resources,
    };

    produce_training(
        TrainingLevel::High,
        &mut production,
        &mut state.population,
        &mut owner,
    );
    assert_eq!(
        owner.pending_actions[PendingActionKind::UniversityExpansion].status(),
        crate::PendingActionStatus::Queued
    );
    assert_eq!(
        owner.pending_actions[PendingActionKind::UniversityExpansion].payload(),
        Some(2)
    );
}

#[test]
fn zero_training_order_leaves_state_untouched() {
    let mut state = city();
    let mut owner = nation();
    let mut production = ProductionProgress::default();
    let expected_state = state.clone();
    let expected_owner = owner.clone();

    produce_training(
        TrainingLevel::High,
        &mut production,
        &mut state.population,
        &mut owner,
    );
    assert_eq!(state, expected_state);
    assert_eq!(owner, expected_owner);
}

struct TestRecruitOrder {
    primary: ResourceCost,
    secondary: Option<ResourceCost>,
    cash_per_unit: i16,
    workforce: SkillBand,
    progress: ProductionProgress,
}

impl TestRecruitOrder {
    fn spec(&self) -> RecruitmentOrderSpec {
        RecruitmentOrderSpec {
            primary: self.primary,
            secondary: self.secondary,
            cash_per_unit: self.cash_per_unit,
            workforce: self.workforce,
        }
    }
}

fn unit_order(workforce: SkillBand) -> TestRecruitOrder {
    TestRecruitOrder {
        primary: ResourceCost::new(ResourceKind::Paper, 2),
        secondary: Some(ResourceCost::new(ResourceKind::Steel, 1)),
        cash_per_unit: 100,
        workforce,
        progress: ProductionProgress::default(),
    }
}

#[test]
fn unit_order_supports_each_retail_workforce_mode() {
    let mut state = city();
    let mut owner = nation();
    owner.controller = crate::MajorNationController::Computer;
    state.stockpile[ResourceKind::Paper] = 200;
    state.stockpile[ResourceKind::Steel] = 200;

    for (workforce, expected) in [
        (SkillBand::Low, 4),
        (SkillBand::Medium, 2),
        (SkillBand::High, 1),
    ] {
        let production = unit_order(workforce);
        assert_eq!(
            recruit_limit(&production.progress, production.spec(), &state, &owner, -1),
            OrderLimit {
                maximum: expected,
                constraint: ProductionConstraint::Workforce,
            }
        );
    }
}

#[test]
fn unit_order_records_primary_secondary_and_treasury_limits() {
    let mut state = city();
    let owner = nation();
    let production = unit_order(SkillBand::Low);
    state.population.production_labor.low = 100;
    state.population.strength = 100;
    state.stockpile[ResourceKind::Paper] = 4;
    state.stockpile[ResourceKind::Steel] = 10;
    assert_eq!(
        recruit_limit(
            &production.progress,
            production.spec(),
            &state,
            &owner,
            i32::MAX,
        )
        .maximum,
        2
    );
    assert_eq!(
        recruit_limit(
            &production.progress,
            production.spec(),
            &state,
            &owner,
            10_000,
        ),
        OrderLimit {
            maximum: 2,
            constraint: ProductionConstraint::Resources,
        }
    );

    state.stockpile[ResourceKind::Paper] = 20;
    state.stockpile[ResourceKind::Steel] = 3;
    assert_eq!(
        recruit_limit(
            &production.progress,
            production.spec(),
            &state,
            &owner,
            10_000,
        ),
        OrderLimit {
            maximum: 3,
            constraint: ProductionConstraint::Resources,
        }
    );

    state.stockpile[ResourceKind::Steel] = 20;
    assert_eq!(
        recruit_limit(&production.progress, production.spec(), &state, &owner, 150,),
        OrderLimit {
            maximum: 1,
            constraint: ProductionConstraint::Treasury,
        }
    );
}

#[test]
fn unit_order_reserves_and_refunds_resources_population_and_cash() {
    let mut state = city();
    let owner = nation();
    let mut treasury = 1_000;
    let mut production = unit_order(SkillBand::Low);
    state.stockpile[ResourceKind::Paper] = 10;
    state.stockpile[ResourceKind::Steel] = 10;
    let spec = production.spec();

    assert!(set_recruit_quantity(
        &mut production.progress,
        spec,
        &mut state,
        &owner,
        &mut treasury,
        2,
    ));
    assert_eq!(state.stockpile[ResourceKind::Paper], 6);
    assert_eq!(state.stockpile[ResourceKind::Steel], 8);
    assert_eq!(treasury, 800);
    assert_eq!(state.population.baseline_labor.low, 2);
    assert_eq!(state.population.production_labor.low, 2);
    assert_eq!(state.population.count, 5);
    assert_eq!(state.population.count_float(), 5.0);
    assert_eq!(state.population.strength, 8);

    assert!(set_recruit_quantity(
        &mut production.progress,
        spec,
        &mut state,
        &owner,
        &mut treasury,
        1,
    ));
    assert_eq!(state.stockpile[ResourceKind::Paper], 8);
    assert_eq!(state.stockpile[ResourceKind::Steel], 9);
    assert_eq!(treasury, 900);
    assert_eq!(state.population.baseline_labor.low, 3);
    assert_eq!(state.population.production_labor.low, 3);
    assert_eq!(state.population.count, 6);
    assert_eq!(state.population.count_float(), 6.0);
    assert_eq!(state.population.strength, 9);
}

#[test]
fn unit_order_ignores_treasury_when_the_nation_is_not_eligible() {
    let mut state = city();
    let mut owner = nation();
    owner.controller = crate::MajorNationController::Computer;
    let production = unit_order(SkillBand::Low);
    state.population.production_labor.low = 100;
    state.population.strength = 100;
    state.stockpile[ResourceKind::Paper] = 12;
    state.stockpile[ResourceKind::Steel] = 12;

    assert_eq!(
        recruit_limit(
            &production.progress,
            production.spec(),
            &state,
            &owner,
            -10_000,
        ),
        OrderLimit {
            maximum: 6,
            constraint: ProductionConstraint::Resources,
        }
    );
}
