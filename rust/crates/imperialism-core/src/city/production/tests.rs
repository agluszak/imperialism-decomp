#![cfg(test)]

use super::*;
use crate::*;

fn slot(value: u8) -> CityFacilitySlot {
    CityFacilitySlot::from_index(value).unwrap()
}

fn city() -> CityState {
    CityState {
        orders: Box::default(),
        power_plant_upgrade_queued: false,
        food_substitution_count: 0,
        starvation_population_loss: 0,
        serialized_state: 0,
        phase_counter: 0,
        military_recruit_count_by_kind: crate::MilitaryUnitTable::default(),
        civilian_recruit_count_by_kind: crate::CivilianUnitTable::default(),
        ship_order_count_by_type: crate::ShipTypeTable::default(),
        rolling_item_production_score: 0,
        low_production: false,
        low_stock: false,
        reserved_by_type: crate::ResourceTable::default(),
        home_town: Some(crate::TownState::for_frog_city(crate::TileId::new(1))),
        power_available: 0,
        stockpile: crate::Stockpile::default(),
        production_orders: crate::ProductionTable::default(),
        production_accum: crate::ProductionTable::default(),
        production_flags: crate::ProductionTable::default(),
        production_current: crate::ProductionTable::default(),
        production_progress: crate::ProductionTable::default(),
        population_growth_penalty_ticks: 0,
        unmet_resource_retries: crate::ResourceTable::default(),
        consumed_production_input_by_type: crate::ResourceTable::default(),
        population: PopulationState {
            count: 7,
            accumulator: crate::PopulationAccumulator::from_bits(7.0_f32.to_bits()),
            strength: 10,
            extra: 0,
            strike_phase: crate::StrikePhase::default(),
            baseline_labor: LaborPool::new(4, 2, 1),
            production_labor: LaborPool::new(4, 2, 1),
            pending_labor_delta: LaborPool::default(),
            predicted_need_by_resource: crate::ResourceTable::default(),
        },
    }
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
    let mut production = item_state();
    let lumber = item_order_spec(ManufacturedItem::Lumber);
    state.production_accum[CityFacilitySlot::LumberMill] = 4;
    state.stockpile[ResourceKind::Timber] = 20;
    assert_eq!(item_max_order(&mut production, &state, lumber), 4);
    assert_eq!(
        production.progress.limiting_constraint,
        ProductionConstraint::Capacity
    );

    state.production_accum[CityFacilitySlot::LumberMill] = 20;
    assert_eq!(item_max_order(&mut production, &state, lumber), 5);
    assert_eq!(
        production.progress.limiting_constraint,
        ProductionConstraint::Workforce
    );

    state.population.strength = 30;
    state.stockpile[ResourceKind::Timber] = 8;
    assert_eq!(item_max_order(&mut production, &state, lumber), 4);
    assert_eq!(
        production.progress.limiting_constraint,
        ProductionConstraint::Resources
    );

    let mut two_input = item_state();
    let steel = item_order_spec(ManufacturedItem::Steel);
    state.production_accum[CityFacilitySlot::SteelMill] = 20;
    state.stockpile[ResourceKind::Iron] = 9;
    state.stockpile[ResourceKind::Coal] = 3;
    assert_eq!(item_max_order(&mut two_input, &state, steel), 3);
    assert_eq!(
        two_input.progress.limiting_constraint,
        ProductionConstraint::Resources
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

    assert!(
        game.adjust_city_order(nation, CityOrderId::Item(ManufacturedItem::Steel), 1)
            .applied()
    );
    let city = game.nations.city(nation);
    let steel = city.orders.items[ResourceKind::Steel].as_ref().unwrap();
    assert_eq!(steel.progress.quantity, 1);
    assert_eq!(steel.requested_quantity, 1);
    assert_eq!(steel.progress.tracking_by_resource[ResourceKind::Iron], 1);
    assert_eq!(steel.progress.tracking_by_resource[ResourceKind::Coal], 1);
    assert_eq!(steel.progress.reserved_workforce, 2);
    assert_eq!(city.stockpile[ResourceKind::Iron], 0);
    assert_eq!(city.stockpile[ResourceKind::Coal], 0);
    assert_eq!(city.population.strength, 10);
    assert_eq!(city.production_accum[CityFacilitySlot::SteelMill], 0);

    assert!(
        game.adjust_city_order(nation, CityOrderId::Item(ManufacturedItem::Steel), -1)
            .applied()
    );
    let city = game.nations.city(nation);
    let steel = city.orders.items[ResourceKind::Steel].as_ref().unwrap();
    assert_eq!(steel.progress.quantity, 0);
    assert_eq!(steel.requested_quantity, 0);
    assert_eq!(steel.progress.tracking_by_resource[ResourceKind::Iron], 0);
    assert_eq!(steel.progress.tracking_by_resource[ResourceKind::Coal], 0);
    assert_eq!(steel.progress.reserved_workforce, 0);
    assert_eq!(city.stockpile[ResourceKind::Iron], 1);
    assert_eq!(city.stockpile[ResourceKind::Coal], 1);
    assert_eq!(city.population.strength, 12);
    assert_eq!(city.production_accum[CityFacilitySlot::SteelMill], 1);
}

#[test]
fn rejected_quantity_keeps_reservations_unchanged() {
    let mut state = city();
    let mut production = item_state();
    let lumber = item_order_spec(ManufacturedItem::Lumber);
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
    let steel = item_order_spec(ManufacturedItem::Steel);
    state.production_accum[CityFacilitySlot::SteelMill] = 10;
    state.stockpile[ResourceKind::Iron] = 5;
    state.stockpile[ResourceKind::Coal] = 4;
    set_item_quantity(&mut production, &mut state, steel, 1);

    produce_item(&mut production, &mut state, steel);
    assert_eq!(state.production_accum[CityFacilitySlot::SteelMill], 10);
    assert_eq!(state.stockpile[ResourceKind::Steel], 1);
    assert_eq!(state.rolling_item_production_score, 1);
    assert_eq!(
        production.progress.tracking_by_resource[ResourceKind::Iron],
        0
    );
    assert_eq!(
        production.progress.tracking_by_resource[ResourceKind::Coal],
        0
    );
    assert_eq!(production.progress.reserved_workforce, 0);
    assert_eq!(production.progress.accumulated_value, 1);
}

#[test]
fn resource_limited_restock_preserves_the_requested_quantity() {
    let mut state = city();
    let mut production = item_state();
    let lumber = item_order_spec(ManufacturedItem::Lumber);
    production.progress.quantity = 5;
    production.requested_quantity = 5;
    state.population.strength = 20;
    state.production_accum[CityFacilitySlot::LumberMill] = 5;
    state.stockpile[ResourceKind::Timber] = 4;

    assert!(restock_item(&mut production, &mut state, lumber));
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
    let fabric = item_order_spec(ManufacturedItem::Fabric);
    state.population.strength = 20;
    state.production_accum[CityFacilitySlot::TextileMill] = 10;
    state.stockpile[ResourceKind::Wool] = 1;
    state.stockpile[ResourceKind::Cotton] = 10;

    assert_eq!(item_max_order(&mut production, &state, fabric), 5);
    assert!(set_item_quantity(&mut production, &mut state, fabric, 3));
    assert_eq!(state.stockpile[ResourceKind::Wool], 0);
    assert_eq!(state.stockpile[ResourceKind::Cotton], 5);
    assert_eq!(
        production.progress.tracking_by_resource[ResourceKind::Wool],
        1
    );
    assert_eq!(
        production.progress.tracking_by_resource[ResourceKind::Cotton],
        5
    );

    assert!(set_item_quantity(&mut production, &mut state, fabric, 1));
    assert_eq!(state.stockpile[ResourceKind::Wool], 1);
    assert_eq!(state.stockpile[ResourceKind::Cotton], 8);
    assert_eq!(
        production.progress.tracking_by_resource[ResourceKind::Wool],
        0
    );
    assert_eq!(
        production.progress.tracking_by_resource[ResourceKind::Cotton],
        2
    );
    assert_eq!(state.population.strength, 18);
    assert_eq!(production.progress.reserved_workforce, 2);
    assert_eq!(state.production_accum[CityFacilitySlot::TextileMill], 9);

    produce_item(&mut production, &mut state, fabric);
    assert_eq!(
        production.progress.tracking_by_resource[ResourceKind::Cotton],
        0
    );
    assert_eq!(production.progress.reserved_workforce, 0);
}

#[test]
fn either_inputs_shift_a_secondary_shortfall_to_the_primary_input() {
    let mut state = city();
    let mut production = item_state();
    let fabric = item_order_spec(ManufacturedItem::Fabric);
    state.population.strength = 20;
    state.production_accum[CityFacilitySlot::TextileMill] = 10;
    state.stockpile[ResourceKind::Wool] = 10;
    state.stockpile[ResourceKind::Cotton] = 1;

    assert!(set_item_quantity(&mut production, &mut state, fabric, 3));
    assert_eq!(state.stockpile[ResourceKind::Wool], 5);
    assert_eq!(state.stockpile[ResourceKind::Cotton], 0);
    assert_eq!(
        production.progress.tracking_by_resource[ResourceKind::Wool],
        5
    );
    assert_eq!(
        production.progress.tracking_by_resource[ResourceKind::Cotton],
        1
    );
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
        reserved_workforce: 7,
        ..ProductionProgress::default()
    };
    produce_food_processing(&mut production, &mut state);
    assert_eq!(state.stockpile[ResourceKind::Food], 4);
    assert_eq!(production.quantity, 0);
    assert_eq!(production.reserved_workforce, 0);
}

#[test]
fn population_growth_selects_resource_then_capacity_limits() {
    let mut state = city();
    let mut production = ProductionProgress::default();
    state.stockpile[ResourceKind::Furniture] = 3;
    state.stockpile[ResourceKind::Clothing] = 2;
    state.stockpile[ResourceKind::Food] = 4;
    state.production_accum[slot(15)] = 10;
    assert_eq!(population_growth_max_order(&mut production, &state), 2);
    assert_eq!(
        production.limiting_constraint,
        ProductionConstraint::Resources
    );

    state.production_accum[slot(15)] = 1;
    assert_eq!(population_growth_max_order(&mut production, &state), 1);
    assert_eq!(
        production.limiting_constraint,
        ProductionConstraint::Capacity
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
        ..ProductionProgress::default()
    };
    owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
        crate::PendingActionState::new(crate::PendingActionStatus::Level3, None);
    let float_count = state.population.accumulator;

    produce_population_growth(&mut production, &mut state, &owner, 12);
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
fn capacity_order_uses_item_reservations_then_expands_a_production_slot() {
    let mut state = city();
    let mut production = capacity_order();
    state.stockpile[ResourceKind::Lumber] = 5;
    state.stockpile[ResourceKind::Steel] = 4;
    state.production_accum[slot(14)] = 10;
    state.production_orders[slot(3)] = 6;

    assert!(set_capacity_quantity(
        &mut production,
        &mut state,
        ResourceKind::Lumber,
        ResourceKind::Steel,
        CityFacilitySlot::Transport,
        2,
    ));
    assert_eq!(state.population.strength, 6);
    assert_eq!(state.production_accum[slot(14)], 8);
    produce_capacity(
        &mut production,
        &mut state,
        &mut nation(),
        CapacityTarget::Production(CityFacilitySlot::Metalworks),
        ResourceKind::Lumber,
        ResourceKind::Steel,
        0,
    );

    assert_eq!(state.production_orders[slot(3)], 8);
    assert_eq!(state.production_accum[slot(3)], 2);
    assert_eq!(production.progress.quantity, 0);
    assert_eq!(production.requested_quantity, 0);
    assert_eq!(production.progress.reserved_workforce, 0);
    assert_eq!(
        production.progress.tracking_by_resource[ResourceKind::Lumber],
        0
    );
    assert_eq!(
        production.progress.tracking_by_resource[ResourceKind::Steel],
        0
    );
}

#[test]
fn capacity_order_transport_target_increases_the_nation_capacity() {
    let mut state = city();
    let mut owner = nation();
    let mut production = capacity_order();
    production.progress.quantity = 3;
    production.requested_quantity = 3;
    production.progress.reserved_workforce = 6;
    production.progress.tracking_by_resource[ResourceKind::Lumber] = 3;
    production.progress.tracking_by_resource[ResourceKind::Steel] = 3;
    owner.capacities.transport = 4;

    produce_capacity(
        &mut production,
        &mut state,
        &mut owner,
        CapacityTarget::Transport,
        ResourceKind::Lumber,
        ResourceKind::Steel,
        0,
    );
    assert_eq!(owner.capacities.transport, 7);
    assert_eq!(state.production_orders, crate::ProductionTable::default());
    assert_eq!(production.progress.quantity, 0);
    assert_eq!(production.progress.reserved_workforce, 0);
}

#[test]
fn capacity_order_region_target_rebases_before_adding_the_order() {
    let mut state = city();
    let mut owner = nation();
    let mut production = capacity_order();
    production.progress.quantity = 2;
    owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
        crate::PendingActionState::new(crate::PendingActionStatus::Level3, None);
    state.production_orders[slot(15)] = 1;
    state.production_accum[slot(15)] = 3;

    produce_capacity(
        &mut production,
        &mut state,
        &mut owner,
        CapacityTarget::RegionalPopulation,
        ResourceKind::Lumber,
        ResourceKind::Steel,
        12,
    );
    assert_eq!(state.production_orders[slot(15)], 6);
    assert_eq!(state.production_accum[slot(15)], 8);
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
    assert_eq!(production.progress.reserved_workforce, 0);

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
fn expansion_production_keeps_the_unused_inherited_workforce_field() {
    let mut state = city();
    let owner = nation();
    let mut production = expansion_order();
    state.production_orders[slot(2)] = 4;
    state.production_accum[slot(2)] = 7;
    production.progress.quantity = 2;
    production.requested_quantity = 2;
    production.progress.reserved_workforce = 9;
    production.progress.tracking_by_resource[ResourceKind::Lumber] = 2;
    production.progress.tracking_by_resource[ResourceKind::Steel] = 2;

    produce_expansion(
        &mut production,
        &mut state,
        &owner,
        ExpansionTarget::Production(CityFacilitySlot::SteelMill),
        ResourceKind::Lumber,
        ResourceKind::Steel,
        0,
    );
    assert_eq!(state.production_orders[slot(2)], 6);
    assert_eq!(state.production_accum[slot(2)], 9);
    assert_eq!(production.progress.quantity, 0);
    assert_eq!(production.requested_quantity, 0);
    assert_eq!(production.progress.reserved_workforce, 9);
    assert_eq!(
        production.progress.tracking_by_resource[ResourceKind::Lumber],
        0
    );
    assert_eq!(
        production.progress.tracking_by_resource[ResourceKind::Steel],
        0
    );
}

#[test]
fn expansion_region_target_uses_the_retail_region_divisor() {
    let mut state = city();
    let mut owner = nation();
    let mut production = expansion_order();
    production.progress.quantity = 1;
    owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
        crate::PendingActionState::new(crate::PendingActionStatus::Queued, None);
    state.production_orders[slot(15)] = 8;
    state.production_accum[slot(15)] = 10;

    produce_expansion(
        &mut production,
        &mut state,
        &owner,
        ExpansionTarget::RegionalPopulation,
        ResourceKind::Lumber,
        ResourceKind::Steel,
        12,
    );
    assert_eq!(state.production_orders[slot(15)], 4);
    assert_eq!(state.production_accum[slot(15)], 6);
}

#[test]
fn zero_capacity_and_expansion_orders_do_not_touch_any_state() {
    let mut state = city();
    let mut owner = nation();
    let mut capacity = capacity_order();
    let mut expansion = expansion_order();
    capacity.requested_quantity = 4;
    capacity.progress.reserved_workforce = 7;
    expansion.requested_quantity = 5;
    expansion.progress.reserved_workforce = 8;
    let expected_state = state.clone();
    let expected_owner = owner.clone();
    let expected_capacity = capacity.clone();
    let expected_expansion = expansion.clone();

    produce_capacity(
        &mut capacity,
        &mut state,
        &mut owner,
        CapacityTarget::RegionalPopulation,
        ResourceKind::Lumber,
        ResourceKind::Steel,
        20,
    );
    produce_expansion(
        &mut expansion,
        &mut state,
        &owner,
        ExpansionTarget::RegionalPopulation,
        ResourceKind::Lumber,
        ResourceKind::Steel,
        20,
    );
    assert_eq!(state, expected_state);
    assert_eq!(owner, expected_owner);
    assert_eq!(capacity, expected_capacity);
    assert_eq!(expansion, expected_expansion);
}

#[test]
fn power_plant_limit_counts_each_fuel_unit_as_six_power() {
    let mut state = city();
    let production = PowerPlantOrderState {
        progress: ProductionProgress {
            quantity: 5,
            ..ProductionProgress::default()
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
            ..ProductionProgress::default()
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

    assert!(restock_power_plant(&mut production, &mut state));
    assert_eq!(production.progress.quantity, 12);
    assert_eq!(production.desired_quantity, 15);
    assert_eq!(state.stockpile[ResourceKind::Fuel], 0);
    assert_eq!(state.power_available, 12);
    assert_eq!(state.population.extra, 12);
    assert_eq!(state.population.strength, 22);
}

#[test]
fn power_plant_production_is_a_retail_no_op() {
    let production = PowerPlantOrderState {
        progress: ProductionProgress {
            quantity: 12,
            accumulated_value: 7,
            ..ProductionProgress::default()
        },
        desired_quantity: 18,
    };
    let expected = production.clone();
    produce_power_plant(&production);
    assert_eq!(production, expected);
}

#[test]
fn training_limits_record_workforce_treasury_resources_and_the_global_cap() {
    let mut state = city();
    let mut owner = nation();
    let mut medium = ProductionProgress::default();
    state.stockpile[ResourceKind::Paper] = 10;
    assert_eq!(
        training_max_order(TrainingLevel::Medium, &mut medium, &state, &owner, 10_000),
        4
    );
    assert_eq!(medium.limiting_constraint, ProductionConstraint::Workforce);
    assert_eq!(
        training_max_order(TrainingLevel::Medium, &mut medium, &state, &owner, i32::MAX),
        4
    );

    assert_eq!(
        training_max_order(TrainingLevel::Medium, &mut medium, &state, &owner, 150),
        1
    );
    assert_eq!(medium.limiting_constraint, ProductionConstraint::Treasury);

    state.stockpile[ResourceKind::Paper] = 0;
    assert_eq!(
        training_max_order(TrainingLevel::Medium, &mut medium, &state, &owner, 10_000),
        0
    );
    assert_eq!(medium.limiting_constraint, ProductionConstraint::Resources);

    owner.controller = crate::MajorNationController::Computer;
    state.stockpile[ResourceKind::Paper] = 100;
    medium.quantity = 98;
    assert_eq!(
        training_max_order(TrainingLevel::Medium, &mut medium, &state, &owner, -50_000),
        99
    );

    let mut high = ProductionProgress::default();
    assert_eq!(
        training_max_order(TrainingLevel::High, &mut high, &state, &owner, 0),
        2
    );
    assert_eq!(high.limiting_constraint, ProductionConstraint::Workforce);
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
        ..ProductionProgress::default()
    };

    produce_training(TrainingLevel::Medium, &mut medium, &mut state, &mut owner);
    assert_eq!(state.population.baseline_labor.low, 2);
    assert_eq!(state.population.baseline_labor.medium, 4);
    assert_eq!(medium.quantity, 0);

    owner.pending_actions[PendingActionKind::UniversityExpansion] =
        crate::PendingActionState::new(crate::PendingActionStatus::Level3, None);
    state.population.baseline_labor.high = 29;
    let mut high = ProductionProgress {
        quantity: 1,
        ..ProductionProgress::default()
    };
    produce_training(TrainingLevel::High, &mut high, &mut state, &mut owner);
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
        ..ProductionProgress::default()
    };

    produce_training(TrainingLevel::High, &mut production, &mut state, &mut owner);
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

    produce_training(TrainingLevel::High, &mut production, &mut state, &mut owner);
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
        let mut production = unit_order(workforce);
        assert_eq!(
            max_recruit_order(
                &mut production.progress,
                production.primary,
                production.secondary,
                production.cash_per_unit,
                production.workforce,
                &state,
                &owner,
                -1,
            ),
            expected
        );
        assert_eq!(
            production.progress.limiting_constraint,
            ProductionConstraint::Workforce
        );
    }
}

#[test]
fn unit_order_records_primary_secondary_and_treasury_limits() {
    let mut state = city();
    let owner = nation();
    let mut production = unit_order(SkillBand::Low);
    state.population.production_labor.low = 100;
    state.population.strength = 100;
    state.stockpile[ResourceKind::Paper] = 4;
    state.stockpile[ResourceKind::Steel] = 10;
    assert_eq!(
        max_recruit_order(
            &mut production.progress,
            production.primary,
            production.secondary,
            production.cash_per_unit,
            production.workforce,
            &state,
            &owner,
            i32::MAX,
        ),
        2
    );
    assert_eq!(
        max_recruit_order(
            &mut production.progress,
            production.primary,
            production.secondary,
            production.cash_per_unit,
            production.workforce,
            &state,
            &owner,
            10_000,
        ),
        2
    );
    assert_eq!(
        production.progress.limiting_constraint,
        ProductionConstraint::Resources
    );

    state.stockpile[ResourceKind::Paper] = 20;
    state.stockpile[ResourceKind::Steel] = 3;
    assert_eq!(
        max_recruit_order(
            &mut production.progress,
            production.primary,
            production.secondary,
            production.cash_per_unit,
            production.workforce,
            &state,
            &owner,
            10_000,
        ),
        3
    );
    assert_eq!(
        production.progress.limiting_constraint,
        ProductionConstraint::Resources
    );

    state.stockpile[ResourceKind::Steel] = 20;
    assert_eq!(
        max_recruit_order(
            &mut production.progress,
            production.primary,
            production.secondary,
            production.cash_per_unit,
            production.workforce,
            &state,
            &owner,
            150,
        ),
        1
    );
    assert_eq!(
        production.progress.limiting_constraint,
        ProductionConstraint::Treasury
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

    assert!(set_recruit_quantity(
        &mut production.progress,
        production.primary,
        production.secondary,
        production.cash_per_unit,
        production.workforce,
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
        production.primary,
        production.secondary,
        production.cash_per_unit,
        production.workforce,
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
    let mut production = unit_order(SkillBand::Low);
    state.population.production_labor.low = 100;
    state.population.strength = 100;
    state.stockpile[ResourceKind::Paper] = 12;
    state.stockpile[ResourceKind::Steel] = 12;

    assert_eq!(
        max_recruit_order(
            &mut production.progress,
            production.primary,
            production.secondary,
            production.cash_per_unit,
            production.workforce,
            &state,
            &owner,
            -10_000,
        ),
        6
    );
    assert_eq!(
        production.progress.limiting_constraint,
        ProductionConstraint::Resources
    );
}
