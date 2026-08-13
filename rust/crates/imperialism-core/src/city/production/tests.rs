#![cfg(test)]

use super::*;
use crate::*;

fn fresh_game() -> (GameState, MajorNationId) {
    (crate::test_support::game_state(), MajorNationId::new(0))
}

fn city(game: &GameState, nation: MajorNationId) -> &CityState {
    game.nations.city(nation)
}

fn city_mut(game: &mut GameState, nation: MajorNationId) -> &mut CityState {
    &mut game.nations.major_mut(nation).city
}

#[test]
fn item_limit_records_capacity_workforce_and_resource_constraints() {
    let (mut game, nation) = fresh_game();
    let lumber = CityOrderId::Item(ManufacturedItem::Lumber);
    {
        let city = city_mut(&mut game, nation);
        city.production_accum[CityFacilitySlot::LumberMill] = 4;
        city.stockpile[ResourceKind::Timber] = 20;
    }
    assert_eq!(
        game.city_order_limit(nation, lumber),
        OrderLimit {
            maximum: 4,
            constraint: ProductionConstraint::Capacity,
        }
    );

    city_mut(&mut game, nation).production_accum[CityFacilitySlot::LumberMill] = 20;
    assert_eq!(
        game.city_order_limit(nation, lumber),
        OrderLimit {
            maximum: 6,
            constraint: ProductionConstraint::Workforce,
        }
    );

    {
        let city = city_mut(&mut game, nation);
        city.population.strength = 30;
        city.stockpile[ResourceKind::Timber] = 8;
    }
    assert_eq!(
        game.city_order_limit(nation, lumber),
        OrderLimit {
            maximum: 4,
            constraint: ProductionConstraint::Resources,
        }
    );

    {
        let city = city_mut(&mut game, nation);
        city.production_accum[CityFacilitySlot::SteelMill] = 20;
        city.stockpile[ResourceKind::Iron] = 9;
        city.stockpile[ResourceKind::Coal] = 3;
    }
    assert_eq!(
        game.city_order_limit(nation, CityOrderId::Item(ManufacturedItem::Steel)),
        OrderLimit {
            maximum: 3,
            constraint: ProductionConstraint::Resources,
        }
    );
}

#[test]
fn steel_order_reserves_both_inputs_and_releases_them() {
    let (mut game, nation) = fresh_game();
    let steel = CityOrderId::Item(ManufacturedItem::Steel);
    {
        let city = city_mut(&mut game, nation);
        city.production_accum[CityFacilitySlot::SteelMill] = 1;
        city.stockpile[ResourceKind::Iron] = 1;
        city.stockpile[ResourceKind::Coal] = 1;
    }

    assert!(game.set_city_order_quantity(nation, steel, 1));
    let after_order = city(&game, nation);
    assert_eq!(game.city_order_quantity(nation, steel), 1);
    assert_eq!(after_order.stockpile[ResourceKind::Iron], 0);
    assert_eq!(after_order.stockpile[ResourceKind::Coal], 0);
    assert_eq!(after_order.population.strength, 10);
    assert_eq!(after_order.production_accum[CityFacilitySlot::SteelMill], 0);

    assert!(game.set_city_order_quantity(nation, steel, 0));
    let after_release = city(&game, nation);
    assert_eq!(game.city_order_quantity(nation, steel), 0);
    assert_eq!(after_release.stockpile[ResourceKind::Iron], 1);
    assert_eq!(after_release.stockpile[ResourceKind::Coal], 1);
    assert_eq!(after_release.population.strength, 12);
    assert_eq!(
        after_release.production_accum[CityFacilitySlot::SteelMill],
        1
    );
}

#[test]
fn rejected_item_order_leaves_stock_and_capacity_unchanged() {
    let (mut game, nation) = fresh_game();
    let lumber = CityOrderId::Item(ManufacturedItem::Lumber);
    {
        let city = city_mut(&mut game, nation);
        city.production_accum[CityFacilitySlot::LumberMill] = 1;
        city.stockpile[ResourceKind::Timber] = 20;
    }

    assert!(!game.set_city_order_quantity(nation, lumber, 2));
    let city = city(&game, nation);
    assert_eq!(game.city_order_quantity(nation, lumber), 0);
    assert_eq!(city.stockpile[ResourceKind::Timber], 20);
    assert_eq!(city.population.strength, 12);
    assert_eq!(city.production_accum[CityFacilitySlot::LumberMill], 1);
}

#[test]
fn fabric_order_shifts_a_wool_shortfall_onto_cotton() {
    let (mut game, nation) = fresh_game();
    let fabric = CityOrderId::Item(ManufacturedItem::Fabric);
    {
        let city = city_mut(&mut game, nation);
        city.production_accum[CityFacilitySlot::TextileMill] = 10;
        city.stockpile[ResourceKind::Wool] = 1;
        city.stockpile[ResourceKind::Cotton] = 10;
    }

    assert_eq!(game.city_order_limit(nation, fabric).maximum, 5);
    assert!(game.set_city_order_quantity(nation, fabric, 3));
    let reserved = city(&game, nation);
    let order = &reserved.orders.items[ManufacturedItem::Fabric];
    assert_eq!(reserved.stockpile[ResourceKind::Wool], 0);
    assert_eq!(reserved.stockpile[ResourceKind::Cotton], 5);
    assert_eq!(order.tracking_by_resource[ResourceKind::Wool], 1);
    assert_eq!(order.tracking_by_resource[ResourceKind::Cotton], 5);

    assert!(game.set_city_order_quantity(nation, fabric, 1));
    let released = city(&game, nation);
    let order = &released.orders.items[ManufacturedItem::Fabric];
    assert_eq!(released.stockpile[ResourceKind::Wool], 1);
    assert_eq!(released.stockpile[ResourceKind::Cotton], 8);
    assert_eq!(order.tracking_by_resource[ResourceKind::Wool], 0);
    assert_eq!(order.tracking_by_resource[ResourceKind::Cotton], 2);
}

#[test]
fn fabric_order_shifts_a_cotton_shortfall_onto_wool() {
    let (mut game, nation) = fresh_game();
    let fabric = CityOrderId::Item(ManufacturedItem::Fabric);
    {
        let city = city_mut(&mut game, nation);
        city.production_accum[CityFacilitySlot::TextileMill] = 10;
        city.stockpile[ResourceKind::Wool] = 10;
        city.stockpile[ResourceKind::Cotton] = 1;
    }

    assert!(game.set_city_order_quantity(nation, fabric, 3));
    let city = city(&game, nation);
    let order = &city.orders.items[ManufacturedItem::Fabric];
    assert_eq!(city.stockpile[ResourceKind::Wool], 5);
    assert_eq!(city.stockpile[ResourceKind::Cotton], 0);
    assert_eq!(order.tracking_by_resource[ResourceKind::Wool], 5);
    assert_eq!(order.tracking_by_resource[ResourceKind::Cotton], 1);
}

#[test]
fn item_restock_clamps_to_resources_and_keeps_the_requested_quantity() {
    let mut state = crate::test_support::city();
    let mut production = RequestedCityOrderState {
        progress: ProductionProgress {
            quantity: 5,
            limiting_constraint: ProductionConstraint::Resources,
        },
        requested_quantity: 5,
        ..RequestedCityOrderState::default()
    };
    state.population.strength = 20;
    state.production_accum[CityFacilitySlot::LumberMill] = 5;
    state.stockpile[ResourceKind::Timber] = 4;

    assert!(restock_item(
        &mut production,
        &mut state.stockpile,
        &mut state.population,
        &mut state.production_accum,
        ManufacturedItem::Lumber,
    ));
    assert_eq!(production.progress.quantity, 2);
    assert_eq!(production.requested_quantity, 5);
    assert_eq!(state.stockpile[ResourceKind::Timber], 0);
    assert_eq!(
        production.progress.limiting_constraint,
        ProductionConstraint::Resources
    );
}

#[test]
fn food_processing_limit_uses_grain_fruit_animals_and_workforce() {
    let (mut game, nation) = fresh_game();
    {
        let city = city_mut(&mut game, nation);
        city.stockpile[ResourceKind::Grain] = 10;
        city.stockpile[ResourceKind::Fruit] = 4;
        city.stockpile[ResourceKind::Fish] = 1;
        city.stockpile[ResourceKind::Livestock] = 2;
        city.population.strength = 10;
    }
    assert_eq!(
        game.city_order_limit(nation, CityOrderId::FoodProcessing)
            .maximum,
        6
    );
}

#[test]
fn food_processing_rounds_odd_orders_up_and_spends_livestock_before_fish() {
    let (mut game, nation) = fresh_game();
    assert!(game.set_city_order_quantity(nation, CityOrderId::FoodProcessing, -1));
    assert_eq!(
        game.city_order_quantity(nation, CityOrderId::FoodProcessing),
        0
    );

    {
        let city = city_mut(&mut game, nation);
        city.stockpile[ResourceKind::Grain] = 10;
        city.stockpile[ResourceKind::Fruit] = 5;
        city.stockpile[ResourceKind::Fish] = 3;
        city.stockpile[ResourceKind::Livestock] = 1;
        city.population.strength = 10;
    }

    assert!(game.set_city_order_quantity(nation, CityOrderId::FoodProcessing, 3));
    let reserved = city(&game, nation);
    assert_eq!(
        game.city_order_quantity(nation, CityOrderId::FoodProcessing),
        4
    );
    assert_eq!(reserved.stockpile[ResourceKind::Grain], 6);
    assert_eq!(reserved.stockpile[ResourceKind::Fruit], 3);
    assert_eq!(reserved.stockpile[ResourceKind::Livestock], 0);
    assert_eq!(reserved.stockpile[ResourceKind::Fish], 2);

    assert!(game.set_city_order_quantity(nation, CityOrderId::FoodProcessing, 1));
    let released = city(&game, nation);
    assert_eq!(
        game.city_order_quantity(nation, CityOrderId::FoodProcessing),
        2
    );
    assert_eq!(released.stockpile[ResourceKind::Grain], 8);
    assert_eq!(released.stockpile[ResourceKind::Fruit], 4);
    assert_eq!(released.stockpile[ResourceKind::Livestock], 1);
    assert_eq!(released.stockpile[ResourceKind::Fish], 2);
}

#[test]
fn population_growth_limit_prefers_the_scarce_input_then_capacity() {
    let (mut game, nation) = fresh_game();
    let growth = CityOrderId::PopulationGrowth;
    {
        let city = city_mut(&mut game, nation);
        city.stockpile[ResourceKind::Furniture] = 3;
        city.stockpile[ResourceKind::Clothing] = 2;
        city.stockpile[ResourceKind::Food] = 4;
        city.production_accum[CityFacilitySlot::RegionalPopulation] = 10;
    }
    assert_eq!(
        game.city_order_limit(nation, growth),
        OrderLimit {
            maximum: 2,
            constraint: ProductionConstraint::Resources,
        }
    );

    city_mut(&mut game, nation).production_accum[CityFacilitySlot::RegionalPopulation] = 1;
    assert_eq!(
        game.city_order_limit(nation, growth),
        OrderLimit {
            maximum: 1,
            constraint: ProductionConstraint::Capacity,
        }
    );
}

#[test]
fn population_growth_order_spends_furniture_clothing_and_food() {
    let (mut game, nation) = fresh_game();
    {
        let city = city_mut(&mut game, nation);
        city.stockpile[ResourceKind::Furniture] = 3;
        city.stockpile[ResourceKind::Clothing] = 3;
        city.stockpile[ResourceKind::Food] = 3;
        city.production_accum[CityFacilitySlot::RegionalPopulation] = 3;
    }

    assert!(game.set_city_order_quantity(nation, CityOrderId::PopulationGrowth, 2));
    let city = city(&game, nation);
    assert_eq!(city.stockpile[ResourceKind::Furniture], 1);
    assert_eq!(city.stockpile[ResourceKind::Clothing], 1);
    assert_eq!(city.stockpile[ResourceKind::Food], 1);
    assert_eq!(
        city.production_accum[CityFacilitySlot::RegionalPopulation],
        1
    );
}

#[test]
fn retail_region_capacity_uses_the_annexation_divisor() {
    let mut owner = crate::test_support::great_power_state();
    assert_eq!(retail_region_capacity(&owner, 12), 3);
    owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
        crate::PendingActionState::new(crate::PendingActionStatus::Level3, None);
    assert_eq!(retail_region_capacity(&owner, 12), 4);
    assert_eq!(retail_region_capacity(&owner, 1), 1);
}

#[test]
fn expansion_order_spends_only_lumber_and_steel() {
    let (mut game, nation) = fresh_game();
    let expansion = CityOrderId::Expansion(ExpandableFacility::SteelMill);
    {
        let city = city_mut(&mut game, nation);
        city.stockpile[ResourceKind::Lumber] = 3;
        city.stockpile[ResourceKind::Steel] = 2;
        city.production_accum[CityFacilitySlot::SteelMill] = 9;
    }

    assert_eq!(game.city_order_limit(nation, expansion).maximum, 2);
    assert!(game.set_city_order_quantity(nation, expansion, 2));
    let reserved = city(&game, nation);
    assert_eq!(reserved.stockpile[ResourceKind::Lumber], 1);
    assert_eq!(reserved.stockpile[ResourceKind::Steel], 0);
    assert_eq!(reserved.population.strength, 12);
    assert_eq!(reserved.production_accum[CityFacilitySlot::SteelMill], 9);

    assert!(game.set_city_order_quantity(nation, expansion, 1));
    let released = city(&game, nation);
    assert_eq!(released.stockpile[ResourceKind::Lumber], 2);
    assert_eq!(released.stockpile[ResourceKind::Steel], 1);
}

#[test]
fn power_plant_limit_counts_each_fuel_unit_as_six_power() {
    let (mut game, nation) = fresh_game();
    {
        let city = city_mut(&mut game, nation);
        city.orders.power_plant.progress.quantity = 5;
        city.stockpile[ResourceKind::Fuel] = 3;
    }
    assert_eq!(
        game.city_order_limit(nation, CityOrderId::PowerPlant)
            .maximum,
        23
    );
}

#[test]
fn power_plant_order_uses_truncating_fuel_division() {
    let (mut game, nation) = fresh_game();
    city_mut(&mut game, nation).stockpile[ResourceKind::Fuel] = 3;

    assert!(game.set_city_order_quantity(nation, CityOrderId::PowerPlant, 13));
    let reserved = city(&game, nation);
    assert_eq!(reserved.stockpile[ResourceKind::Fuel], 1);
    assert_eq!(reserved.orders.power_plant.desired_quantity, 13);
    assert_eq!(reserved.power_available, 13);
    assert_eq!(reserved.population.extra, 13);
    assert_eq!(reserved.population.strength, 25);

    assert!(game.set_city_order_quantity(nation, CityOrderId::PowerPlant, 6));
    let released = city(&game, nation);
    assert_eq!(released.stockpile[ResourceKind::Fuel], 2);
    assert_eq!(released.orders.power_plant.desired_quantity, 6);
    assert_eq!(released.power_available, 6);
    assert_eq!(released.population.extra, 6);
    assert_eq!(released.population.strength, 18);
}

#[test]
fn power_plant_rejects_a_cut_that_exceeds_available_strength() {
    let (mut game, nation) = fresh_game();
    city_mut(&mut game, nation).stockpile[ResourceKind::Fuel] = 2;
    assert!(game.set_city_order_quantity(nation, CityOrderId::PowerPlant, 6));
    city_mut(&mut game, nation).population.strength = 2;
    let expected = city(&game, nation).clone();

    assert!(!game.set_city_order_quantity(nation, CityOrderId::PowerPlant, 0));
    assert_eq!(city(&game, nation), &expected);
}

#[test]
fn power_plant_restock_clamps_but_keeps_the_desired_quantity() {
    let mut state = crate::test_support::city();
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
    assert_eq!(state.population.strength, 24);
}

#[test]
fn training_limit_records_workforce_treasury_paper_and_the_global_cap() {
    let (mut game, nation) = fresh_game();
    let medium = CityOrderId::Training(TrainingLevel::Medium);
    city_mut(&mut game, nation).stockpile[ResourceKind::Paper] = 10;
    assert_eq!(
        game.city_order_limit(nation, medium),
        OrderLimit {
            maximum: 4,
            constraint: ProductionConstraint::Workforce,
        }
    );

    game.nations.major_mut(nation).common.treasury = 150;
    assert_eq!(
        game.city_order_limit(nation, medium),
        OrderLimit {
            maximum: 1,
            constraint: ProductionConstraint::Treasury,
        }
    );

    game.nations.major_mut(nation).common.treasury = 10_000;
    city_mut(&mut game, nation).stockpile[ResourceKind::Paper] = 0;
    assert_eq!(
        game.city_order_limit(nation, medium),
        OrderLimit {
            maximum: 0,
            constraint: ProductionConstraint::Resources,
        }
    );

    game.nations.major_mut(nation).economy.controller = MajorNationController::Computer;
    game.nations.major_mut(nation).economy.diplomacy_eligible = false;
    {
        let city = city_mut(&mut game, nation);
        city.stockpile[ResourceKind::Paper] = 100;
        city.orders.training[TrainingLevel::Medium].quantity = 98;
    }
    assert_eq!(game.city_order_limit(nation, medium).maximum, 99);

    assert_eq!(
        game.city_order_limit(nation, CityOrderId::Training(TrainingLevel::High)),
        OrderLimit {
            maximum: 2,
            constraint: ProductionConstraint::Workforce,
        }
    );
}

#[test]
fn training_order_spends_paper_cash_and_workers() {
    let (mut game, nation) = fresh_game();
    let medium = CityOrderId::Training(TrainingLevel::Medium);
    city_mut(&mut game, nation).stockpile[ResourceKind::Paper] = 10;

    assert!(game.set_city_order_quantity(nation, medium, 2));
    {
        let city = city(&game, nation);
        assert_eq!(city.stockpile[ResourceKind::Paper], 8);
        assert_eq!(game.nations.major(nation).common.treasury, 800);
        assert_eq!(city.population.production_labor.low, 2);
        assert_eq!(city.population.strength, 10);
    }

    assert!(game.set_city_order_quantity(nation, medium, 1));
    {
        let city = city(&game, nation);
        assert_eq!(city.stockpile[ResourceKind::Paper], 9);
        assert_eq!(game.nations.major(nation).common.treasury, 900);
        assert_eq!(city.population.production_labor.low, 3);
        assert_eq!(city.population.strength, 11);
    }

    let (mut game, nation) = fresh_game();
    let high = CityOrderId::Training(TrainingLevel::High);
    city_mut(&mut game, nation).stockpile[ResourceKind::Paper] = 6;
    game.nations.major_mut(nation).common.treasury = 3_000;
    assert!(game.set_city_order_quantity(nation, high, 2));
    let city = city(&game, nation);
    assert_eq!(city.stockpile[ResourceKind::Paper], 2);
    assert_eq!(game.nations.major(nation).common.treasury, 1_000);
    assert_eq!(city.population.production_labor.medium, 0);
    assert_eq!(city.population.strength, 8);
}

#[test]
fn high_training_queues_university_expansion_at_the_retail_thresholds() {
    let mut state = crate::test_support::city();
    let mut owner = crate::test_support::great_power_state();
    state.population.baseline_labor.high = 9;
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
    assert_eq!(state.population.baseline_labor.high, 10);
    assert_eq!(
        owner.pending_actions[PendingActionKind::UniversityExpansion].status(),
        crate::PendingActionStatus::Queued
    );
    assert_eq!(
        owner.pending_actions[PendingActionKind::UniversityExpansion].payload(),
        Some(2)
    );
    assert_eq!(production.quantity, 0);

    owner.pending_actions[PendingActionKind::UniversityExpansion] =
        crate::PendingActionState::new(crate::PendingActionStatus::Level3, None);
    state.population.baseline_labor.high = 29;
    production.quantity = 1;
    produce_training(
        TrainingLevel::High,
        &mut production,
        &mut state.population,
        &mut owner,
    );
    assert_eq!(state.population.baseline_labor.high, 30);
    assert_eq!(
        owner.pending_actions[PendingActionKind::UniversityExpansion].payload(),
        Some(3)
    );
}

#[test]
fn recruit_limit_uses_workforce_mode_resources_and_human_treasury() {
    let (mut game, nation) = fresh_game();
    {
        let city = city_mut(&mut game, nation);
        city.stockpile[ResourceKind::Arms] = 200;
        city.stockpile[ResourceKind::Horses] = 200;
    }
    game.nations.major_mut(nation).common.treasury = i32::MAX;

    assert_eq!(
        game.city_order_limit(
            nation,
            CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::LightInfantry),
        ),
        OrderLimit {
            maximum: 4,
            constraint: ProductionConstraint::Workforce,
        }
    );
    assert_eq!(
        game.city_order_limit(
            nation,
            CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::HeavyInfantry),
        ),
        OrderLimit {
            maximum: 2,
            constraint: ProductionConstraint::Workforce,
        }
    );
    assert_eq!(
        game.city_order_limit(
            nation,
            CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::Demolitionist),
        ),
        OrderLimit {
            maximum: 1,
            constraint: ProductionConstraint::Workforce,
        }
    );

    let hussars = CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::LightCavalry);
    {
        let city = city_mut(&mut game, nation);
        city.population.production_labor.low = 100;
        city.population.strength = 100;
        city.stockpile[ResourceKind::Arms] = 4;
        city.stockpile[ResourceKind::Horses] = 10;
    }
    game.nations.major_mut(nation).common.treasury = i32::MAX;
    assert_eq!(
        game.city_order_limit(nation, hussars),
        OrderLimit {
            maximum: 4,
            constraint: ProductionConstraint::Resources,
        }
    );

    city_mut(&mut game, nation).stockpile[ResourceKind::Horses] = 3;
    assert_eq!(
        game.city_order_limit(nation, hussars),
        OrderLimit {
            maximum: 3,
            constraint: ProductionConstraint::Resources,
        }
    );

    city_mut(&mut game, nation).stockpile[ResourceKind::Horses] = 20;
    game.nations.major_mut(nation).common.treasury = 150;
    assert_eq!(
        game.city_order_limit(nation, hussars),
        OrderLimit {
            maximum: 1,
            constraint: ProductionConstraint::Treasury,
        }
    );

    game.nations.major_mut(nation).economy.controller = MajorNationController::Computer;
    game.nations.major_mut(nation).economy.diplomacy_eligible = false;
    game.nations.major_mut(nation).common.treasury = -10_000;
    {
        let city = city_mut(&mut game, nation);
        city.stockpile[ResourceKind::Arms] = 12;
        city.stockpile[ResourceKind::Horses] = 12;
    }
    assert_eq!(
        game.city_order_limit(nation, hussars),
        OrderLimit {
            maximum: 12,
            constraint: ProductionConstraint::Resources,
        }
    );
}

#[test]
fn recruit_order_removes_population_and_refunds_it() {
    let (mut game, nation) = fresh_game();
    let skirmishers = CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::LightInfantry);
    city_mut(&mut game, nation).stockpile[ResourceKind::Arms] = 10;

    assert!(game.set_city_order_quantity(nation, skirmishers, 2));
    {
        let city = city(&game, nation);
        assert_eq!(city.stockpile[ResourceKind::Arms], 8);
        assert_eq!(game.nations.major(nation).common.treasury, 600);
        assert_eq!(city.population.baseline_labor.low, 2);
        assert_eq!(city.population.count, 5);
        assert_eq!(city.population.strength, 10);
    }

    assert!(game.set_city_order_quantity(nation, skirmishers, 1));
    let city = city(&game, nation);
    assert_eq!(city.stockpile[ResourceKind::Arms], 9);
    assert_eq!(game.nations.major(nation).common.treasury, 800);
    assert_eq!(city.population.baseline_labor.low, 3);
    assert_eq!(city.population.count, 6);
    assert_eq!(city.population.strength, 11);
}
