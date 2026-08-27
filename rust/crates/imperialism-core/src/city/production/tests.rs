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
fn steel_order_reserves_both_inputs_and_releases_them() {
    let (mut game, nation) = fresh_game();
    let steel = CityOrderId::Item(ManufacturedItem::Steel);
    {
        let city = city_mut(&mut game, nation);
        city.production_accum[CityFacilitySlot::SteelMill] = 1;
        city.stockpile[ResourceKind::Iron] = 1;
        city.stockpile[ResourceKind::Coal] = 1;
    }

    assert_eq!(
        game.set_city_order_quantity(nation, steel, 1),
        CityOrderUpdate::Applied
    );
    let after_order = city(&game, nation);
    assert_eq!(game.city_order_quantity(nation, steel), 1);
    assert_eq!(after_order.stockpile[ResourceKind::Iron], 0);
    assert_eq!(after_order.stockpile[ResourceKind::Coal], 0);
    assert_eq!(after_order.population.strength, 10);
    assert_eq!(after_order.production_accum[CityFacilitySlot::SteelMill], 0);

    assert_eq!(
        game.set_city_order_quantity(nation, steel, 0),
        CityOrderUpdate::Applied
    );
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
    assert_eq!(
        game.set_city_order_quantity(nation, fabric, 3),
        CityOrderUpdate::Applied
    );
    let reserved = city(&game, nation);
    let order = &reserved.orders.items[ManufacturedItem::Fabric];
    assert_eq!(reserved.stockpile[ResourceKind::Wool], 0);
    assert_eq!(reserved.stockpile[ResourceKind::Cotton], 5);
    assert_eq!(order.tracking_by_resource[ResourceKind::Wool], 1);
    assert_eq!(order.tracking_by_resource[ResourceKind::Cotton], 5);

    assert_eq!(
        game.set_city_order_quantity(nation, fabric, 1),
        CityOrderUpdate::Applied
    );
    let released = city(&game, nation);
    let order = &released.orders.items[ManufacturedItem::Fabric];
    assert_eq!(released.stockpile[ResourceKind::Wool], 1);
    assert_eq!(released.stockpile[ResourceKind::Cotton], 8);
    assert_eq!(order.tracking_by_resource[ResourceKind::Wool], 0);
    assert_eq!(order.tracking_by_resource[ResourceKind::Cotton], 2);
}

#[test]
fn food_processing_rounds_odd_orders_up_and_spends_livestock_before_fish() {
    let (mut game, nation) = fresh_game();
    assert_eq!(
        game.set_city_order_quantity(nation, CityOrderId::FoodProcessing, -1),
        CityOrderUpdate::Applied
    );
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

    assert_eq!(
        game.set_city_order_quantity(nation, CityOrderId::FoodProcessing, 3),
        CityOrderUpdate::Applied
    );
    let reserved = city(&game, nation);
    assert_eq!(
        game.city_order_quantity(nation, CityOrderId::FoodProcessing),
        4
    );
    assert_eq!(reserved.stockpile[ResourceKind::Grain], 6);
    assert_eq!(reserved.stockpile[ResourceKind::Fruit], 3);
    assert_eq!(reserved.stockpile[ResourceKind::Livestock], 0);
    assert_eq!(reserved.stockpile[ResourceKind::Fish], 2);

    assert_eq!(
        game.set_city_order_quantity(nation, CityOrderId::FoodProcessing, 1),
        CityOrderUpdate::Applied
    );
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
fn population_growth_order_spends_furniture_clothing_and_food() {
    let (mut game, nation) = fresh_game();
    {
        let city = city_mut(&mut game, nation);
        city.stockpile[ResourceKind::Furniture] = 3;
        city.stockpile[ResourceKind::Clothing] = 3;
        city.stockpile[ResourceKind::Food] = 3;
        city.production_accum[CityFacilitySlot::RegionalPopulation] = 3;
    }

    assert_eq!(
        game.set_city_order_quantity(nation, CityOrderId::PopulationGrowth, 2),
        CityOrderUpdate::Applied
    );
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
    assert_eq!(
        game.set_city_order_quantity(nation, expansion, 2),
        CityOrderUpdate::Applied
    );
    let reserved = city(&game, nation);
    assert_eq!(reserved.stockpile[ResourceKind::Lumber], 1);
    assert_eq!(reserved.stockpile[ResourceKind::Steel], 0);
    assert_eq!(reserved.population.strength, 12);
    assert_eq!(reserved.production_accum[CityFacilitySlot::SteelMill], 9);

    assert_eq!(
        game.set_city_order_quantity(nation, expansion, 1),
        CityOrderUpdate::Applied
    );
    let released = city(&game, nation);
    assert_eq!(released.stockpile[ResourceKind::Lumber], 2);
    assert_eq!(released.stockpile[ResourceKind::Steel], 1);
}

#[test]
fn power_plant_order_uses_truncating_fuel_division() {
    let (mut game, nation) = fresh_game();
    city_mut(&mut game, nation).stockpile[ResourceKind::Fuel] = 3;

    assert_eq!(
        game.set_city_order_quantity(nation, CityOrderId::PowerPlant, 13),
        CityOrderUpdate::Applied
    );
    let reserved = city(&game, nation);
    assert_eq!(reserved.stockpile[ResourceKind::Fuel], 1);
    assert_eq!(reserved.orders.power_plant.desired_quantity, 13);
    assert_eq!(reserved.power_available, 13);
    assert_eq!(reserved.population.extra, 13);
    assert_eq!(reserved.population.strength, 25);

    assert_eq!(
        game.set_city_order_quantity(nation, CityOrderId::PowerPlant, 6),
        CityOrderUpdate::Applied
    );
    let released = city(&game, nation);
    assert_eq!(released.stockpile[ResourceKind::Fuel], 2);
    assert_eq!(released.orders.power_plant.desired_quantity, 6);
    assert_eq!(released.power_available, 6);
    assert_eq!(released.population.extra, 6);
    assert_eq!(released.population.strength, 18);
}

#[test]
fn training_order_spends_paper_cash_and_workers() {
    let (mut game, nation) = fresh_game();
    let medium = CityOrderId::Training(TrainingLevel::Medium);
    city_mut(&mut game, nation).stockpile[ResourceKind::Paper] = 10;

    assert_eq!(
        game.set_city_order_quantity(nation, medium, 2),
        CityOrderUpdate::Applied
    );
    {
        let city = city(&game, nation);
        assert_eq!(city.stockpile[ResourceKind::Paper], 8);
        assert_eq!(game.nations.major(nation).common.treasury, 800);
        assert_eq!(city.population.production_labor.low, 2);
        assert_eq!(city.population.strength, 10);
    }

    assert_eq!(
        game.set_city_order_quantity(nation, medium, 1),
        CityOrderUpdate::Applied
    );
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
    assert_eq!(
        game.set_city_order_quantity(nation, high, 2),
        CityOrderUpdate::Applied
    );
    let city = city(&game, nation);
    assert_eq!(city.stockpile[ResourceKind::Paper], 2);
    assert_eq!(game.nations.major(nation).common.treasury, 1_000);
    assert_eq!(city.population.production_labor.medium, 0);
    assert_eq!(city.population.strength, 8);
}

#[test]
fn recruit_order_removes_population_and_refunds_it() {
    let (mut game, nation) = fresh_game();
    let skirmishers = CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::LightInfantry);
    city_mut(&mut game, nation).stockpile[ResourceKind::Arms] = 10;

    assert_eq!(
        game.set_city_order_quantity(nation, skirmishers, 2),
        CityOrderUpdate::Applied
    );
    {
        let city = city(&game, nation);
        assert_eq!(city.stockpile[ResourceKind::Arms], 8);
        assert_eq!(game.nations.major(nation).common.treasury, 600);
        assert_eq!(city.population.baseline_labor.low, 2);
        assert_eq!(city.population.count, 5);
        assert_eq!(city.population.strength, 10);
    }

    assert_eq!(
        game.set_city_order_quantity(nation, skirmishers, 1),
        CityOrderUpdate::Applied
    );
    let city = city(&game, nation);
    assert_eq!(city.stockpile[ResourceKind::Arms], 9);
    assert_eq!(game.nations.major(nation).common.treasury, 800);
    assert_eq!(city.population.baseline_labor.low, 3);
    assert_eq!(city.population.count, 6);
    assert_eq!(city.population.strength, 11);
}
