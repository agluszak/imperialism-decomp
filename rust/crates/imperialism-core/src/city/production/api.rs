//! `GameState` city-order query and mutation API.

use super::*;
use crate::*;

impl GameState {
    /// Calculates the current retail maximum without changing authoritative state.
    pub fn city_order_limit(&self, nation: MajorNationId, order: CityOrderId) -> OrderLimit {
        let major = self.nations.major(nation);
        let city = &major.city;
        let owner = &major.economy;
        let treasury = major.common.treasury;
        match order {
            CityOrderId::Item(output) => {
                let state = &city.orders.items[output];
                item_limit(state, city, output)
            }
            CityOrderId::CivilianRecruit(kind) => recruit_limit(
                &city.orders.civilian_recruitment[kind],
                civilian_recruitment_spec(kind),
                city,
                owner,
                treasury,
            ),
            CityOrderId::MilitaryRecruit(category) => {
                let state = &city.orders.military_recruitment[category];
                let spec = military_recruitment_spec(state.unit_kind)
                    .expect("military order has a recruitable retail unit recipe");
                recruit_limit(&state.progress, spec, city, owner, treasury)
            }
            CityOrderId::Ship(track) => {
                let state = &city.orders.ships[track];
                OrderLimit {
                    maximum: ship_max_order(state, city),
                    constraint: state.progress.limiting_constraint,
                }
            }
            CityOrderId::Training(level) => {
                training_limit(level, &city.orders.training[level], city, owner, treasury)
            }
            CityOrderId::Expansion(facility) => {
                let state = &city.orders.expansions[facility];
                let (primary, secondary) = EXPANSION_INPUTS;
                OrderLimit {
                    maximum: expansion_max_order(state, city, primary, secondary),
                    constraint: state.progress.limiting_constraint,
                }
            }
            CityOrderId::FoodProcessing => OrderLimit {
                maximum: food_processing_max_order(&city.orders.food_processing, city),
                constraint: city.orders.food_processing.limiting_constraint,
            },
            CityOrderId::PowerPlant => OrderLimit {
                maximum: power_plant_max_order(&city.orders.power_plant, city),
                constraint: city.orders.power_plant.progress.limiting_constraint,
            },
            CityOrderId::TransportCapacity => {
                transport_capacity_limit(&city.orders.transport_capacity, city)
            }
            CityOrderId::PopulationGrowth => {
                population_growth_limit(&city.orders.population_growth, city)
            }
        }
    }

    /// Current ordered quantity for a city production row.
    pub fn city_order_quantity(&self, nation: MajorNationId, order: CityOrderId) -> i16 {
        let city = self.nations.city(nation);
        match order {
            CityOrderId::Item(output) => city.orders.items[output].progress.quantity,
            CityOrderId::CivilianRecruit(kind) => city.orders.civilian_recruitment[kind].quantity,
            CityOrderId::MilitaryRecruit(category) => {
                city.orders.military_recruitment[category].progress.quantity
            }
            CityOrderId::Ship(track) => city.orders.ships[track].progress.quantity,
            CityOrderId::Training(level) => city.orders.training[level].quantity,
            CityOrderId::Expansion(facility) => city.orders.expansions[facility].progress.quantity,
            CityOrderId::FoodProcessing => city.orders.food_processing.quantity,
            CityOrderId::PowerPlant => city.orders.power_plant.progress.quantity,
            CityOrderId::TransportCapacity => city.orders.transport_capacity.progress.quantity,
            CityOrderId::PopulationGrowth => city.orders.population_growth.quantity,
        }
    }

    /// Applies an absolute retail city-order quantity and reports whether retail accepted it.
    pub fn set_city_order_quantity(
        &mut self,
        nation: MajorNationId,
        order: CityOrderId,
        quantity: i16,
    ) -> bool {
        let limit = self.city_order_limit(nation, order);
        let MajorNation { common, city, .. } = self.nations.major_mut(nation);
        let CityState {
            orders,
            stockpile,
            population,
            production_accum,
            power_available,
            ..
        } = city;
        match order {
            CityOrderId::Item(output) => {
                let state = &mut orders.items[output];
                set_item_quantity(
                    state,
                    stockpile,
                    population,
                    production_accum,
                    output,
                    limit,
                    quantity,
                )
            }
            CityOrderId::CivilianRecruit(kind) => set_recruit_quantity(
                &mut orders.civilian_recruitment[kind],
                civilian_recruitment_spec(kind),
                stockpile,
                population,
                &mut common.treasury,
                limit,
                quantity,
            ),
            CityOrderId::MilitaryRecruit(category) => {
                let state = &mut orders.military_recruitment[category];
                let spec = military_recruitment_spec(state.unit_kind)
                    .expect("military order has a recruitable retail unit recipe");
                set_recruit_quantity(
                    &mut state.progress,
                    spec,
                    stockpile,
                    population,
                    &mut common.treasury,
                    limit,
                    quantity,
                )
            }
            CityOrderId::Ship(track) => {
                set_ship_quantity(&mut orders.ships[track], stockpile, limit.maximum, quantity)
            }
            CityOrderId::Training(level) => set_training_quantity(
                level,
                &mut orders.training[level],
                stockpile,
                population,
                &mut common.treasury,
                limit,
                quantity,
            ),
            CityOrderId::Expansion(facility) => {
                let (primary, secondary) = EXPANSION_INPUTS;
                let state = &mut orders.expansions[facility];
                set_expansion_quantity(
                    state,
                    stockpile,
                    primary,
                    secondary,
                    limit.maximum,
                    quantity,
                )
            }
            CityOrderId::FoodProcessing => set_food_processing_quantity(
                &mut orders.food_processing,
                stockpile,
                population,
                limit.maximum,
                quantity,
            ),
            CityOrderId::PowerPlant => set_power_plant_quantity(
                &mut orders.power_plant,
                stockpile,
                population,
                power_available,
                limit.maximum,
                quantity,
            ),
            CityOrderId::TransportCapacity => set_transport_capacity_quantity(
                &mut orders.transport_capacity,
                stockpile,
                population,
                production_accum,
                limit,
                quantity,
            ),
            CityOrderId::PopulationGrowth => set_population_growth_quantity(
                &mut orders.population_growth,
                stockpile,
                production_accum,
                limit,
                quantity,
            ),
        }
    }

    /// Applies a signed quantity step through the same absolute retail setter.
    pub fn adjust_city_order(
        &mut self,
        nation: MajorNationId,
        order: CityOrderId,
        delta: i16,
    ) -> bool {
        let quantity = self.city_order_quantity(nation, order);
        self.set_city_order_quantity(nation, order, quantity + delta)
    }
}
