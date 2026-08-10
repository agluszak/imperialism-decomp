//! `GameState` city-order query and mutation API.

use crate::*;
use super::*;

impl GameState {
    fn with_city_orders<R>(
        &mut self,
        nation: MajorNationId,
        operation: impl FnOnce(&mut CityOrders, &mut CityState, &GreatPowerState, &mut i32) -> R,
    ) -> R {
        let major = self.nations.major_mut(nation);
        let mut orders = std::mem::take(&mut major.city.orders);
        let result = operation(
            &mut orders,
            &mut major.city,
            &major.economy,
            &mut major.common.treasury,
        );
        major.city.orders = orders;
        result
    }

    /// Recomputes the retail maximum and remembered limiting constraint for a
    /// city order. Call this from explicit UI actions (dialog open, order edit),
    /// never from frame-driven projection.
    pub fn refresh_city_order(
        &mut self,
        nation: MajorNationId,
        order: CityOrderId,
    ) -> CityOrderStatus {
        self.with_city_orders(nation, |orders, city, owner, treasury| {
            let (progress, requested_quantity, maximum) = match order {
                CityOrderId::Item(output) => {
                    let spec = item_order_spec(output);
                    let state = orders.items[output.resource()]
                        .as_mut()
                        .expect("item order exists for every retail item recipe");
                    let maximum = item_max_order(state, city, spec);
                    (&state.progress, state.requested_quantity, maximum)
                }
                CityOrderId::CivilianRecruit(kind) => {
                    let spec = civilian_recruitment_spec(kind);
                    let progress = &mut orders.civilian_recruitment[kind];
                    let maximum = max_recruit_order(
                        progress,
                        spec.primary,
                        spec.secondary,
                        spec.cash_per_unit,
                        spec.workforce,
                        city,
                        owner,
                        *treasury,
                    );
                    (&*progress, progress.quantity, maximum)
                }
                CityOrderId::MilitaryRecruit(category) => {
                    let state = &mut orders.military_recruitment[category];
                    let spec = military_recruitment_spec(state.unit_kind)
                        .expect("military order has a recruitable retail unit recipe");
                    let maximum = max_recruit_order(
                        &mut state.progress,
                        spec.primary,
                        spec.secondary,
                        spec.cash_per_unit,
                        spec.workforce,
                        city,
                        owner,
                        *treasury,
                    );
                    (&state.progress, state.progress.quantity, maximum)
                }
                CityOrderId::Ship(track) => {
                    let state = &orders.ships[track];
                    let maximum = ship_max_order(state, city);
                    (&state.progress, state.progress.quantity, maximum)
                }
                CityOrderId::Training(level) => {
                    let progress = &mut orders.training[level];
                    let maximum = training_max_order(level, progress, city, owner, *treasury);
                    (&*progress, progress.quantity, maximum)
                }
                CityOrderId::Expansion(facility) => {
                    let spec = expansion_order_spec(facility);
                    let state = orders.expansions[facility.slot()]
                        .as_mut()
                        .expect("expansion order exists for every expandable production slot");
                    let maximum = expansion_max_order(state, city, spec.primary, spec.secondary);
                    (&state.progress, state.requested_quantity, maximum)
                }
                CityOrderId::FoodProcessing => {
                    let progress = &orders.food_processing;
                    let maximum = food_processing_max_order(progress, city);
                    (progress, progress.quantity, maximum)
                }
                CityOrderId::PowerPlant => {
                    let state = &orders.power_plant;
                    let maximum = power_plant_max_order(state, city);
                    (&state.progress, state.desired_quantity, maximum)
                }
                CityOrderId::TransportCapacity => {
                    let spec = transport_capacity_order_spec();
                    let state = &mut orders.transport_capacity;
                    let maximum = capacity_max_order(
                        state,
                        city,
                        spec.primary,
                        spec.secondary,
                        spec.production_slot,
                    );
                    (&state.progress, state.requested_quantity, maximum)
                }
                CityOrderId::PopulationGrowth => {
                    let progress = &mut orders.population_growth;
                    let maximum = population_growth_max_order(progress, city);
                    (&*progress, progress.quantity, maximum)
                }
            };
            CityOrderStatus {
                quantity: progress.quantity,
                requested_quantity,
                maximum,
                limiting_constraint: progress.limiting_constraint,
            }
        })
    }

    /// Pure projection of a city order's current quantity, request, maximum, and
    /// remembered limiting constraint. Does not mutate authoritative state.
    pub fn city_order_status(&self, nation: MajorNationId, order: CityOrderId) -> CityOrderStatus {
        let major = self.nations.major(nation);
        let city = major.city();
        let owner = major.economy();
        let treasury = major.common().treasury;
        // Compute maxima against temporary order copies so projection cannot
        // refresh the remembered limiting constraint.
        match order {
            CityOrderId::Item(output) => {
                let spec = item_order_spec(output);
                let mut state = city.orders.items[output.resource()]
                    .clone()
                    .expect("item order exists for every retail item recipe");
                let maximum = item_max_order(&mut state, city, spec);
                CityOrderStatus {
                    quantity: state.progress.quantity,
                    requested_quantity: state.requested_quantity,
                    maximum,
                    limiting_constraint: city.orders.items[output.resource()]
                        .as_ref()
                        .expect("item order exists for every retail item recipe")
                        .progress
                        .limiting_constraint,
                }
            }
            CityOrderId::CivilianRecruit(kind) => {
                let spec = civilian_recruitment_spec(kind);
                let mut progress = city.orders.civilian_recruitment[kind].clone();
                let maximum = max_recruit_order(
                    &mut progress,
                    spec.primary,
                    spec.secondary,
                    spec.cash_per_unit,
                    spec.workforce,
                    city,
                    owner,
                    treasury,
                );
                CityOrderStatus {
                    quantity: city.orders.civilian_recruitment[kind].quantity,
                    requested_quantity: city.orders.civilian_recruitment[kind].quantity,
                    maximum,
                    limiting_constraint: city.orders.civilian_recruitment[kind].limiting_constraint,
                }
            }
            CityOrderId::MilitaryRecruit(category) => {
                let mut state = city.orders.military_recruitment[category].clone();
                let spec = military_recruitment_spec(state.unit_kind)
                    .expect("military order has a recruitable retail unit recipe");
                let maximum = max_recruit_order(
                    &mut state.progress,
                    spec.primary,
                    spec.secondary,
                    spec.cash_per_unit,
                    spec.workforce,
                    city,
                    owner,
                    treasury,
                );
                let original = &city.orders.military_recruitment[category];
                CityOrderStatus {
                    quantity: original.progress.quantity,
                    requested_quantity: original.progress.quantity,
                    maximum,
                    limiting_constraint: original.progress.limiting_constraint,
                }
            }
            CityOrderId::Ship(track) => {
                let state = &city.orders.ships[track];
                let maximum = ship_max_order(state, city);
                CityOrderStatus {
                    quantity: state.progress.quantity,
                    requested_quantity: state.progress.quantity,
                    maximum,
                    limiting_constraint: state.progress.limiting_constraint,
                }
            }
            CityOrderId::Training(level) => {
                let mut progress = city.orders.training[level].clone();
                let maximum = training_max_order(level, &mut progress, city, owner, treasury);
                let original = &city.orders.training[level];
                CityOrderStatus {
                    quantity: original.quantity,
                    requested_quantity: original.quantity,
                    maximum,
                    limiting_constraint: original.limiting_constraint,
                }
            }
            CityOrderId::Expansion(facility) => {
                let spec = expansion_order_spec(facility);
                let state = city.orders.expansions[facility.slot()]
                    .clone()
                    .expect("expansion order exists for every expandable production slot");
                let maximum = expansion_max_order(&state, city, spec.primary, spec.secondary);
                let original = city.orders.expansions[facility.slot()]
                    .as_ref()
                    .expect("expansion order exists for every expandable production slot");
                CityOrderStatus {
                    quantity: original.progress.quantity,
                    requested_quantity: original.requested_quantity,
                    maximum,
                    limiting_constraint: original.progress.limiting_constraint,
                }
            }
            CityOrderId::FoodProcessing => {
                let progress = &city.orders.food_processing;
                let maximum = food_processing_max_order(progress, city);
                CityOrderStatus {
                    quantity: progress.quantity,
                    requested_quantity: progress.quantity,
                    maximum,
                    limiting_constraint: progress.limiting_constraint,
                }
            }
            CityOrderId::PowerPlant => {
                let state = &city.orders.power_plant;
                let maximum = power_plant_max_order(state, city);
                CityOrderStatus {
                    quantity: state.progress.quantity,
                    requested_quantity: state.desired_quantity,
                    maximum,
                    limiting_constraint: state.progress.limiting_constraint,
                }
            }
            CityOrderId::TransportCapacity => {
                let spec = transport_capacity_order_spec();
                let mut state = city.orders.transport_capacity.clone();
                let maximum = capacity_max_order(
                    &mut state,
                    city,
                    spec.primary,
                    spec.secondary,
                    spec.production_slot,
                );
                let original = &city.orders.transport_capacity;
                CityOrderStatus {
                    quantity: original.progress.quantity,
                    requested_quantity: original.requested_quantity,
                    maximum,
                    limiting_constraint: original.progress.limiting_constraint,
                }
            }
            CityOrderId::PopulationGrowth => {
                let mut progress = city.orders.population_growth.clone();
                let maximum = population_growth_max_order(&mut progress, city);
                let original = &city.orders.population_growth;
                CityOrderStatus {
                    quantity: original.quantity,
                    requested_quantity: original.quantity,
                    maximum,
                    limiting_constraint: original.limiting_constraint,
                }
            }
        }
    }

    /// Applies an absolute retail city-order quantity. Legal rejection is an
    /// explicit [`CityOrderChange::Rejected`]; the remembered limiting constraint may
    /// still be refreshed by either outcome.
    pub fn set_city_order_quantity(
        &mut self,
        nation: MajorNationId,
        order: CityOrderId,
        quantity: i16,
    ) -> CityOrderChange {
        let applied = self.with_city_orders(nation, |orders, city, owner, treasury| match order {
            CityOrderId::Item(output) => {
                let spec = item_order_spec(output);
                let state = orders.items[output.resource()]
                    .as_mut()
                    .expect("item order exists for every retail item recipe");
                set_item_quantity(state, city, spec, quantity)
            }
            CityOrderId::CivilianRecruit(kind) => {
                let spec = civilian_recruitment_spec(kind);
                set_recruit_quantity(
                    &mut orders.civilian_recruitment[kind],
                    spec.primary,
                    spec.secondary,
                    spec.cash_per_unit,
                    spec.workforce,
                    city,
                    owner,
                    treasury,
                    quantity,
                )
            }
            CityOrderId::MilitaryRecruit(category) => {
                let state = &mut orders.military_recruitment[category];
                let spec = military_recruitment_spec(state.unit_kind)
                    .expect("military order has a recruitable retail unit recipe");
                set_recruit_quantity(
                    &mut state.progress,
                    spec.primary,
                    spec.secondary,
                    spec.cash_per_unit,
                    spec.workforce,
                    city,
                    owner,
                    treasury,
                    quantity,
                )
            }
            CityOrderId::Ship(track) => set_ship_quantity(&mut orders.ships[track], city, quantity),
            CityOrderId::Training(level) => set_training_quantity(
                level,
                &mut orders.training[level],
                city,
                owner,
                treasury,
                quantity,
            ),
            CityOrderId::Expansion(facility) => {
                let spec = expansion_order_spec(facility);
                let state = orders.expansions[facility.slot()]
                    .as_mut()
                    .expect("expansion order exists for every expandable production slot");
                set_expansion_quantity(state, city, spec.primary, spec.secondary, quantity)
            }
            CityOrderId::FoodProcessing => {
                set_food_processing_quantity(&mut orders.food_processing, city, quantity)
            }
            CityOrderId::PowerPlant => {
                set_power_plant_quantity(&mut orders.power_plant, city, quantity)
            }
            CityOrderId::TransportCapacity => {
                let spec = transport_capacity_order_spec();
                set_capacity_quantity(
                    &mut orders.transport_capacity,
                    city,
                    spec.primary,
                    spec.secondary,
                    spec.production_slot,
                    quantity,
                )
            }
            CityOrderId::PopulationGrowth => {
                set_population_growth_quantity(&mut orders.population_growth, city, quantity)
            }
        });
        let status = self.city_order_status(nation, order);
        if applied {
            CityOrderChange::Applied(status)
        } else {
            CityOrderChange::Rejected(status)
        }
    }

    /// Applies a signed quantity step through the same absolute retail setter.
    pub fn adjust_city_order(
        &mut self,
        nation: MajorNationId,
        order: CityOrderId,
        delta: i16,
    ) -> CityOrderChange {
        let quantity = {
            let city = self.nations.city(nation);
            match order {
                CityOrderId::Item(output) => {
                    city.orders.items[output.resource()]
                        .as_ref()
                        .expect("item order has a retail recipe")
                        .progress
                        .quantity
                }
                CityOrderId::CivilianRecruit(kind) => {
                    city.orders.civilian_recruitment[kind].quantity
                }
                CityOrderId::MilitaryRecruit(category) => {
                    city.orders.military_recruitment[category].progress.quantity
                }
                CityOrderId::Ship(track) => city.orders.ships[track].progress.quantity,
                CityOrderId::Training(level) => city.orders.training[level].quantity,
                CityOrderId::Expansion(facility) => {
                    city.orders.expansions[facility.slot()]
                        .as_ref()
                        .expect("expansion order exists for every expandable production slot")
                        .progress
                        .quantity
                }
                CityOrderId::FoodProcessing => city.orders.food_processing.quantity,
                CityOrderId::PowerPlant => city.orders.power_plant.progress.quantity,
                CityOrderId::TransportCapacity => city.orders.transport_capacity.progress.quantity,
                CityOrderId::PopulationGrowth => city.orders.population_growth.quantity,
            }
        };
        self.set_city_order_quantity(nation, order, quantity + delta)
    }
}
