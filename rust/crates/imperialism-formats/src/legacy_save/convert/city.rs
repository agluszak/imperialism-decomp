use super::*;
use imperialism_core::*;

fn production_progress(order: &LegacyProductionOrder) -> ProductionProgress {
    ProductionProgress {
        quantity: order.quantity,
        limiting_constraint: match order.limiting_constraint {
            0 => ProductionConstraint::Resources,
            1 => ProductionConstraint::Workforce,
            2 => ProductionConstraint::Capacity,
            3 => ProductionConstraint::Treasury,
            value => panic!("unrecovered city production constraint {value}"),
        },
    }
}

fn requested_city_order(order: &LegacyItemOrder) -> RequestedCityOrderState {
    RequestedCityOrderState {
        progress: production_progress(&order.order),
        requested_quantity: order.requested_quantity,
        tracking_by_resource: ResourceTable::from_array(order.order.tracking_slots),
        accumulated_value: order.order.accumulated_value,
    }
}

impl LegacyCityOrders {
    fn city_orders(&self) -> CityOrders {
        CityOrders {
            items: ItemOrderTable::from_array(self.items.each_ref().map(requested_city_order)),
            civilian_recruitment: CivilianUnitTable::from_array(std::array::from_fn(|index| {
                production_progress(&self.civilian_recruitment[index].order)
            })),
            military_recruitment: MilitaryRecruitOrderTable::from_array(std::array::from_fn(
                |index| {
                    let order = &self.military_recruitment[index];
                    MilitaryRecruitOrderState {
                        unit_kind: MilitaryUnitKind::from_index(
                            order.order.resource_type_index as u8,
                        )
                        .expect("retail military recruitment unit kind"),
                        progress: production_progress(&order.order),
                    }
                },
            )),
            ships: ShipOrderTable::from_array(std::array::from_fn(|index| {
                let order = &self.ships[index];
                let tracking = ResourceTable::from_array(order.tracking_slots);
                ShipOrderState {
                    ship_type: super::units::ship_type_from_retail(order.resource_type_index),
                    progress: production_progress(order),
                    materials: ShipMaterials {
                        lumber: tracking[ResourceKind::Lumber],
                        fabric: tracking[ResourceKind::Fabric],
                        arms: tracking[ResourceKind::Arms],
                        steel: tracking[ResourceKind::Steel],
                        coal: tracking[ResourceKind::Coal],
                        fuel: tracking[ResourceKind::Fuel],
                    },
                }
            })),
            training: TrainingOrderTable::from_array(
                self.training.each_ref().map(production_progress),
            ),
            expansions: ExpansionOrderTable::from_array(
                self.expansions.each_ref().map(requested_city_order),
            ),
            food_processing: production_progress(&self.food_processing),
            power_plant: PowerPlantOrderState {
                progress: production_progress(&self.power_plant.order),
                desired_quantity: self.power_plant.desired_quantity,
            },
            transport_capacity: requested_city_order(&self.transport_capacity),
            population_growth: production_progress(&self.population_growth),
        }
    }
}

impl LegacyCityState {
    pub(super) fn city_state(&self) -> CityState {
        assert!(
            self.tasks.is_empty(),
            "semantic projection of city tasks is not implemented"
        );
        assert!(
            self.transport_requests.records.is_empty(),
            "semantic projection of city transport requests is not implemented"
        );

        let strike_phase = StrikePhase::from_retail(self.population.phase_value)
            .expect("retail population strike phase");
        let accumulator =
            PopulationAccumulator::new(f32::from_bits(self.population.count_float_bits))
                .expect("retail population accumulator is finite");

        CityState {
            orders: self.orders.city_orders(),
            power_plant_upgrade_queued: self.power_plant_upgrade_queued != 0,
            food_substitution_count: self.food_substitution_count,
            starvation_population_loss: self.starvation_population_loss,
            serialized_state: self.serialized_state,
            phase_counter: self.phase_counter,
            military_recruit_count_by_kind: MilitaryUnitTable::from_array(
                self.military_recruit_count_by_kind,
            ),
            civilian_recruit_count_by_kind: CivilianUnitTable::from_array(
                self.civilian_recruit_count_by_kind,
            ),
            ship_order_count_by_type: ShipTypeTable::from_array(self.order_count_by_type),
            rolling_item_production_score: self.rolling_item_production_score,
            low_production: self.low_production != 0,
            low_stock: self.low_stock != 0,
            reserved_by_type: ResourceTable::from_array(self.reserved_by_type),
            power_available: self.power_available,
            stockpile: Stockpile::from_table(ResourceTable::from_array(self.stockpile)),
            production_orders: ProductionTable::from_array(self.production_orders),
            production_accum: ProductionTable::from_array(self.production_accum),
            building_windows: city_windows_from_retail(
                self.production_flags,
                self.production_current,
                self.production_progress,
            ),
            // This constructed cache is not persisted by TCity::ReadFrom.
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: ResourceTable::from_array(self.unmet_resource_retries),
            consumed_production_input_by_type: ResourceTable::from_array(
                self.consumed_production_input_by_type,
            ),
            population: PopulationState::new(
                self.population.count,
                accumulator,
                self.population.strength,
                self.population.extra,
                strike_phase,
                LaborPool::from(self.population.baseline_labor),
                LaborPool::from(self.population.production_labor),
                LaborPool::from(self.population.pending_labor_delta),
                ResourceTable::from_array(self.population.predicted_need_by_resource),
            ),
        }
    }
}

pub(super) fn town_state(town: &LegacyTown) -> TownState {
    TownState {
        name: town.name.clone(),
        tile: optional_tile_id(i32::from(town.tile_index)).expect("retail town has a tile"),
        created_turn: town.created_turn,
        owner_nation: NationId::new(town.owner_nation as u8),
        resource_yield_by_type: ResourceTable::from_array(town.resource_yield_by_type),
        transport_linked: town.transport_linked != 0,
        enabled: town.enabled,
        has_adjacent_city: town.has_adjacent_city,
        active: town.active != 0,
    }
}

pub(super) fn city_dto(city: &CityState) -> LegacyCityState {
    let orders = &city.orders;
    let (production_flags, production_current, production_progress) =
        city_windows_to_retail(&city.building_windows);
    LegacyCityState {
        power_plant_upgrade_queued: u8::from(city.power_plant_upgrade_queued),
        low_production: u8::from(city.low_production),
        low_stock: u8::from(city.low_stock),
        production_flags,
        food_substitution_count: city.food_substitution_count,
        starvation_population_loss: city.starvation_population_loss,
        serialized_state: city.serialized_state,
        phase_counter: city.phase_counter,
        power_available: city.power_available,
        military_recruit_count_by_kind: enum_i16(&city.military_recruit_count_by_kind),
        civilian_recruit_count_by_kind: enum_i16(&city.civilian_recruit_count_by_kind),
        order_count_by_type: enum_i16(&city.ship_order_count_by_type),
        stockpile: resource_i16_from_stockpile(&city.stockpile),
        production_orders: *city.production_orders.as_array(),
        production_accum: *city.production_accum.as_array(),
        unmet_resource_retries: resource_i16(&city.unmet_resource_retries),
        reserved_by_type: resource_i16(&city.reserved_by_type),
        production_current,
        production_progress,
        consumed_production_input_by_type: resource_i16(&city.consumed_production_input_by_type),
        rolling_item_production_score: city.rolling_item_production_score,
        population: LegacyPopulationState {
            count: city.population.count(),
            strength: city.population.strength(),
            extra: city.population.extra(),
            phase_value: city.population.strike_phase().retail(),
            predicted_need_by_resource: resource_i16(city.population.predicted_need_by_resource()),
            count_float_bits: city.population.accumulator().to_bits(),
            baseline_labor: city.population.baseline_labor().into(),
            production_labor: city.population.production_labor().into(),
            pending_labor_delta: city.population.pending_labor_delta().into(),
        },
        orders: city_orders_dto(orders),
        tasks: Vec::new(),
        transport_requests: empty_records(),
    }
}

fn city_orders_dto(orders: &CityOrders) -> LegacyCityOrders {
    LegacyCityOrders {
        food_processing: production_from_progress(&orders.food_processing, 0),
        items: std::array::from_fn(|index| {
            let item = ManufacturedItem::from_usize(index);
            item_from_requested(&orders.items[item], item.resource() as i16)
        }),
        training: std::array::from_fn(|index| {
            production_from_progress(&orders.training[TrainingLevel::from_usize(index)], 0)
        }),
        military_recruitment: std::array::from_fn(|index| {
            let order =
                &orders.military_recruitment[MilitaryRecruitmentCategory::from_usize(index)];
            unit_from_progress(&order.progress, i16::from(order.unit_kind as u8))
        }),
        civilian_recruitment: std::array::from_fn(|index| {
            unit_from_progress(
                &orders.civilian_recruitment[CivilianUnitKind::from_usize(index)],
                index as i16,
            )
        }),
        ships: std::array::from_fn(|index| {
            production_from_ship(&orders.ships[ShipOrderSlot::from_usize(index)])
        }),
        transport_capacity: item_from_requested(&orders.transport_capacity, 0),
        power_plant: LegacyPowerPlantOrder {
            order: production_from_progress(&orders.power_plant.progress, 0),
            desired_quantity: orders.power_plant.desired_quantity,
        },
        expansions: std::array::from_fn(|index| {
            item_from_requested(&orders.expansions[ExpandableFacility::from_usize(index)], 0)
        }),
        population_growth: production_from_progress(&orders.population_growth, 0),
    }
}

pub(super) fn post_city_dto(
    economy: &GreatPowerState,
    towns: &[TownState],
    civilians: &[CivilianUnitState],
    topology: MapTopology,
) -> LegacyGreatPowerPostCity {
    LegacyGreatPowerPostCity {
        towns: towns.iter().map(town_dto).collect(),
        civilian_units: civilians
            .iter()
            .map(|unit| super::units::civilian_unit_dto(unit, topology))
            .collect(),
        candidate_nation_flags: *economy.candidate_nation_flags.as_array(),
        diplomacy_budget_base: economy.diplomacy_budget_base,
        escalation_counter: economy.escalation_counter as i8,
        pending_commitment_cost: economy.pending_commitment_cost,
        pressure_counter: economy.pressure_counter as i8,
        army_movement_budget: economy.army_movement_budget,
        turn_finished_flag: u8::from(economy.turn_finished),
        special_resource_trade_balance: economy.special_resource_trade_balance,
        aid_allocation_total: economy.aid_allocation_total,
        colony_boycott_flags: *economy.colony_boycott_flags.as_array(),
        military_expenses: economy.military_expenses,
    }
}

fn town_dto(town: &TownState) -> LegacyTown {
    LegacyTown {
        name: town.name.clone(),
        tile_index: town.tile.get() as i16,
        opaque_fields: [0; 2],
        created_turn: town.created_turn,
        owner_nation: i16::from(town.owner_nation.get()),
        resource_yield_by_type: resource_i16(&town.resource_yield_by_type),
        transport_linked: u8::from(town.transport_linked),
        enabled: town.enabled,
        has_adjacent_city: town.has_adjacent_city,
        active: u8::from(town.active),
    }
}

fn production_from_progress(
    progress: &ProductionProgress,
    resource_type_index: i16,
) -> LegacyProductionOrder {
    production_order(progress, resource_type_index, [0; RESOURCE_KIND_COUNT], 0)
}

fn production_from_ship(order: &ShipOrderState) -> LegacyProductionOrder {
    let mut tracking_slots = [0_i16; RESOURCE_KIND_COUNT];
    for (kind, amount) in order.materials.iter() {
        tracking_slots[kind as usize] = amount;
    }
    production_order(&order.progress, order.ship_type as i16, tracking_slots, 0)
}

fn production_order(
    progress: &ProductionProgress,
    resource_type_index: i16,
    tracking_slots: [i16; RESOURCE_KIND_COUNT],
    accumulated_value: i32,
) -> LegacyProductionOrder {
    LegacyProductionOrder {
        resource_type_index,
        quantity: progress.quantity,
        limiting_constraint: match progress.limiting_constraint {
            ProductionConstraint::Resources => 0,
            ProductionConstraint::Workforce => 1,
            ProductionConstraint::Capacity => 2,
            ProductionConstraint::Treasury => 3,
        },
        tracking_slots,
        accumulated_value,
    }
}

fn item_from_requested(
    order: &RequestedCityOrderState,
    resource_type_index: i16,
) -> LegacyItemOrder {
    LegacyItemOrder {
        order: production_order(
            &order.progress,
            resource_type_index,
            resource_i16(&order.tracking_by_resource),
            order.accumulated_value,
        ),
        requested_quantity: order.requested_quantity,
        primary_input_resource_id: 0,
        secondary_input_resource_id: 0,
        production_slot: 0,
    }
}

fn unit_from_progress(progress: &ProductionProgress, resource_type_index: i16) -> LegacyUnitOrder {
    LegacyUnitOrder {
        order: production_from_progress(progress, resource_type_index),
        primary_input_resource_id: 0,
        secondary_input_resource_id: 0,
        primary_input_per_unit: 0,
        secondary_input_per_unit: 0,
        cash_cost_per_unit: 0,
        workforce_mode: 0,
        specialist_mode: 0,
    }
}
