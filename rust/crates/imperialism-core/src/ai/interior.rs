//! AI city interior-minister orders issued during [`GameState::do_city_and_transport`].

use crate::*;

/// How [`GameState::request_ai_resource`] spends city stock, transport, and order metrics.
#[derive(Clone, Copy)]
struct AiResourcePolicy {
    deduct_city_stock: bool,
    request_extra_transport: bool,
    record_order_shortfall: bool,
}

impl AiResourcePolicy {
    /// Draw from stock first; request wagons and remember unmet amounts for later city orders.
    const FOR_PRODUCTION: Self = Self {
        deduct_city_stock: true,
        request_extra_transport: true,
        record_order_shortfall: true,
    };

    /// Draw from stock first and request wagons, without recording a production shortfall.
    const FOR_TRANSPORT: Self = Self {
        deduct_city_stock: true,
        request_extra_transport: true,
        record_order_shortfall: false,
    };

    /// Ignore stock and request wagons so leftover need can still come from the map.
    const SUPPLEMENT_FROM_MAP: Self = Self {
        deduct_city_stock: false,
        request_extra_transport: true,
        record_order_shortfall: false,
    };

    /// Ignore stock and do not request extra wagons; soak remaining transport capacity.
    const FILL_SPARE_CAPACITY: Self = Self {
        deduct_city_stock: false,
        request_extra_transport: false,
        record_order_shortfall: false,
    };
}

impl GameState {
    pub(crate) fn rebalance_ai_transport(&mut self, nation: MajorNationId) {
        let summary = {
            let city = self.nations.city_mut(nation);
            let population_order = city.orders.population_growth.quantity;
            *city.refresh_unreserved_city_needs(population_order)
        };

        let mut unfilled = 0_i16;
        for resource in [ResourceKind::Grain, ResourceKind::Fruit] {
            let requested = summary[resource];
            let allocated = self.request_ai_resource(
                nation,
                resource,
                requested,
                AiResourcePolicy::FOR_PRODUCTION,
            );
            unfilled += requested - allocated;
        }

        let animal_need = summary[ResourceKind::Livestock];
        let fish = self.request_ai_resource(
            nation,
            ResourceKind::Fish,
            animal_need,
            AiResourcePolicy::FOR_TRANSPORT,
        );
        if fish < animal_need {
            let livestock = self.request_ai_resource(
                nation,
                ResourceKind::Livestock,
                animal_need,
                AiResourcePolicy::FOR_PRODUCTION,
            );
            unfilled += animal_need - fish - livestock;
        }

        for resource in [
            ResourceKind::Grain,
            ResourceKind::Fruit,
            ResourceKind::Livestock,
            ResourceKind::Fish,
        ] {
            if unfilled == 0 {
                break;
            }
            unfilled -= self.request_ai_resource(
                nation,
                resource,
                unfilled,
                AiResourcePolicy::SUPPLEMENT_FROM_MAP,
            );
        }

        let gold = self.nations.majors[nation].economy.need_current_by_type[ResourceKind::Gold];
        self.request_ai_resource(
            nation,
            ResourceKind::Gold,
            gold,
            AiResourcePolicy::FOR_TRANSPORT,
        );
        for index in ResourceKind::Food as u8..=ResourceKind::Arms as u8 {
            let resource = ResourceKind::from_index(index).expect("manufactured resource index");
            let current = self.nations.majors[nation].economy.need_current_by_type[resource];
            self.request_ai_resource(
                nation,
                resource,
                summary[resource] + current,
                AiResourcePolicy::FOR_TRANSPORT,
            );
        }
    }

    fn request_ai_resource(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
        requested: i16,
        policy: AiResourcePolicy,
    ) -> i16 {
        let MajorNation {
            common,
            economy,
            city,
            ..
        } = &mut self.nations.majors[nation];
        let mut remaining = requested;
        if policy.deduct_city_stock {
            if city.stockpile[resource] >= requested {
                return requested;
            }
            remaining = requested - city.stockpile[resource];
        }

        let available_capacity =
            economy.capacities.transport - economy.capacities.reserved_transport;
        let current_target = economy.need_target_by_type[resource];
        let available_supply =
            (economy.need_current_by_type[resource] - current_target).min(remaining);
        let mut unavailable_supply = 0_i16;
        if available_supply > available_capacity {
            unavailable_supply = available_supply - available_capacity;
            if policy.request_extra_transport {
                economy
                    .interior_civilian
                    .city_order_demand
                    .transport_capacity += unavailable_supply;
            }
            economy.update_need_target(resource, current_target + available_capacity);
            if resource == ResourceKind::Gold {
                common.treasury += i32::from(available_capacity) * 200;
            } else if resource == ResourceKind::Gems {
                common.treasury += i32::from(available_capacity) * 500;
            } else {
                city.adjust_stock(resource, available_capacity);
            }
            remaining -= available_capacity;
        } else {
            economy.update_need_target(resource, current_target + available_supply);
            if resource == ResourceKind::Gold {
                // Retail's short branch uses the Gems value here.
                common.treasury += i32::from(available_supply) * 500;
            } else {
                city.adjust_stock(resource, available_supply);
            }
            remaining -= available_supply;
        }

        if remaining != 0 && policy.record_order_shortfall {
            let shortfall = remaining - unavailable_supply;
            if shortfall > 0 {
                economy.interior_civilian.resource_order_metrics[resource] += shortfall;
            }
        }
        requested - remaining
    }

    pub(crate) fn clear_ai_city_orders(&mut self, nation: MajorNationId) {
        self.set_city_order_quantity(nation, CityOrderId::FoodProcessing, 0);
        for output in ManufacturedItem::ALL {
            self.set_city_order_quantity(nation, CityOrderId::Item(output), 0);
        }
        for level in TrainingLevel::ALL {
            self.set_city_order_quantity(nation, CityOrderId::Training(level), 0);
        }
        for category in MilitaryRecruitmentCategory::ALL {
            self.set_city_order_quantity(nation, CityOrderId::MilitaryRecruit(category), 0);
        }
        for kind in CivilianUnitKind::ALL {
            self.set_city_order_quantity(nation, CityOrderId::CivilianRecruit(kind), 0);
        }
        for slot in ShipOrderSlot::ALL {
            self.set_city_order_quantity(nation, CityOrderId::Ship(slot), 0);
        }
        self.set_city_order_quantity(nation, CityOrderId::TransportCapacity, 0);
        self.set_city_order_quantity(nation, CityOrderId::PowerPlant, 0);
        for facility in ExpandableFacility::ALL {
            self.set_city_order_quantity(nation, CityOrderId::Expansion(facility), 0);
        }
        self.set_city_order_quantity(nation, CityOrderId::PopulationGrowth, 0);
    }

    pub(crate) fn process_ai_pending_ship(&mut self, nation: MajorNationId) {
        let reserved_arms = {
            let interior = self.nations.majors[nation]
                .economy
                .interior_civilian
                .as_mut();
            std::mem::take(&mut interior.temporarily_reserved_ship_arms)
        };
        self.nations
            .city_mut(nation)
            .adjust_stock(ResourceKind::Arms, reserved_arms);

        let Some(ship_type) = self.nations.majors[nation].economy.pending_ship.take() else {
            return;
        };
        let Some(slot) = ShipOrderSlot::ALL
            .into_iter()
            .find(|&slot| self.nations.city(nation).orders.ships[slot].ship_type == ship_type)
        else {
            return;
        };
        let costs = ship_order_costs(ship_type);
        for (resource, amount) in costs.iter() {
            if amount != 0 {
                self.request_ai_resource(
                    nation,
                    resource,
                    amount,
                    AiResourcePolicy::FOR_PRODUCTION,
                );
            }
        }
        let maximum = self
            .city_order_limit(nation, CityOrderId::Ship(slot))
            .maximum;
        assert!(self.set_city_order_quantity(nation, CityOrderId::Ship(slot), maximum.min(1)));
    }

    pub(crate) fn rebalance_ai_labor(&mut self, nation: MajorNationId) -> i16 {
        let average = self.nations.majors[nation]
            .economy
            .interior_civilian
            .average_development_order_allocation;
        let target = average as i16 + 2;
        let baseline = self.nations.city(nation).population.baseline_labor;
        let capacity =
            self.nations.city(nation).production_accum[CityFacilitySlot::RegionalPopulation];
        let interior = self.nations.majors[nation]
            .economy
            .interior_civilian
            .as_mut();
        debug_assert_eq!(interior.deferred_labor_shortfall, 0);
        interior.city_order_demand.training[TrainingLevel::Medium] =
            (target - baseline.medium).clamp(0, capacity);
        let remaining = capacity - interior.city_order_demand.training[TrainingLevel::Medium];
        interior.city_order_demand.population_growth = (target - baseline.low).clamp(0, remaining);

        for level in TrainingLevel::ALL {
            let requested = self.nations.majors[nation]
                .economy
                .interior_civilian
                .city_order_demand
                .training[level];
            let maximum = self
                .city_order_limit(nation, CityOrderId::Training(level))
                .maximum;
            let accepted = requested.min(maximum);
            assert!(self.set_city_order_quantity(nation, CityOrderId::Training(level), accepted));
            self.nations.majors[nation]
                .economy
                .interior_civilian
                .city_order_demand
                .training[level] = 0;
        }
        let requested = self.nations.majors[nation]
            .economy
            .interior_civilian
            .city_order_demand
            .population_growth;
        let maximum = self
            .city_order_limit(nation, CityOrderId::PopulationGrowth)
            .maximum;
        assert!(self.set_city_order_quantity(
            nation,
            CityOrderId::PopulationGrowth,
            requested.min(maximum),
        ));
        self.nations.majors[nation]
            .economy
            .interior_civilian
            .city_order_demand
            .population_growth = 0;

        let city = self.nations.city_mut(nation);
        let clothing = city.stockpile[ResourceKind::Clothing].min(2);
        let furniture = city.stockpile[ResourceKind::Furniture].min(2);
        city.adjust_stock(ResourceKind::Clothing, -clothing);
        city.consumed_production_input_by_type[ResourceKind::Clothing] = clothing;
        city.adjust_stock(ResourceKind::Furniture, -furniture);
        city.consumed_production_input_by_type[ResourceKind::Furniture] = furniture;
        if furniture == 0 && city.stockpile[ResourceKind::Lumber] > 1 {
            city.adjust_stock(ResourceKind::Lumber, -2);
            2
        } else {
            0
        }
    }

    pub(crate) fn choose_ai_expansion(&mut self, nation: MajorNationId) {
        let mut priority = [0_usize, 1, 2, 3, 4, 5, 6];
        {
            let deficits = &mut self.nations.majors[nation]
                .economy
                .interior_civilian
                .production_deficit_by_slot;
            deficits[CityFacilitySlot::OilRefinery] = -1;
        }
        for destination in 0..6 {
            let mut best = destination;
            for candidate in destination + 1..7 {
                let deficits = &self.nations.majors[nation]
                    .economy
                    .interior_civilian
                    .production_deficit_by_slot;
                let candidate_score = deficits[ExpandableFacility::ALL[priority[candidate]].slot()];
                let best_score = deficits[ExpandableFacility::ALL[priority[best]].slot()];
                if candidate_score > best_score
                    || (candidate_score == best_score && self.rng.next_crt_rand() & 1 != 0)
                {
                    best = candidate;
                }
            }
            priority.swap(destination, best);
        }

        let best_facility = ExpandableFacility::ALL[priority[0]];
        if self.nations.majors[nation]
            .economy
            .interior_civilian
            .production_deficit_by_slot[best_facility.slot()]
            == 0
            && self.turn.economic_turn & 1 != 0
        {
            // Every supported building ratio is 0/0. VC5's unordered x87
            // comparison takes the primary member of the selected pair.
            let selected = ExpandableFacility::ALL[(self.rng.next_crt_rand() % 3) as usize];
            self.nations.majors[nation]
                .economy
                .interior_civilian
                .city_order_demand
                .expansions[selected.slot()] = 1;
        }

        for facility in ExpandableFacility::ALL {
            let requested = self.nations.majors[nation]
                .economy
                .interior_civilian
                .city_order_demand
                .expansions[facility.slot()];
            if requested == 0 {
                continue;
            }
            let (primary, secondary) = EXPANSION_INPUTS;
            self.request_ai_resource(nation, primary, requested, AiResourcePolicy::FOR_PRODUCTION);
            self.request_ai_resource(
                nation,
                secondary,
                requested,
                AiResourcePolicy::FOR_PRODUCTION,
            );
            let maximum = self
                .city_order_limit(nation, CityOrderId::Expansion(facility))
                .maximum;
            let accepted = requested.min(maximum);
            assert!(self.set_city_order_quantity(
                nation,
                CityOrderId::Expansion(facility),
                accepted
            ));
            let interior = self.nations.majors[nation]
                .economy
                .interior_civilian
                .as_mut();
            interior.city_order_demand.expansions[facility.slot()] -= accepted;
            if interior.city_order_demand.expansions[facility.slot()] < 2 {
                interior.production_deficit_by_slot[facility.slot()] = 0;
            }
        }
    }

    pub(crate) fn compute_ai_item_demands(&mut self, nation: MajorNationId) {
        let city = self.nations.city(nation);
        let lumber = city.production_orders[CityFacilitySlot::LumberMill] + 1;
        let fabric = city.production_orders[CityFacilitySlot::TextileMill] + 1;
        let steel = city.production_orders[CityFacilitySlot::SteelMill] + 1;
        let needs_paper = city.stockpile[ResourceKind::Paper] < 3;
        let metrics = &mut self.nations.majors[nation]
            .economy
            .interior_civilian
            .resource_order_metrics;
        metrics[ResourceKind::Lumber] = lumber;
        metrics[ResourceKind::Fabric] = fabric;
        metrics[ResourceKind::Steel] = steel;
        if needs_paper && metrics[ResourceKind::Paper] == 0 {
            metrics[ResourceKind::Paper] = 1;
        }
    }

    pub(crate) fn issue_ai_item_orders(&mut self, nation: MajorNationId) {
        for output in [
            ManufacturedItem::Clothing,
            ManufacturedItem::Furniture,
            ManufacturedItem::Arms,
            ManufacturedItem::Hardware,
        ] {
            self.issue_ai_item_order(nation, output);
        }
        self.issue_ai_food_order(nation);
        self.issue_ai_item_order(nation, ManufacturedItem::Paper);
        if self.nations.city(nation).stockpile[ResourceKind::Lumber]
            < self.nations.city(nation).stockpile[ResourceKind::Steel]
        {
            self.issue_ai_item_order(nation, ManufacturedItem::Lumber);
            self.issue_ai_item_order(nation, ManufacturedItem::Steel);
        } else {
            self.issue_ai_item_order(nation, ManufacturedItem::Steel);
            self.issue_ai_item_order(nation, ManufacturedItem::Lumber);
        }
        self.issue_ai_item_order(nation, ManufacturedItem::Fabric);
    }

    fn issue_ai_food_order(&mut self, nation: MajorNationId) {
        let requested = self.nations.majors[nation]
            .economy
            .interior_civilian
            .resource_order_metrics[ResourceKind::Food];
        let maximum = self
            .city_order_limit(nation, CityOrderId::FoodProcessing)
            .maximum;
        let accepted = requested.min(maximum);
        assert!(self.set_city_order_quantity(nation, CityOrderId::FoodProcessing, accepted));
        let metric = &mut self.nations.majors[nation]
            .economy
            .interior_civilian
            .resource_order_metrics[ResourceKind::Food];
        *metric = (*metric - accepted).max(0);
    }

    fn issue_ai_item_order(&mut self, nation: MajorNationId, output: ManufacturedItem) {
        let resource = output.resource();
        let mut requested = self.nations.majors[nation]
            .economy
            .interior_civilian
            .resource_order_metrics[resource];
        let facility = output.facility();
        let production_limit = self.nations.city(nation).production_orders[facility] * 2 + 2;
        requested = requested.min(production_limit);
        self.nations.majors[nation]
            .economy
            .interior_civilian
            .resource_order_metrics[resource] = requested;

        match output.inputs() {
            ItemInputs::Double(primary) => {
                self.request_ai_resource(
                    nation,
                    primary,
                    requested * 2,
                    AiResourcePolicy::FOR_PRODUCTION,
                );
            }
            ItemInputs::Both(primary, secondary) => {
                self.request_ai_resource(
                    nation,
                    primary,
                    requested,
                    AiResourcePolicy::FOR_PRODUCTION,
                );
                self.request_ai_resource(
                    nation,
                    secondary,
                    requested,
                    AiResourcePolicy::FOR_PRODUCTION,
                );
            }
            ItemInputs::Either(_, _) => {
                let material_need = requested * 2;
                self.request_ai_resource(
                    nation,
                    ResourceKind::Cotton,
                    material_need,
                    AiResourcePolicy::FOR_PRODUCTION,
                );
                let stock = self.nations.city(nation).stockpile[ResourceKind::Cotton]
                    + self.nations.city(nation).stockpile[ResourceKind::Wool];
                if stock < material_need {
                    self.request_ai_resource(
                        nation,
                        ResourceKind::Wool,
                        material_need - stock,
                        AiResourcePolicy::FOR_PRODUCTION,
                    );
                }
            }
        }

        let limit = self.city_order_limit(nation, CityOrderId::Item(output));
        let accepted = requested.min(limit.maximum);
        if accepted < requested && limit.constraint == ProductionConstraint::Capacity {
            self.nations.majors[nation]
                .economy
                .interior_civilian
                .production_deficit_by_slot[facility] += requested - accepted;
        }
        assert!(self.set_city_order_quantity(nation, CityOrderId::Item(output), accepted));
        let metric = &mut self.nations.majors[nation]
            .economy
            .interior_civilian
            .resource_order_metrics[resource];
        *metric = (*metric - accepted).max(0);
    }

    pub(crate) fn fill_ai_transport_capacity(&mut self, nation: MajorNationId) {
        let horses = self.nations.city(nation).stockpile[ResourceKind::Horses];
        if horses < 5 {
            self.request_ai_resource(
                nation,
                ResourceKind::Horses,
                5 - horses,
                AiResourcePolicy::FILL_SPARE_CAPACITY,
            );
        }

        let mut remaining = self.nations.majors[nation].economy.capacities.transport
            - self.nations.majors[nation]
                .economy
                .capacities
                .reserved_transport;
        let mut previous = -1_i16;
        while remaining > 0 && previous != remaining {
            previous = remaining;
            for resource in all_resources() {
                remaining -= self.request_ai_resource(
                    nation,
                    resource,
                    1,
                    AiResourcePolicy::FILL_SPARE_CAPACITY,
                );
            }
        }
    }

    pub(crate) fn rebuild_ai_allocation_average(&mut self, nation: MajorNationId) {
        let mut allocation = ProductionTable::<i16>::default();
        for output in ManufacturedItem::ALL {
            let order = &self.nations.city(nation).orders.items[output];
            allocation[output.facility()] += order.progress.quantity;
        }
        let total = (0..CityFacilitySlot::COUNT)
            .map(|index| {
                allocation[CityFacilitySlot::from_index(index as u8).expect("production slot")]
            })
            .fold(0_i16, i16::wrapping_add);
        self.nations.majors[nation]
            .economy
            .interior_civilian
            .average_development_order_allocation = i32::from(total / 20);
    }

    pub(crate) fn determine_ai_trade_bid(&mut self, nation: MajorNationId) {
        let cotton = self.nations.majors[nation]
            .economy
            .interior_civilian
            .resource_order_metrics[ResourceKind::Cotton];
        let wool = self.nations.majors[nation]
            .economy
            .interior_civilian
            .resource_order_metrics[ResourceKind::Wool];
        if cotton != 0 || wool != 0 {
            let delta = i16::from(self.rng.next_crt_rand() % 100 >= 75);
            self.nations.majors[nation]
                .economy
                .foreign_trade
                .purchase_priority[TradeCommodity::Cotton] += delta;
        }
        for index in ResourceKind::Timber as u8..=ResourceKind::Oil as u8 {
            let resource = ResourceKind::from_index(index).expect("raw trade resource");
            let delta = self.nations.majors[nation]
                .economy
                .interior_civilian
                .resource_order_metrics[resource];
            if delta != 0 {
                let commodity = TradeCommodity::from_retail(i16::from(index))
                    .expect("raw resource has a trade row");
                self.nations.majors[nation]
                    .economy
                    .foreign_trade
                    .purchase_priority[commodity] += delta;
            }
        }

        let food = {
            let major = &self.nations.majors[nation];
            major
                .city
                .forecast_population_food(&major.economy.need_target_by_type)
        };
        let bid = if food.substitution_count != 0 || food.starvation_count != 0 {
            Some(ForeignTradeBid {
                commodity: TradeCommodity::Food,
                amount: food.substitution_count + food.starvation_count,
            })
        } else {
            let city = self.nations.city(nation);
            if city.stockpile[ResourceKind::Steel] == 0 {
                Some(ForeignTradeBid {
                    commodity: TradeCommodity::Steel,
                    amount: 4,
                })
            } else if city.stockpile[ResourceKind::Lumber] == 0 {
                Some(ForeignTradeBid {
                    commodity: TradeCommodity::Lumber,
                    amount: 4,
                })
            } else {
                let need = city.population.count / 2;
                (city.stockpile[ResourceKind::Food] < need).then(|| ForeignTradeBid {
                    commodity: TradeCommodity::Food,
                    amount: (city.population.count - city.stockpile[ResourceKind::Food]).min(6),
                })
            }
        };
        if let Some(bid) = bid {
            self.nations.majors[nation]
                .economy
                .foreign_trade
                .interior_bid = Some(bid);
        }
    }
}
