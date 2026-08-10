//! First-turn city and transport resolution (`TSimMgr` phase 8).

use crate::*;

const ITEM_OUTPUTS: [ManufacturedItem; 9] = ManufacturedItem::ALL;

const CIVILIAN_KINDS: [CivilianUnitKind; 9] = [
    CivilianUnitKind::Miner,
    CivilianUnitKind::Prospector,
    CivilianUnitKind::Farmer,
    CivilianUnitKind::Forester,
    CivilianUnitKind::Engineer,
    CivilianUnitKind::Rancher,
    CivilianUnitKind::Fisherman,
    CivilianUnitKind::Developer,
    CivilianUnitKind::Driller,
];

const MILITARY_CATEGORIES: [MilitaryRecruitmentCategory; 8] = [
    MilitaryRecruitmentCategory::LightInfantry,
    MilitaryRecruitmentCategory::RegularInfantry,
    MilitaryRecruitmentCategory::HeavyInfantry,
    MilitaryRecruitmentCategory::LightCavalry,
    MilitaryRecruitmentCategory::HeavyCavalry,
    MilitaryRecruitmentCategory::LightArtillery,
    MilitaryRecruitmentCategory::HeavyArtillery,
    MilitaryRecruitmentCategory::Demolitionist,
];

const SHIP_SLOTS: [ShipOrderSlot; 8] = [
    ShipOrderSlot::MerchantEarlyPrimary,
    ShipOrderSlot::MerchantEarlySecondary,
    ShipOrderSlot::MerchantAdvancedPrimary,
    ShipOrderSlot::MerchantAdvancedSecondary,
    ShipOrderSlot::WarshipEarlyPrimary,
    ShipOrderSlot::WarshipEarlySecondary,
    ShipOrderSlot::WarshipAdvancedPrimary,
    ShipOrderSlot::WarshipAdvancedSecondary,
];

const EXPANSION_SLOTS: [ExpandableFacility; 7] = ExpandableFacility::ALL;

impl GameState {
    pub(crate) fn supports_first_turn_city_transport_phase(&self) -> bool {
        let player = MajorNationId::new(6);
        if self.turn.phase != PhaseCode::CITY_AND_TRANSPORT
            || self.turn.economic_turn != 1
            || self.turn.difficulty != Difficulty::Easy
            || self.turn.scenario_map.is_some()
            || self.turn.active_nation != player.nation()
            || self.turn.selected_nation != player.nation()
            || !self.ships.is_empty()
            || !self.task_forces.is_empty()
            || self.technology.oil_drilling_available()
            || self.military_units.iter().any(|unit| unit.roster_id == 0)
            || (0..MajorNationId::COUNT).any(|major| {
                (MajorNationId::COUNT..NationId::COUNT).any(|minor| {
                    self.diplomacy.standings[MajorNationId::new(major).nation()]
                        [NationId::new(minor)]
                        > 169
                })
            })
        {
            return false;
        }

        (0..MajorNationId::COUNT).all(|index| {
            let nation = MajorNationId::new(index);
            let major = self.nations.major(nation);
            let should_be_human = nation == player;
            let expected_controller = if should_be_human {
                MajorNationController::Human
            } else {
                MajorNationController::Computer
            };
            let city = major.city();
            let economy = major.economy();
            let interior = economy.interior_civilian.as_ref();

            major.common().status() == CountryStatus::Independent
                && economy.controller == expected_controller
                && city.home_town.is_some()
                && city.population.count == 7
                && city.population.baseline_labor == LaborPool::new(4, 2, 1)
                && city.population.strength == 12
                && city.power_available == 0
                && (should_be_human
                    || EXPANSION_SLOTS
                        .into_iter()
                        .all(|facility| city.production_orders[facility.slot()] == 0))
                && !self.technology.city_capabilities_by_nation[nation].oil_drilling
                && economy.pending_actions == PendingActionTable::default()
                && economy.transported_items_by_resource == ResourceTable::default()
                && economy.purchased_items_by_resource == ResourceTable::default()
                && city_orders_are_idle(city.orders.as_ref())
                && interior.pending_recruitment.is_none()
                && interior.deferred_labor_shortfall == 0
                && interior.production_deficit_by_slot == ProductionTable::default()
                && interior.temporarily_reserved_ship_arms == 0
                && interior.resource_order_metrics == ResourceTable::default()
                && interior.average_development_order_allocation == 0
                && if should_be_human {
                    economy.pending_ship.is_none()
                        && interior.city_order_demand == AiCityOrderDemand::default()
                        && economy.pressure_counter == 0
                } else {
                    matches!(
                        economy.pending_ship,
                        Some(ShipType::Trader | ShipType::Indiaman)
                    ) && interior.city_order_demand == first_turn_ai_city_demand()
                        && major.common().treasury >= -20_000
                }
        })
    }

    pub(crate) fn run_first_turn_city_transport_phase(&mut self) {
        assert!(
            self.supports_first_turn_city_transport_phase(),
            "city-and-transport phase contains an unrecovered branch"
        );

        for index in (0..MajorNationId::COUNT).rev() {
            let nation = MajorNationId::new(index);
            if self.nations.major(nation).economy.controller.is_human() {
                self.nations.city_mut(nation).refresh_local_summary_flags();
                self.produce_city_units(nation);
                self.rebuild_nation_resource_yields(nation);
                self.add_created_items(nation);
                self.end_city_phase(nation);
            } else {
                self.fill_first_turn_ai_city_orders(nation);
                self.nations.city_mut(nation).refresh_local_summary_flags();
                self.produce_city_units(nation);
                self.rebuild_nation_resource_yields(nation);
            }
            self.refresh_merchant_capacity(nation);
        }
    }

    fn fill_first_turn_ai_city_orders(&mut self, nation: MajorNationId) {
        for resource in all_resources() {
            self.nations.majors[nation]
                .economy
                .update_need_target(resource, 0);
        }
        self.rebalance_first_turn_ai_transport(nation);
        self.end_city_phase(nation);
        self.clear_ai_city_orders(nation);
        self.process_first_turn_ai_pending_ship(nation);
        let temporary_lumber = self.rebalance_first_turn_ai_labor(nation);
        self.choose_first_turn_ai_expansion(nation);
        self.compute_first_turn_ai_item_demands(nation);
        if temporary_lumber != 0 {
            self.nations
                .city_mut(nation)
                .adjust_stock(ResourceKind::Lumber, temporary_lumber);
        }
        self.issue_first_turn_ai_item_orders(nation);
        self.fill_first_turn_ai_transport_capacity(nation);
        self.rebuild_first_turn_ai_allocation_average(nation);
        self.determine_first_turn_ai_trade_bid(nation);
    }

    fn rebalance_first_turn_ai_transport(&mut self, nation: MajorNationId) {
        let summary = {
            let city = self.nations.city_mut(nation);
            let population_order = city.orders.population_growth.quantity;
            *city.refresh_unreserved_city_needs(population_order)
        };

        let mut unfilled = 0_i16;
        for resource in [ResourceKind::Grain, ResourceKind::Fruit] {
            let requested = summary[resource];
            let allocated = self.request_first_turn_ai_resource(nation, resource, requested, 7);
            unfilled += requested - allocated;
        }

        let animal_need = summary[ResourceKind::Livestock];
        let fish = self.request_first_turn_ai_resource(nation, ResourceKind::Fish, animal_need, 1);
        if fish < animal_need {
            let livestock = self.request_first_turn_ai_resource(
                nation,
                ResourceKind::Livestock,
                animal_need,
                7,
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
            unfilled -= self.request_first_turn_ai_resource(nation, resource, unfilled, 9);
        }

        let gold = self.nations.majors[nation].economy.need_current_by_type[ResourceKind::Gold];
        self.request_first_turn_ai_resource(nation, ResourceKind::Gold, gold, 1);
        for index in ResourceKind::Food as u8..=ResourceKind::Arms as u8 {
            let resource = ResourceKind::from_index(index).expect("manufactured resource index");
            let current = self.nations.majors[nation].economy.need_current_by_type[resource];
            self.request_first_turn_ai_resource(nation, resource, summary[resource] + current, 1);
        }
    }

    fn request_first_turn_ai_resource(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
        requested: i16,
        flags: i16,
    ) -> i16 {
        let MajorNation {
            common,
            economy,
            city,
        } = &mut self.nations.majors[nation];
        let mut remaining = requested;
        if flags & 8 == 0 {
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
            if flags & 1 != 0 {
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

        if remaining != 0 && flags & 2 != 0 {
            let shortfall = remaining - unavailable_supply;
            if shortfall > 0 {
                economy.interior_civilian.resource_order_metrics[resource] += shortfall;
            }
        }
        requested - remaining
    }

    fn clear_ai_city_orders(&mut self, nation: MajorNationId) {
        self.set_city_order_quantity(nation, CityOrderId::FoodProcessing, 0);
        for output in ITEM_OUTPUTS {
            self.set_city_order_quantity(nation, CityOrderId::Item(output), 0);
        }
        for level in [TrainingLevel::Medium, TrainingLevel::High] {
            self.set_city_order_quantity(nation, CityOrderId::Training(level), 0);
        }
        for category in MILITARY_CATEGORIES {
            self.set_city_order_quantity(nation, CityOrderId::MilitaryRecruit(category), 0);
        }
        for kind in CIVILIAN_KINDS {
            self.set_city_order_quantity(nation, CityOrderId::CivilianRecruit(kind), 0);
        }
        for slot in SHIP_SLOTS {
            self.set_city_order_quantity(nation, CityOrderId::Ship(slot), 0);
        }
        self.set_city_order_quantity(nation, CityOrderId::TransportCapacity, 0);
        self.set_city_order_quantity(nation, CityOrderId::PowerPlant, 0);
        for facility in EXPANSION_SLOTS {
            self.set_city_order_quantity(nation, CityOrderId::Expansion(facility), 0);
        }
        self.set_city_order_quantity(nation, CityOrderId::PopulationGrowth, 0);
    }

    fn process_first_turn_ai_pending_ship(&mut self, nation: MajorNationId) {
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

        let ship_type = self.nations.majors[nation]
            .economy
            .pending_ship
            .take()
            .expect("the supported AI city pass has one pending merchant ship");
        let slot = SHIP_SLOTS
            .into_iter()
            .find(|&slot| self.nations.city(nation).orders.ships[slot].ship_type == ship_type)
            .expect("pending merchant ship has a matching shipyard row");
        let costs = ship_order_costs(ship_type);
        for resource in all_resources() {
            let amount = costs[resource];
            if amount != 0 {
                self.request_first_turn_ai_resource(nation, resource, amount, 7);
            }
        }
        let maximum = self
            .refresh_city_order(nation, CityOrderId::Ship(slot))
            .maximum;
        assert!(
            self.set_city_order_quantity(nation, CityOrderId::Ship(slot), maximum.min(1))
                .applied()
        );
    }

    fn rebalance_first_turn_ai_labor(&mut self, nation: MajorNationId) -> i16 {
        let average = self.nations.majors[nation]
            .economy
            .interior_civilian
            .average_development_order_allocation;
        let target = average as i16 + 2;
        let baseline = self.nations.city(nation).population.baseline_labor;
        let capacity =
            self.nations.city(nation).production_accum[ProductionSlot::RegionalPopulation];
        let interior = self.nations.majors[nation]
            .economy
            .interior_civilian
            .as_mut();
        debug_assert_eq!(interior.deferred_labor_shortfall, 0);
        interior.city_order_demand.training[TrainingLevel::Medium] =
            (target - baseline.medium).clamp(0, capacity);
        let remaining = capacity - interior.city_order_demand.training[TrainingLevel::Medium];
        interior.city_order_demand.population_growth = (target - baseline.low).clamp(0, remaining);

        for level in [TrainingLevel::Medium, TrainingLevel::High] {
            let requested = self.nations.majors[nation]
                .economy
                .interior_civilian
                .city_order_demand
                .training[level];
            let maximum = self
                .refresh_city_order(nation, CityOrderId::Training(level))
                .maximum;
            let accepted = requested.min(maximum);
            assert!(
                self.set_city_order_quantity(nation, CityOrderId::Training(level), accepted)
                    .applied()
            );
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
            .refresh_city_order(nation, CityOrderId::PopulationGrowth)
            .maximum;
        assert!(
            self.set_city_order_quantity(
                nation,
                CityOrderId::PopulationGrowth,
                requested.min(maximum),
            )
            .applied()
        );
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

    fn choose_first_turn_ai_expansion(&mut self, nation: MajorNationId) {
        let mut priority = [0_usize, 1, 2, 3, 4, 5, 6];
        {
            let deficits = &mut self.nations.majors[nation]
                .economy
                .interior_civilian
                .production_deficit_by_slot;
            deficits[ProductionSlot::OilRefinery] = -1;
        }
        for destination in 0..6 {
            let mut best = destination;
            for candidate in destination + 1..7 {
                let deficits = &self.nations.majors[nation]
                    .economy
                    .interior_civilian
                    .production_deficit_by_slot;
                let candidate_score = deficits[EXPANSION_SLOTS[priority[candidate]].slot()];
                let best_score = deficits[EXPANSION_SLOTS[priority[best]].slot()];
                if candidate_score > best_score
                    || (candidate_score == best_score && self.rng.next_crt_rand() & 1 != 0)
                {
                    best = candidate;
                }
            }
            priority.swap(destination, best);
        }

        let best_facility = EXPANSION_SLOTS[priority[0]];
        if self.nations.majors[nation]
            .economy
            .interior_civilian
            .production_deficit_by_slot[best_facility.slot()]
            == 0
            && self.turn.economic_turn & 1 != 0
        {
            // Every supported building ratio is 0/0. VC5's unordered x87
            // comparison takes the primary member of the selected pair.
            let selected = EXPANSION_SLOTS[(self.rng.next_crt_rand() % 3) as usize];
            self.nations.majors[nation]
                .economy
                .interior_civilian
                .city_order_demand
                .expansions[selected.slot()] = 1;
        }

        for facility in EXPANSION_SLOTS {
            let requested = self.nations.majors[nation]
                .economy
                .interior_civilian
                .city_order_demand
                .expansions[facility.slot()];
            if requested == 0 {
                continue;
            }
            let spec = expansion_order_spec(facility);
            self.request_first_turn_ai_resource(nation, spec.primary, requested, 7);
            self.request_first_turn_ai_resource(nation, spec.secondary, requested, 7);
            let maximum = self
                .refresh_city_order(nation, CityOrderId::Expansion(facility))
                .maximum;
            let accepted = requested.min(maximum);
            assert!(
                self.set_city_order_quantity(nation, CityOrderId::Expansion(facility), accepted)
                    .applied()
            );
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

    fn compute_first_turn_ai_item_demands(&mut self, nation: MajorNationId) {
        let city = self.nations.city(nation);
        let lumber = city.production_orders[ProductionSlot::LumberMill] + 1;
        let fabric = city.production_orders[ProductionSlot::TextileMill] + 1;
        let steel = city.production_orders[ProductionSlot::SteelMill] + 1;
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

    fn issue_first_turn_ai_item_orders(&mut self, nation: MajorNationId) {
        for output in [
            ManufacturedItem::Clothing,
            ManufacturedItem::Furniture,
            ManufacturedItem::Arms,
            ManufacturedItem::Hardware,
        ] {
            self.issue_first_turn_ai_item_order(nation, output);
        }
        self.issue_first_turn_ai_food_order(nation);
        self.issue_first_turn_ai_item_order(nation, ManufacturedItem::Paper);
        if self.nations.city(nation).stockpile[ResourceKind::Lumber]
            < self.nations.city(nation).stockpile[ResourceKind::Steel]
        {
            self.issue_first_turn_ai_item_order(nation, ManufacturedItem::Lumber);
            self.issue_first_turn_ai_item_order(nation, ManufacturedItem::Steel);
        } else {
            self.issue_first_turn_ai_item_order(nation, ManufacturedItem::Steel);
            self.issue_first_turn_ai_item_order(nation, ManufacturedItem::Lumber);
        }
        self.issue_first_turn_ai_item_order(nation, ManufacturedItem::Fabric);
    }

    fn issue_first_turn_ai_food_order(&mut self, nation: MajorNationId) {
        let requested = self.nations.majors[nation]
            .economy
            .interior_civilian
            .resource_order_metrics[ResourceKind::Food];
        let maximum = self
            .refresh_city_order(nation, CityOrderId::FoodProcessing)
            .maximum;
        let accepted = requested.min(maximum);
        assert!(
            self.set_city_order_quantity(nation, CityOrderId::FoodProcessing, accepted)
                .applied()
        );
        let metric = &mut self.nations.majors[nation]
            .economy
            .interior_civilian
            .resource_order_metrics[ResourceKind::Food];
        *metric = (*metric - accepted).max(0);
    }

    fn issue_first_turn_ai_item_order(&mut self, nation: MajorNationId, output: ManufacturedItem) {
        let resource = output.resource();
        let mut requested = self.nations.majors[nation]
            .economy
            .interior_civilian
            .resource_order_metrics[resource];
        let spec = item_order_spec(output);
        let production_limit =
            self.nations.city(nation).production_orders[spec.production_slot] * 2 + 2;
        requested = requested.min(production_limit);
        self.nations.majors[nation]
            .economy
            .interior_civilian
            .resource_order_metrics[resource] = requested;

        match spec.inputs {
            ItemInputs::Double(primary) => {
                self.request_first_turn_ai_resource(nation, primary, requested * 2, 7);
            }
            ItemInputs::Both(primary, secondary) => {
                self.request_first_turn_ai_resource(nation, primary, requested, 7);
                self.request_first_turn_ai_resource(nation, secondary, requested, 7);
            }
            ItemInputs::Either(_, _) => {
                let material_need = requested * 2;
                self.request_first_turn_ai_resource(nation, ResourceKind::Cotton, material_need, 7);
                let stock = self.nations.city(nation).stockpile[ResourceKind::Cotton]
                    + self.nations.city(nation).stockpile[ResourceKind::Wool];
                if stock < material_need {
                    self.request_first_turn_ai_resource(
                        nation,
                        ResourceKind::Wool,
                        material_need - stock,
                        7,
                    );
                }
            }
        }

        let view = self.refresh_city_order(nation, CityOrderId::Item(output));
        let accepted = requested.min(view.maximum);
        if accepted < requested && view.limiting_constraint == ProductionConstraint::Capacity {
            self.nations.majors[nation]
                .economy
                .interior_civilian
                .production_deficit_by_slot[spec.production_slot] += requested - accepted;
        }
        assert!(
            self.set_city_order_quantity(nation, CityOrderId::Item(output), accepted)
                .applied()
        );
        let metric = &mut self.nations.majors[nation]
            .economy
            .interior_civilian
            .resource_order_metrics[resource];
        *metric = (*metric - accepted).max(0);
    }

    fn fill_first_turn_ai_transport_capacity(&mut self, nation: MajorNationId) {
        let horses = self.nations.city(nation).stockpile[ResourceKind::Horses];
        if horses < 5 {
            self.request_first_turn_ai_resource(nation, ResourceKind::Horses, 5 - horses, 8);
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
                remaining -= self.request_first_turn_ai_resource(nation, resource, 1, 8);
            }
        }
    }

    fn rebuild_first_turn_ai_allocation_average(&mut self, nation: MajorNationId) {
        let mut allocation = ProductionTable::<i16>::default();
        for output in ITEM_OUTPUTS {
            let order = self.nations.city(nation).orders.items[output.resource()]
                .as_ref()
                .expect("retail item order");
            let slot = item_order_spec(output).production_slot;
            allocation[slot] += order.progress.quantity;
        }
        let total = (0..ProductionSlot::COUNT)
            .map(|index| {
                allocation[ProductionSlot::from_index(index as u8).expect("production slot")]
            })
            .fold(0_i16, i16::wrapping_add);
        self.nations.majors[nation]
            .economy
            .interior_civilian
            .average_development_order_allocation = i32::from(total / 20);
    }

    fn determine_first_turn_ai_trade_bid(&mut self, nation: MajorNationId) {
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

fn city_orders_are_idle(orders: &CityOrders) -> bool {
    orders.food_processing.quantity == 0
        && ITEM_OUTPUTS.into_iter().all(|item| {
            orders.items[item.resource()]
                .as_ref()
                .is_some_and(|order| order.progress.quantity == 0)
        })
        && [TrainingLevel::Medium, TrainingLevel::High]
            .into_iter()
            .all(|level| orders.training[level].quantity == 0)
        && MILITARY_CATEGORIES
            .into_iter()
            .all(|category| orders.military_recruitment[category].progress.quantity == 0)
        && CIVILIAN_KINDS
            .into_iter()
            .all(|kind| orders.civilian_recruitment[kind].quantity == 0)
        && SHIP_SLOTS
            .into_iter()
            .all(|slot| orders.ships[slot].progress.quantity == 0)
        && orders.transport_capacity.progress.quantity == 0
        && orders.power_plant.progress.quantity == 0
        && EXPANSION_SLOTS.into_iter().all(|facility| {
            orders.expansions[facility.slot()]
                .as_ref()
                .is_some_and(|order| order.progress.quantity == 0)
        })
        && orders.population_growth.quantity == 0
}

fn first_turn_ai_city_demand() -> AiCityOrderDemand {
    let mut demand = AiCityOrderDemand::default();
    demand.expansions[ProductionSlot::TextileMill] = 2;
    demand.expansions[ProductionSlot::ClothingFactory] = 1;
    demand.expansions[ProductionSlot::SteelMill] = 2;
    demand.expansions[ProductionSlot::LumberMill] = 2;
    demand
}
