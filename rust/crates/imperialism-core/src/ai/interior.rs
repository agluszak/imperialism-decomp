//! AI city interior-minister orders issued during [`GameState::do_city_and_transport`].

use crate::*;
use enum_map::Enum;

const CITY_PRODUCTION_POLICY_BANDS: [[f32; 4]; 4] = [
    [-100_000_000.0, -100_000.0, -20_000.0, -10_000.0],
    [-15_000.0, -5_000.0, -5_000.0, 1_000.0],
    [0.0, 5_000.0, 10_000.0, 15_000.0],
    [10_000.0, 20_000.0, 1_000_000.0, 1_000_000_000.0],
];
const CITY_PRODUCTION_RESERVE_BY_POLICY_BAND: [i16; 4] = [0, 2, 6, 12];

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

#[allow(clippy::excessive_precision)]
fn select_city_production_policy_band(rng: &mut RngState, treasury: f32) -> usize {
    let mut weights = [0.0_f32; 4];
    let mut total = 0.0_f32;
    for (index, [start, full_start, full_end, end]) in
        CITY_PRODUCTION_POLICY_BANDS.into_iter().enumerate()
    {
        let weight = if treasury <= start || treasury >= end {
            0.0
        } else if treasury < full_start {
            (treasury - start) / (full_start - start)
        } else if treasury <= full_end {
            1.0
        } else {
            (end - treasury) / (end - full_end)
        };
        weights[index] = weight;
        total += weight;
    }
    assert_ne!(total, 0.0, "retail city policy bands cover the treasury");
    for weight in &mut weights {
        *weight /= total;
    }

    let mut selection = (rng.next_crt_rand() & 0x3fff) as f32 * 0.000_061_035_156_25;
    for (index, weight) in weights.into_iter().enumerate() {
        if selection <= weight {
            return index;
        }
        selection -= weight;
    }
    unreachable!("normalized retail fuzzy weights select a policy band")
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

        let gold = self.nations.majors[&nation].economy.need_current_by_type[ResourceKind::Gold];
        self.request_ai_resource(
            nation,
            ResourceKind::Gold,
            gold,
            AiResourcePolicy::FOR_TRANSPORT,
        );
        for resource in ResourceKind::CITY_PRODUCTION {
            let current = self.nations.majors[&nation].economy.need_current_by_type[resource];
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
        } = &mut self.nations.majors[&nation];
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
        for level in (0..enum_map::enum_len::<TrainingLevel>()).map(TrainingLevel::from_usize) {
            self.set_city_order_quantity(nation, CityOrderId::Training(level), 0);
        }
        for category in (0..enum_map::enum_len::<MilitaryRecruitmentCategory>())
            .map(MilitaryRecruitmentCategory::from_usize)
        {
            self.set_city_order_quantity(nation, CityOrderId::MilitaryRecruit(category), 0);
        }
        for kind in (0..CivilianUnitKind::LENGTH).map(CivilianUnitKind::from_usize) {
            self.set_city_order_quantity(nation, CityOrderId::CivilianRecruit(kind), 0);
        }
        for slot in (0..enum_map::enum_len::<ShipOrderSlot>()).map(ShipOrderSlot::from_usize) {
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
            let interior = self.nations.majors[&nation]
                .economy
                .interior_civilian
                .as_mut();
            std::mem::take(&mut interior.temporarily_reserved_ship_arms)
        };
        self.nations
            .city_mut(nation)
            .adjust_stock(ResourceKind::Arms, reserved_arms);

        let Some(ship_type) = self.nations.majors[&nation].economy.pending_ship.take() else {
            return;
        };
        let Some(slot) = (0..enum_map::enum_len::<ShipOrderSlot>())
            .map(ShipOrderSlot::from_usize)
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
        assert_eq!(
            self.set_city_order_quantity(nation, CityOrderId::Ship(slot), maximum.min(1)),
            CityOrderUpdate::Applied
        );
    }

    pub(crate) fn process_ai_pending_civilian_recruitment(&mut self, nation: MajorNationId) {
        let recruitment_allowed = self.nations.city(nation).population.count >= 7;
        if !recruitment_allowed {
            let demand = &mut self.nations.majors[&nation]
                .economy
                .interior_civilian
                .city_order_demand
                .population_growth;
            if *demand == 0 {
                *demand = 2;
            }
            return;
        }

        let treasury_threshold = if self.turn.scenario_map.is_none() {
            [-20_000, -40_000, -60_000, -80_000, -100_000]
                [usize::from(self.turn.difficulty.retail())]
        } else {
            -80_000
        };
        if self.nations.majors[&nation].common.treasury < treasury_threshold {
            return;
        }

        if let Some(kind) = self.nations.majors[&nation]
            .economy
            .interior_civilian
            .pending_recruitment
            .take()
        {
            self.issue_ai_civilian_recruitment(nation, kind, 1);
        }
        for kind in (0..CivilianUnitKind::LENGTH).map(CivilianUnitKind::from_usize) {
            let requested = self.nations.majors[&nation]
                .economy
                .interior_civilian
                .city_order_demand
                .civilian_recruitment[kind];
            if requested == 0 {
                continue;
            }
            let accepted = self.issue_ai_civilian_recruitment(nation, kind, requested);
            self.nations.majors[&nation]
                .economy
                .interior_civilian
                .city_order_demand
                .civilian_recruitment[kind] -= accepted;
        }
    }

    fn issue_ai_civilian_recruitment(
        &mut self,
        nation: MajorNationId,
        kind: CivilianUnitKind,
        requested: i16,
    ) -> i16 {
        let spec = civilian_recruitment_spec(kind);
        self.request_ai_resource(
            nation,
            spec.primary.resource,
            spec.primary.per_unit() * requested,
            AiResourcePolicy::FOR_PRODUCTION,
        );
        let accepted = requested.min(
            self.city_order_limit(nation, CityOrderId::CivilianRecruit(kind))
                .maximum,
        );
        assert_eq!(
            self.set_city_order_quantity(nation, CityOrderId::CivilianRecruit(kind), accepted),
            CityOrderUpdate::Applied
        );
        accepted
    }

    pub(crate) fn rebalance_ai_labor(&mut self, nation: MajorNationId) -> (i16, i16) {
        let average = self.nations.majors[&nation]
            .economy
            .interior_civilian
            .average_development_order_allocation;
        let target = average as i16 + 2;
        let baseline = self.nations.city(nation).population.baseline_labor;
        let capacity =
            self.nations.city(nation).production_accum[CityFacilitySlot::RegionalPopulation];
        let interior = self.nations.majors[&nation]
            .economy
            .interior_civilian
            .as_mut();
        debug_assert_eq!(interior.deferred_labor_shortfall, 0);
        interior.city_order_demand.training[TrainingLevel::Medium] =
            (target - baseline.medium).clamp(0, capacity);
        let remaining = capacity - interior.city_order_demand.training[TrainingLevel::Medium];
        if baseline.low < target {
            interior.city_order_demand.population_growth = (target - baseline.low).min(remaining);
        }

        for level in (0..enum_map::enum_len::<TrainingLevel>()).map(TrainingLevel::from_usize) {
            let requested = self.nations.majors[&nation]
                .economy
                .interior_civilian
                .city_order_demand
                .training[level];
            let paper = match level {
                TrainingLevel::Medium => requested,
                TrainingLevel::High => requested * 2,
            };
            self.request_ai_resource(
                nation,
                ResourceKind::Paper,
                paper,
                AiResourcePolicy::FOR_PRODUCTION,
            );
            let maximum = self
                .city_order_limit(nation, CityOrderId::Training(level))
                .maximum;
            let accepted = requested.min(maximum);
            assert_eq!(
                self.set_city_order_quantity(nation, CityOrderId::Training(level), accepted),
                CityOrderUpdate::Applied
            );
            self.nations.majors[&nation]
                .economy
                .interior_civilian
                .city_order_demand
                .training[level] = 0;
        }
        let requested = self.nations.majors[&nation]
            .economy
            .interior_civilian
            .city_order_demand
            .population_growth;
        for resource in [
            ResourceKind::Food,
            ResourceKind::Clothing,
            ResourceKind::Furniture,
        ] {
            self.request_ai_resource(
                nation,
                resource,
                requested,
                AiResourcePolicy::FOR_PRODUCTION,
            );
        }
        let maximum = self
            .city_order_limit(nation, CityOrderId::PopulationGrowth)
            .maximum;
        let accepted = requested.min(maximum);
        assert_eq!(
            self.set_city_order_quantity(nation, CityOrderId::PopulationGrowth, accepted,),
            CityOrderUpdate::Applied
        );
        self.nations.majors[&nation]
            .economy
            .interior_civilian
            .city_order_demand
            .population_growth = requested - accepted;

        let city = self.nations.city_mut(nation);
        let clothing = city.stockpile[ResourceKind::Clothing].min(2);
        let furniture = city.stockpile[ResourceKind::Furniture].min(2);
        city.adjust_stock(ResourceKind::Clothing, -clothing);
        city.consumed_production_input_by_type[ResourceKind::Clothing] = clothing;
        city.adjust_stock(ResourceKind::Furniture, -furniture);
        city.consumed_production_input_by_type[ResourceKind::Furniture] = furniture;
        let temporary_lumber = if furniture == 0 && city.stockpile[ResourceKind::Lumber] > 1 {
            city.adjust_stock(ResourceKind::Lumber, -2);
            2
        } else {
            0
        };
        (temporary_lumber, requested - accepted)
    }

    pub(crate) fn choose_ai_expansion(
        &mut self,
        nation: MajorNationId,
        previous_allocation: Option<&ProductionTable<i16>>,
    ) {
        let mut priority = ExpandableFacility::ALL;
        let oil = self.technology.city_capabilities_by_nation[nation].oil_drilling;
        if !oil {
            let deficits = &mut self.nations.majors[&nation]
                .economy
                .interior_civilian
                .production_deficit_by_slot;
            deficits[CityFacilitySlot::OilRefinery] = -1;
        }
        for destination in 0..6 {
            let mut best = destination;
            for candidate in destination + 1..7 {
                let deficits = &self.nations.majors[&nation]
                    .economy
                    .interior_civilian
                    .production_deficit_by_slot;
                let candidate_score = deficits[priority[candidate].slot()];
                let best_score = deficits[priority[best].slot()];
                if candidate_score > best_score
                    || (candidate_score == best_score && self.rng.next_crt_rand() & 1 != 0)
                {
                    best = candidate;
                }
            }
            priority.swap(destination, best);
        }

        let best_facility = priority[0];
        let selected = if self.nations.majors[&nation]
            .economy
            .interior_civilian
            .production_deficit_by_slot[best_facility.slot()]
            == 0
            && self.turn.economic_turn & 1 != 0
        {
            let choice = self.rng.next_crt_rand() % if oil { 4 } else { 3 };
            let selected = if choice == 3 {
                ExpandableFacility::OilRefinery
            } else {
                let left = ExpandableFacility::ALL[choice as usize];
                let right = ExpandableFacility::ALL[choice as usize + 1];
                let left_level = self.nations.city(nation).production_orders[left.slot()];
                let right_level = self.nations.city(nation).production_orders[right.slot()];
                let ratio = left_level as f32 / right_level as f32;
                // VC5's x87 comparison selects the left member when 0/0 is unordered.
                if (left_level == 0 && right_level == 0) || ratio <= 2.0 {
                    left
                } else {
                    right
                }
            };
            previous_allocation
                .is_none_or(|allocation| {
                    allocation[selected.slot()] + 2
                        >= self.nations.city(nation).production_orders[selected.slot()]
                })
                .then_some(selected)
        } else {
            let mut selected = best_facility;
            let index = selected as usize;
            if index & 1 != 0
                && self.nations.city(nation).production_orders[selected.slot()]
                    >= self.nations.city(nation).production_orders
                        [ExpandableFacility::ALL[index - 1].slot()]
            {
                selected = ExpandableFacility::ALL[index - 1];
            }
            Some(selected)
        };
        if let Some(selected) = selected {
            self.nations.majors[&nation]
                .economy
                .interior_civilian
                .city_order_demand
                .expansions[selected] = 1;
        }

        for facility in ExpandableFacility::ALL {
            let requested = self.nations.majors[&nation]
                .economy
                .interior_civilian
                .city_order_demand
                .expansions[facility];
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
            assert_eq!(
                self.set_city_order_quantity(nation, CityOrderId::Expansion(facility), accepted),
                CityOrderUpdate::Applied
            );
            let interior = self.nations.majors[&nation]
                .economy
                .interior_civilian
                .as_mut();
            interior.city_order_demand.expansions[facility] -= accepted;
            if interior.city_order_demand.expansions[facility] < 2 {
                interior.production_deficit_by_slot[facility.slot()] = 0;
            }
        }
    }

    pub(crate) fn compute_ai_item_demands(&mut self, nation: MajorNationId) {
        let (lumber, fabric, steel, needs_paper) = {
            let city = self.nations.city(nation);
            (
                city.production_orders[CityFacilitySlot::LumberMill] + 1,
                city.production_orders[CityFacilitySlot::TextileMill] + 1,
                city.production_orders[CityFacilitySlot::SteelMill] + 1,
                city.stockpile[ResourceKind::Paper] < 3,
            )
        };
        let metrics = &mut self.nations.majors[&nation]
            .economy
            .interior_civilian
            .resource_order_metrics;
        metrics[ResourceKind::Lumber] = lumber;
        metrics[ResourceKind::Fabric] = fabric;
        metrics[ResourceKind::Steel] = steel;
        if needs_paper && metrics[ResourceKind::Paper] == 0 {
            metrics[ResourceKind::Paper] = 1;
        }
        if self.turn.economic_turn <= 2 {
            return;
        }

        let policy_band = select_city_production_policy_band(
            &mut self.rng,
            self.nations.major(nation).common.treasury as f32,
        );
        let reserve = CITY_PRODUCTION_RESERVE_BY_POLICY_BAND[policy_band];
        let city = self.nations.city(nation);
        let furniture = ((city.stockpile[ResourceKind::Lumber] - reserve) / 2)
            .min(city.production_orders[CityFacilitySlot::FurnitureFactory] + 1);
        let clothing = ((city.stockpile[ResourceKind::Fabric] - reserve) / 2)
            .min(city.production_orders[CityFacilitySlot::ClothingFactory] + 1);
        let metal = ((city.stockpile[ResourceKind::Steel] - reserve) / 2)
            .min(city.production_orders[CityFacilitySlot::Metalworks] + 1);
        let previous_allocation = self.nations.majors[&nation]
            .economy
            .interior_civilian
            .previous_item_allocation_by_facility;
        let metrics = &mut self.nations.majors[&nation]
            .economy
            .interior_civilian
            .resource_order_metrics;
        if furniture > 0 {
            metrics[ResourceKind::Furniture] = furniture;
        }
        if clothing > 0 {
            metrics[ResourceKind::Clothing] = clothing;
        }
        if metal > 0 {
            if metrics[ResourceKind::Arms] != 0 {
                metrics[ResourceKind::Arms] = metal;
                return;
            }
            let average = previous_allocation.map_or(0, |allocation| {
                (0..CityFacilitySlot::COUNT)
                    .map(CityFacilitySlot::from_usize)
                    .map(|slot| allocation[slot])
                    .fold(0_i16, i16::wrapping_add)
                    / 20
            });
            metrics[ResourceKind::Arms] = average;
            metrics[ResourceKind::Hardware] = metal - average;
        }
    }

    pub(crate) fn issue_ai_item_orders(&mut self, nation: MajorNationId, low_skill_shortfall: i16) {
        let finishing_order = match self.turn.economic_turn % 3 {
            0 => [
                ManufacturedItem::Arms,
                ManufacturedItem::Hardware,
                ManufacturedItem::Clothing,
                ManufacturedItem::Furniture,
            ],
            1 => [
                ManufacturedItem::Clothing,
                ManufacturedItem::Furniture,
                ManufacturedItem::Arms,
                ManufacturedItem::Hardware,
            ],
            _ => [
                ManufacturedItem::Furniture,
                ManufacturedItem::Clothing,
                ManufacturedItem::Arms,
                ManufacturedItem::Hardware,
            ],
        };
        for output in finishing_order {
            self.issue_ai_item_order(nation, output);
        }
        let support_ready = low_skill_shortfall > 0
            && self.nations.majors[&nation]
                .economy
                .interior_civilian
                .resource_order_metrics[ResourceKind::Clothing]
                > 0;
        self.issue_ai_food_order(nation);
        if support_ready {
            self.issue_ai_item_order(nation, ManufacturedItem::Fabric);
        }
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
        if !support_ready {
            self.issue_ai_item_order(nation, ManufacturedItem::Fabric);
        }
    }

    fn issue_ai_food_order(&mut self, nation: MajorNationId) {
        let requested = self.nations.majors[&nation]
            .economy
            .interior_civilian
            .resource_order_metrics[ResourceKind::Food];
        let maximum = self
            .city_order_limit(nation, CityOrderId::FoodProcessing)
            .maximum;
        let accepted = requested.min(maximum);
        assert_eq!(
            self.set_city_order_quantity(nation, CityOrderId::FoodProcessing, accepted),
            CityOrderUpdate::Applied
        );
        let metric = &mut self.nations.majors[&nation]
            .economy
            .interior_civilian
            .resource_order_metrics[ResourceKind::Food];
        *metric = (*metric - accepted).max(0);
    }

    fn issue_ai_item_order(&mut self, nation: MajorNationId, output: ManufacturedItem) {
        let resource = output.resource();
        let mut requested = self.nations.majors[&nation]
            .economy
            .interior_civilian
            .resource_order_metrics[resource];
        let facility = output.facility();
        let production_limit = self.nations.city(nation).production_orders[facility] * 2 + 2;
        requested = requested.min(production_limit);
        self.nations.majors[&nation]
            .economy
            .interior_civilian
            .resource_order_metrics[resource] = requested;

        let target_labor = requested * 2;
        let available_labor =
            self.raise_ai_power_plant_order_to_reach_labor_target(nation, target_labor);
        let labor_shortfall = target_labor.saturating_sub(available_labor);
        if available_labor < target_labor {
            requested = available_labor / 2;
        }

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
            self.nations.majors[&nation]
                .economy
                .interior_civilian
                .production_deficit_by_slot[facility] += requested - accepted;
        }
        if accepted == requested && labor_shortfall > 0 {
            self.nations.majors[&nation]
                .economy
                .interior_civilian
                .deferred_labor_shortfall += labor_shortfall;
        }
        assert_eq!(
            self.set_city_order_quantity(nation, CityOrderId::Item(output), accepted),
            CityOrderUpdate::Applied
        );
        let metric = &mut self.nations.majors[&nation]
            .economy
            .interior_civilian
            .resource_order_metrics[resource];
        *metric = (*metric - accepted).max(0);
    }

    fn raise_ai_power_plant_order_to_reach_labor_target(
        &mut self,
        nation: MajorNationId,
        target_labor: i16,
    ) -> i16 {
        let current_labor = self.nations.city(nation).population.strength;
        if current_labor >= target_labor {
            return target_labor;
        }
        if self.technology.research_status_by_nation[nation][Technology::OilDrilling]
            != TechnologyResearchStatus::Researched
        {
            return current_labor;
        }

        let order = CityOrderId::PowerPlant;
        let current_quantity = self.city_order_quantity(nation, order);
        let maximum_quantity = self.city_order_limit(nation, order).maximum;
        let mut increment = ((target_labor - current_labor) / 6 + 1) * 6;
        if maximum_quantity < current_quantity + increment {
            self.nations.majors[&nation]
                .economy
                .interior_civilian
                .resource_order_metrics[ResourceKind::Fuel] +=
                current_quantity - maximum_quantity + increment;
            increment = maximum_quantity - current_quantity;
        }
        assert_eq!(
            self.set_city_order_quantity(nation, order, current_quantity + increment),
            CityOrderUpdate::Applied
        );
        self.nations
            .city(nation)
            .population
            .strength
            .min(target_labor)
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

        let mut remaining = self.nations.majors[&nation].economy.capacities.transport
            - self.nations.majors[&nation]
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
            .map(CityFacilitySlot::from_usize)
            .map(|slot| allocation[slot])
            .fold(0_i16, i16::wrapping_add);
        self.nations.majors[&nation]
            .economy
            .interior_civilian
            .average_development_order_allocation = i32::from(total / 20);
        self.nations.majors[&nation]
            .economy
            .interior_civilian
            .previous_item_allocation_by_facility = Some(allocation);
    }

    pub(crate) fn determine_ai_trade_bid(&mut self, nation: MajorNationId) {
        let cotton = self.nations.majors[&nation]
            .economy
            .interior_civilian
            .resource_order_metrics[ResourceKind::Cotton];
        let wool = self.nations.majors[&nation]
            .economy
            .interior_civilian
            .resource_order_metrics[ResourceKind::Wool];
        if cotton != 0 || wool != 0 {
            let delta = i16::from(self.rng.next_crt_rand() % 100 >= 75);
            self.nations.majors[&nation]
                .economy
                .foreign_trade
                .purchase_priority[TradeCommodity::Cotton] += delta;
        }
        for resource in ResourceKind::INDUSTRIAL_RAW {
            let delta = self.nations.majors[&nation]
                .economy
                .interior_civilian
                .resource_order_metrics[resource];
            if delta != 0 {
                let commodity = TradeCommodity::from_resource(resource)
                    .expect("industrial raw resource has a trade row");
                self.nations.majors[&nation]
                    .economy
                    .foreign_trade
                    .purchase_priority[commodity] += delta;
            }
        }

        let food = {
            let major = &self.nations.majors[&nation];
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
            self.nations.majors[&nation]
                .economy
                .foreign_trade
                .interior_bid = Some(bid);
        }
    }
}
