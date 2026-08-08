use crate::{
    CityState, MajorNationState, PopulationError, ProductionSlot, ResourceKind, ResourceTable,
};

const TRANSPORT_CAPACITY_INDEX: usize = 2;
const RESERVED_TRANSPORT_CAPACITY_INDEX: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CityEconomyError {
    #[error(
        "purchased item vector has {actual} entries, expected {}",
        ResourceKind::PURCHASED_COUNT
    )]
    InvalidPurchasedItemCount { actual: usize },
    #[error(transparent)]
    Population(#[from] PopulationError),
}

impl CityState {
    /// Mirrors the state effect of `TCity::VerifyStocks`; UI invalidation from
    /// the C++ method remains a presentation concern.
    pub fn verify_stocks(&mut self) {
        for (_, stock) in &mut self.stock_by_type {
            if *stock < 0 {
                *stock = 0;
            }
        }
    }

    /// Mirrors `TCity::AddPurchasedItems`, whose three source loops cover the
    /// contiguous Cotton-through-Arms range.
    pub fn add_purchased_items(&mut self, amounts: &[i16]) -> Result<(), CityEconomyError> {
        if amounts.len() != ResourceKind::PURCHASED_COUNT {
            return Err(CityEconomyError::InvalidPurchasedItemCount {
                actual: amounts.len(),
            });
        }
        for ((_, stock), amount) in self.stock_by_type.iter_mut().zip(amounts) {
            *stock = stock.wrapping_add(*amount);
        }
        Ok(())
    }

    /// Mirrors the pointer-taking `TCity::AddTransportedItems` overload.
    pub fn add_transported_items(&mut self, amounts: &ResourceTable<i16>) {
        for (resource, amount) in amounts {
            self.stock_by_type[resource] = self.stock_by_type[resource].wrapping_add(*amount);
        }
        self.clear_precious_metal_stock();
    }

    /// Mirrors the no-argument `TCity::AddTransportedItems` overload.
    pub fn add_nation_target_items(&mut self, nation: &MajorNationState) {
        self.add_transported_items(&nation.need_target_by_type)
    }

    /// Mirrors `TCity::DirectTransport`, including signed-short surplus and
    /// remaining-capacity limits and the target/reservation update.
    pub fn direct_transport(
        &mut self,
        nation: &mut MajorNationState,
        resource: ResourceKind,
        requested: i16,
    ) -> i16 {
        let mut amount = requested;
        let surplus = nation.need_current_by_type[resource]
            .wrapping_sub(nation.need_target_by_type[resource]);
        if surplus < amount {
            amount = surplus;
        }
        let available_capacity = nation.capacities[TRANSPORT_CAPACITY_INDEX]
            .wrapping_sub(nation.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX]);
        if available_capacity < amount {
            amount = available_capacity;
        }

        self.stock_by_type[resource] = self.stock_by_type[resource].wrapping_add(amount);
        nation.update_need_target(
            resource,
            nation.need_target_by_type[resource].wrapping_add(amount),
        );
        amount
    }

    /// Mirrors `TGreatPower::IncreaseRollingStock` against the owning city's
    /// lumber and steel stockpile.
    pub fn increase_rolling_stock(&mut self, nation: &mut MajorNationState) -> bool {
        if self.stock_by_type[ResourceKind::Lumber] == 0
            || self.stock_by_type[ResourceKind::Steel] == 0
        {
            return false;
        }

        self.add_to_stock_and_verify(ResourceKind::Lumber, -1);
        self.add_to_stock_and_verify(ResourceKind::Steel, -1);
        let capacity = nation.transport_capacity_mut();
        *capacity = capacity.wrapping_add(1);
        true
    }

    /// Mirrors `TGreatPower::IncreaseMerchantMarine` against the owning
    /// city's lumber and fabric stockpile.
    pub fn increase_merchant_marine(&mut self, nation: &mut MajorNationState) -> bool {
        if self.stock_by_type[ResourceKind::Lumber] <= 2
            || self.stock_by_type[ResourceKind::Fabric] == 0
        {
            return false;
        }

        self.add_to_stock_and_verify(ResourceKind::Lumber, -3);
        self.add_to_stock_and_verify(ResourceKind::Fabric, -1);
        let capacity = nation.merchant_capacity_mut();
        *capacity = capacity.wrapping_add(1);
        true
    }

    /// Mirrors `TCity::GetCitySummaryRecordSlot74` after the population need
    /// vector has been refreshed.
    pub fn refresh_unreserved_city_needs(
        &mut self,
        supported_order_quantity: i16,
    ) -> &ResourceTable<i16> {
        let summary = self
            .population
            .refresh_predicted_needs(supported_order_quantity);
        for (resource, reserved) in &self.reserved_by_type {
            let remaining = summary[resource];
            if remaining != 0 {
                summary[resource] = remaining.wrapping_sub(*reserved);
                if resource == ResourceKind::Livestock {
                    summary[resource] =
                        summary[resource].wrapping_sub(self.reserved_by_type[ResourceKind::Fish]);
                }
                if summary[resource] < 0 {
                    summary[resource] = 0;
                }
            }
        }
        summary
    }

    /// Ports the local flag calculation in `TCity::PredictedNeeds`. The
    /// original's subsequent nation-stockpile publication belongs to the event
    /// boundary that will call this method.
    pub fn refresh_local_summary_flags(&mut self) {
        self.low_stock = self.population.strength >= 2;
        let mut shortage_count = if self.production_accum[ProductionSlot::new(4).unwrap()] > 0 {
            2_i16
        } else {
            3_i16
        };
        if self.production_accum[ProductionSlot::new(2).unwrap()] > 0 {
            shortage_count = shortage_count.wrapping_sub(1);
        }
        if self.production_accum[ProductionSlot::new(0).unwrap()] > 0 {
            shortage_count = shortage_count.wrapping_sub(1);
        }
        self.low_production = shortage_count < 2;
    }

    fn clear_precious_metal_stock(&mut self) {
        self.stock_by_type[ResourceKind::Gold] = 0;
        self.stock_by_type[ResourceKind::Gems] = 0;
    }

    pub(crate) fn add_to_stock_and_verify(&mut self, resource: ResourceKind, delta: i16) {
        let stock = &mut self.stock_by_type[resource];
        *stock = stock.wrapping_add(delta);
        for (_, stock) in &mut self.stock_by_type {
            if *stock < 0 {
                *stock = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LaborPool, PopulationState};

    fn slot(value: u8) -> ProductionSlot {
        ProductionSlot::new(value).unwrap()
    }

    fn city() -> CityState {
        CityState {
            power_plant_upgrade_queued: false,
            food_substitution_count: 0,
            starvation_population_loss: 0,
            serialized_state: 0,
            phase_counter: 0,
            military_recruit_count_by_kind: crate::MilitaryUnitTable::default(),
            civilian_recruit_count_by_kind: crate::CivilianUnitTable::default(),
            order_count_by_type: [0; 14],
            rolling_item_production_score: 0,
            low_production: false,
            low_stock: false,
            reserved_by_type: crate::ResourceTable::default(),
            home_town_tile: 1,
            power_available: 0,
            stock_by_type: crate::ResourceTable::default(),
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
                count_float_bits: 7.0_f32.to_bits(),
                strength: 12,
                extra: 0,
                phase_value: 0,
                baseline_labor: Some(LaborPool::new(4, 2, 1)),
                production_labor: Some(LaborPool::new(4, 2, 1)),
                pending_labor_delta: Some(LaborPool::default()),
                predicted_need_by_resource: crate::ResourceTable::default(),
            },
        }
    }

    fn nation() -> MajorNationState {
        MajorNationState {
            diplomacy_eligible: true,
            capacities: [0, 0, 15, 11],
            grant_total_cost: 0,
            unfilled_trade_offer_count: 0,
            diplomacy_policy_by_nation: crate::NationTable::default(),
            diplomacy_grant_by_nation: crate::NationTable::default(),
            need_current_by_type: crate::ResourceTable::default(),
            need_target_by_type: crate::ResourceTable::default(),
            relation_delta_current: crate::ResourceTable::default(),
            purchased_items_by_resource: crate::ResourceTable::default(),
            item_potentials: crate::ResourceTable::default(),
            unfilled_trade_turns_by_resource: crate::ResourceTable::default(),
            transported_items_by_resource: crate::ResourceTable::default(),
            remembered_trade_offers_by_resource: crate::ResourceTable::default(),
            aid_allocation_matrix: crate::AidAllocationTable::default(),
            budget_pool_base: 0,
            budget_pool_delta: 0,
            special_resource_trade_balance: 0,
            candidate_nation_flags: crate::NationTable::default(),
            scenario_initialized: false,
            turn_finished: false,
            pending_action_status: crate::PendingActionTable::default(),
            pending_action_payload_by_action: crate::PendingActionTable::default(),
            diplomacy_budget_base: 0,
            escalation_counter: 0,
            pending_commitment_cost: 0,
            pressure_counter: 0,
            aid_allocation_total: 0,
            colony_boycott_flags: crate::NationTable::default(),
            military_expenses: 0,
        }
    }

    #[test]
    fn clamps_negative_stocks_and_adds_only_purchased_resource_bands() {
        let mut state = city();
        state.stock_by_type = ResourceTable::from_fn(|_| -1);
        state.verify_stocks();
        assert!(state.stock_by_type.iter().all(|(_, stock)| *stock == 0));

        let amounts: Vec<i16> = (1..=ResourceKind::PURCHASED_COUNT as i16).collect();
        state.add_purchased_items(&amounts).unwrap();
        assert_eq!(state.stock_by_type[ResourceKind::Cotton], 1);
        assert_eq!(state.stock_by_type[ResourceKind::Arms], 17);
        assert_eq!(state.stock_by_type[ResourceKind::Grain], 0);
        assert_eq!(state.stock_by_type[ResourceKind::Gold], 0);
    }

    #[test]
    fn transported_items_cover_all_resources_then_clear_precious_metals() {
        let mut state = city();
        state.stock_by_type = ResourceTable::from_fn(|_| 1);
        state.add_transported_items(&ResourceTable::from_fn(|_| 2));
        assert_eq!(state.stock_by_type[ResourceKind::Cotton], 3);
        assert_eq!(state.stock_by_type[ResourceKind::Livestock], 3);
        assert_eq!(state.stock_by_type[ResourceKind::Gems], 0);
        assert_eq!(state.stock_by_type[ResourceKind::Gold], 0);
    }

    #[test]
    fn direct_transport_obeys_surplus_then_remaining_capacity() {
        let mut state = city();
        let mut owner = nation();
        let resource = ResourceKind::Steel;
        owner.need_current_by_type[resource] = 10;
        owner.need_target_by_type[resource] = 4;

        assert_eq!(state.direct_transport(&mut owner, resource, 5), 4);
        assert_eq!(state.stock_by_type[resource], 4);
        assert_eq!(owner.need_target_by_type[resource], 8);
        assert_eq!(owner.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX], 15);
    }

    #[test]
    fn nation_target_transport_uses_the_same_full_table_path() {
        let mut state = city();
        let mut owner = nation();
        owner.need_target_by_type = ResourceTable::from_fn(|_| 2);
        state.add_nation_target_items(&owner);
        assert_eq!(state.stock_by_type[ResourceKind::Cotton], 2);
        assert_eq!(state.stock_by_type[ResourceKind::Livestock], 2);
        assert_eq!(state.stock_by_type[ResourceKind::Gems], 0);
        assert_eq!(state.stock_by_type[ResourceKind::Gold], 0);
    }

    #[test]
    fn rolling_stock_consumes_lumber_and_steel() {
        let mut state = city();
        let mut owner = nation();
        state.stock_by_type[ResourceKind::Lumber] = 2;
        state.stock_by_type[ResourceKind::Steel] = 1;

        assert!(state.increase_rolling_stock(&mut owner));
        assert_eq!(state.stock_by_type[ResourceKind::Lumber], 1);
        assert_eq!(state.stock_by_type[ResourceKind::Steel], 0);
        assert_eq!(owner.capacities[TRANSPORT_CAPACITY_INDEX], 16);
        assert!(!state.increase_rolling_stock(&mut owner));
        assert_eq!(owner.capacities[TRANSPORT_CAPACITY_INDEX], 16);
    }

    #[test]
    fn merchant_marine_requires_three_lumber_and_one_fabric() {
        let mut state = city();
        let mut owner = nation();
        state.stock_by_type[ResourceKind::Lumber] = 2;
        state.stock_by_type[ResourceKind::Fabric] = 1;
        assert!(!state.increase_merchant_marine(&mut owner));

        state.stock_by_type[ResourceKind::Lumber] = 3;
        assert!(state.increase_merchant_marine(&mut owner));
        assert_eq!(state.stock_by_type[ResourceKind::Lumber], 0);
        assert_eq!(state.stock_by_type[ResourceKind::Fabric], 0);
        assert_eq!(owner.capacities[1], 1);
    }

    #[test]
    fn city_summary_subtracts_both_animal_food_reservations() {
        let mut state = city();
        state.reserved_by_type[ResourceKind::Grain] = 1;
        state.reserved_by_type[ResourceKind::Fruit] = 3;
        state.reserved_by_type[ResourceKind::Fish] = 1;
        let summary = state.refresh_unreserved_city_needs(0);
        assert_eq!(summary[ResourceKind::Grain], 3);
        assert_eq!(summary[ResourceKind::Fruit], 0);
        assert_eq!(summary[ResourceKind::Fish], 0);
        assert_eq!(summary[ResourceKind::Livestock], 0);
    }

    #[test]
    fn refreshes_the_retail_local_summary_flags() {
        let mut state = city();
        state.population.strength = 1;
        state.production_accum[slot(4)] = 1;
        state.production_accum[slot(2)] = 1;
        state.refresh_local_summary_flags();
        assert!(!state.low_stock);
        assert!(state.low_production);

        state.population.strength = 2;
        state.production_accum.fill(0);
        state.refresh_local_summary_flags();
        assert!(state.low_stock);
        assert!(!state.low_production);
    }
}
