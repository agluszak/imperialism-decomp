use crate::{CityState, MajorNationState, ProductionSlot, ResourceKind, ResourceTable};

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

    /// Mirrors the pointer-taking `TCity::AddTransportedItems` overload.
    pub fn add_transported_items(&mut self, amounts: &ResourceTable<i16>) {
        for (resource, amount) in amounts {
            self.stock_by_type[resource] += *amount;
        }
        self.clear_precious_metal_stock();
    }

    /// Mirrors the no-argument `TCity::AddTransportedItems` overload.
    pub fn add_nation_target_items(&mut self, nation: &MajorNationState) {
        self.add_transported_items(&nation.need_target_by_type)
    }

    /// Mirrors `TCity::DirectTransport`, including surplus and remaining-capacity
    /// limits and the target/reservation update.
    pub(crate) fn direct_transport(
        &mut self,
        nation: &mut MajorNationState,
        resource: ResourceKind,
        requested: i16,
    ) -> i16 {
        let mut amount = requested;
        let surplus = nation.need_current_by_type[resource] - nation.need_target_by_type[resource];
        if surplus < amount {
            amount = surplus;
        }
        let available_capacity = nation.capacities.transport - nation.capacities.reserved_transport;
        if available_capacity < amount {
            amount = available_capacity;
        }

        self.stock_by_type[resource] += amount;
        nation.update_need_target(resource, nation.need_target_by_type[resource] + amount);
        amount
    }

    /// Mirrors `TGreatPower::IncreaseRollingStock` against the owning city's
    /// lumber and steel stockpile.
    pub(crate) fn increase_rolling_stock(&mut self, nation: &mut MajorNationState) -> bool {
        if self.stock_by_type[ResourceKind::Lumber] == 0
            || self.stock_by_type[ResourceKind::Steel] == 0
        {
            return false;
        }

        self.add_to_stock_and_verify(ResourceKind::Lumber, -1);
        self.add_to_stock_and_verify(ResourceKind::Steel, -1);
        let capacity = nation.transport_capacity_mut();
        *capacity += 1;
        true
    }

    /// Mirrors `TGreatPower::IncreaseMerchantMarine` against the owning
    /// city's lumber and fabric stockpile.
    pub(crate) fn increase_merchant_marine(&mut self, nation: &mut MajorNationState) -> bool {
        if self.stock_by_type[ResourceKind::Lumber] <= 2
            || self.stock_by_type[ResourceKind::Fabric] == 0
        {
            return false;
        }

        self.add_to_stock_and_verify(ResourceKind::Lumber, -3);
        self.add_to_stock_and_verify(ResourceKind::Fabric, -1);
        let capacity = nation.merchant_capacity_mut();
        *capacity += 1;
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
                summary[resource] = remaining - *reserved;
                if resource == ResourceKind::Livestock {
                    summary[resource] -= self.reserved_by_type[ResourceKind::Fish];
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
        let mut shortage_count = if self.production_accum[ProductionSlot::EVEN_CAPACITY_4] > 0 {
            2_i16
        } else {
            3_i16
        };
        if self.production_accum[ProductionSlot::EVEN_CAPACITY_2] > 0 {
            shortage_count -= 1;
        }
        if self.production_accum[ProductionSlot::EVEN_CAPACITY_0] > 0 {
            shortage_count -= 1;
        }
        self.low_production = shortage_count < 2;
    }

    fn clear_precious_metal_stock(&mut self) {
        self.stock_by_type[ResourceKind::Gold] = 0;
        self.stock_by_type[ResourceKind::Gems] = 0;
    }

    pub(crate) fn add_to_stock_and_verify(&mut self, resource: ResourceKind, delta: i16) {
        let stock = &mut self.stock_by_type[resource];
        *stock += delta;
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
    use crate::test_support;

    fn slot(value: u8) -> ProductionSlot {
        ProductionSlot::new(value).unwrap()
    }

    fn city() -> CityState {
        test_support::city()
    }

    fn nation() -> MajorNationState {
        let mut state = test_support::major_nation_state();
        state.capacities = crate::NationCapacities::from_array([0, 0, 15, 11]);
        state
    }

    #[test]
    fn clamps_negative_stocks() {
        let mut state = city();
        state.stock_by_type = ResourceTable::from_fn(|_| -1);
        state.verify_stocks();
        assert!(state.stock_by_type.iter().all(|(_, stock)| *stock == 0));
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
        assert_eq!(owner.capacities.reserved_transport, 15);
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
        assert_eq!(owner.capacities.transport, 16);
        assert!(!state.increase_rolling_stock(&mut owner));
        assert_eq!(owner.capacities.transport, 16);
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
        assert_eq!(owner.capacities.trade_offer, 1);
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
