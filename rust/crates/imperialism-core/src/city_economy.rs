use crate::{CityFacilitySlot, CityState, GreatPowerState, ResourceKind, ResourceTable};

impl CityState {
    /// Mirrors the state effect of `TCity::VerifyStocks`; UI invalidation from
    /// the C++ method remains a presentation concern.
    /// Mirrors the pointer-taking `TCity::AddTransportedItems` overload.
    pub fn add_transported_items(&mut self, amounts: &ResourceTable<i16>) {
        for (resource, amount) in amounts {
            self.stockpile.credit(resource, *amount);
        }
        self.clear_precious_metal_stock();
    }

    /// Mirrors the no-argument `TCity::AddTransportedItems` overload.
    pub fn add_nation_target_items(&mut self, nation: &GreatPowerState) {
        self.add_transported_items(&nation.need_target_by_type)
    }

    /// Mirrors `TCity::DirectTransport`, including surplus and remaining-capacity
    /// limits and the target/reservation update.
    pub(crate) fn direct_transport(
        &mut self,
        nation: &mut GreatPowerState,
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

        self.stockpile.credit(resource, amount);
        nation.update_need_target(resource, nation.need_target_by_type[resource] + amount);
        amount
    }

    /// Mirrors `TGreatPower::IncreaseRollingStock` against the owning city's
    /// lumber and steel stockpile.
    pub(crate) fn increase_rolling_stock(&mut self, nation: &mut GreatPowerState) -> bool {
        if self.stockpile[ResourceKind::Lumber] == 0 || self.stockpile[ResourceKind::Steel] == 0 {
            return false;
        }

        self.adjust_stock(ResourceKind::Lumber, -1);
        self.adjust_stock(ResourceKind::Steel, -1);
        nation.capacities.transport += 1;
        true
    }

    /// Mirrors `TGreatPower::IncreaseMerchantMarine` against the owning
    /// city's lumber and fabric stockpile.
    pub(crate) fn increase_merchant_marine(&mut self, nation: &mut GreatPowerState) -> bool {
        if self.stockpile[ResourceKind::Lumber] <= 2 || self.stockpile[ResourceKind::Fabric] == 0 {
            return false;
        }

        self.adjust_stock(ResourceKind::Lumber, -3);
        self.adjust_stock(ResourceKind::Fabric, -1);
        nation.capacities.trade_offer += 1;
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
        let mut shortage_count = if self.production_accum[CityFacilitySlot::LumberMill] > 0 {
            2_i16
        } else {
            3_i16
        };
        if self.production_accum[CityFacilitySlot::SteelMill] > 0 {
            shortage_count -= 1;
        }
        if self.production_accum[CityFacilitySlot::TextileMill] > 0 {
            shortage_count -= 1;
        }
        self.low_production = shortage_count < 2;
    }

    fn clear_precious_metal_stock(&mut self) {
        self.stockpile.set_nonnegative(ResourceKind::Gold, 0);
        self.stockpile.set_nonnegative(ResourceKind::Gems, 0);
    }

    pub(crate) fn adjust_stock(&mut self, resource: ResourceKind, delta: i16) {
        self.stockpile.credit(resource, delta);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(value: u8) -> CityFacilitySlot {
        CityFacilitySlot::from_index(value).unwrap()
    }

    fn city() -> CityState {
        crate::test_support::city()
    }

    fn nation() -> GreatPowerState {
        let mut nation = crate::test_support::great_power_state();
        nation.capacities = crate::NationCapacities::from_array([0, 0, 15, 11]);
        nation
    }

    #[test]
    fn transported_items_cover_all_resources_then_clear_precious_metals() {
        let mut state = city();
        state.stockpile = crate::Stockpile::from_table(ResourceTable::from_fn(|_| 1));
        state.add_transported_items(&ResourceTable::from_fn(|_| 2));
        assert_eq!(state.stockpile[ResourceKind::Cotton], 3);
        assert_eq!(state.stockpile[ResourceKind::Livestock], 3);
        assert_eq!(state.stockpile[ResourceKind::Gems], 0);
        assert_eq!(state.stockpile[ResourceKind::Gold], 0);
    }

    #[test]
    fn merchant_marine_requires_three_lumber_and_one_fabric() {
        let mut state = city();
        let mut owner = nation();
        state.stockpile[ResourceKind::Lumber] = 2;
        state.stockpile[ResourceKind::Fabric] = 1;
        assert!(!state.increase_merchant_marine(&mut owner));

        state.stockpile[ResourceKind::Lumber] = 3;
        assert!(state.increase_merchant_marine(&mut owner));
        assert_eq!(state.stockpile[ResourceKind::Lumber], 0);
        assert_eq!(state.stockpile[ResourceKind::Fabric], 0);
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
        state.production_accum = crate::ProductionTable::default();
        state.refresh_local_summary_flags();
        assert!(state.low_stock);
        assert!(!state.low_production);
    }
}
