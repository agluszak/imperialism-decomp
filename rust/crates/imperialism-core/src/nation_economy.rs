use crate::{CityState, MajorNationState, ResourceKind, all_resources};

const MERCHANT_CAPACITY_INDEX: usize = 1;
const TRANSPORT_CAPACITY_INDEX: usize = 2;
const RESERVED_TRANSPORT_CAPACITY_INDEX: usize = 3;

impl MajorNationState {
    /// Mirrors the inline `TGreatPower::ComputeAvailableDiplomacyBudget` clamp.
    pub fn available_diplomacy_budget(&self, treasury: i32) -> i32 {
        let available = treasury + self.diplomacy_budget_base / 100;
        if available <= 0 { 0 } else { available }
    }

    pub fn set_need_current(&mut self, resource: ResourceKind, value: i32) {
        self.need_current_by_type[resource] = value as i16;
    }

    pub fn need_target(&self, resource: ResourceKind) -> i16 {
        self.need_target_by_type[resource]
    }

    pub fn need_target_equals_current(&self, resource: ResourceKind) -> bool {
        self.need_target_by_type[resource] == self.need_current_by_type[resource]
    }

    pub fn update_need_target(&mut self, resource: ResourceKind, value: i16) {
        let target = &mut self.need_target_by_type[resource];
        let delta = value.wrapping_sub(*target);
        self.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX] =
            self.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX].wrapping_add(delta);
        *target = value;
    }

    pub fn increment_need_target_toward_current(&mut self, resource: ResourceKind) {
        let target = self.need_target_by_type[resource];
        if target < self.need_current_by_type[resource] {
            self.update_need_target(resource, target.wrapping_add(1));
        }
    }

    pub fn is_transport_capacity_exceeded(&self) -> bool {
        let current_total = self
            .need_current_by_type
            .iter()
            .fold(0_i32, |total, (_, value)| {
                total.wrapping_add(i32::from(*value))
            });
        current_total > i32::from(self.capacities[TRANSPORT_CAPACITY_INDEX])
    }

    pub fn add_purchased_item_amount(&mut self, resource: ResourceKind, delta: i16) {
        let amount = &mut self.purchased_items_by_resource[resource];
        *amount = amount.wrapping_add(delta);
    }

    pub fn available_merchant_capacity(&self) -> i16 {
        self.capacities[0]
    }

    pub fn deliver_item(&mut self, amount: i16) {
        self.capacities[0] = self.capacities[0].wrapping_sub(amount);
    }

    pub fn consume_merchant_capacity_for_purchase(&mut self, amount: i32) {
        self.capacities[0] = self.capacities[0].wrapping_sub(amount as i16);
    }

    pub fn amount_unsold(&self, resource: ResourceKind) -> i16 {
        self.item_potentials[resource].wrapping_add(self.purchased_items_by_resource[resource])
    }

    pub fn advanced_manufactured_offers_exhausted(&self) -> bool {
        for resource in [
            ResourceKind::Clothing,
            ResourceKind::Furniture,
            ResourceKind::Hardware,
            ResourceKind::Arms,
        ] {
            let potential = self.item_potentials[resource];
            if potential > 0
                && i32::from(self.purchased_items_by_resource[resource]) + i32::from(potential) > 0
            {
                return false;
            }
        }
        true
    }

    pub fn trade_offer(&self, resource: ResourceKind) -> i16 {
        self.item_potentials[resource]
    }

    pub fn set_item_potential(&mut self, resource: ResourceKind, value: i16) {
        self.item_potentials[resource] = value.min(self.capacities[MERCHANT_CAPACITY_INDEX]);
    }

    pub fn remember_trade_bids(&mut self) {
        self.remembered_trade_offers_by_resource
            .clone_from(&self.item_potentials);
    }

    pub fn clear_trade_offer(&mut self, resource: ResourceKind) {
        self.item_potentials[resource] = 0;
    }

    pub fn is_still_buying(&self, resource: ResourceKind) -> bool {
        self.available_merchant_capacity() > 0 && self.item_potentials[resource] < 0
    }

    pub fn settle_transported_items(&mut self, city: &mut CityState) {
        for resource in all_resources() {
            let amount = self.transported_items_by_resource[resource];
            city.add_to_stock_and_verify(resource, amount);
            self.transported_items_by_resource[resource] = 0;
        }
    }

    pub fn settle_purchased_items(&mut self, city: &mut CityState) {
        for resource in all_resources() {
            let purchased = self.purchased_items_by_resource[resource];
            city.add_to_stock_and_verify(resource, purchased);
            if self.remembered_trade_offers_by_resource[resource] == -1 && purchased == 0 {
                self.unfilled_trade_turns_by_resource[resource] =
                    self.unfilled_trade_turns_by_resource[resource].wrapping_add(1);
            } else {
                self.unfilled_trade_turns_by_resource[resource] = 0;
            }
            self.purchased_items_by_resource[resource] = 0;
        }
    }

    pub(crate) fn merchant_capacity_mut(&mut self) -> &mut i16 {
        &mut self.capacities[MERCHANT_CAPACITY_INDEX]
    }

    pub(crate) fn transport_capacity_mut(&mut self) -> &mut i16 {
        &mut self.capacities[TRANSPORT_CAPACITY_INDEX]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LaborPool, PopulationState};

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
            diplomacy_grants_by_nation: crate::NationTable::default(),
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
    fn clamps_the_available_diplomacy_budget() {
        let mut state = nation();
        state.diplomacy_budget_base = 250;
        assert_eq!(state.available_diplomacy_budget(10), 12);
        assert_eq!(state.available_diplomacy_budget(-2), 0);
        assert_eq!(state.available_diplomacy_budget(-20), 0);
    }

    #[test]
    fn updates_current_target_and_reserved_capacity_with_short_arithmetic() {
        let mut state = nation();
        let resource = ResourceKind::Steel;
        state.set_need_current(resource, 0x1_000a);
        assert_eq!(state.need_current_by_type[resource], 10);
        assert!(!state.need_target_equals_current(resource));

        state.update_need_target(resource, 7);
        assert_eq!(state.need_target(resource), 7);
        assert_eq!(state.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX], 18);
        state.update_need_target(resource, 3);
        assert_eq!(state.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX], 14);
    }

    #[test]
    fn increments_a_target_only_toward_its_current_need() {
        let mut state = nation();
        let resource = ResourceKind::Coal;
        state.need_current_by_type[resource] = 2;
        state.need_target_by_type[resource] = 1;
        state.increment_need_target_toward_current(resource);
        assert_eq!(state.need_target(resource), 2);
        assert_eq!(state.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX], 12);
        state.increment_need_target_toward_current(resource);
        assert_eq!(state.need_target(resource), 2);
        assert_eq!(state.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX], 12);
    }

    #[test]
    fn compares_total_current_needs_with_transport_capacity() {
        let mut state = nation();
        state.need_current_by_type[ResourceKind::Coal] = 8;
        state.need_current_by_type[ResourceKind::Steel] = 7;
        assert!(!state.is_transport_capacity_exceeded());
        state.need_current_by_type[ResourceKind::Food] = 1;
        assert!(state.is_transport_capacity_exceeded());
    }

    #[test]
    fn purchased_item_accumulation_wraps_like_the_retail_short() {
        let mut state = nation();
        let resource = ResourceKind::Arms;
        state.purchased_items_by_resource[resource] = i16::MAX;
        state.add_purchased_item_amount(resource, 1);
        assert_eq!(state.purchased_items_by_resource[resource], i16::MIN);
    }

    #[test]
    fn trade_offer_leaves_preserve_capacity_and_short_arithmetic() {
        let mut state = nation();
        state.capacities[0] = 5;
        state.capacities[MERCHANT_CAPACITY_INDEX] = 3;
        state.deliver_item(2);
        state.consume_merchant_capacity_for_purchase(0x1_0001);
        assert_eq!(state.available_merchant_capacity(), 2);

        let resource = ResourceKind::Coal;
        state.set_item_potential(resource, 7);
        assert_eq!(state.trade_offer(resource), 3);
        state.set_item_potential(resource, -1);
        assert!(state.is_still_buying(resource));
        state.purchased_items_by_resource[resource] = 4;
        assert_eq!(state.amount_unsold(resource), 3);
        state.clear_trade_offer(resource);
        assert!(!state.is_still_buying(resource));
    }

    #[test]
    fn advanced_manufactured_exhaustion_uses_only_resources_thirteen_through_sixteen() {
        let mut state = nation();
        state.item_potentials[ResourceKind::Steel] = 10;
        state.item_potentials[ResourceKind::Clothing] = 2;
        state.purchased_items_by_resource[ResourceKind::Clothing] = -2;
        assert!(state.advanced_manufactured_offers_exhausted());

        state.purchased_items_by_resource[ResourceKind::Clothing] = -1;
        assert!(!state.advanced_manufactured_offers_exhausted());
    }

    #[test]
    fn remembers_trade_bids_as_a_full_resource_table_copy() {
        let mut state = nation();
        for resource in crate::all_resources() {
            state.item_potentials[resource] = resource as i16 - 4;
        }
        state.remember_trade_bids();
        assert_eq!(
            state.remembered_trade_offers_by_resource,
            state.item_potentials
        );
    }

    #[test]
    fn settles_and_clears_all_transported_items() {
        let mut state = nation();
        let mut owner_city = city();
        owner_city.stock_by_type[ResourceKind::Lumber] = 2;
        state.transported_items_by_resource[ResourceKind::Lumber] = 3;
        state.transported_items_by_resource[ResourceKind::Gold] = 4;

        state.settle_transported_items(&mut owner_city);
        assert_eq!(owner_city.stock_by_type[ResourceKind::Lumber], 5);
        assert_eq!(owner_city.stock_by_type[ResourceKind::Gold], 4);
        assert!(
            state
                .transported_items_by_resource
                .iter()
                .all(|(_, amount)| *amount == 0)
        );
    }

    #[test]
    fn purchased_settlement_tracks_only_unfilled_requested_offers() {
        let mut state = nation();
        let mut owner_city = city();
        let cotton = ResourceKind::Cotton;
        let wool = ResourceKind::Wool;
        let timber = ResourceKind::Timber;
        state.remembered_trade_offers_by_resource[cotton] = -1;
        state.unfilled_trade_turns_by_resource[cotton] = i16::MAX;
        state.remembered_trade_offers_by_resource[wool] = -1;
        state.purchased_items_by_resource[wool] = 2;
        state.unfilled_trade_turns_by_resource[wool] = 9;
        state.unfilled_trade_turns_by_resource[timber] = 9;

        state.settle_purchased_items(&mut owner_city);
        assert_eq!(state.unfilled_trade_turns_by_resource[cotton], i16::MIN);
        assert_eq!(state.unfilled_trade_turns_by_resource[wool], 0);
        assert_eq!(state.unfilled_trade_turns_by_resource[timber], 0);
        assert_eq!(owner_city.stock_by_type[wool], 2);
        assert!(
            state
                .purchased_items_by_resource
                .iter()
                .all(|(_, amount)| *amount == 0)
        );
    }
}
