use crate::{CityState, MajorNationState, NationCapacity, ResourceKind, all_resources};

const TRANSPORT_NEED_PRIORITY: [ResourceKind; 10] = [
    ResourceKind::Grain,
    ResourceKind::Fruit,
    ResourceKind::Livestock,
    ResourceKind::Fish,
    ResourceKind::Timber,
    ResourceKind::Coal,
    ResourceKind::Iron,
    ResourceKind::Cotton,
    ResourceKind::Wool,
    ResourceKind::Horses,
];

impl MajorNationState {
    /// Mirrors the inline `TGreatPower::ComputeAvailableDiplomacyBudget` clamp.
    pub fn available_diplomacy_budget(&self, treasury: i32) -> i32 {
        let available = treasury + self.diplomacy_budget_base / 100;
        if available <= 0 { 0 } else { available }
    }

    pub fn need_target_equals_current(&self, resource: ResourceKind) -> bool {
        self.need_target_by_type[resource] == self.need_current_by_type[resource]
    }

    pub fn update_need_target(&mut self, resource: ResourceKind, value: i16) {
        let target = &mut self.need_target_by_type[resource];
        let delta = value - *target;
        self.capacities[NationCapacity::ReservedTransport] += delta;
        *target = value;
    }

    pub fn increment_need_target_toward_current(&mut self, resource: ResourceKind) {
        let target = self.need_target_by_type[resource];
        if target < self.need_current_by_type[resource] {
            self.update_need_target(resource, target + 1);
        }
    }

    pub fn is_transport_capacity_exceeded(&self) -> bool {
        let current_total = self
            .need_current_by_type
            .iter()
            .fold(0_i32, |total, (_, value)| total + i32::from(*value));
        current_total > i32::from(self.capacities[NationCapacity::Transport])
    }

    pub(crate) fn allocate_transport_needs(&mut self) {
        for resource in TRANSPORT_NEED_PRIORITY {
            let headroom = self.capacities[NationCapacity::Transport]
                - self.capacities[NationCapacity::ReservedTransport];
            if headroom == 0 {
                break;
            }
            self.update_need_target(resource, self.need_current_by_type[resource].min(headroom));
        }
    }

    pub fn add_purchased_item_amount(&mut self, resource: ResourceKind, delta: i16) {
        let amount = &mut self.purchased_items_by_resource[resource];
        *amount += delta;
    }

    pub fn deliver_item(&mut self, amount: i16) {
        self.capacities[NationCapacity::AvailableMerchant] -= amount;
    }

    pub fn consume_merchant_capacity_for_purchase(&mut self, amount: i16) {
        self.capacities[NationCapacity::AvailableMerchant] -= amount;
    }

    pub fn amount_unsold(&self, resource: ResourceKind) -> i16 {
        self.item_potentials[resource] + self.purchased_items_by_resource[resource]
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

    pub fn set_item_potential(&mut self, resource: ResourceKind, value: i16) {
        self.item_potentials[resource] =
            value.min(self.capacities[NationCapacity::MerchantCapacity]);
    }

    pub fn remember_trade_bids(&mut self) {
        self.remembered_trade_offers_by_resource
            .clone_from(&self.item_potentials);
    }

    pub fn clear_trade_offer(&mut self, resource: ResourceKind) {
        self.item_potentials[resource] = 0;
    }

    pub fn is_still_buying(&self, resource: ResourceKind) -> bool {
        self.capacities[NationCapacity::AvailableMerchant] > 0 && self.item_potentials[resource] < 0
    }

    pub(crate) fn settle_transported_items(&mut self, city: &mut CityState) {
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
                self.unfilled_trade_turns_by_resource[resource] += 1;
            } else {
                self.unfilled_trade_turns_by_resource[resource] = 0;
            }
            self.purchased_items_by_resource[resource] = 0;
        }
    }

    pub(crate) fn merchant_capacity_mut(&mut self) -> &mut i16 {
        &mut self.capacities[NationCapacity::MerchantCapacity]
    }

    pub(crate) fn transport_capacity_mut(&mut self) -> &mut i16 {
        &mut self.capacities[NationCapacity::Transport]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn city() -> CityState {
        crate::test_support::city()
    }

    fn nation() -> MajorNationState {
        MajorNationState {
            diplomacy_eligible: true,
            capacities: crate::NationCapacityTable::from_array([0, 0, 15, 11]),
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
            aid_allocation_by_minor_nation: crate::MinorNationTable::default(),
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
    fn updates_current_target_and_reserved_capacity() {
        let mut state = nation();
        let resource = ResourceKind::Steel;
        state.need_current_by_type[resource] = 10;
        assert_eq!(state.need_current_by_type[resource], 10);
        assert!(!state.need_target_equals_current(resource));

        state.update_need_target(resource, 7);
        assert_eq!(state.need_target_by_type[resource], 7);
        assert_eq!(state.capacities[NationCapacity::ReservedTransport], 18);
        state.update_need_target(resource, 3);
        assert_eq!(state.capacities[NationCapacity::ReservedTransport], 14);
    }

    #[test]
    fn increments_a_target_only_toward_its_current_need() {
        let mut state = nation();
        let resource = ResourceKind::Coal;
        state.need_current_by_type[resource] = 2;
        state.need_target_by_type[resource] = 1;
        state.increment_need_target_toward_current(resource);
        assert_eq!(state.need_target_by_type[resource], 2);
        assert_eq!(state.capacities[NationCapacity::ReservedTransport], 12);
        state.increment_need_target_toward_current(resource);
        assert_eq!(state.need_target_by_type[resource], 2);
        assert_eq!(state.capacities[NationCapacity::ReservedTransport], 12);
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
    fn trade_offer_leaves_preserve_capacity() {
        let mut state = nation();
        state.capacities[NationCapacity::AvailableMerchant] = 5;
        state.capacities[NationCapacity::MerchantCapacity] = 3;
        state.deliver_item(2);
        state.consume_merchant_capacity_for_purchase(1);
        assert_eq!(state.capacities[NationCapacity::AvailableMerchant], 2);

        let resource = ResourceKind::Coal;
        state.set_item_potential(resource, 7);
        assert_eq!(state.item_potentials[resource], 3);
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
        state.unfilled_trade_turns_by_resource[cotton] = 3;
        state.remembered_trade_offers_by_resource[wool] = -1;
        state.purchased_items_by_resource[wool] = 2;
        state.unfilled_trade_turns_by_resource[wool] = 9;
        state.unfilled_trade_turns_by_resource[timber] = 9;

        state.settle_purchased_items(&mut owner_city);
        assert_eq!(state.unfilled_trade_turns_by_resource[cotton], 4);
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

    #[test]
    fn allocates_transport_needs_in_retail_priority_order() {
        let mut state = nation();
        state.capacities[NationCapacity::Transport] = 8;
        state.capacities[NationCapacity::ReservedTransport] = 2;
        state.need_current_by_type[ResourceKind::Grain] = 4;
        state.need_current_by_type[ResourceKind::Fruit] = 3;
        state.need_current_by_type[ResourceKind::Livestock] = 6;

        state.allocate_transport_needs();

        assert_eq!(state.need_target_by_type[ResourceKind::Grain], 4);
        assert_eq!(state.need_target_by_type[ResourceKind::Fruit], 2);
        assert_eq!(state.need_target_by_type[ResourceKind::Livestock], 0);
        assert_eq!(state.capacities[NationCapacity::ReservedTransport], 8);
    }
}
