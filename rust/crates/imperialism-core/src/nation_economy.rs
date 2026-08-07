use crate::{CityState, MajorNationState, ResourceKind};
use std::error::Error;
use std::fmt;

const MERCHANT_CAPACITY_INDEX: usize = 1;
const TRANSPORT_CAPACITY_INDEX: usize = 2;
const RESERVED_TRANSPORT_CAPACITY_INDEX: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NationEconomyError {
    InvalidResourceCount { field: &'static str, actual: usize },
}

impl fmt::Display for NationEconomyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidResourceCount { field, actual } => write!(
                formatter,
                "{field} has {actual} entries, expected {}",
                ResourceKind::COUNT
            ),
        }
    }
}

impl Error for NationEconomyError {}

impl MajorNationState {
    /// Mirrors the inline `TGreatPower::ComputeAvailableDiplomacyBudget` clamp.
    pub fn available_diplomacy_budget(&self, treasury: i32) -> i32 {
        let available = treasury.wrapping_add(self.diplomacy_budget_base / 100);
        if available <= 0 { 0 } else { available }
    }

    pub fn set_need_current(
        &mut self,
        resource: ResourceKind,
        value: i32,
    ) -> Result<(), NationEconomyError> {
        validate_resources("current nation needs", &self.need_current_by_type)?;
        self.need_current_by_type[resource.index()] = value as i16;
        Ok(())
    }

    pub fn need_target(&self, resource: ResourceKind) -> Result<i16, NationEconomyError> {
        validate_resources("target nation needs", &self.need_target_by_type)?;
        Ok(self.need_target_by_type[resource.index()])
    }

    pub fn need_target_equals_current(
        &self,
        resource: ResourceKind,
    ) -> Result<bool, NationEconomyError> {
        validate_resources("current nation needs", &self.need_current_by_type)?;
        validate_resources("target nation needs", &self.need_target_by_type)?;
        let index = resource.index();
        Ok(self.need_target_by_type[index] == self.need_current_by_type[index])
    }

    pub fn update_need_target(
        &mut self,
        resource: ResourceKind,
        value: i16,
    ) -> Result<(), NationEconomyError> {
        validate_resources("target nation needs", &self.need_target_by_type)?;
        let target = &mut self.need_target_by_type[resource.index()];
        let delta = value.wrapping_sub(*target);
        self.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX] =
            self.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX].wrapping_add(delta);
        *target = value;
        Ok(())
    }

    pub fn increment_need_target_toward_current(
        &mut self,
        resource: ResourceKind,
    ) -> Result<(), NationEconomyError> {
        validate_resources("current nation needs", &self.need_current_by_type)?;
        validate_resources("target nation needs", &self.need_target_by_type)?;
        let index = resource.index();
        let target = self.need_target_by_type[index];
        if target < self.need_current_by_type[index] {
            self.update_need_target(resource, target.wrapping_add(1))?;
        }
        Ok(())
    }

    pub fn is_transport_capacity_exceeded(&self) -> Result<bool, NationEconomyError> {
        validate_resources("current nation needs", &self.need_current_by_type)?;
        let current_total = self
            .need_current_by_type
            .iter()
            .fold(0_i32, |total, value| total.wrapping_add(i32::from(*value)));
        Ok(current_total > i32::from(self.capacities[TRANSPORT_CAPACITY_INDEX]))
    }

    pub fn add_purchased_item_amount(
        &mut self,
        resource: ResourceKind,
        delta: i16,
    ) -> Result<(), NationEconomyError> {
        validate_resources("purchased nation items", &self.purchased_items_by_resource)?;
        let amount = &mut self.purchased_items_by_resource[resource.index()];
        *amount = amount.wrapping_add(delta);
        Ok(())
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

    pub fn amount_unsold(&self, resource: ResourceKind) -> Result<i16, NationEconomyError> {
        validate_resources("nation item potentials", &self.item_potentials)?;
        validate_resources("purchased nation items", &self.purchased_items_by_resource)?;
        let index = resource.index();
        Ok(self.item_potentials[index].wrapping_add(self.purchased_items_by_resource[index]))
    }

    pub fn advanced_manufactured_offers_exhausted(&self) -> Result<bool, NationEconomyError> {
        validate_resources("nation item potentials", &self.item_potentials)?;
        validate_resources("purchased nation items", &self.purchased_items_by_resource)?;
        for resource in [
            ResourceKind::Clothing,
            ResourceKind::Furniture,
            ResourceKind::Hardware,
            ResourceKind::Arms,
        ] {
            let index = resource.index();
            let potential = self.item_potentials[index];
            if potential > 0
                && i32::from(self.purchased_items_by_resource[index]) + i32::from(potential) > 0
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn trade_offer(&self, resource: ResourceKind) -> Result<i16, NationEconomyError> {
        validate_resources("nation item potentials", &self.item_potentials)?;
        Ok(self.item_potentials[resource.index()])
    }

    pub fn set_item_potential(
        &mut self,
        resource: ResourceKind,
        value: i16,
    ) -> Result<(), NationEconomyError> {
        validate_resources("nation item potentials", &self.item_potentials)?;
        self.item_potentials[resource.index()] =
            value.min(self.capacities[MERCHANT_CAPACITY_INDEX]);
        Ok(())
    }

    pub fn remember_trade_bids(&mut self) -> Result<(), NationEconomyError> {
        validate_resources("nation item potentials", &self.item_potentials)?;
        validate_resources(
            "remembered nation trade offers",
            &self.remembered_trade_offers_by_resource,
        )?;
        self.remembered_trade_offers_by_resource
            .clone_from_slice(&self.item_potentials);
        Ok(())
    }

    pub fn clear_trade_offer(&mut self, resource: ResourceKind) -> Result<(), NationEconomyError> {
        validate_resources("nation item potentials", &self.item_potentials)?;
        self.item_potentials[resource.index()] = 0;
        Ok(())
    }

    pub fn is_still_buying(&self, resource: ResourceKind) -> Result<bool, NationEconomyError> {
        validate_resources("nation item potentials", &self.item_potentials)?;
        Ok(self.available_merchant_capacity() > 0 && self.item_potentials[resource.index()] < 0)
    }

    pub fn settle_transported_items(
        &mut self,
        city: &mut CityState,
    ) -> Result<(), NationEconomyError> {
        validate_resources(
            "transported nation items",
            &self.transported_items_by_resource,
        )?;
        validate_resources("city stock", &city.stock_by_type)?;
        for resource in ResourceKind::ALL {
            let amount = self.transported_items_by_resource[resource.index()];
            city.add_to_stock_and_verify(resource, amount);
            self.transported_items_by_resource[resource.index()] = 0;
        }
        Ok(())
    }

    pub fn settle_purchased_items(
        &mut self,
        city: &mut CityState,
    ) -> Result<(), NationEconomyError> {
        validate_resources("purchased nation items", &self.purchased_items_by_resource)?;
        validate_resources(
            "remembered nation trade offers",
            &self.remembered_trade_offers_by_resource,
        )?;
        validate_resources(
            "unfilled nation trade turns",
            &self.unfilled_trade_turns_by_resource,
        )?;
        validate_resources("city stock", &city.stock_by_type)?;

        for resource in ResourceKind::ALL {
            let index = resource.index();
            let purchased = self.purchased_items_by_resource[index];
            city.add_to_stock_and_verify(resource, purchased);
            if self.remembered_trade_offers_by_resource[index] == -1 && purchased == 0 {
                self.unfilled_trade_turns_by_resource[index] =
                    self.unfilled_trade_turns_by_resource[index].wrapping_add(1);
            } else {
                self.unfilled_trade_turns_by_resource[index] = 0;
            }
            self.purchased_items_by_resource[index] = 0;
        }
        Ok(())
    }

    pub(crate) fn merchant_capacity_mut(&mut self) -> &mut i16 {
        &mut self.capacities[MERCHANT_CAPACITY_INDEX]
    }

    pub(crate) fn transport_capacity_mut(&mut self) -> &mut i16 {
        &mut self.capacities[TRANSPORT_CAPACITY_INDEX]
    }
}

fn validate_resources(field: &'static str, values: &[i16]) -> Result<(), NationEconomyError> {
    if values.len() == ResourceKind::COUNT {
        Ok(())
    } else {
        Err(NationEconomyError::InvalidResourceCount {
            field,
            actual: values.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LaborPool, NationId, PopulationState};

    fn city() -> CityState {
        CityState {
            nation: NationId::new(0),
            power_plant_upgrade_queued: false,
            food_substitution_count: 0,
            starvation_population_loss: 0,
            serialized_state: 0,
            phase_counter: 0,
            metrics_0e: vec![0; 30],
            metrics_4a: vec![0; 9],
            order_count_by_type: vec![0; 14],
            rolling_item_production_score: 0,
            low_production: false,
            low_stock: false,
            reserved_by_type: vec![0; ResourceKind::COUNT],
            home_town_tile: 1,
            power_available: 0,
            stock_by_type: vec![0; ResourceKind::COUNT],
            production_orders: vec![0; 16],
            production_accum: vec![0; 16],
            production_flags: vec![0; 16],
            production_current: vec![0; 16],
            production_progress: vec![0; 16],
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: vec![0; ResourceKind::COUNT],
            consumed_production_input_by_type: vec![0; ResourceKind::COUNT],
            population: PopulationState {
                count: 7,
                count_float_bits: 7.0_f32.to_bits(),
                strength: 12,
                extra: 0,
                phase_value: 0,
                baseline_labor: Some(LaborPool::new(4, 2, 1)),
                production_labor: Some(LaborPool::new(4, 2, 1)),
                pending_labor_delta: Some(LaborPool::default()),
                predicted_need_by_resource: vec![0; ResourceKind::COUNT],
            },
        }
    }

    fn nation() -> MajorNationState {
        MajorNationState {
            diplomacy_eligible: true,
            capacities: [0, 0, 15, 11],
            grant_total_cost: 0,
            unfilled_trade_offer_count: 0,
            diplomacy_policy_by_nation: vec![0; ResourceKind::COUNT],
            diplomacy_grant_by_nation: vec![0; ResourceKind::COUNT],
            need_current_by_type: vec![0; ResourceKind::COUNT],
            need_target_by_type: vec![0; ResourceKind::COUNT],
            relation_delta_current: vec![0; ResourceKind::COUNT],
            purchased_items_by_resource: vec![0; ResourceKind::COUNT],
            item_potentials: vec![0; ResourceKind::COUNT],
            unfilled_trade_turns_by_resource: vec![0; ResourceKind::COUNT],
            transported_items_by_resource: vec![0; ResourceKind::COUNT],
            remembered_trade_offers_by_resource: vec![0; ResourceKind::COUNT],
            aid_allocation_matrix: vec![],
            budget_pool_base: 0,
            budget_pool_delta: 0,
            special_resource_trade_balance: 0,
            candidate_nation_flags: vec![],
            scenario_initialized: false,
            turn_finished: false,
            pending_action_status: vec![],
            pending_action_payload_by_action: vec![],
            diplomacy_budget_base: 0,
            escalation_counter: 0,
            pending_commitment_cost: 0,
            pressure_counter: 0,
            aid_allocation_total: 0,
            colony_boycott_flags: vec![],
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
        state.set_need_current(resource, 0x1_000a).unwrap();
        assert_eq!(state.need_current_by_type[resource.index()], 10);
        assert!(!state.need_target_equals_current(resource).unwrap());

        state.update_need_target(resource, 7).unwrap();
        assert_eq!(state.need_target(resource).unwrap(), 7);
        assert_eq!(state.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX], 18);
        state.update_need_target(resource, 3).unwrap();
        assert_eq!(state.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX], 14);
    }

    #[test]
    fn increments_a_target_only_toward_its_current_need() {
        let mut state = nation();
        let resource = ResourceKind::Coal;
        state.need_current_by_type[resource.index()] = 2;
        state.need_target_by_type[resource.index()] = 1;
        state
            .increment_need_target_toward_current(resource)
            .unwrap();
        assert_eq!(state.need_target(resource).unwrap(), 2);
        assert_eq!(state.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX], 12);
        state
            .increment_need_target_toward_current(resource)
            .unwrap();
        assert_eq!(state.need_target(resource).unwrap(), 2);
        assert_eq!(state.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX], 12);
    }

    #[test]
    fn compares_total_current_needs_with_transport_capacity() {
        let mut state = nation();
        state.need_current_by_type[ResourceKind::Coal.index()] = 8;
        state.need_current_by_type[ResourceKind::Steel.index()] = 7;
        assert!(!state.is_transport_capacity_exceeded().unwrap());
        state.need_current_by_type[ResourceKind::Food.index()] = 1;
        assert!(state.is_transport_capacity_exceeded().unwrap());
    }

    #[test]
    fn purchased_item_accumulation_wraps_like_the_retail_short() {
        let mut state = nation();
        let resource = ResourceKind::Arms;
        state.purchased_items_by_resource[resource.index()] = i16::MAX;
        state.add_purchased_item_amount(resource, 1).unwrap();
        assert_eq!(
            state.purchased_items_by_resource[resource.index()],
            i16::MIN
        );
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
        state.set_item_potential(resource, 7).unwrap();
        assert_eq!(state.trade_offer(resource).unwrap(), 3);
        state.set_item_potential(resource, -1).unwrap();
        assert!(state.is_still_buying(resource).unwrap());
        state.purchased_items_by_resource[resource.index()] = 4;
        assert_eq!(state.amount_unsold(resource).unwrap(), 3);
        state.clear_trade_offer(resource).unwrap();
        assert!(!state.is_still_buying(resource).unwrap());
    }

    #[test]
    fn advanced_manufactured_exhaustion_uses_only_resources_thirteen_through_sixteen() {
        let mut state = nation();
        state.item_potentials[ResourceKind::Steel.index()] = 10;
        state.item_potentials[ResourceKind::Clothing.index()] = 2;
        state.purchased_items_by_resource[ResourceKind::Clothing.index()] = -2;
        assert!(state.advanced_manufactured_offers_exhausted().unwrap());

        state.purchased_items_by_resource[ResourceKind::Clothing.index()] = -1;
        assert!(!state.advanced_manufactured_offers_exhausted().unwrap());
    }

    #[test]
    fn remembers_trade_bids_as_a_full_resource_table_copy() {
        let mut state = nation();
        for resource in ResourceKind::ALL {
            state.item_potentials[resource.index()] = resource.index() as i16 - 4;
        }
        state.remember_trade_bids().unwrap();
        assert_eq!(
            state.remembered_trade_offers_by_resource,
            state.item_potentials
        );
    }

    #[test]
    fn settles_and_clears_all_transported_items() {
        let mut state = nation();
        let mut owner_city = city();
        owner_city.stock_by_type[ResourceKind::Lumber.index()] = 2;
        state.transported_items_by_resource[ResourceKind::Lumber.index()] = 3;
        state.transported_items_by_resource[ResourceKind::Gold.index()] = 4;

        state.settle_transported_items(&mut owner_city).unwrap();
        assert_eq!(owner_city.stock_by_type[ResourceKind::Lumber.index()], 5);
        assert_eq!(owner_city.stock_by_type[ResourceKind::Gold.index()], 4);
        assert!(
            state
                .transported_items_by_resource
                .iter()
                .all(|amount| *amount == 0)
        );
    }

    #[test]
    fn purchased_settlement_tracks_only_unfilled_requested_offers() {
        let mut state = nation();
        let mut owner_city = city();
        let cotton = ResourceKind::Cotton.index();
        let wool = ResourceKind::Wool.index();
        let timber = ResourceKind::Timber.index();
        state.remembered_trade_offers_by_resource[cotton] = -1;
        state.unfilled_trade_turns_by_resource[cotton] = i16::MAX;
        state.remembered_trade_offers_by_resource[wool] = -1;
        state.purchased_items_by_resource[wool] = 2;
        state.unfilled_trade_turns_by_resource[wool] = 9;
        state.unfilled_trade_turns_by_resource[timber] = 9;

        state.settle_purchased_items(&mut owner_city).unwrap();
        assert_eq!(state.unfilled_trade_turns_by_resource[cotton], i16::MIN);
        assert_eq!(state.unfilled_trade_turns_by_resource[wool], 0);
        assert_eq!(state.unfilled_trade_turns_by_resource[timber], 0);
        assert_eq!(owner_city.stock_by_type[wool], 2);
        assert!(
            state
                .purchased_items_by_resource
                .iter()
                .all(|amount| *amount == 0)
        );
    }
}
