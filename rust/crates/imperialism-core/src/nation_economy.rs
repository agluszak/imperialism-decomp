use crate::{MajorNationState, ResourceKind};
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
}
