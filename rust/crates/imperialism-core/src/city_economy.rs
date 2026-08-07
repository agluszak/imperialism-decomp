use crate::{CityState, MajorNationState, PopulationError, ResourceKind};
use std::error::Error;
use std::fmt;

const TRANSPORT_CAPACITY_INDEX: usize = 2;
const RESERVED_TRANSPORT_CAPACITY_INDEX: usize = 3;
const PRODUCTION_ACCUM_COUNT: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CityEconomyError {
    InvalidResourceCount { field: &'static str, actual: usize },
    InvalidPurchasedItemCount { actual: usize },
    InvalidProductionAccumCount { actual: usize },
    Population(PopulationError),
}

impl fmt::Display for CityEconomyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidResourceCount { field, actual } => write!(
                formatter,
                "{field} has {actual} entries, expected {}",
                ResourceKind::COUNT
            ),
            Self::InvalidPurchasedItemCount { actual } => write!(
                formatter,
                "purchased item vector has {actual} entries, expected {}",
                ResourceKind::PURCHASED_COUNT
            ),
            Self::InvalidProductionAccumCount { actual } => write!(
                formatter,
                "city production accumulation has {actual} entries, expected {PRODUCTION_ACCUM_COUNT}"
            ),
            Self::Population(error) => error.fmt(formatter),
        }
    }
}

impl Error for CityEconomyError {}

impl From<PopulationError> for CityEconomyError {
    fn from(value: PopulationError) -> Self {
        Self::Population(value)
    }
}

impl CityState {
    /// Mirrors the state effect of `TCity::VerifyStocks`; UI invalidation from
    /// the C++ method remains a presentation concern.
    pub fn verify_stocks(&mut self) -> Result<(), CityEconomyError> {
        validate_resources("city stock", &self.stock_by_type)?;
        for stock in &mut self.stock_by_type {
            if *stock < 0 {
                *stock = 0;
            }
        }
        Ok(())
    }

    /// Mirrors `TCity::AddPurchasedItems`, whose three source loops cover the
    /// contiguous Cotton-through-Arms range.
    pub fn add_purchased_items(&mut self, amounts: &[i16]) -> Result<(), CityEconomyError> {
        validate_resources("city stock", &self.stock_by_type)?;
        if amounts.len() != ResourceKind::PURCHASED_COUNT {
            return Err(CityEconomyError::InvalidPurchasedItemCount {
                actual: amounts.len(),
            });
        }
        for (stock, amount) in self.stock_by_type.iter_mut().zip(amounts) {
            *stock = stock.wrapping_add(*amount);
        }
        Ok(())
    }

    /// Mirrors the pointer-taking `TCity::AddTransportedItems` overload.
    pub fn add_transported_items(&mut self, amounts: &[i16]) -> Result<(), CityEconomyError> {
        validate_resources("city stock", &self.stock_by_type)?;
        validate_resources("transported items", amounts)?;
        for (stock, amount) in self.stock_by_type.iter_mut().zip(amounts) {
            *stock = stock.wrapping_add(*amount);
        }
        self.clear_precious_metal_stock();
        Ok(())
    }

    /// Mirrors the no-argument `TCity::AddTransportedItems` overload.
    pub fn add_nation_target_items(
        &mut self,
        nation: &MajorNationState,
    ) -> Result<(), CityEconomyError> {
        self.add_transported_items(&nation.need_target_by_type)
    }

    /// Mirrors `TCity::DirectTransport`, including signed-short surplus and
    /// remaining-capacity limits and the target/reservation update.
    pub fn direct_transport(
        &mut self,
        nation: &mut MajorNationState,
        resource: ResourceKind,
        requested: i16,
    ) -> Result<i16, CityEconomyError> {
        validate_resources("city stock", &self.stock_by_type)?;
        validate_resources("current nation needs", &nation.need_current_by_type)?;
        validate_resources("target nation needs", &nation.need_target_by_type)?;

        let index = resource.index();
        let mut amount = requested;
        let surplus =
            nation.need_current_by_type[index].wrapping_sub(nation.need_target_by_type[index]);
        if surplus < amount {
            amount = surplus;
        }
        let available_capacity = nation.capacities[TRANSPORT_CAPACITY_INDEX]
            .wrapping_sub(nation.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX]);
        if available_capacity < amount {
            amount = available_capacity;
        }

        self.stock_by_type[index] = self.stock_by_type[index].wrapping_add(amount);
        nation.need_target_by_type[index] = nation.need_target_by_type[index].wrapping_add(amount);
        nation.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX] =
            nation.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX].wrapping_add(amount);
        Ok(amount)
    }

    /// Mirrors `TCity::GetCitySummaryRecordSlot74` after the population need
    /// vector has been refreshed.
    pub fn refresh_unreserved_city_needs(
        &mut self,
        supported_order_quantity: i16,
    ) -> Result<&[i16], CityEconomyError> {
        validate_resources("city reservations", &self.reserved_by_type)?;
        let summary = self
            .population
            .refresh_predicted_needs(supported_order_quantity)?;
        for (index, reserved) in self.reserved_by_type.iter().copied().enumerate() {
            let remaining = summary[index];
            if remaining != 0 {
                summary[index] = remaining.wrapping_sub(reserved);
                if index == ResourceKind::Livestock.index() {
                    summary[index] = summary[index]
                        .wrapping_sub(self.reserved_by_type[ResourceKind::Fish.index()]);
                }
                if summary[index] < 0 {
                    summary[index] = 0;
                }
            }
        }
        Ok(summary)
    }

    /// Ports the local flag calculation in `TCity::PredictedNeeds`. The
    /// original's subsequent nation-stockpile publication belongs to the event
    /// boundary that will call this method.
    pub fn refresh_local_summary_flags(&mut self) -> Result<(), CityEconomyError> {
        if self.production_accum.len() != PRODUCTION_ACCUM_COUNT {
            return Err(CityEconomyError::InvalidProductionAccumCount {
                actual: self.production_accum.len(),
            });
        }
        self.low_stock = self.population.strength >= 2;
        let mut shortage_count = if self.production_accum[4] > 0 {
            2_i16
        } else {
            3_i16
        };
        if self.production_accum[2] > 0 {
            shortage_count = shortage_count.wrapping_sub(1);
        }
        if self.production_accum[0] > 0 {
            shortage_count = shortage_count.wrapping_sub(1);
        }
        self.low_production = shortage_count < 2;
        Ok(())
    }

    fn clear_precious_metal_stock(&mut self) {
        self.stock_by_type[ResourceKind::Gold.index()] = 0;
        self.stock_by_type[ResourceKind::Gems.index()] = 0;
    }
}

fn validate_resources(field: &'static str, values: &[i16]) -> Result<(), CityEconomyError> {
    if values.len() == ResourceKind::COUNT {
        Ok(())
    } else {
        Err(CityEconomyError::InvalidResourceCount {
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
            production_orders: vec![0; PRODUCTION_ACCUM_COUNT],
            production_accum: vec![0; PRODUCTION_ACCUM_COUNT],
            production_flags: vec![0; PRODUCTION_ACCUM_COUNT],
            production_current: vec![0; PRODUCTION_ACCUM_COUNT],
            production_progress: vec![0; PRODUCTION_ACCUM_COUNT],
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
            diplomacy_policy_by_nation: vec![0; 23],
            diplomacy_grant_by_nation: vec![0; 23],
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
    fn clamps_negative_stocks_and_adds_only_purchased_resource_bands() {
        let mut state = city();
        state.stock_by_type.fill(-1);
        state.verify_stocks().unwrap();
        assert!(state.stock_by_type.iter().all(|stock| *stock == 0));

        let amounts: Vec<i16> = (1..=ResourceKind::PURCHASED_COUNT as i16).collect();
        state.add_purchased_items(&amounts).unwrap();
        assert_eq!(state.stock_by_type[ResourceKind::Cotton.index()], 1);
        assert_eq!(state.stock_by_type[ResourceKind::Arms.index()], 17);
        assert_eq!(state.stock_by_type[ResourceKind::Grain.index()], 0);
        assert_eq!(state.stock_by_type[ResourceKind::Gold.index()], 0);
    }

    #[test]
    fn transported_items_cover_all_resources_then_clear_precious_metals() {
        let mut state = city();
        state.stock_by_type.fill(1);
        state
            .add_transported_items(&[2; ResourceKind::COUNT])
            .unwrap();
        assert_eq!(state.stock_by_type[ResourceKind::Cotton.index()], 3);
        assert_eq!(state.stock_by_type[ResourceKind::Livestock.index()], 3);
        assert_eq!(state.stock_by_type[ResourceKind::Gems.index()], 0);
        assert_eq!(state.stock_by_type[ResourceKind::Gold.index()], 0);
    }

    #[test]
    fn direct_transport_obeys_surplus_then_remaining_capacity() {
        let mut state = city();
        let mut owner = nation();
        let resource = ResourceKind::Steel;
        owner.need_current_by_type[resource.index()] = 10;
        owner.need_target_by_type[resource.index()] = 4;

        assert_eq!(state.direct_transport(&mut owner, resource, 5).unwrap(), 4);
        assert_eq!(state.stock_by_type[resource.index()], 4);
        assert_eq!(owner.need_target_by_type[resource.index()], 8);
        assert_eq!(owner.capacities[RESERVED_TRANSPORT_CAPACITY_INDEX], 15);
    }

    #[test]
    fn nation_target_transport_uses_the_same_full_table_path() {
        let mut state = city();
        let mut owner = nation();
        owner.need_target_by_type.fill(2);
        state.add_nation_target_items(&owner).unwrap();
        assert_eq!(state.stock_by_type[ResourceKind::Cotton.index()], 2);
        assert_eq!(state.stock_by_type[ResourceKind::Livestock.index()], 2);
        assert_eq!(state.stock_by_type[ResourceKind::Gems.index()], 0);
        assert_eq!(state.stock_by_type[ResourceKind::Gold.index()], 0);
    }

    #[test]
    fn city_summary_subtracts_both_animal_food_reservations() {
        let mut state = city();
        state.reserved_by_type[ResourceKind::Grain.index()] = 1;
        state.reserved_by_type[ResourceKind::Fruit.index()] = 3;
        state.reserved_by_type[ResourceKind::Fish.index()] = 1;
        let summary = state.refresh_unreserved_city_needs(0).unwrap();
        assert_eq!(summary[ResourceKind::Grain.index()], 3);
        assert_eq!(summary[ResourceKind::Fruit.index()], 0);
        assert_eq!(summary[ResourceKind::Fish.index()], 0);
        assert_eq!(summary[ResourceKind::Livestock.index()], 0);
    }

    #[test]
    fn refreshes_the_retail_local_summary_flags() {
        let mut state = city();
        state.population.strength = 1;
        state.production_accum[4] = 1;
        state.production_accum[2] = 1;
        state.refresh_local_summary_flags().unwrap();
        assert!(!state.low_stock);
        assert!(state.low_production);

        state.population.strength = 2;
        state.production_accum.fill(0);
        state.refresh_local_summary_flags().unwrap();
        assert!(state.low_stock);
        assert!(!state.low_production);
    }
}
