use crate::{CityState, MajorNationState, ProductionSlot, ResourceKind};
use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionConstraint {
    Resources,
    Workforce,
    Capacity,
    Treasury,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemInputs {
    Double(ResourceKind),
    Both(ResourceKind, ResourceKind),
    Either(ResourceKind, ResourceKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityTarget {
    Production(ProductionSlot),
    Transport,
    RegionalPopulation,
}

impl CapacityTarget {
    pub const fn from_retail_slot(slot: ProductionSlot) -> Self {
        match slot.get() {
            14 => Self::Transport,
            15 => Self::RegionalPopulation,
            _ => Self::Production(slot),
        }
    }

    pub const fn slot(self) -> ProductionSlot {
        match self {
            Self::Production(slot) => slot,
            Self::Transport => ProductionSlot::new(14).expect("retail transport slot is valid"),
            Self::RegionalPopulation => {
                ProductionSlot::new(15).expect("retail population slot is valid")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpansionTarget {
    Production(ProductionSlot),
    RegionalPopulation,
}

impl ExpansionTarget {
    pub const fn from_retail_slot(slot: ProductionSlot) -> Self {
        if slot.get() == 15 {
            Self::RegionalPopulation
        } else {
            Self::Production(slot)
        }
    }

    pub const fn slot(self) -> ProductionSlot {
        match self {
            Self::Production(slot) => slot,
            Self::RegionalPopulation => {
                ProductionSlot::new(15).expect("retail population slot is valid")
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemProductionOrder {
    pub output: ResourceKind,
    pub quantity: i16,
    pub tracking_by_resource: [i16; ResourceKind::COUNT],
    pub reserved_workforce: i16,
    pub limiting_constraint: ProductionConstraint,
    pub accumulated_value: i32,
    pub requested_quantity: i16,
    pub inputs: ItemInputs,
    pub production_slot: ProductionSlot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityProductionOrder {
    pub target: CapacityTarget,
    pub quantity: i16,
    pub tracking_by_resource: [i16; ResourceKind::COUNT],
    pub reserved_workforce: i16,
    pub limiting_constraint: ProductionConstraint,
    pub accumulated_value: i32,
    pub requested_quantity: i16,
    pub primary_input: ResourceKind,
    pub secondary_input: ResourceKind,
    pub production_slot: ProductionSlot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpansionProductionOrder {
    pub target: ExpansionTarget,
    pub quantity: i16,
    pub tracking_by_resource: [i16; ResourceKind::COUNT],
    pub reserved_workforce: i16,
    pub limiting_constraint: ProductionConstraint,
    pub accumulated_value: i32,
    pub requested_quantity: i16,
    pub primary_input: ResourceKind,
    pub secondary_input: ResourceKind,
    pub production_slot: ProductionSlot,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FoodProductionOrder {
    pub quantity: i16,
    pub reserved_workforce: i16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PopulationGrowthOrder {
    pub quantity: i16,
    pub limiting_constraint: ProductionConstraint,
}

impl Default for PopulationGrowthOrder {
    fn default() -> Self {
        Self {
            quantity: 0,
            limiting_constraint: ProductionConstraint::Resources,
        }
    }
}

impl PopulationGrowthOrder {
    pub fn max_order(&mut self, city: &CityState) -> Result<i16, ProductionError> {
        validate_city(city)?;
        let mut limit =
            city.stock_by_type[ResourceKind::Furniture.index()].wrapping_add(self.quantity);
        limit = limit
            .min(city.stock_by_type[ResourceKind::Clothing.index()].wrapping_add(self.quantity));
        limit =
            limit.min(city.stock_by_type[ResourceKind::Food.index()].wrapping_add(self.quantity));
        let capacity_limit = city.production_accum[15].wrapping_add(self.quantity);

        self.limiting_constraint = ProductionConstraint::Resources;
        if capacity_limit < limit {
            self.limiting_constraint = ProductionConstraint::Capacity;
            limit = capacity_limit;
        }
        Ok(limit)
    }

    pub fn set_quantity(
        &mut self,
        city: &mut CityState,
        quantity: i16,
    ) -> Result<bool, ProductionError> {
        validate_city(city)?;
        let delta = quantity.wrapping_sub(self.quantity);
        if quantity > self.max_order(city)? || quantity < 0 {
            return Ok(false);
        }
        self.quantity = quantity;
        city.add_to_stock_and_verify(ResourceKind::Furniture, delta.wrapping_neg());
        city.add_to_stock_and_verify(ResourceKind::Clothing, delta.wrapping_neg());
        city.add_to_stock_and_verify(ResourceKind::Food, delta.wrapping_neg());
        city.production_accum[15] = city.production_accum[15].wrapping_sub(delta);
        Ok(true)
    }

    pub fn produce(
        &mut self,
        city: &mut CityState,
        owner: &MajorNationState,
        owned_region_count: i32,
    ) -> Result<(), ProductionError> {
        validate_city(city)?;
        validate_pending_actions(owner)?;
        if city.population.baseline_labor.is_none() {
            return Err(ProductionError::MissingLaborPool("baseline"));
        }
        if city.population.production_labor.is_none() {
            return Err(ProductionError::MissingLaborPool("production"));
        }
        let baseline = city
            .population
            .baseline_labor
            .as_mut()
            .expect("baseline labor was validated");
        baseline.low = baseline.low.wrapping_add(self.quantity);
        let production = city
            .population
            .production_labor
            .as_mut()
            .expect("production labor was validated");
        production.low = production.low.wrapping_add(self.quantity);
        city.population.count = city.population.count.wrapping_add(self.quantity);

        city.production_accum[15] = retail_region_capacity(owner, owned_region_count);
        self.quantity = 0;
        Ok(())
    }
}

impl FoodProductionOrder {
    pub fn max_order(&self, city: &CityState) -> Result<i16, ProductionError> {
        validate_city(city)?;
        let mut limit = city.stock_by_type[ResourceKind::Grain.index()] / 2;
        let animal_food = city.stock_by_type[ResourceKind::Fish.index()]
            .wrapping_add(city.stock_by_type[ResourceKind::Livestock.index()]);
        let workforce_limit = city.population.strength / 2;
        limit = limit.min(city.stock_by_type[ResourceKind::Fruit.index()]);
        limit = limit.min(animal_food);
        limit = limit.min(workforce_limit);
        Ok(self.quantity.wrapping_add(limit.wrapping_mul(2)))
    }

    pub fn set_quantity(
        &mut self,
        city: &mut CityState,
        mut quantity: i16,
    ) -> Result<bool, ProductionError> {
        validate_city(city)?;
        if quantity & 1 != 0 {
            quantity = quantity.wrapping_add(1);
        }
        let previous_quantity = self.quantity;
        if quantity > self.max_order(city)? || quantity < 0 {
            return Ok(false);
        }
        self.quantity = quantity;

        let half_delta = quantity.wrapping_sub(previous_quantity) / 2;
        city.add_to_stock_and_verify(ResourceKind::Grain, half_delta.wrapping_mul(-2));
        city.add_to_stock_and_verify(ResourceKind::Fruit, half_delta.wrapping_neg());
        city.population.strength = city
            .population
            .strength
            .wrapping_sub(half_delta.wrapping_mul(2));

        let livestock_index = ResourceKind::Livestock.index();
        let livestock = city.stock_by_type[livestock_index];
        if livestock < half_delta {
            city.stock_by_type[livestock_index] = 0;
            let fish_change = half_delta.wrapping_sub(livestock);
            city.add_to_stock_and_verify(ResourceKind::Fish, fish_change.wrapping_neg());
        } else {
            city.add_to_stock_and_verify(ResourceKind::Livestock, half_delta.wrapping_neg());
        }
        Ok(true)
    }

    pub fn produce(&mut self, city: &mut CityState) -> Result<(), ProductionError> {
        validate_city(city)?;
        city.add_to_stock_and_verify(ResourceKind::Food, self.quantity);
        self.quantity = 0;
        self.reserved_workforce = 0;
        Ok(())
    }
}

impl CapacityProductionOrder {
    pub fn new(
        target: CapacityTarget,
        primary_input: ResourceKind,
        secondary_input: ResourceKind,
        production_slot: ProductionSlot,
    ) -> Self {
        Self {
            target,
            quantity: 0,
            tracking_by_resource: [0; ResourceKind::COUNT],
            reserved_workforce: 0,
            limiting_constraint: ProductionConstraint::Resources,
            accumulated_value: 0,
            requested_quantity: 0,
            primary_input,
            secondary_input,
            production_slot,
        }
    }

    pub fn max_order(&mut self, city: &CityState) -> Result<i16, ProductionError> {
        validate_city(city)?;
        let workforce_limit = (city.population.strength / 2).wrapping_add(self.quantity);
        let production_limit =
            city.production_accum[self.production_slot.index()].wrapping_add(self.quantity);
        let primary_index = self.primary_input.index();
        let secondary_index = self.secondary_input.index();
        let resource_limit = self.tracking_by_resource[primary_index]
            .wrapping_add(city.stock_by_type[primary_index])
            .min(
                self.tracking_by_resource[secondary_index]
                    .wrapping_add(city.stock_by_type[secondary_index]),
            );

        self.limiting_constraint = ProductionConstraint::Capacity;
        let mut limit = production_limit;
        if workforce_limit < limit {
            self.limiting_constraint = ProductionConstraint::Workforce;
            limit = workforce_limit;
        }
        if resource_limit < limit {
            self.limiting_constraint = ProductionConstraint::Resources;
            limit = resource_limit;
        }
        Ok(limit)
    }

    pub fn set_quantity(
        &mut self,
        city: &mut CityState,
        quantity: i16,
    ) -> Result<bool, ProductionError> {
        validate_city(city)?;
        let delta = quantity.wrapping_sub(self.quantity);
        if quantity > self.max_order(city)? || quantity < 0 {
            return Ok(false);
        }

        self.quantity = quantity;
        self.requested_quantity = quantity;
        self.apply_input_change(city, self.primary_input, delta);
        self.apply_input_change(city, self.secondary_input, delta);
        let workforce_change = delta.wrapping_mul(2);
        city.population.strength = city.population.strength.wrapping_sub(workforce_change);
        self.reserved_workforce = self.reserved_workforce.wrapping_add(workforce_change);
        let production = &mut city.production_accum[self.production_slot.index()];
        *production = production.wrapping_sub(delta);
        Ok(true)
    }

    pub fn produce(
        &mut self,
        city: &mut CityState,
        owner: &mut MajorNationState,
        owned_region_count: i32,
    ) -> Result<(), ProductionError> {
        if self.quantity == 0 {
            return Ok(());
        }

        match self.target {
            CapacityTarget::Transport => {
                let capacity = owner.transport_capacity_mut();
                *capacity = capacity.wrapping_add(self.quantity);
            }
            CapacityTarget::Production(slot) => {
                validate_city(city)?;
                let base = city.production_orders[slot.index()];
                self.apply_production_increase(city, slot, base);
            }
            CapacityTarget::RegionalPopulation => {
                validate_city(city)?;
                validate_pending_actions(owner)?;
                let base = retail_region_capacity(owner, owned_region_count);
                self.apply_production_increase(city, self.target.slot(), base);
            }
        }

        self.requested_quantity = 0;
        self.quantity = 0;
        self.tracking_by_resource[self.primary_input.index()] = 0;
        self.tracking_by_resource[self.secondary_input.index()] = 0;
        self.reserved_workforce = 0;
        Ok(())
    }

    pub fn restock(&mut self, city: &mut CityState) -> Result<bool, ProductionError> {
        let max_order = self.max_order(city)?;
        let saved_requested_quantity = self.requested_quantity;
        self.quantity = 0;
        if max_order < saved_requested_quantity
            && self.limiting_constraint == ProductionConstraint::Resources
        {
            let accepted = self.set_quantity(city, max_order)?;
            self.requested_quantity = saved_requested_quantity;
            Ok(accepted)
        } else {
            self.set_quantity(city, saved_requested_quantity)
        }
    }

    fn apply_input_change(&mut self, city: &mut CityState, resource: ResourceKind, change: i16) {
        city.add_to_stock_and_verify(resource, change.wrapping_neg());
        let tracking = &mut self.tracking_by_resource[resource.index()];
        *tracking = tracking.wrapping_add(change);
    }

    fn apply_production_increase(&self, city: &mut CityState, slot: ProductionSlot, base: i16) {
        let index = slot.index();
        let new_value = base.wrapping_add(self.quantity);
        let delta = new_value.wrapping_sub(city.production_orders[index]);
        city.production_accum[index] = city.production_accum[index].wrapping_add(delta);
        city.production_orders[index] = new_value;
    }
}

impl ExpansionProductionOrder {
    pub fn new(
        target: ExpansionTarget,
        primary_input: ResourceKind,
        secondary_input: ResourceKind,
        production_slot: ProductionSlot,
    ) -> Self {
        Self {
            target,
            quantity: 0,
            tracking_by_resource: [0; ResourceKind::COUNT],
            reserved_workforce: 0,
            limiting_constraint: ProductionConstraint::Resources,
            accumulated_value: 0,
            requested_quantity: 0,
            primary_input,
            secondary_input,
            production_slot,
        }
    }

    pub fn max_order(&self, city: &CityState) -> Result<i16, ProductionError> {
        validate_city(city)?;
        let primary_index = self.primary_input.index();
        let secondary_index = self.secondary_input.index();
        Ok(self.tracking_by_resource[primary_index]
            .wrapping_add(city.stock_by_type[primary_index])
            .min(
                self.tracking_by_resource[secondary_index]
                    .wrapping_add(city.stock_by_type[secondary_index]),
            ))
    }

    pub fn set_quantity(
        &mut self,
        city: &mut CityState,
        quantity: i16,
    ) -> Result<bool, ProductionError> {
        validate_city(city)?;
        let delta = quantity.wrapping_sub(self.quantity);
        if quantity > self.max_order(city)? || quantity < 0 {
            return Ok(false);
        }

        self.quantity = quantity;
        self.requested_quantity = quantity;
        self.apply_input_change(city, self.primary_input, delta);
        self.apply_input_change(city, self.secondary_input, delta);
        Ok(true)
    }

    pub fn produce(
        &mut self,
        city: &mut CityState,
        owner: &MajorNationState,
        owned_region_count: i32,
    ) -> Result<(), ProductionError> {
        if self.quantity == 0 {
            return Ok(());
        }
        validate_city(city)?;

        let (slot, base) = match self.target {
            ExpansionTarget::Production(slot) => (slot, city.production_orders[slot.index()]),
            ExpansionTarget::RegionalPopulation => {
                validate_pending_actions(owner)?;
                (
                    self.target.slot(),
                    retail_region_capacity(owner, owned_region_count),
                )
            }
        };
        let index = slot.index();
        let new_value = base.wrapping_add(self.quantity);
        let delta = new_value.wrapping_sub(city.production_orders[index]);
        city.production_accum[index] = city.production_accum[index].wrapping_add(delta);
        city.production_orders[index] = new_value;

        self.requested_quantity = 0;
        self.quantity = 0;
        self.tracking_by_resource[self.primary_input.index()] = 0;
        self.tracking_by_resource[self.secondary_input.index()] = 0;
        Ok(())
    }

    pub fn restock(&mut self, city: &mut CityState) -> Result<bool, ProductionError> {
        let max_order = self.max_order(city)?;
        let saved_requested_quantity = self.requested_quantity;
        self.quantity = 0;
        if max_order < saved_requested_quantity
            && self.limiting_constraint == ProductionConstraint::Resources
        {
            let accepted = self.set_quantity(city, max_order)?;
            self.requested_quantity = saved_requested_quantity;
            Ok(accepted)
        } else {
            self.set_quantity(city, saved_requested_quantity)
        }
    }

    fn apply_input_change(&mut self, city: &mut CityState, resource: ResourceKind, change: i16) {
        city.add_to_stock_and_verify(resource, change.wrapping_neg());
        let tracking = &mut self.tracking_by_resource[resource.index()];
        *tracking = tracking.wrapping_add(change);
    }
}

impl ItemProductionOrder {
    pub fn new(output: ResourceKind, inputs: ItemInputs, production_slot: ProductionSlot) -> Self {
        Self {
            output,
            quantity: 0,
            tracking_by_resource: [0; ResourceKind::COUNT],
            reserved_workforce: 0,
            limiting_constraint: ProductionConstraint::Resources,
            accumulated_value: 0,
            requested_quantity: 0,
            inputs,
            production_slot,
        }
    }

    pub fn max_order(&mut self, city: &CityState) -> Result<i16, ProductionError> {
        validate_city(city)?;
        let workforce_limit = (city.population.strength / 2).wrapping_add(self.quantity);
        let production_limit =
            city.production_accum[self.production_slot.index()].wrapping_add(self.quantity);
        let resource_limit = match self.inputs {
            ItemInputs::Double(primary) => {
                let index = primary.index();
                self.tracking_by_resource[index].wrapping_add(city.stock_by_type[index]) / 2
            }
            ItemInputs::Both(primary, secondary) => {
                let primary_index = primary.index();
                let secondary_index = secondary.index();
                let primary_limit = self.tracking_by_resource[primary_index]
                    .wrapping_add(city.stock_by_type[primary_index]);
                let secondary_limit = self.tracking_by_resource[secondary_index]
                    .wrapping_add(city.stock_by_type[secondary_index]);
                primary_limit.min(secondary_limit)
            }
            ItemInputs::Either(primary, secondary) => {
                let primary_index = primary.index();
                let secondary_index = secondary.index();
                self.tracking_by_resource[secondary_index]
                    .wrapping_add(self.tracking_by_resource[primary_index])
                    .wrapping_add(city.stock_by_type[secondary_index])
                    .wrapping_add(city.stock_by_type[primary_index])
                    / 2
            }
        };

        self.limiting_constraint = ProductionConstraint::Capacity;
        let mut limit = production_limit;
        if workforce_limit < limit {
            self.limiting_constraint = ProductionConstraint::Workforce;
            limit = workforce_limit;
        }
        if resource_limit < limit {
            self.limiting_constraint = ProductionConstraint::Resources;
            limit = resource_limit;
        }
        Ok(limit)
    }

    pub fn set_quantity(
        &mut self,
        city: &mut CityState,
        quantity: i16,
    ) -> Result<bool, ProductionError> {
        validate_city(city)?;
        let delta = quantity.wrapping_sub(self.quantity);
        if quantity > self.max_order(city)? || quantity < 0 {
            return Ok(false);
        }

        self.quantity = quantity;
        self.requested_quantity = quantity;
        match self.inputs {
            ItemInputs::Double(primary) => {
                self.apply_input_change(city, primary, delta.wrapping_mul(2));
            }
            ItemInputs::Both(primary, secondary) => {
                self.apply_input_change(city, primary, delta);
                self.apply_input_change(city, secondary, delta);
            }
            ItemInputs::Either(primary, secondary) => {
                let (mut primary_change, mut secondary_change) = if delta > 0 {
                    (delta, delta)
                } else {
                    let release = delta.wrapping_neg();
                    (release, release)
                };
                let primary_available = if delta > 0 {
                    city.stock_by_type[primary.index()]
                } else {
                    self.tracking_by_resource[primary.index()]
                };
                let secondary_available = if delta > 0 {
                    city.stock_by_type[secondary.index()]
                } else {
                    self.tracking_by_resource[secondary.index()]
                };

                if primary_available < primary_change {
                    let shortfall = primary_change.wrapping_sub(primary_available);
                    primary_change = primary_change.wrapping_sub(shortfall);
                    secondary_change = secondary_change.wrapping_add(shortfall);
                } else if secondary_available < secondary_change {
                    let shortfall = secondary_change.wrapping_sub(secondary_available);
                    secondary_change = secondary_change.wrapping_sub(shortfall);
                    primary_change = primary_change.wrapping_add(shortfall);
                }
                if delta < 0 {
                    primary_change = primary_change.wrapping_neg();
                    secondary_change = secondary_change.wrapping_neg();
                }
                self.apply_input_change(city, primary, primary_change);
                self.apply_input_change(city, secondary, secondary_change);
            }
        }

        let workforce_change = delta.wrapping_mul(2);
        city.population.strength = city.population.strength.wrapping_sub(workforce_change);
        self.reserved_workforce = self.reserved_workforce.wrapping_add(workforce_change);
        let production = &mut city.production_accum[self.production_slot.index()];
        *production = production.wrapping_sub(delta);
        Ok(true)
    }

    pub fn produce(&mut self, city: &mut CityState) -> Result<(), ProductionError> {
        validate_city(city)?;
        let production = &mut city.production_accum[self.production_slot.index()];
        *production = production.wrapping_add(self.quantity);
        city.add_to_stock_and_verify(self.output, self.quantity);
        city.rolling_item_production_score = city
            .rolling_item_production_score
            .wrapping_add(i32::from(self.quantity));
        match self.inputs {
            ItemInputs::Double(primary) => {
                self.tracking_by_resource[primary.index()] = 0;
            }
            ItemInputs::Both(primary, secondary) | ItemInputs::Either(primary, secondary) => {
                self.tracking_by_resource[primary.index()] = 0;
                self.tracking_by_resource[secondary.index()] = 0;
            }
        }
        self.reserved_workforce = 0;
        self.accumulated_value = self
            .accumulated_value
            .wrapping_add(i32::from(self.quantity));
        Ok(())
    }

    pub fn restock(&mut self, city: &mut CityState) -> Result<bool, ProductionError> {
        let max_order = self.max_order(city)?;
        let saved_requested_quantity = self.requested_quantity;
        self.quantity = 0;
        if max_order < saved_requested_quantity
            && self.limiting_constraint == ProductionConstraint::Resources
        {
            let accepted = self.set_quantity(city, max_order)?;
            self.requested_quantity = saved_requested_quantity;
            Ok(accepted)
        } else {
            self.set_quantity(city, saved_requested_quantity)
        }
    }

    fn apply_input_change(&mut self, city: &mut CityState, resource: ResourceKind, change: i16) {
        city.add_to_stock_and_verify(resource, change.wrapping_neg());
        let tracking = &mut self.tracking_by_resource[resource.index()];
        *tracking = tracking.wrapping_add(change);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionError {
    InvalidResourceCount { actual: usize },
    InvalidProductionCount { field: &'static str, actual: usize },
    InvalidPendingActionCount { actual: usize },
    MissingLaborPool(&'static str),
}

impl fmt::Display for ProductionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidResourceCount { actual } => write!(
                formatter,
                "city stock has {actual} entries, expected {}",
                ResourceKind::COUNT
            ),
            Self::InvalidProductionCount { field, actual } => write!(
                formatter,
                "{field} has {actual} entries, expected {}",
                ProductionSlot::COUNT
            ),
            Self::InvalidPendingActionCount { actual } => write!(
                formatter,
                "pending nation actions have {actual} entries, expected at least 10"
            ),
            Self::MissingLaborPool(name) => write!(formatter, "city has no {name} labor pool"),
        }
    }
}

impl Error for ProductionError {}

fn validate_city(city: &CityState) -> Result<(), ProductionError> {
    if city.stock_by_type.len() != ResourceKind::COUNT {
        return Err(ProductionError::InvalidResourceCount {
            actual: city.stock_by_type.len(),
        });
    }
    if city.production_orders.len() != ProductionSlot::COUNT {
        return Err(ProductionError::InvalidProductionCount {
            field: "city production orders",
            actual: city.production_orders.len(),
        });
    }
    if city.production_accum.len() != ProductionSlot::COUNT {
        return Err(ProductionError::InvalidProductionCount {
            field: "city production accumulation",
            actual: city.production_accum.len(),
        });
    }
    Ok(())
}

fn retail_region_capacity(owner: &MajorNationState, owned_region_count: i32) -> i16 {
    let divisor = if owner.pending_action_status[9] >= b'3' as i8 {
        3
    } else {
        4
    };
    let capacity = owned_region_count / divisor;
    if capacity > 1 { capacity as i16 } else { 1 }
}

fn validate_pending_actions(owner: &MajorNationState) -> Result<(), ProductionError> {
    if owner.pending_action_status.len() >= 10 {
        Ok(())
    } else {
        Err(ProductionError::InvalidPendingActionCount {
            actual: owner.pending_action_status.len(),
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
            production_orders: vec![0; ProductionSlot::COUNT],
            production_accum: vec![0; ProductionSlot::COUNT],
            production_flags: vec![0; ProductionSlot::COUNT],
            production_current: vec![0; ProductionSlot::COUNT],
            production_progress: vec![0; ProductionSlot::COUNT],
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: vec![0; ResourceKind::COUNT],
            consumed_production_input_by_type: vec![0; ResourceKind::COUNT],
            population: PopulationState {
                count: 7,
                count_float_bits: 7.0_f32.to_bits(),
                strength: 10,
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
            capacities: [0; 4],
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
            pending_action_status: vec![0; 13],
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

    fn order(inputs: ItemInputs) -> ItemProductionOrder {
        ItemProductionOrder::new(ResourceKind::Steel, inputs, ProductionSlot::new(3).unwrap())
    }

    #[test]
    fn max_order_records_capacity_workforce_and_resource_constraints() {
        let mut state = city();
        let mut production = order(ItemInputs::Double(ResourceKind::Iron));
        state.production_accum[3] = 4;
        state.stock_by_type[ResourceKind::Iron.index()] = 20;
        assert_eq!(production.max_order(&state).unwrap(), 4);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Capacity
        );

        state.production_accum[3] = 20;
        assert_eq!(production.max_order(&state).unwrap(), 5);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Workforce
        );

        state.population.strength = 30;
        state.stock_by_type[ResourceKind::Iron.index()] = 8;
        assert_eq!(production.max_order(&state).unwrap(), 4);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Resources
        );

        let mut two_input = order(ItemInputs::Both(ResourceKind::Iron, ResourceKind::Coal));
        state.stock_by_type[ResourceKind::Iron.index()] = 9;
        state.stock_by_type[ResourceKind::Coal.index()] = 3;
        assert_eq!(two_input.max_order(&state).unwrap(), 3);
        assert_eq!(
            two_input.limiting_constraint,
            ProductionConstraint::Resources
        );
    }

    #[test]
    fn set_quantity_reserves_and_releases_inputs_workforce_and_capacity() {
        let mut state = city();
        let mut production = order(ItemInputs::Both(ResourceKind::Iron, ResourceKind::Coal));
        state.production_accum[3] = 10;
        state.stock_by_type[ResourceKind::Iron.index()] = 5;
        state.stock_by_type[ResourceKind::Coal.index()] = 4;

        assert!(production.set_quantity(&mut state, 3).unwrap());
        assert_eq!(state.stock_by_type[ResourceKind::Iron.index()], 2);
        assert_eq!(state.stock_by_type[ResourceKind::Coal.index()], 1);
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Iron.index()],
            3
        );
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Coal.index()],
            3
        );
        assert_eq!(state.population.strength, 4);
        assert_eq!(production.reserved_workforce, 6);
        assert_eq!(state.production_accum[3], 7);

        assert!(production.set_quantity(&mut state, 1).unwrap());
        assert_eq!(state.stock_by_type[ResourceKind::Iron.index()], 4);
        assert_eq!(state.stock_by_type[ResourceKind::Coal.index()], 3);
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Iron.index()],
            1
        );
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Coal.index()],
            1
        );
        assert_eq!(state.population.strength, 8);
        assert_eq!(production.reserved_workforce, 2);
        assert_eq!(state.production_accum[3], 9);
    }

    #[test]
    fn rejected_quantity_keeps_reservations_unchanged() {
        let mut state = city();
        let mut production = order(ItemInputs::Double(ResourceKind::Iron));
        state.production_accum[3] = 1;
        state.stock_by_type[ResourceKind::Iron.index()] = 20;
        assert!(!production.set_quantity(&mut state, 2).unwrap());
        assert_eq!(production.quantity, 0);
        assert_eq!(state.stock_by_type[ResourceKind::Iron.index()], 20);
        assert_eq!(state.population.strength, 10);
        assert_eq!(state.production_accum[3], 1);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Capacity
        );
    }

    #[test]
    fn produce_restores_capacity_creates_output_and_clears_reservations() {
        let mut state = city();
        let mut production = order(ItemInputs::Both(ResourceKind::Iron, ResourceKind::Coal));
        state.production_accum[3] = 10;
        state.stock_by_type[ResourceKind::Iron.index()] = 5;
        state.stock_by_type[ResourceKind::Coal.index()] = 4;
        production.set_quantity(&mut state, 1).unwrap();

        production.produce(&mut state).unwrap();
        assert_eq!(state.production_accum[3], 10);
        assert_eq!(state.stock_by_type[ResourceKind::Steel.index()], 1);
        assert_eq!(state.rolling_item_production_score, 1);
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Iron.index()],
            0
        );
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Coal.index()],
            0
        );
        assert_eq!(production.reserved_workforce, 0);
        assert_eq!(production.accumulated_value, 1);
    }

    #[test]
    fn resource_limited_restock_preserves_the_requested_quantity() {
        let mut state = city();
        let mut production = order(ItemInputs::Double(ResourceKind::Iron));
        production.quantity = 5;
        production.requested_quantity = 5;
        state.population.strength = 20;
        state.production_accum[3] = 5;
        state.stock_by_type[ResourceKind::Iron.index()] = 4;

        assert!(production.restock(&mut state).unwrap());
        assert_eq!(production.quantity, 2);
        assert_eq!(production.requested_quantity, 5);
        assert_eq!(state.stock_by_type[ResourceKind::Iron.index()], 0);
        assert_eq!(state.population.strength, 16);
        assert_eq!(state.production_accum[3], 3);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Resources
        );
    }

    #[test]
    fn either_inputs_shift_shortfalls_and_reverse_the_tracked_split() {
        let mut state = city();
        let mut production = order(ItemInputs::Either(ResourceKind::Iron, ResourceKind::Coal));
        state.population.strength = 20;
        state.production_accum[3] = 10;
        state.stock_by_type[ResourceKind::Iron.index()] = 1;
        state.stock_by_type[ResourceKind::Coal.index()] = 10;

        assert_eq!(production.max_order(&state).unwrap(), 5);
        assert!(production.set_quantity(&mut state, 3).unwrap());
        assert_eq!(state.stock_by_type[ResourceKind::Iron.index()], 0);
        assert_eq!(state.stock_by_type[ResourceKind::Coal.index()], 5);
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Iron.index()],
            1
        );
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Coal.index()],
            5
        );

        assert!(production.set_quantity(&mut state, 1).unwrap());
        assert_eq!(state.stock_by_type[ResourceKind::Iron.index()], 1);
        assert_eq!(state.stock_by_type[ResourceKind::Coal.index()], 8);
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Iron.index()],
            0
        );
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Coal.index()],
            2
        );
        assert_eq!(state.population.strength, 18);
        assert_eq!(production.reserved_workforce, 2);
        assert_eq!(state.production_accum[3], 9);

        production.produce(&mut state).unwrap();
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Coal.index()],
            0
        );
        assert_eq!(production.reserved_workforce, 0);
    }

    #[test]
    fn either_inputs_shift_a_secondary_shortfall_to_the_primary_input() {
        let mut state = city();
        let mut production = order(ItemInputs::Either(ResourceKind::Iron, ResourceKind::Coal));
        state.population.strength = 20;
        state.production_accum[3] = 10;
        state.stock_by_type[ResourceKind::Iron.index()] = 10;
        state.stock_by_type[ResourceKind::Coal.index()] = 1;

        assert!(production.set_quantity(&mut state, 3).unwrap());
        assert_eq!(state.stock_by_type[ResourceKind::Iron.index()], 5);
        assert_eq!(state.stock_by_type[ResourceKind::Coal.index()], 0);
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Iron.index()],
            5
        );
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Coal.index()],
            1
        );
    }

    #[test]
    fn food_processing_limit_uses_grain_fruit_animals_and_workforce() {
        let mut state = city();
        let production = FoodProductionOrder::default();
        state.stock_by_type[ResourceKind::Grain.index()] = 10;
        state.stock_by_type[ResourceKind::Fruit.index()] = 4;
        state.stock_by_type[ResourceKind::Fish.index()] = 1;
        state.stock_by_type[ResourceKind::Livestock.index()] = 2;
        state.population.strength = 10;
        assert_eq!(production.max_order(&state).unwrap(), 6);
    }

    #[test]
    fn food_processing_rounds_even_and_consumes_livestock_before_fish() {
        let mut state = city();
        let mut production = FoodProductionOrder::default();
        state.stock_by_type[ResourceKind::Grain.index()] = 10;
        state.stock_by_type[ResourceKind::Fruit.index()] = 5;
        state.stock_by_type[ResourceKind::Fish.index()] = 3;
        state.stock_by_type[ResourceKind::Livestock.index()] = 1;
        state.population.strength = 10;

        assert!(production.set_quantity(&mut state, 3).unwrap());
        assert_eq!(production.quantity, 4);
        assert_eq!(state.stock_by_type[ResourceKind::Grain.index()], 6);
        assert_eq!(state.stock_by_type[ResourceKind::Fruit.index()], 3);
        assert_eq!(state.stock_by_type[ResourceKind::Livestock.index()], 0);
        assert_eq!(state.stock_by_type[ResourceKind::Fish.index()], 2);
        assert_eq!(state.population.strength, 6);

        assert!(production.set_quantity(&mut state, 1).unwrap());
        assert_eq!(production.quantity, 2);
        assert_eq!(state.stock_by_type[ResourceKind::Grain.index()], 8);
        assert_eq!(state.stock_by_type[ResourceKind::Fruit.index()], 4);
        assert_eq!(state.stock_by_type[ResourceKind::Livestock.index()], 1);
        assert_eq!(state.stock_by_type[ResourceKind::Fish.index()], 2);
        assert_eq!(state.population.strength, 8);
    }

    #[test]
    fn food_processing_accepts_minus_one_as_zero_after_retail_rounding() {
        let mut state = city();
        let mut production = FoodProductionOrder::default();
        assert!(production.set_quantity(&mut state, -1).unwrap());
        assert_eq!(production.quantity, 0);
        assert_eq!(state.population.strength, 10);
    }

    #[test]
    fn food_processing_produces_canned_food_and_clears_the_order() {
        let mut state = city();
        let mut production = FoodProductionOrder {
            quantity: 4,
            reserved_workforce: 7,
        };
        production.produce(&mut state).unwrap();
        assert_eq!(state.stock_by_type[ResourceKind::Food.index()], 4);
        assert_eq!(production.quantity, 0);
        assert_eq!(production.reserved_workforce, 0);
    }

    #[test]
    fn population_growth_selects_resource_then_capacity_limits() {
        let mut state = city();
        let mut production = PopulationGrowthOrder::default();
        state.stock_by_type[ResourceKind::Furniture.index()] = 3;
        state.stock_by_type[ResourceKind::Clothing.index()] = 2;
        state.stock_by_type[ResourceKind::Food.index()] = 4;
        state.production_accum[15] = 10;
        assert_eq!(production.max_order(&state).unwrap(), 2);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Resources
        );

        state.production_accum[15] = 1;
        assert_eq!(production.max_order(&state).unwrap(), 1);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Capacity
        );
    }

    #[test]
    fn population_growth_quantity_reserves_and_refunds_all_inputs() {
        let mut state = city();
        let mut production = PopulationGrowthOrder::default();
        state.stock_by_type[ResourceKind::Furniture.index()] = 3;
        state.stock_by_type[ResourceKind::Clothing.index()] = 3;
        state.stock_by_type[ResourceKind::Food.index()] = 3;
        state.production_accum[15] = 3;

        assert!(production.set_quantity(&mut state, 2).unwrap());
        assert_eq!(state.stock_by_type[ResourceKind::Furniture.index()], 1);
        assert_eq!(state.stock_by_type[ResourceKind::Clothing.index()], 1);
        assert_eq!(state.stock_by_type[ResourceKind::Food.index()], 1);
        assert_eq!(state.production_accum[15], 1);

        assert!(production.set_quantity(&mut state, 1).unwrap());
        assert_eq!(state.stock_by_type[ResourceKind::Furniture.index()], 2);
        assert_eq!(state.stock_by_type[ResourceKind::Clothing.index()], 2);
        assert_eq!(state.stock_by_type[ResourceKind::Food.index()], 2);
        assert_eq!(state.production_accum[15], 2);
    }

    #[test]
    fn population_growth_produces_low_skill_population_and_refreshes_capacity() {
        let mut state = city();
        let mut owner = nation();
        let mut production = PopulationGrowthOrder {
            quantity: 2,
            limiting_constraint: ProductionConstraint::Resources,
        };
        owner.pending_action_status[9] = b'3' as i8;
        let float_count = state.population.count_float_bits;

        production.produce(&mut state, &owner, 12).unwrap();
        assert_eq!(state.population.baseline_labor.unwrap().low, 6);
        assert_eq!(state.population.production_labor.unwrap().low, 6);
        assert_eq!(state.population.count, 9);
        assert_eq!(state.population.count_float_bits, float_count);
        assert_eq!(state.production_accum[15], 4);
        assert_eq!(production.quantity, 0);
    }

    fn capacity_order(target: CapacityTarget) -> CapacityProductionOrder {
        CapacityProductionOrder::new(
            target,
            ResourceKind::Lumber,
            ResourceKind::Steel,
            ProductionSlot::new(14).unwrap(),
        )
    }

    fn expansion_order(target: ExpansionTarget) -> ExpansionProductionOrder {
        ExpansionProductionOrder::new(
            target,
            ResourceKind::Lumber,
            ResourceKind::Steel,
            ProductionSlot::new(14).unwrap(),
        )
    }

    #[test]
    fn capacity_order_uses_item_reservations_then_expands_a_production_slot() {
        let mut state = city();
        let mut production =
            capacity_order(CapacityTarget::Production(ProductionSlot::new(3).unwrap()));
        state.stock_by_type[ResourceKind::Lumber.index()] = 5;
        state.stock_by_type[ResourceKind::Steel.index()] = 4;
        state.production_accum[14] = 10;
        state.production_orders[3] = 6;

        assert!(production.set_quantity(&mut state, 2).unwrap());
        assert_eq!(state.population.strength, 6);
        assert_eq!(state.production_accum[14], 8);
        production.produce(&mut state, &mut nation(), 0).unwrap();

        assert_eq!(state.production_orders[3], 8);
        assert_eq!(state.production_accum[3], 2);
        assert_eq!(production.quantity, 0);
        assert_eq!(production.requested_quantity, 0);
        assert_eq!(production.reserved_workforce, 0);
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Lumber.index()],
            0
        );
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Steel.index()],
            0
        );
    }

    #[test]
    fn capacity_order_transport_target_increases_the_nation_capacity() {
        let mut state = city();
        let mut owner = nation();
        let mut production = capacity_order(CapacityTarget::Transport);
        production.quantity = 3;
        production.requested_quantity = 3;
        production.reserved_workforce = 6;
        production.tracking_by_resource[ResourceKind::Lumber.index()] = 3;
        production.tracking_by_resource[ResourceKind::Steel.index()] = 3;
        owner.capacities[2] = i16::MAX;

        production.produce(&mut state, &mut owner, 0).unwrap();
        assert_eq!(owner.capacities[2], i16::MIN.wrapping_add(2));
        assert_eq!(state.production_orders, vec![0; ProductionSlot::COUNT]);
        assert_eq!(production.quantity, 0);
        assert_eq!(production.reserved_workforce, 0);
    }

    #[test]
    fn capacity_order_region_target_rebases_before_adding_the_order() {
        let mut state = city();
        let mut owner = nation();
        let mut production = capacity_order(CapacityTarget::RegionalPopulation);
        production.quantity = 2;
        owner.pending_action_status[9] = b'3' as i8;
        state.production_orders[15] = 1;
        state.production_accum[15] = 3;

        production.produce(&mut state, &mut owner, 12).unwrap();
        assert_eq!(state.production_orders[15], 6);
        assert_eq!(state.production_accum[15], 8);
    }

    #[test]
    fn expansion_order_reserves_only_its_two_material_inputs() {
        let mut state = city();
        let mut production =
            expansion_order(ExpansionTarget::Production(ProductionSlot::new(2).unwrap()));
        state.stock_by_type[ResourceKind::Lumber.index()] = 3;
        state.stock_by_type[ResourceKind::Steel.index()] = 2;
        state.production_accum[14] = 9;

        assert_eq!(production.max_order(&state).unwrap(), 2);
        assert!(production.set_quantity(&mut state, 2).unwrap());
        assert_eq!(state.stock_by_type[ResourceKind::Lumber.index()], 1);
        assert_eq!(state.stock_by_type[ResourceKind::Steel.index()], 0);
        assert_eq!(state.population.strength, 10);
        assert_eq!(state.production_accum[14], 9);
        assert_eq!(production.reserved_workforce, 0);

        assert!(production.set_quantity(&mut state, 1).unwrap());
        assert_eq!(state.stock_by_type[ResourceKind::Lumber.index()], 2);
        assert_eq!(state.stock_by_type[ResourceKind::Steel.index()], 1);
    }

    #[test]
    fn expansion_production_keeps_the_unused_inherited_workforce_field() {
        let mut state = city();
        let owner = nation();
        let mut production =
            expansion_order(ExpansionTarget::Production(ProductionSlot::new(2).unwrap()));
        state.production_orders[2] = 4;
        state.production_accum[2] = 7;
        production.quantity = 2;
        production.requested_quantity = 2;
        production.reserved_workforce = 9;
        production.tracking_by_resource[ResourceKind::Lumber.index()] = 2;
        production.tracking_by_resource[ResourceKind::Steel.index()] = 2;

        production.produce(&mut state, &owner, 0).unwrap();
        assert_eq!(state.production_orders[2], 6);
        assert_eq!(state.production_accum[2], 9);
        assert_eq!(production.quantity, 0);
        assert_eq!(production.requested_quantity, 0);
        assert_eq!(production.reserved_workforce, 9);
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Lumber.index()],
            0
        );
        assert_eq!(
            production.tracking_by_resource[ResourceKind::Steel.index()],
            0
        );
    }

    #[test]
    fn expansion_region_target_uses_the_retail_region_divisor() {
        let mut state = city();
        let mut owner = nation();
        let mut production = expansion_order(ExpansionTarget::RegionalPopulation);
        production.quantity = 1;
        owner.pending_action_status[9] = b'2' as i8;
        state.production_orders[15] = 8;
        state.production_accum[15] = 10;

        production.produce(&mut state, &owner, 12).unwrap();
        assert_eq!(state.production_orders[15], 4);
        assert_eq!(state.production_accum[15], 6);
    }

    #[test]
    fn zero_capacity_and_expansion_orders_do_not_touch_any_state() {
        let mut state = city();
        let mut owner = nation();
        let mut capacity = capacity_order(CapacityTarget::RegionalPopulation);
        let mut expansion = expansion_order(ExpansionTarget::RegionalPopulation);
        capacity.requested_quantity = 4;
        capacity.reserved_workforce = 7;
        expansion.requested_quantity = 5;
        expansion.reserved_workforce = 8;
        owner.pending_action_status.clear();
        state.production_orders.clear();
        state.production_accum.clear();
        let expected_state = state.clone();
        let expected_owner = owner.clone();
        let expected_capacity = capacity.clone();
        let expected_expansion = expansion.clone();

        capacity.produce(&mut state, &mut owner, 20).unwrap();
        expansion.produce(&mut state, &owner, 20).unwrap();
        assert_eq!(state, expected_state);
        assert_eq!(owner, expected_owner);
        assert_eq!(capacity, expected_capacity);
        assert_eq!(expansion, expected_expansion);
    }
}
