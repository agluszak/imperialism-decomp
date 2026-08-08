use crate::{
    CityState, MajorNationState, PendingActionKind, PopulationError, ProductionSlot, ResourceKind,
    ResourceTable, SkillBand,
};

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
            Self::Transport => ProductionSlot::TRANSPORT,
            Self::RegionalPopulation => ProductionSlot::REGIONAL_POPULATION,
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
            Self::RegionalPopulation => ProductionSlot::REGIONAL_POPULATION,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemProductionOrder {
    pub output: ResourceKind,
    pub quantity: i16,
    pub tracking_by_resource: ResourceTable<i16>,
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
    pub tracking_by_resource: ResourceTable<i16>,
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
    pub tracking_by_resource: ResourceTable<i16>,
    pub reserved_workforce: i16,
    pub limiting_constraint: ProductionConstraint,
    pub accumulated_value: i32,
    pub requested_quantity: i16,
    pub primary_input: ResourceKind,
    pub secondary_input: ResourceKind,
    pub production_slot: ProductionSlot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PowerPlantProductionOrder {
    pub quantity: i16,
    pub tracking_by_resource: ResourceTable<i16>,
    pub reserved_workforce: i16,
    pub limiting_constraint: ProductionConstraint,
    pub accumulated_value: i32,
    pub desired_quantity: i16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrainingLevel {
    Medium,
    High,
}

impl TrainingLevel {
    const fn input_band(self) -> SkillBand {
        match self {
            Self::Medium => SkillBand::Low,
            Self::High => SkillBand::Medium,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrainingProductionOrder {
    pub level: TrainingLevel,
    pub quantity: i16,
    pub tracking_by_resource: ResourceTable<i16>,
    pub reserved_workforce: i16,
    pub limiting_constraint: ProductionConstraint,
    pub accumulated_value: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceCost {
    pub resource: ResourceKind,
    pub per_unit: i16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnitCostProfile {
    pub entry_id: i16,
    pub primary: ResourceCost,
    pub secondary: Option<ResourceCost>,
    pub cash_per_unit: i16,
    pub workforce: Option<SkillBand>,
    pub specialist: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitProductionOrder {
    pub profile: UnitCostProfile,
    pub quantity: i16,
    pub tracking_by_resource: ResourceTable<i16>,
    pub reserved_workforce: i16,
    pub limiting_constraint: ProductionConstraint,
    pub accumulated_value: i32,
}

impl UnitProductionOrder {
    pub fn new(profile: UnitCostProfile) -> Self {
        Self {
            profile,
            quantity: 0,
            tracking_by_resource: ResourceTable::default(),
            reserved_workforce: 0,
            limiting_constraint: ProductionConstraint::Resources,
            accumulated_value: 0,
        }
    }
}

impl TrainingProductionOrder {
    pub fn new(level: TrainingLevel) -> Self {
        Self {
            level,
            quantity: 0,
            tracking_by_resource: ResourceTable::default(),
            reserved_workforce: 0,
            limiting_constraint: ProductionConstraint::Resources,
            accumulated_value: 0,
        }
    }
}

impl Default for PowerPlantProductionOrder {
    fn default() -> Self {
        Self {
            quantity: 0,
            tracking_by_resource: ResourceTable::default(),
            reserved_workforce: 0,
            limiting_constraint: ProductionConstraint::Resources,
            accumulated_value: 0,
            desired_quantity: 0,
        }
    }
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
    pub fn max_order(&mut self, city: &CityState) -> i16 {
        let mut limit = city.stock_by_type[ResourceKind::Furniture].wrapping_add(self.quantity);
        limit = limit.min(city.stock_by_type[ResourceKind::Clothing].wrapping_add(self.quantity));
        limit = limit.min(city.stock_by_type[ResourceKind::Food].wrapping_add(self.quantity));
        let capacity_limit =
            city.production_accum[ProductionSlot::REGIONAL_POPULATION].wrapping_add(self.quantity);

        self.limiting_constraint = ProductionConstraint::Resources;
        if capacity_limit < limit {
            self.limiting_constraint = ProductionConstraint::Capacity;
            limit = capacity_limit;
        }
        limit
    }

    pub fn set_quantity(&mut self, city: &mut CityState, quantity: i16) -> bool {
        let delta = quantity.wrapping_sub(self.quantity);
        if quantity > self.max_order(city) || quantity < 0 {
            return false;
        }
        self.quantity = quantity;
        city.add_to_stock_and_verify(ResourceKind::Furniture, delta.wrapping_neg());
        city.add_to_stock_and_verify(ResourceKind::Clothing, delta.wrapping_neg());
        city.add_to_stock_and_verify(ResourceKind::Food, delta.wrapping_neg());
        city.production_accum[ProductionSlot::REGIONAL_POPULATION] =
            city.production_accum[ProductionSlot::REGIONAL_POPULATION].wrapping_sub(delta);
        true
    }

    pub fn produce(
        &mut self,
        city: &mut CityState,
        owner: &MajorNationState,
        owned_region_count: i32,
    ) -> Result<(), ProductionError> {
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

        city.production_accum[ProductionSlot::REGIONAL_POPULATION] =
            retail_region_capacity(owner, owned_region_count);
        self.quantity = 0;
        Ok(())
    }
}

impl FoodProductionOrder {
    pub fn max_order(&self, city: &CityState) -> i16 {
        let mut limit = city.stock_by_type[ResourceKind::Grain] / 2;
        let animal_food = city.stock_by_type[ResourceKind::Fish]
            .wrapping_add(city.stock_by_type[ResourceKind::Livestock]);
        let workforce_limit = city.population.strength / 2;
        limit = limit.min(city.stock_by_type[ResourceKind::Fruit]);
        limit = limit.min(animal_food);
        limit = limit.min(workforce_limit);
        self.quantity.wrapping_add(limit.wrapping_mul(2))
    }

    pub fn set_quantity(&mut self, city: &mut CityState, mut quantity: i16) -> bool {
        if quantity & 1 != 0 {
            quantity = quantity.wrapping_add(1);
        }
        let previous_quantity = self.quantity;
        if quantity > self.max_order(city) || quantity < 0 {
            return false;
        }
        self.quantity = quantity;

        let half_delta = quantity.wrapping_sub(previous_quantity) / 2;
        city.add_to_stock_and_verify(ResourceKind::Grain, half_delta.wrapping_mul(-2));
        city.add_to_stock_and_verify(ResourceKind::Fruit, half_delta.wrapping_neg());
        city.population.strength = city
            .population
            .strength
            .wrapping_sub(half_delta.wrapping_mul(2));

        let livestock_index = ResourceKind::Livestock;
        let livestock = city.stock_by_type[livestock_index];
        if livestock < half_delta {
            city.stock_by_type[livestock_index] = 0;
            let fish_change = half_delta.wrapping_sub(livestock);
            city.add_to_stock_and_verify(ResourceKind::Fish, fish_change.wrapping_neg());
        } else {
            city.add_to_stock_and_verify(ResourceKind::Livestock, half_delta.wrapping_neg());
        }
        true
    }

    pub fn produce(&mut self, city: &mut CityState) {
        city.add_to_stock_and_verify(ResourceKind::Food, self.quantity);
        self.quantity = 0;
        self.reserved_workforce = 0;
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
            tracking_by_resource: ResourceTable::default(),
            reserved_workforce: 0,
            limiting_constraint: ProductionConstraint::Resources,
            accumulated_value: 0,
            requested_quantity: 0,
            primary_input,
            secondary_input,
            production_slot,
        }
    }

    pub fn max_order(&mut self, city: &CityState) -> i16 {
        let workforce_limit = (city.population.strength / 2).wrapping_add(self.quantity);
        let production_limit =
            city.production_accum[self.production_slot].wrapping_add(self.quantity);
        let resource_limit = self.tracking_by_resource[self.primary_input]
            .wrapping_add(city.stock_by_type[self.primary_input])
            .min(
                self.tracking_by_resource[self.secondary_input]
                    .wrapping_add(city.stock_by_type[self.secondary_input]),
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
        limit
    }

    pub fn set_quantity(&mut self, city: &mut CityState, quantity: i16) -> bool {
        let delta = quantity.wrapping_sub(self.quantity);
        if quantity > self.max_order(city) || quantity < 0 {
            return false;
        }

        self.quantity = quantity;
        self.requested_quantity = quantity;
        self.apply_input_change(city, self.primary_input, delta);
        self.apply_input_change(city, self.secondary_input, delta);
        let workforce_change = delta.wrapping_mul(2);
        city.population.strength = city.population.strength.wrapping_sub(workforce_change);
        self.reserved_workforce = self.reserved_workforce.wrapping_add(workforce_change);
        let production = &mut city.production_accum[self.production_slot];
        *production = production.wrapping_sub(delta);
        true
    }

    pub fn produce(
        &mut self,
        city: &mut CityState,
        owner: &mut MajorNationState,
        owned_region_count: i32,
    ) {
        if self.quantity == 0 {
            return;
        }

        match self.target {
            CapacityTarget::Transport => {
                let capacity = owner.transport_capacity_mut();
                *capacity = capacity.wrapping_add(self.quantity);
            }
            CapacityTarget::Production(slot) => {
                let base = city.production_orders[slot];
                self.apply_production_increase(city, slot, base);
            }
            CapacityTarget::RegionalPopulation => {
                let base = retail_region_capacity(owner, owned_region_count);
                self.apply_production_increase(city, self.target.slot(), base);
            }
        }

        self.requested_quantity = 0;
        self.quantity = 0;
        self.tracking_by_resource[self.primary_input] = 0;
        self.tracking_by_resource[self.secondary_input] = 0;
        self.reserved_workforce = 0;
    }

    pub fn restock(&mut self, city: &mut CityState) -> bool {
        let max_order = self.max_order(city);
        let saved_requested_quantity = self.requested_quantity;
        self.quantity = 0;
        if max_order < saved_requested_quantity
            && self.limiting_constraint == ProductionConstraint::Resources
        {
            let accepted = self.set_quantity(city, max_order);
            self.requested_quantity = saved_requested_quantity;
            accepted
        } else {
            self.set_quantity(city, saved_requested_quantity)
        }
    }

    fn apply_input_change(&mut self, city: &mut CityState, resource: ResourceKind, change: i16) {
        city.add_to_stock_and_verify(resource, change.wrapping_neg());
        let tracking = &mut self.tracking_by_resource[resource];
        *tracking = tracking.wrapping_add(change);
    }

    fn apply_production_increase(&self, city: &mut CityState, slot: ProductionSlot, base: i16) {
        let new_value = base.wrapping_add(self.quantity);
        let delta = new_value.wrapping_sub(city.production_orders[slot]);
        city.production_accum[slot] = city.production_accum[slot].wrapping_add(delta);
        city.production_orders[slot] = new_value;
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
            tracking_by_resource: ResourceTable::default(),
            reserved_workforce: 0,
            limiting_constraint: ProductionConstraint::Resources,
            accumulated_value: 0,
            requested_quantity: 0,
            primary_input,
            secondary_input,
            production_slot,
        }
    }

    pub fn max_order(&self, city: &CityState) -> i16 {
        self.tracking_by_resource[self.primary_input]
            .wrapping_add(city.stock_by_type[self.primary_input])
            .min(
                self.tracking_by_resource[self.secondary_input]
                    .wrapping_add(city.stock_by_type[self.secondary_input]),
            )
    }

    pub fn set_quantity(&mut self, city: &mut CityState, quantity: i16) -> bool {
        let delta = quantity.wrapping_sub(self.quantity);
        if quantity > self.max_order(city) || quantity < 0 {
            return false;
        }

        self.quantity = quantity;
        self.requested_quantity = quantity;
        self.apply_input_change(city, self.primary_input, delta);
        self.apply_input_change(city, self.secondary_input, delta);
        true
    }

    pub fn produce(
        &mut self,
        city: &mut CityState,
        owner: &MajorNationState,
        owned_region_count: i32,
    ) {
        if self.quantity == 0 {
            return;
        }

        let (slot, base) = match self.target {
            ExpansionTarget::Production(slot) => (slot, city.production_orders[slot]),
            ExpansionTarget::RegionalPopulation => (
                self.target.slot(),
                retail_region_capacity(owner, owned_region_count),
            ),
        };
        let new_value = base.wrapping_add(self.quantity);
        let delta = new_value.wrapping_sub(city.production_orders[slot]);
        city.production_accum[slot] = city.production_accum[slot].wrapping_add(delta);
        city.production_orders[slot] = new_value;

        self.requested_quantity = 0;
        self.quantity = 0;
        self.tracking_by_resource[self.primary_input] = 0;
        self.tracking_by_resource[self.secondary_input] = 0;
    }

    pub fn restock(&mut self, city: &mut CityState) -> bool {
        let max_order = self.max_order(city);
        let saved_requested_quantity = self.requested_quantity;
        self.quantity = 0;
        if max_order < saved_requested_quantity
            && self.limiting_constraint == ProductionConstraint::Resources
        {
            let accepted = self.set_quantity(city, max_order);
            self.requested_quantity = saved_requested_quantity;
            accepted
        } else {
            self.set_quantity(city, saved_requested_quantity)
        }
    }

    fn apply_input_change(&mut self, city: &mut CityState, resource: ResourceKind, change: i16) {
        city.add_to_stock_and_verify(resource, change.wrapping_neg());
        let tracking = &mut self.tracking_by_resource[resource];
        *tracking = tracking.wrapping_add(change);
    }
}

impl PowerPlantProductionOrder {
    pub fn max_order(&self, city: &CityState) -> i16 {
        self.quantity
            .wrapping_add(city.stock_by_type[ResourceKind::Fuel].wrapping_mul(6))
    }

    pub fn set_quantity(&mut self, city: &mut CityState, quantity: i16) -> bool {
        let delta = quantity.wrapping_sub(self.quantity);
        if quantity > self.max_order(city) || quantity < 0 {
            return false;
        }
        self.quantity = quantity;

        if i32::from(city.population.strength) < -i32::from(delta) {
            self.quantity = self.quantity.wrapping_sub(delta);
            return false;
        }

        self.desired_quantity = quantity;
        city.add_to_stock_and_verify(ResourceKind::Fuel, -(delta / 6));
        let previous_power = city.population.extra;
        city.power_available = quantity;
        city.population.extra = quantity;
        let power_change = quantity.wrapping_sub(previous_power);
        city.population.strength = city.population.strength.wrapping_add(power_change);
        true
    }

    pub const fn produce(&self) {}

    pub fn restock(&mut self, city: &mut CityState) -> bool {
        let max_order = self.max_order(city);
        let saved_desired_quantity = self.desired_quantity;
        self.quantity = 0;
        if max_order < saved_desired_quantity {
            let accepted = self.set_quantity(city, max_order);
            self.desired_quantity = saved_desired_quantity;
            accepted
        } else {
            self.set_quantity(city, saved_desired_quantity)
        }
    }
}

impl TrainingProductionOrder {
    pub fn max_order(
        &mut self,
        city: &CityState,
        owner: &MajorNationState,
        treasury: i32,
    ) -> Result<i16, ProductionError> {
        let production = city
            .population
            .production_labor
            .as_ref()
            .ok_or(ProductionError::MissingLaborPool("production"))?;
        let (paper_per_unit, cash_per_unit, workforce_limit) = match self.level {
            TrainingLevel::Medium => (1_i16, 100_i32, production.low.min(city.population.strength)),
            TrainingLevel::High => (
                2_i16,
                1_000_i32,
                production.medium.min(city.population.strength / 2),
            ),
        };

        let cash_limit = if !owner.diplomacy_eligible {
            workforce_limit
        } else {
            let available = treasury.wrapping_add(owner.diplomacy_budget_base / 100);
            let available = if available <= 0 { 0 } else { available };
            let limit = (available / cash_per_unit) as i16;
            if limit < 0 { 0 } else { limit }
        };
        let paper_limit = city.stock_by_type[ResourceKind::Paper] / paper_per_unit;

        self.limiting_constraint = ProductionConstraint::Workforce;
        let mut limit = workforce_limit;
        if cash_limit < limit {
            self.limiting_constraint = ProductionConstraint::Treasury;
            limit = cash_limit;
        }
        if paper_limit < limit {
            self.limiting_constraint = ProductionConstraint::Resources;
            limit = paper_limit;
        }
        if i32::from(self.quantity) + i32::from(limit) > 99 {
            limit = 99_i16.wrapping_sub(self.quantity);
        }
        Ok(self.quantity.wrapping_add(limit))
    }

    pub fn set_quantity(
        &mut self,
        city: &mut CityState,
        owner: &MajorNationState,
        treasury: &mut i32,
        quantity: i16,
    ) -> Result<bool, ProductionError> {
        let delta = quantity.wrapping_sub(self.quantity);
        if quantity > self.max_order(city, owner, *treasury)? || quantity < 0 {
            return Ok(false);
        }
        self.quantity = quantity;

        let (paper_change, cash_change) = match self.level {
            TrainingLevel::Medium => (delta, i32::from(delta).wrapping_mul(100)),
            TrainingLevel::High => (delta.wrapping_mul(2), i32::from(delta).wrapping_mul(1_000)),
        };
        city.add_to_stock_and_verify(ResourceKind::Paper, paper_change.wrapping_neg());
        *treasury = treasury.wrapping_sub(cash_change);
        city.population
            .make_unavailable(self.level.input_band(), delta)?;
        Ok(true)
    }

    pub fn produce(
        &mut self,
        city: &mut CityState,
        owner: &mut MajorNationState,
    ) -> Result<(), ProductionError> {
        if self.quantity == 0 {
            return Ok(());
        }
        let baseline = city
            .population
            .baseline_labor
            .as_mut()
            .ok_or(ProductionError::MissingLaborPool("baseline"))?;

        match self.level {
            TrainingLevel::Medium => {
                baseline.low = baseline.low.wrapping_sub(self.quantity);
                baseline.medium = baseline.medium.wrapping_add(self.quantity);
            }
            TrainingLevel::High => {
                let new_level = i32::from(baseline.high) + i32::from(self.quantity);
                if new_level >= 10 {
                    let payload = if owner.pending_action_status
                        [PendingActionKind::UniversityExpansion]
                        < b'2' as i8
                    {
                        Some(2)
                    } else if new_level >= 30
                        && owner.pending_action_status[PendingActionKind::UniversityExpansion]
                            <= b'3' as i8
                    {
                        Some(3)
                    } else {
                        None
                    };
                    if let Some(payload) = payload {
                        set_pending_action(owner, PendingActionKind::UniversityExpansion, payload);
                    }
                }
                baseline.medium = baseline.medium.wrapping_sub(self.quantity);
                baseline.high = baseline.high.wrapping_add(self.quantity);
            }
        }
        self.quantity = 0;
        Ok(())
    }

    pub const fn restock(&self) {}
}

impl UnitProductionOrder {
    pub fn max_order(
        &mut self,
        city: &CityState,
        owner: &MajorNationState,
        treasury: i32,
    ) -> Result<i16, ProductionError> {
        validate_unit_resource_cost(self.profile.primary)?;
        if let Some(secondary) = self.profile.secondary {
            validate_unit_resource_cost(secondary)?;
        }

        let workforce_limit = if let Some(band) = self.profile.workforce {
            if city.population.baseline_labor.is_none() {
                return Err(ProductionError::MissingLaborPool("baseline"));
            }
            let production = city
                .population
                .production_labor
                .as_ref()
                .ok_or(ProductionError::MissingLaborPool("production"))?;
            let (available, divisor) = match band {
                SkillBand::Low => (production.low, 1),
                SkillBand::Medium => (production.medium, 2),
                SkillBand::High => (production.high, 4),
            };
            available.min(city.population.strength / divisor)
        } else {
            9_999
        };

        let primary_limit =
            city.stock_by_type[self.profile.primary.resource] / self.profile.primary.per_unit;
        let secondary_limit = if let Some(secondary) = self.profile.secondary {
            city.stock_by_type[secondary.resource] / secondary.per_unit
        } else {
            primary_limit
        };
        let cash_limit = if self.profile.cash_per_unit != 0 && owner.diplomacy_eligible {
            let limit = (owner.available_diplomacy_budget(treasury)
                / i32::from(self.profile.cash_per_unit)) as i16;
            if limit < 0 { 0 } else { limit }
        } else {
            primary_limit
        };

        self.limiting_constraint = ProductionConstraint::Workforce;
        let mut limit = workforce_limit;
        if primary_limit < limit {
            self.limiting_constraint = ProductionConstraint::Resources;
            limit = primary_limit;
        }
        if secondary_limit < limit {
            self.limiting_constraint = ProductionConstraint::Resources;
            limit = secondary_limit;
        }
        if cash_limit < limit {
            self.limiting_constraint = ProductionConstraint::Treasury;
            limit = cash_limit;
        }
        Ok(self.quantity.wrapping_add(limit))
    }

    pub fn set_quantity(
        &mut self,
        city: &mut CityState,
        owner: &MajorNationState,
        treasury: &mut i32,
        quantity: i16,
    ) -> Result<bool, ProductionError> {
        let delta = quantity.wrapping_sub(self.quantity);
        if quantity > self.max_order(city, owner, *treasury)? || quantity < 0 {
            return Ok(false);
        }
        self.quantity = quantity;

        apply_resource_cost(city, self.profile.primary, delta);
        if let Some(secondary) = self.profile.secondary {
            apply_resource_cost(city, secondary, delta);
        }
        if let Some(workforce) = self.profile.workforce {
            city.population.remove_population(workforce, delta)?;
        }
        let cash_change = i32::from(self.profile.cash_per_unit).wrapping_mul(i32::from(delta));
        *treasury = treasury.wrapping_sub(cash_change);
        Ok(true)
    }
}

impl ItemProductionOrder {
    pub fn new(output: ResourceKind, inputs: ItemInputs, production_slot: ProductionSlot) -> Self {
        Self {
            output,
            quantity: 0,
            tracking_by_resource: ResourceTable::default(),
            reserved_workforce: 0,
            limiting_constraint: ProductionConstraint::Resources,
            accumulated_value: 0,
            requested_quantity: 0,
            inputs,
            production_slot,
        }
    }

    pub fn max_order(&mut self, city: &CityState) -> i16 {
        let workforce_limit = (city.population.strength / 2).wrapping_add(self.quantity);
        let production_limit =
            city.production_accum[self.production_slot].wrapping_add(self.quantity);
        let resource_limit = match self.inputs {
            ItemInputs::Double(primary) => {
                let index = primary;
                self.tracking_by_resource[index].wrapping_add(city.stock_by_type[index]) / 2
            }
            ItemInputs::Both(primary, secondary) => {
                let primary_index = primary;
                let secondary_index = secondary;
                let primary_limit = self.tracking_by_resource[primary_index]
                    .wrapping_add(city.stock_by_type[primary_index]);
                let secondary_limit = self.tracking_by_resource[secondary_index]
                    .wrapping_add(city.stock_by_type[secondary_index]);
                primary_limit.min(secondary_limit)
            }
            ItemInputs::Either(primary, secondary) => {
                let primary_index = primary;
                let secondary_index = secondary;
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
        limit
    }

    pub fn set_quantity(&mut self, city: &mut CityState, quantity: i16) -> bool {
        let delta = quantity.wrapping_sub(self.quantity);
        if quantity > self.max_order(city) || quantity < 0 {
            return false;
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
                    city.stock_by_type[primary]
                } else {
                    self.tracking_by_resource[primary]
                };
                let secondary_available = if delta > 0 {
                    city.stock_by_type[secondary]
                } else {
                    self.tracking_by_resource[secondary]
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
        let production = &mut city.production_accum[self.production_slot];
        *production = production.wrapping_sub(delta);
        true
    }

    pub fn produce(&mut self, city: &mut CityState) {
        let production = &mut city.production_accum[self.production_slot];
        *production = production.wrapping_add(self.quantity);
        city.add_to_stock_and_verify(self.output, self.quantity);
        city.rolling_item_production_score = city
            .rolling_item_production_score
            .wrapping_add(i32::from(self.quantity));
        match self.inputs {
            ItemInputs::Double(primary) => {
                self.tracking_by_resource[primary] = 0;
            }
            ItemInputs::Both(primary, secondary) | ItemInputs::Either(primary, secondary) => {
                self.tracking_by_resource[primary] = 0;
                self.tracking_by_resource[secondary] = 0;
            }
        }
        self.reserved_workforce = 0;
        self.accumulated_value = self
            .accumulated_value
            .wrapping_add(i32::from(self.quantity));
    }

    pub fn restock(&mut self, city: &mut CityState) -> bool {
        let max_order = self.max_order(city);
        let saved_requested_quantity = self.requested_quantity;
        self.quantity = 0;
        if max_order < saved_requested_quantity
            && self.limiting_constraint == ProductionConstraint::Resources
        {
            let accepted = self.set_quantity(city, max_order);
            self.requested_quantity = saved_requested_quantity;
            accepted
        } else {
            self.set_quantity(city, saved_requested_quantity)
        }
    }

    fn apply_input_change(&mut self, city: &mut CityState, resource: ResourceKind, change: i16) {
        city.add_to_stock_and_verify(resource, change.wrapping_neg());
        let tracking = &mut self.tracking_by_resource[resource];
        *tracking = tracking.wrapping_add(change);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProductionError {
    #[error("city has no {0} labor pool")]
    MissingLaborPool(&'static str),
    #[error("unit resource cost for {resource:?} is zero")]
    ZeroUnitResourceCost { resource: ResourceKind },
    #[error(transparent)]
    Population(#[from] PopulationError),
}

fn retail_region_capacity(owner: &MajorNationState, owned_region_count: i32) -> i16 {
    let divisor = if owner.pending_action_status
        [PendingActionKind::AnnexedGreatPowerCapitalExpansion]
        >= b'3' as i8
    {
        3
    } else {
        4
    };
    let capacity = owned_region_count / divisor;
    if capacity > 1 { capacity as i16 } else { 1 }
}

fn validate_unit_resource_cost(cost: ResourceCost) -> Result<(), ProductionError> {
    if cost.per_unit == 0 {
        Err(ProductionError::ZeroUnitResourceCost {
            resource: cost.resource,
        })
    } else {
        Ok(())
    }
}

fn apply_resource_cost(city: &mut CityState, cost: ResourceCost, quantity: i16) {
    let change = cost.per_unit.wrapping_mul(quantity);
    city.add_to_stock_and_verify(cost.resource, change.wrapping_neg());
}

fn set_pending_action(owner: &mut MajorNationState, action: PendingActionKind, payload: i16) {
    owner.pending_action_status[action] = b'2' as i8;
    owner.pending_action_payload_by_action[action] = payload;
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
                strength: 10,
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
            capacities: [0; 4],
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

    fn order(inputs: ItemInputs) -> ItemProductionOrder {
        ItemProductionOrder::new(ResourceKind::Steel, inputs, ProductionSlot::new(3).unwrap())
    }

    #[test]
    fn max_order_records_capacity_workforce_and_resource_constraints() {
        let mut state = city();
        let mut production = order(ItemInputs::Double(ResourceKind::Iron));
        state.production_accum[slot(3)] = 4;
        state.stock_by_type[ResourceKind::Iron] = 20;
        assert_eq!(production.max_order(&state), 4);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Capacity
        );

        state.production_accum[slot(3)] = 20;
        assert_eq!(production.max_order(&state), 5);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Workforce
        );

        state.population.strength = 30;
        state.stock_by_type[ResourceKind::Iron] = 8;
        assert_eq!(production.max_order(&state), 4);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Resources
        );

        let mut two_input = order(ItemInputs::Both(ResourceKind::Iron, ResourceKind::Coal));
        state.stock_by_type[ResourceKind::Iron] = 9;
        state.stock_by_type[ResourceKind::Coal] = 3;
        assert_eq!(two_input.max_order(&state), 3);
        assert_eq!(
            two_input.limiting_constraint,
            ProductionConstraint::Resources
        );
    }

    #[test]
    fn set_quantity_reserves_and_releases_inputs_workforce_and_capacity() {
        let mut state = city();
        let mut production = order(ItemInputs::Both(ResourceKind::Iron, ResourceKind::Coal));
        state.production_accum[slot(3)] = 10;
        state.stock_by_type[ResourceKind::Iron] = 5;
        state.stock_by_type[ResourceKind::Coal] = 4;

        assert!(production.set_quantity(&mut state, 3));
        assert_eq!(state.stock_by_type[ResourceKind::Iron], 2);
        assert_eq!(state.stock_by_type[ResourceKind::Coal], 1);
        assert_eq!(production.tracking_by_resource[ResourceKind::Iron], 3);
        assert_eq!(production.tracking_by_resource[ResourceKind::Coal], 3);
        assert_eq!(state.population.strength, 4);
        assert_eq!(production.reserved_workforce, 6);
        assert_eq!(state.production_accum[slot(3)], 7);

        assert!(production.set_quantity(&mut state, 1));
        assert_eq!(state.stock_by_type[ResourceKind::Iron], 4);
        assert_eq!(state.stock_by_type[ResourceKind::Coal], 3);
        assert_eq!(production.tracking_by_resource[ResourceKind::Iron], 1);
        assert_eq!(production.tracking_by_resource[ResourceKind::Coal], 1);
        assert_eq!(state.population.strength, 8);
        assert_eq!(production.reserved_workforce, 2);
        assert_eq!(state.production_accum[slot(3)], 9);
    }

    #[test]
    fn rejected_quantity_keeps_reservations_unchanged() {
        let mut state = city();
        let mut production = order(ItemInputs::Double(ResourceKind::Iron));
        state.production_accum[slot(3)] = 1;
        state.stock_by_type[ResourceKind::Iron] = 20;
        assert!(!production.set_quantity(&mut state, 2));
        assert_eq!(production.quantity, 0);
        assert_eq!(state.stock_by_type[ResourceKind::Iron], 20);
        assert_eq!(state.population.strength, 10);
        assert_eq!(state.production_accum[slot(3)], 1);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Capacity
        );
    }

    #[test]
    fn produce_restores_capacity_creates_output_and_clears_reservations() {
        let mut state = city();
        let mut production = order(ItemInputs::Both(ResourceKind::Iron, ResourceKind::Coal));
        state.production_accum[slot(3)] = 10;
        state.stock_by_type[ResourceKind::Iron] = 5;
        state.stock_by_type[ResourceKind::Coal] = 4;
        production.set_quantity(&mut state, 1);

        production.produce(&mut state);
        assert_eq!(state.production_accum[slot(3)], 10);
        assert_eq!(state.stock_by_type[ResourceKind::Steel], 1);
        assert_eq!(state.rolling_item_production_score, 1);
        assert_eq!(production.tracking_by_resource[ResourceKind::Iron], 0);
        assert_eq!(production.tracking_by_resource[ResourceKind::Coal], 0);
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
        state.production_accum[slot(3)] = 5;
        state.stock_by_type[ResourceKind::Iron] = 4;

        assert!(production.restock(&mut state));
        assert_eq!(production.quantity, 2);
        assert_eq!(production.requested_quantity, 5);
        assert_eq!(state.stock_by_type[ResourceKind::Iron], 0);
        assert_eq!(state.population.strength, 16);
        assert_eq!(state.production_accum[slot(3)], 3);
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
        state.production_accum[slot(3)] = 10;
        state.stock_by_type[ResourceKind::Iron] = 1;
        state.stock_by_type[ResourceKind::Coal] = 10;

        assert_eq!(production.max_order(&state), 5);
        assert!(production.set_quantity(&mut state, 3));
        assert_eq!(state.stock_by_type[ResourceKind::Iron], 0);
        assert_eq!(state.stock_by_type[ResourceKind::Coal], 5);
        assert_eq!(production.tracking_by_resource[ResourceKind::Iron], 1);
        assert_eq!(production.tracking_by_resource[ResourceKind::Coal], 5);

        assert!(production.set_quantity(&mut state, 1));
        assert_eq!(state.stock_by_type[ResourceKind::Iron], 1);
        assert_eq!(state.stock_by_type[ResourceKind::Coal], 8);
        assert_eq!(production.tracking_by_resource[ResourceKind::Iron], 0);
        assert_eq!(production.tracking_by_resource[ResourceKind::Coal], 2);
        assert_eq!(state.population.strength, 18);
        assert_eq!(production.reserved_workforce, 2);
        assert_eq!(state.production_accum[slot(3)], 9);

        production.produce(&mut state);
        assert_eq!(production.tracking_by_resource[ResourceKind::Coal], 0);
        assert_eq!(production.reserved_workforce, 0);
    }

    #[test]
    fn either_inputs_shift_a_secondary_shortfall_to_the_primary_input() {
        let mut state = city();
        let mut production = order(ItemInputs::Either(ResourceKind::Iron, ResourceKind::Coal));
        state.population.strength = 20;
        state.production_accum[slot(3)] = 10;
        state.stock_by_type[ResourceKind::Iron] = 10;
        state.stock_by_type[ResourceKind::Coal] = 1;

        assert!(production.set_quantity(&mut state, 3));
        assert_eq!(state.stock_by_type[ResourceKind::Iron], 5);
        assert_eq!(state.stock_by_type[ResourceKind::Coal], 0);
        assert_eq!(production.tracking_by_resource[ResourceKind::Iron], 5);
        assert_eq!(production.tracking_by_resource[ResourceKind::Coal], 1);
    }

    #[test]
    fn food_processing_limit_uses_grain_fruit_animals_and_workforce() {
        let mut state = city();
        let production = FoodProductionOrder::default();
        state.stock_by_type[ResourceKind::Grain] = 10;
        state.stock_by_type[ResourceKind::Fruit] = 4;
        state.stock_by_type[ResourceKind::Fish] = 1;
        state.stock_by_type[ResourceKind::Livestock] = 2;
        state.population.strength = 10;
        assert_eq!(production.max_order(&state), 6);
    }

    #[test]
    fn food_processing_rounds_even_and_consumes_livestock_before_fish() {
        let mut state = city();
        let mut production = FoodProductionOrder::default();
        state.stock_by_type[ResourceKind::Grain] = 10;
        state.stock_by_type[ResourceKind::Fruit] = 5;
        state.stock_by_type[ResourceKind::Fish] = 3;
        state.stock_by_type[ResourceKind::Livestock] = 1;
        state.population.strength = 10;

        assert!(production.set_quantity(&mut state, 3));
        assert_eq!(production.quantity, 4);
        assert_eq!(state.stock_by_type[ResourceKind::Grain], 6);
        assert_eq!(state.stock_by_type[ResourceKind::Fruit], 3);
        assert_eq!(state.stock_by_type[ResourceKind::Livestock], 0);
        assert_eq!(state.stock_by_type[ResourceKind::Fish], 2);
        assert_eq!(state.population.strength, 6);

        assert!(production.set_quantity(&mut state, 1));
        assert_eq!(production.quantity, 2);
        assert_eq!(state.stock_by_type[ResourceKind::Grain], 8);
        assert_eq!(state.stock_by_type[ResourceKind::Fruit], 4);
        assert_eq!(state.stock_by_type[ResourceKind::Livestock], 1);
        assert_eq!(state.stock_by_type[ResourceKind::Fish], 2);
        assert_eq!(state.population.strength, 8);
    }

    #[test]
    fn food_processing_accepts_minus_one_as_zero_after_retail_rounding() {
        let mut state = city();
        let mut production = FoodProductionOrder::default();
        assert!(production.set_quantity(&mut state, -1));
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
        production.produce(&mut state);
        assert_eq!(state.stock_by_type[ResourceKind::Food], 4);
        assert_eq!(production.quantity, 0);
        assert_eq!(production.reserved_workforce, 0);
    }

    #[test]
    fn population_growth_selects_resource_then_capacity_limits() {
        let mut state = city();
        let mut production = PopulationGrowthOrder::default();
        state.stock_by_type[ResourceKind::Furniture] = 3;
        state.stock_by_type[ResourceKind::Clothing] = 2;
        state.stock_by_type[ResourceKind::Food] = 4;
        state.production_accum[slot(15)] = 10;
        assert_eq!(production.max_order(&state), 2);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Resources
        );

        state.production_accum[slot(15)] = 1;
        assert_eq!(production.max_order(&state), 1);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Capacity
        );
    }

    #[test]
    fn population_growth_quantity_reserves_and_refunds_all_inputs() {
        let mut state = city();
        let mut production = PopulationGrowthOrder::default();
        state.stock_by_type[ResourceKind::Furniture] = 3;
        state.stock_by_type[ResourceKind::Clothing] = 3;
        state.stock_by_type[ResourceKind::Food] = 3;
        state.production_accum[slot(15)] = 3;

        assert!(production.set_quantity(&mut state, 2));
        assert_eq!(state.stock_by_type[ResourceKind::Furniture], 1);
        assert_eq!(state.stock_by_type[ResourceKind::Clothing], 1);
        assert_eq!(state.stock_by_type[ResourceKind::Food], 1);
        assert_eq!(state.production_accum[slot(15)], 1);

        assert!(production.set_quantity(&mut state, 1));
        assert_eq!(state.stock_by_type[ResourceKind::Furniture], 2);
        assert_eq!(state.stock_by_type[ResourceKind::Clothing], 2);
        assert_eq!(state.stock_by_type[ResourceKind::Food], 2);
        assert_eq!(state.production_accum[slot(15)], 2);
    }

    #[test]
    fn population_growth_produces_low_skill_population_and_refreshes_capacity() {
        let mut state = city();
        let mut owner = nation();
        let mut production = PopulationGrowthOrder {
            quantity: 2,
            limiting_constraint: ProductionConstraint::Resources,
        };
        owner.pending_action_status[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
            b'3' as i8;
        let float_count = state.population.count_float_bits;

        production.produce(&mut state, &owner, 12).unwrap();
        assert_eq!(state.population.baseline_labor.unwrap().low, 6);
        assert_eq!(state.population.production_labor.unwrap().low, 6);
        assert_eq!(state.population.count, 9);
        assert_eq!(state.population.count_float_bits, float_count);
        assert_eq!(state.production_accum[slot(15)], 4);
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
        state.stock_by_type[ResourceKind::Lumber] = 5;
        state.stock_by_type[ResourceKind::Steel] = 4;
        state.production_accum[slot(14)] = 10;
        state.production_orders[slot(3)] = 6;

        assert!(production.set_quantity(&mut state, 2));
        assert_eq!(state.population.strength, 6);
        assert_eq!(state.production_accum[slot(14)], 8);
        production.produce(&mut state, &mut nation(), 0);

        assert_eq!(state.production_orders[slot(3)], 8);
        assert_eq!(state.production_accum[slot(3)], 2);
        assert_eq!(production.quantity, 0);
        assert_eq!(production.requested_quantity, 0);
        assert_eq!(production.reserved_workforce, 0);
        assert_eq!(production.tracking_by_resource[ResourceKind::Lumber], 0);
        assert_eq!(production.tracking_by_resource[ResourceKind::Steel], 0);
    }

    #[test]
    fn capacity_order_transport_target_increases_the_nation_capacity() {
        let mut state = city();
        let mut owner = nation();
        let mut production = capacity_order(CapacityTarget::Transport);
        production.quantity = 3;
        production.requested_quantity = 3;
        production.reserved_workforce = 6;
        production.tracking_by_resource[ResourceKind::Lumber] = 3;
        production.tracking_by_resource[ResourceKind::Steel] = 3;
        owner.capacities[2] = i16::MAX;

        production.produce(&mut state, &mut owner, 0);
        assert_eq!(owner.capacities[2], i16::MIN.wrapping_add(2));
        assert_eq!(state.production_orders, crate::ProductionTable::default());
        assert_eq!(production.quantity, 0);
        assert_eq!(production.reserved_workforce, 0);
    }

    #[test]
    fn capacity_order_region_target_rebases_before_adding_the_order() {
        let mut state = city();
        let mut owner = nation();
        let mut production = capacity_order(CapacityTarget::RegionalPopulation);
        production.quantity = 2;
        owner.pending_action_status[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
            b'3' as i8;
        state.production_orders[slot(15)] = 1;
        state.production_accum[slot(15)] = 3;

        production.produce(&mut state, &mut owner, 12);
        assert_eq!(state.production_orders[slot(15)], 6);
        assert_eq!(state.production_accum[slot(15)], 8);
    }

    #[test]
    fn expansion_order_reserves_only_its_two_material_inputs() {
        let mut state = city();
        let mut production =
            expansion_order(ExpansionTarget::Production(ProductionSlot::new(2).unwrap()));
        state.stock_by_type[ResourceKind::Lumber] = 3;
        state.stock_by_type[ResourceKind::Steel] = 2;
        state.production_accum[slot(14)] = 9;

        assert_eq!(production.max_order(&state), 2);
        assert!(production.set_quantity(&mut state, 2));
        assert_eq!(state.stock_by_type[ResourceKind::Lumber], 1);
        assert_eq!(state.stock_by_type[ResourceKind::Steel], 0);
        assert_eq!(state.population.strength, 10);
        assert_eq!(state.production_accum[slot(14)], 9);
        assert_eq!(production.reserved_workforce, 0);

        assert!(production.set_quantity(&mut state, 1));
        assert_eq!(state.stock_by_type[ResourceKind::Lumber], 2);
        assert_eq!(state.stock_by_type[ResourceKind::Steel], 1);
    }

    #[test]
    fn expansion_production_keeps_the_unused_inherited_workforce_field() {
        let mut state = city();
        let owner = nation();
        let mut production =
            expansion_order(ExpansionTarget::Production(ProductionSlot::new(2).unwrap()));
        state.production_orders[slot(2)] = 4;
        state.production_accum[slot(2)] = 7;
        production.quantity = 2;
        production.requested_quantity = 2;
        production.reserved_workforce = 9;
        production.tracking_by_resource[ResourceKind::Lumber] = 2;
        production.tracking_by_resource[ResourceKind::Steel] = 2;

        production.produce(&mut state, &owner, 0);
        assert_eq!(state.production_orders[slot(2)], 6);
        assert_eq!(state.production_accum[slot(2)], 9);
        assert_eq!(production.quantity, 0);
        assert_eq!(production.requested_quantity, 0);
        assert_eq!(production.reserved_workforce, 9);
        assert_eq!(production.tracking_by_resource[ResourceKind::Lumber], 0);
        assert_eq!(production.tracking_by_resource[ResourceKind::Steel], 0);
    }

    #[test]
    fn expansion_region_target_uses_the_retail_region_divisor() {
        let mut state = city();
        let mut owner = nation();
        let mut production = expansion_order(ExpansionTarget::RegionalPopulation);
        production.quantity = 1;
        owner.pending_action_status[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
            b'2' as i8;
        state.production_orders[slot(15)] = 8;
        state.production_accum[slot(15)] = 10;

        production.produce(&mut state, &owner, 12);
        assert_eq!(state.production_orders[slot(15)], 4);
        assert_eq!(state.production_accum[slot(15)], 6);
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
        let expected_state = state.clone();
        let expected_owner = owner.clone();
        let expected_capacity = capacity.clone();
        let expected_expansion = expansion.clone();

        capacity.produce(&mut state, &mut owner, 20);
        expansion.produce(&mut state, &owner, 20);
        assert_eq!(state, expected_state);
        assert_eq!(owner, expected_owner);
        assert_eq!(capacity, expected_capacity);
        assert_eq!(expansion, expected_expansion);
    }

    #[test]
    fn power_plant_limit_counts_each_fuel_unit_as_six_power() {
        let mut state = city();
        let mut production = PowerPlantProductionOrder {
            quantity: 5,
            ..PowerPlantProductionOrder::default()
        };
        state.stock_by_type[ResourceKind::Fuel] = 3;
        assert_eq!(production.max_order(&state), 23);

        production.quantity = i16::MAX;
        state.stock_by_type[ResourceKind::Fuel] = 1;
        assert_eq!(production.max_order(&state), i16::MIN + 5);
    }

    #[test]
    fn power_plant_quantity_reserves_and_refunds_fuel_with_truncating_division() {
        let mut state = city();
        let mut production = PowerPlantProductionOrder::default();
        state.stock_by_type[ResourceKind::Fuel] = 3;

        assert!(production.set_quantity(&mut state, 13));
        assert_eq!(state.stock_by_type[ResourceKind::Fuel], 1);
        assert_eq!(production.desired_quantity, 13);
        assert_eq!(state.power_available, 13);
        assert_eq!(state.population.extra, 13);
        assert_eq!(state.population.strength, 23);

        assert!(production.set_quantity(&mut state, 6));
        assert_eq!(state.stock_by_type[ResourceKind::Fuel], 2);
        assert_eq!(production.desired_quantity, 6);
        assert_eq!(state.power_available, 6);
        assert_eq!(state.population.extra, 6);
        assert_eq!(state.population.strength, 16);
    }

    #[test]
    fn power_plant_rejects_a_reduction_that_exceeds_available_strength() {
        let mut state = city();
        let mut production = PowerPlantProductionOrder {
            quantity: 6,
            desired_quantity: 6,
            ..PowerPlantProductionOrder::default()
        };
        state.stock_by_type[ResourceKind::Fuel] = 2;
        state.population.strength = 2;
        state.population.extra = 6;
        state.power_available = 6;
        let expected_state = state.clone();

        assert!(!production.set_quantity(&mut state, 0));
        assert_eq!(production.quantity, 6);
        assert_eq!(production.desired_quantity, 6);
        assert_eq!(state, expected_state);
    }

    #[test]
    fn power_plant_restock_clamps_but_preserves_the_desired_quantity() {
        let mut state = city();
        let mut production = PowerPlantProductionOrder {
            desired_quantity: 15,
            ..PowerPlantProductionOrder::default()
        };
        state.stock_by_type[ResourceKind::Fuel] = 2;

        assert!(production.restock(&mut state));
        assert_eq!(production.quantity, 12);
        assert_eq!(production.desired_quantity, 15);
        assert_eq!(state.stock_by_type[ResourceKind::Fuel], 0);
        assert_eq!(state.power_available, 12);
        assert_eq!(state.population.extra, 12);
        assert_eq!(state.population.strength, 22);
    }

    #[test]
    fn power_plant_production_is_a_retail_no_op() {
        let production = PowerPlantProductionOrder {
            quantity: 12,
            desired_quantity: 18,
            accumulated_value: 7,
            ..PowerPlantProductionOrder::default()
        };
        let expected = production.clone();
        production.produce();
        assert_eq!(production, expected);
    }

    #[test]
    fn training_limits_record_workforce_treasury_resources_and_the_global_cap() {
        let mut state = city();
        let mut owner = nation();
        let mut medium = TrainingProductionOrder::new(TrainingLevel::Medium);
        state.stock_by_type[ResourceKind::Paper] = 10;
        assert_eq!(medium.max_order(&state, &owner, 10_000).unwrap(), 4);
        assert_eq!(medium.limiting_constraint, ProductionConstraint::Workforce);

        assert_eq!(medium.max_order(&state, &owner, 150).unwrap(), 1);
        assert_eq!(medium.limiting_constraint, ProductionConstraint::Treasury);

        state.stock_by_type[ResourceKind::Paper] = 0;
        assert_eq!(medium.max_order(&state, &owner, 10_000).unwrap(), 0);
        assert_eq!(medium.limiting_constraint, ProductionConstraint::Resources);

        owner.diplomacy_eligible = false;
        state.stock_by_type[ResourceKind::Paper] = 100;
        medium.quantity = 98;
        assert_eq!(medium.max_order(&state, &owner, -50_000).unwrap(), 99);

        let mut high = TrainingProductionOrder::new(TrainingLevel::High);
        assert_eq!(high.max_order(&state, &owner, 0).unwrap(), 2);
        assert_eq!(high.limiting_constraint, ProductionConstraint::Workforce);
    }

    #[test]
    fn training_quantity_reserves_and_refunds_paper_cash_and_workers() {
        let mut state = city();
        let owner = nation();
        let mut treasury = 1_000;
        let mut production = TrainingProductionOrder::new(TrainingLevel::Medium);
        state.stock_by_type[ResourceKind::Paper] = 10;

        assert!(
            production
                .set_quantity(&mut state, &owner, &mut treasury, 2)
                .unwrap()
        );
        assert_eq!(state.stock_by_type[ResourceKind::Paper], 8);
        assert_eq!(treasury, 800);
        assert_eq!(state.population.production_labor.unwrap().low, 2);
        assert_eq!(state.population.strength, 8);

        assert!(
            production
                .set_quantity(&mut state, &owner, &mut treasury, 1)
                .unwrap()
        );
        assert_eq!(state.stock_by_type[ResourceKind::Paper], 9);
        assert_eq!(treasury, 900);
        assert_eq!(state.population.production_labor.unwrap().low, 3);
        assert_eq!(state.population.strength, 9);
    }

    #[test]
    fn high_training_uses_two_paper_and_one_thousand_cash_per_worker() {
        let mut state = city();
        let owner = nation();
        let mut treasury = 3_000;
        let mut production = TrainingProductionOrder::new(TrainingLevel::High);
        state.stock_by_type[ResourceKind::Paper] = 6;

        assert!(
            production
                .set_quantity(&mut state, &owner, &mut treasury, 2)
                .unwrap()
        );
        assert_eq!(state.stock_by_type[ResourceKind::Paper], 2);
        assert_eq!(treasury, 1_000);
        assert_eq!(state.population.production_labor.unwrap().medium, 0);
        assert_eq!(state.population.strength, 6);
    }

    #[test]
    fn training_production_promotes_the_requested_baseline_workers() {
        let mut state = city();
        let mut owner = nation();
        let mut medium = TrainingProductionOrder::new(TrainingLevel::Medium);
        medium.quantity = 2;

        medium.produce(&mut state, &mut owner).unwrap();
        assert_eq!(state.population.baseline_labor.unwrap().low, 2);
        assert_eq!(state.population.baseline_labor.unwrap().medium, 4);
        assert_eq!(medium.quantity, 0);

        owner.pending_action_status[PendingActionKind::UniversityExpansion] = b'3' as i8;
        owner.pending_action_payload_by_action = crate::PendingActionTable::default();
        state.population.baseline_labor.as_mut().unwrap().high = 29;
        let mut high = TrainingProductionOrder::new(TrainingLevel::High);
        high.quantity = 1;
        high.produce(&mut state, &mut owner).unwrap();
        assert_eq!(state.population.baseline_labor.unwrap().medium, 3);
        assert_eq!(state.population.baseline_labor.unwrap().high, 30);
        assert_eq!(
            owner.pending_action_status[PendingActionKind::UniversityExpansion],
            b'2' as i8
        );
        assert_eq!(
            owner.pending_action_payload_by_action[PendingActionKind::UniversityExpansion],
            3
        );
        assert_eq!(high.quantity, 0);
    }

    #[test]
    fn high_training_preserves_the_retail_pending_action_threshold_order() {
        let mut state = city();
        let mut owner = nation();
        owner.pending_action_payload_by_action = crate::PendingActionTable::default();
        state.population.baseline_labor.as_mut().unwrap().high = 29;
        let mut production = TrainingProductionOrder::new(TrainingLevel::High);
        production.quantity = 1;

        production.produce(&mut state, &mut owner).unwrap();
        assert_eq!(
            owner.pending_action_status[PendingActionKind::UniversityExpansion],
            b'2' as i8
        );
        assert_eq!(
            owner.pending_action_payload_by_action[PendingActionKind::UniversityExpansion],
            2
        );
    }

    #[test]
    fn zero_training_order_does_not_require_population_state() {
        let mut state = city();
        let mut owner = nation();
        state.population.baseline_labor = None;
        let mut production = TrainingProductionOrder::new(TrainingLevel::High);
        let expected_state = state.clone();
        let expected_owner = owner.clone();

        production.produce(&mut state, &mut owner).unwrap();
        assert_eq!(state, expected_state);
        assert_eq!(owner, expected_owner);
    }

    fn unit_profile(workforce: Option<SkillBand>) -> UnitCostProfile {
        UnitCostProfile {
            entry_id: 4,
            primary: ResourceCost {
                resource: ResourceKind::Paper,
                per_unit: 2,
            },
            secondary: Some(ResourceCost {
                resource: ResourceKind::Steel,
                per_unit: 1,
            }),
            cash_per_unit: 100,
            workforce,
            specialist: true,
        }
    }

    #[test]
    fn unit_order_supports_each_retail_workforce_mode() {
        let mut state = city();
        let mut owner = nation();
        owner.diplomacy_eligible = false;
        state.stock_by_type[ResourceKind::Paper] = 200;
        state.stock_by_type[ResourceKind::Steel] = 200;

        for (workforce, expected) in [
            (Some(SkillBand::Low), 4),
            (Some(SkillBand::Medium), 2),
            (Some(SkillBand::High), 1),
            (None, 100),
        ] {
            let mut production = UnitProductionOrder::new(unit_profile(workforce));
            assert_eq!(production.max_order(&state, &owner, -1).unwrap(), expected);
            assert_eq!(
                production.limiting_constraint,
                if workforce.is_some() {
                    ProductionConstraint::Workforce
                } else {
                    ProductionConstraint::Resources
                }
            );
        }
    }

    #[test]
    fn unit_order_records_primary_secondary_and_treasury_limits() {
        let mut state = city();
        let owner = nation();
        let mut production = UnitProductionOrder::new(unit_profile(None));
        state.stock_by_type[ResourceKind::Paper] = 4;
        state.stock_by_type[ResourceKind::Steel] = 10;
        assert_eq!(production.max_order(&state, &owner, 10_000).unwrap(), 2);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Resources
        );

        state.stock_by_type[ResourceKind::Paper] = 20;
        state.stock_by_type[ResourceKind::Steel] = 3;
        assert_eq!(production.max_order(&state, &owner, 10_000).unwrap(), 3);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Resources
        );

        state.stock_by_type[ResourceKind::Steel] = 20;
        assert_eq!(production.max_order(&state, &owner, 150).unwrap(), 1);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Treasury
        );
    }

    #[test]
    fn unit_order_reserves_and_refunds_resources_population_and_cash() {
        let mut state = city();
        let owner = nation();
        let mut treasury = 1_000;
        let mut production = UnitProductionOrder::new(unit_profile(Some(SkillBand::Low)));
        state.stock_by_type[ResourceKind::Paper] = 10;
        state.stock_by_type[ResourceKind::Steel] = 10;

        assert!(
            production
                .set_quantity(&mut state, &owner, &mut treasury, 2)
                .unwrap()
        );
        assert_eq!(state.stock_by_type[ResourceKind::Paper], 6);
        assert_eq!(state.stock_by_type[ResourceKind::Steel], 8);
        assert_eq!(treasury, 800);
        assert_eq!(state.population.baseline_labor.unwrap().low, 2);
        assert_eq!(state.population.production_labor.unwrap().low, 2);
        assert_eq!(state.population.count, 5);
        assert_eq!(state.population.count_float(), 5.0);
        assert_eq!(state.population.strength, 8);

        assert!(
            production
                .set_quantity(&mut state, &owner, &mut treasury, 1)
                .unwrap()
        );
        assert_eq!(state.stock_by_type[ResourceKind::Paper], 8);
        assert_eq!(state.stock_by_type[ResourceKind::Steel], 9);
        assert_eq!(treasury, 900);
        assert_eq!(state.population.baseline_labor.unwrap().low, 3);
        assert_eq!(state.population.production_labor.unwrap().low, 3);
        assert_eq!(state.population.count, 6);
        assert_eq!(state.population.count_float(), 6.0);
        assert_eq!(state.population.strength, 9);
    }

    #[test]
    fn unit_order_ignores_treasury_when_the_nation_is_not_eligible() {
        let mut state = city();
        let mut owner = nation();
        owner.diplomacy_eligible = false;
        let mut production = UnitProductionOrder::new(unit_profile(None));
        state.stock_by_type[ResourceKind::Paper] = 12;
        state.stock_by_type[ResourceKind::Steel] = 12;

        assert_eq!(production.max_order(&state, &owner, -10_000).unwrap(), 6);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Resources
        );
    }

    #[test]
    fn unit_order_rejects_zero_per_unit_cost_before_mutating_state() {
        let mut state = city();
        let owner = nation();
        let mut treasury = 1_000;
        let mut profile = unit_profile(None);
        profile.primary.per_unit = 0;
        let mut production = UnitProductionOrder::new(profile);
        let expected_state = state.clone();

        assert_eq!(
            production.set_quantity(&mut state, &owner, &mut treasury, 1),
            Err(ProductionError::ZeroUnitResourceCost {
                resource: ResourceKind::Paper
            })
        );
        assert_eq!(state, expected_state);
        assert_eq!(treasury, 1_000);
        assert_eq!(production.quantity, 0);
    }
}
