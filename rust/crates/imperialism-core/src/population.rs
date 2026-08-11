use crate::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const STRIKE_RESOURCES: [ResourceKind; 3] = [
    ResourceKind::Hardware,
    ResourceKind::Clothing,
    ResourceKind::Furniture,
];

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaborPool {
    pub low: i16,
    pub medium: i16,
    pub high: i16,
}

impl LaborPool {
    pub const fn new(low: i16, medium: i16, high: i16) -> Self {
        Self { low, medium, high }
    }

    pub(crate) const fn strength(self) -> i16 {
        self.low + (self.medium + self.high * 2) * 2
    }

    /// Mirrors `TLaborPool::TransferToLowSkillFirst`.
    pub fn transfer_low_skill_first(&mut self, destination: &mut Self, amount: i16) -> bool {
        let mut remaining = amount;
        transfer_band(&mut self.low, &mut destination.low, &mut remaining);
        transfer_band(&mut self.medium, &mut destination.medium, &mut remaining);
        transfer_band(&mut self.high, &mut destination.high, &mut remaining);
        remaining == 0
    }

    /// Mirrors `TLaborPool::TransferToHighSkillFirst`.
    pub fn transfer_high_skill_first(&mut self, destination: &mut Self, amount: i16) -> bool {
        let mut remaining = amount;
        transfer_band(&mut self.high, &mut destination.high, &mut remaining);
        transfer_band(&mut self.medium, &mut destination.medium, &mut remaining);
        transfer_band(&mut self.low, &mut destination.low, &mut remaining);
        remaining == 0
    }

    const fn band(self, band: SkillBand) -> i16 {
        match band {
            SkillBand::Low => self.low,
            SkillBand::Medium => self.medium,
            SkillBand::High => self.high,
        }
    }

    fn band_mut(&mut self, band: SkillBand) -> &mut i16 {
        match band {
            SkillBand::Low => &mut self.low,
            SkillBand::Medium => &mut self.medium,
            SkillBand::High => &mut self.high,
        }
    }
}

impl From<[i16; 3]> for LaborPool {
    fn from([low, medium, high]: [i16; 3]) -> Self {
        Self::new(low, medium, high)
    }
}

impl From<LaborPool> for [i16; 3] {
    fn from(value: LaborPool) -> Self {
        [value.low, value.medium, value.high]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(i16)]
#[serde(rename_all = "snake_case")]
pub enum SkillBand {
    Low = 1,
    Medium = 2,
    High = 4,
}

impl SkillBand {
    const fn weight(self) -> i16 {
        self as i16
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FoodOutcome {
    pub substitution_count: i16,
    pub starvation_count: i16,
}

impl CityState {
    /// Mirrors `TPopulationMgr::Eat` and records the two city summary fields
    /// updated by the original routine.
    pub fn consume_population_food(&mut self) -> FoodOutcome {
        let outcome = self.population.consume_food(&mut self.stockpile);
        self.food_substitution_count = outcome.substitution_count;
        self.starvation_population_loss = outcome.starvation_count;
        outcome
    }

    /// Mirrors `TPopulationMgr::StartProductionPhase`.
    pub fn start_production_phase(&mut self) -> FoodOutcome {
        self.population.production_labor = self.population.baseline_labor;
        let outcome = self.consume_population_food();
        self.population.strength = self.population.production_labor.strength();
        self.population.extra = 0;
        outcome
    }

    /// Mirrors `TPopulationMgr::PretendToEat` without mutating either input.
    pub fn forecast_population_food(
        &self,
        nation_need_targets: &ResourceTable<i16>,
    ) -> FoodOutcome {
        self.population
            .forecast_food(nation_need_targets, self.stockpile[ResourceKind::Food])
    }

    /// Mirrors `TPopulationMgr::Strike` and returns whether any of the three
    /// rotated resources was short.
    pub fn apply_population_strike(&mut self) -> bool {
        let baseline = self.population.baseline_labor;
        let skilled = i32::from(baseline.medium) + i32::from(baseline.high);
        let mut cycles = (skilled / 10) as i16;
        let mut consumption = [0_i16; 4];

        while cycles != 0 {
            let amount = &mut consumption[self.population.strike_phase.index()];
            *amount += 1;
            self.population.strike_phase = self.population.strike_phase.next();
            cycles -= 1;
        }

        let mut shortage = false;
        for (resource, amount) in STRIKE_RESOURCES.into_iter().zip(consumption) {
            if self.stockpile[resource] < amount {
                self.stockpile.set_nonnegative(resource, 0);
                shortage = true;
            } else {
                self.stockpile.debit_clamped(resource, amount);
            }
        }
        shortage
    }
}

impl PopulationState {
    pub fn count_float(&self) -> f32 {
        self.accumulator.get()
    }

    /// Mirrors the one-argument `TPopulationMgr::SetPopulation` overload. The
    /// original only replaces the low-skill bands and leaves the others alone.
    pub fn set_untrained_population(&mut self, count: i16) {
        self.baseline_labor.low = count;
        self.production_labor.low = count;
        self.strength = count;
        self.count = count;
        self.accumulator = crate::PopulationAccumulator::from_count(count);
        self.pending_labor_delta = LaborPool::default();
        self.strike_phase = crate::StrikePhase::default();
    }

    /// Mirrors the three-argument `TPopulationMgr::SetPopulation` overload.
    pub fn set_population(&mut self, low: i16, medium: i16, high: i16) {
        let labor = LaborPool::new(low, medium, high);
        self.baseline_labor = labor;
        self.production_labor = labor;
        self.strength = labor.strength();
        self.count = medium + high + low;
        self.accumulator = crate::PopulationAccumulator::from_count(self.count);
        self.pending_labor_delta = LaborPool::default();
        self.strike_phase = crate::StrikePhase::default();
    }

    /// Mirrors the retail growth table and its signed penalty constants. The
    /// recovered constants are negative, so retry ticks increase this result.
    pub fn growth_rate(&self, penalty_ticks: i16) -> f32 {
        let base = if self.count < 10 {
            1.2_f32
        } else if self.count < 15 {
            1.03_f32
        } else if self.count < 20 {
            1.02_f32
        } else if self.count < 30 {
            1.015_f32
        } else if self.count < 40 {
            1.012_f32
        } else if self.count < 60 {
            1.011_f32
        } else if self.count < 80 {
            1.01_f32
        } else if self.count < 400 {
            1.005_f32
        } else {
            return 1.0_f32;
        };

        if penalty_ticks < 20 {
            (f64::from(base) - f64::from(penalty_ticks) * -0.001_f64) as f32
        } else {
            (f64::from(base) - -0.02_f64) as f32
        }
    }

    /// Mirrors `TPopulationMgr::PredictedNeeds`; the order quantity is the
    /// city's trailing order slot 9 contribution to supported population.
    pub fn refresh_predicted_needs(&mut self, order_quantity: i16) -> &mut ResourceTable<i16> {
        for resource in STRIKE_RESOURCES {
            self.predicted_need_by_resource[resource] = 0;
        }
        let supported = self.count + order_quantity;
        self.predicted_need_by_resource[ResourceKind::Grain] =
            ((i32::from(supported) + 1) / 2) as i16;
        self.predicted_need_by_resource[ResourceKind::Fruit] =
            ((i32::from(supported) + 2) / 4) as i16;
        self.predicted_need_by_resource[ResourceKind::Livestock] = supported / 4;
        &mut self.predicted_need_by_resource
    }

    /// Mirrors `TPopulationMgr::RemovePopulation`, including its unusual use
    /// of the post-band remainder in the strength adjustments.
    pub fn remove_population(&mut self, starting_band: SkillBand, amount: i16) {
        let mut remaining = amount;
        let mut band = Some(starting_band);

        while let Some(current) = band {
            let available = self.baseline_labor.band(current);
            if remaining <= available {
                *self.baseline_labor.band_mut(current) = available - remaining;
                let production = self.production_labor.band_mut(current);
                *production -= remaining;
                self.strength -= remaining * current.weight();
                remaining = 0;
                break;
            }

            remaining -= available;
            *self.baseline_labor.band_mut(current) = 0;
            *self.production_labor.band_mut(current) = 0;
            self.strength -= remaining * current.weight();
            band = match current {
                SkillBand::Low => Some(SkillBand::Medium),
                SkillBand::Medium => Some(SkillBand::High),
                SkillBand::High => None,
            };
        }

        let removed = amount - remaining;
        self.count -= removed;
        self.accumulator.remove(removed);
    }

    pub fn make_unavailable(&mut self, band: SkillBand, amount: i16) {
        let production = self.production_labor.band_mut(band);
        *production -= amount;
        self.strength -= amount * band.weight();
    }

    pub fn add_untrained(&mut self, count: i16) {
        self.baseline_labor.low += count;
        self.production_labor.low += count;
        self.count += count;
    }

    pub fn add_expert(&mut self, count: i16) {
        self.baseline_labor.high += count;
        self.production_labor.high += count;
        self.count += count;
        self.strength += count * 4;
    }

    fn consume_food(&mut self, stocks: &mut crate::Stockpile) -> FoodOutcome {
        let pending = self.pending_labor_delta;
        let production = &mut self.production_labor;
        production.low += pending.low;
        production.medium += pending.medium;
        production.high += pending.high;

        let mut food = FoodRemainders::from_city_stocks(stocks);
        let mut unmet = food.consume_normal_needs(self.count);
        let mut substituted = 0;

        if unmet != 0 {
            let canned = stocks[ResourceKind::Food];
            if unmet < canned {
                stocks.debit_clamped(ResourceKind::Food, unmet);
                unmet = 0;
            } else {
                unmet -= canned;
                stocks.set_nonnegative(ResourceKind::Food, 0);
            }

            if unmet != 0 {
                let before = unmet;
                food.substitute_surpluses(&mut unmet);
                substituted = before - unmet;
            }
        }

        food.write_back(stocks);

        let starvation = if unmet != 0 {
            let mut lost = LaborPool::default();
            self.baseline_labor
                .transfer_low_skill_first(&mut lost, unmet);
            self.count -= unmet;
            self.accumulator.remove(unmet);
            unmet.max(0)
        } else {
            0
        };

        self.production_labor = self.baseline_labor;
        if substituted != 0 {
            let production = &mut self.production_labor;
            let pending = &mut self.pending_labor_delta;
            production.transfer_low_skill_first(pending, substituted);
        }

        FoodOutcome {
            substitution_count: substituted,
            starvation_count: starvation,
        }
    }

    fn forecast_food(&self, available: &ResourceTable<i16>, canned_food: i16) -> FoodOutcome {
        let mut food = FoodRemainders {
            grain: available[ResourceKind::Grain],
            fruit: available[ResourceKind::Fruit],
            animal: available[ResourceKind::Fish] + available[ResourceKind::Livestock],
            original_fish: available[ResourceKind::Fish],
            original_livestock: available[ResourceKind::Livestock],
        };
        let mut unmet = food.consume_normal_needs(self.count);
        let mut substitution = 0;

        if unmet != 0 {
            if unmet < canned_food {
                unmet = 0;
            } else {
                unmet -= canned_food;
            }
            if unmet != 0 {
                let before = unmet;
                food.substitute_surpluses(&mut unmet);
                substitution = before - unmet;
            }
        }

        FoodOutcome {
            substitution_count: substitution,
            starvation_count: unmet.max(0),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct FoodRemainders {
    grain: i16,
    fruit: i16,
    animal: i16,
    original_fish: i16,
    original_livestock: i16,
}

impl FoodRemainders {
    fn from_city_stocks(stocks: &crate::Stockpile) -> Self {
        Self {
            grain: stocks[ResourceKind::Grain],
            fruit: stocks[ResourceKind::Fruit],
            animal: stocks[ResourceKind::Fish] + stocks[ResourceKind::Livestock],
            original_fish: stocks[ResourceKind::Fish],
            original_livestock: stocks[ResourceKind::Livestock],
        }
    }

    fn consume_normal_needs(&mut self, population: i16) -> i16 {
        let grain_need = ((i32::from(population) + 1) / 2) as i16;
        let fruit_need = ((i32::from(population) + 2) / 4) as i16;
        let animal_need = (i32::from(population) / 4) as i16;
        let mut unmet = 0;
        consume_need(&mut self.grain, grain_need, &mut unmet);
        consume_need(&mut self.fruit, fruit_need, &mut unmet);
        consume_need(&mut self.animal, animal_need, &mut unmet);
        unmet
    }

    fn substitute_surpluses(&mut self, unmet: &mut i16) {
        consume_surplus(&mut self.grain, unmet);
        if *unmet != 0 {
            consume_surplus(&mut self.fruit, unmet);
        }
        if *unmet != 0 {
            consume_surplus(&mut self.animal, unmet);
        }
    }

    fn write_back(self, stocks: &mut crate::Stockpile) {
        stocks.set_nonnegative(ResourceKind::Grain, self.grain);
        stocks.set_nonnegative(ResourceKind::Fruit, self.fruit);

        if self.animal == 0 {
            stocks.set_nonnegative(ResourceKind::Livestock, 0);
            stocks.set_nonnegative(ResourceKind::Fish, 0);
            return;
        }

        let mut livestock = if self.animal & 1 != 0 {
            self.animal / 2 + 1
        } else {
            self.animal / 2
        };
        let mut fish = if self.animal & 1 != 0 {
            livestock - 1
        } else {
            livestock
        };
        if self.original_livestock < livestock {
            let shift = livestock - self.original_livestock;
            livestock -= shift;
            fish += shift;
        } else if self.original_fish < fish {
            let shift = fish - self.original_fish;
            fish -= shift;
            livestock += shift;
        }
        stocks.set_nonnegative(ResourceKind::Livestock, livestock);
        stocks.set_nonnegative(ResourceKind::Fish, fish);
    }
}

fn consume_need(remaining: &mut i16, need: i16, unmet: &mut i16) {
    if *remaining < need {
        *unmet += need - *remaining;
        *remaining = 0;
    } else {
        *remaining -= need;
    }
}

fn consume_surplus(remaining: &mut i16, unmet: &mut i16) {
    if *remaining < *unmet {
        *unmet -= *remaining;
        *remaining = 0;
    } else {
        *remaining -= *unmet;
        *unmet = 0;
    }
}

fn transfer_band(source: &mut i16, destination: &mut i16, remaining: &mut i16) {
    let moved = if *source < *remaining {
        *source
    } else {
        *remaining
    };
    *source -= moved;
    *destination += moved;
    *remaining -= moved;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PopulationState {
    pub(crate) count: i16,
    pub(crate) accumulator: PopulationAccumulator,
    pub(crate) strength: i16,
    pub(crate) extra: i16,
    pub(crate) strike_phase: StrikePhase,
    pub(crate) baseline_labor: LaborPool,
    pub(crate) production_labor: LaborPool,
    pub(crate) pending_labor_delta: LaborPool,
    pub(crate) predicted_need_by_resource: ResourceTable<i16>,
}

impl PopulationState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        count: i16,
        accumulator: PopulationAccumulator,
        strength: i16,
        extra: i16,
        strike_phase: StrikePhase,
        baseline_labor: LaborPool,
        production_labor: LaborPool,
        pending_labor_delta: LaborPool,
        predicted_need_by_resource: ResourceTable<i16>,
    ) -> Self {
        Self {
            count,
            accumulator,
            strength,
            extra,
            strike_phase,
            baseline_labor,
            production_labor,
            pending_labor_delta,
            predicted_need_by_resource,
        }
    }

    /// Builds a fresh population whose baseline and production bands both equal
    /// `labor`, with no pending reassignment. Mirrors the retail
    /// `SetPopulation`-time state used when a city first appears.
    pub(crate) fn from_labor(labor: LaborPool) -> Self {
        let count = labor.low + labor.medium + labor.high;
        Self::new(
            count,
            PopulationAccumulator::from_count(count),
            labor.strength(),
            0,
            StrikePhase::default(),
            labor,
            labor,
            LaborPool::default(),
            ResourceTable::default(),
        )
    }

    pub const fn count(&self) -> i16 {
        self.count
    }

    pub const fn accumulator(&self) -> PopulationAccumulator {
        self.accumulator
    }

    pub const fn strength(&self) -> i16 {
        self.strength
    }

    pub const fn baseline_labor(&self) -> LaborPool {
        self.baseline_labor
    }

    pub const fn production_labor(&self) -> LaborPool {
        self.production_labor
    }

    pub fn predicted_need(&self, resource: ResourceKind) -> i16 {
        self.predicted_need_by_resource[resource]
    }
}

/// A finite semantic population total.
///
/// The retail save stores its IEEE-754 bits, but core state exposes the value
/// itself. The retained bits preserve exact arithmetic between rule steps.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PopulationAccumulator(u32);

impl PopulationAccumulator {
    pub fn new(value: f32) -> Option<Self> {
        value.is_finite().then_some(Self(value.to_bits()))
    }

    #[cfg(test)]
    pub(crate) fn from_bits(bits: u32) -> Self {
        Self::new(f32::from_bits(bits)).expect("population accumulator stays finite")
    }

    pub(crate) fn from_count(count: i16) -> Self {
        Self(f32::from(count).to_bits())
    }

    pub fn get(self) -> f32 {
        f32::from_bits(self.0)
    }
    pub(crate) fn remove(&mut self, amount: i16) {
        self.0 = (self.get() - f32::from(amount)).to_bits();
    }
}

impl Serialize for PopulationAccumulator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.get().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PopulationAccumulator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f32::deserialize(deserializer)?;
        Self::new(value)
            .ok_or_else(|| serde::de::Error::custom("population accumulator must be finite"))
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u8)]
pub enum StrikePhase {
    #[default]
    Clothing,
    Furniture,
    Hardware,
    Arms,
}

impl StrikePhase {
    pub const fn from_retail(value: i16) -> Option<Self> {
        match value {
            0 => Some(Self::Clothing),
            1 => Some(Self::Furniture),
            2 => Some(Self::Hardware),
            3 => Some(Self::Arms),
            _ => None,
        }
    }
    pub const fn retail(self) -> i16 {
        self as i16
    }
    pub(crate) const fn index(self) -> usize {
        self as usize
    }
    pub(crate) const fn next(self) -> Self {
        match self {
            Self::Clothing => Self::Furniture,
            Self::Furniture => Self::Hardware,
            Self::Hardware => Self::Arms,
            Self::Arms => Self::Clothing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn population() -> PopulationState {
        PopulationState {
            count: 7,
            accumulator: crate::PopulationAccumulator::from_bits(7.0_f32.to_bits()),
            strength: 12,
            extra: 5,
            strike_phase: crate::StrikePhase::Arms,
            baseline_labor: LaborPool::new(4, 2, 1),
            production_labor: LaborPool::new(4, 2, 1),
            pending_labor_delta: LaborPool::new(1, -1, 2),
            predicted_need_by_resource: ResourceTable::from_fn(|_| 9),
        }
    }

    fn city() -> CityState {
        let mut population = population();
        population.extra = 5;
        population.strike_phase = crate::StrikePhase::default();
        population.pending_labor_delta = LaborPool::default();
        CityState {
            population,
            ..crate::test_support::city()
        }
    }

    fn stock_food(
        city: &mut CityState,
        canned: i16,
        grain: i16,
        fruit: i16,
        fish: i16,
        livestock: i16,
    ) {
        city.stockpile[ResourceKind::Food] = canned;
        city.stockpile[ResourceKind::Grain] = grain;
        city.stockpile[ResourceKind::Fruit] = fruit;
        city.stockpile[ResourceKind::Fish] = fish;
        city.stockpile[ResourceKind::Livestock] = livestock;
    }

    #[test]
    fn transfers_workers_in_the_requested_skill_order() {
        let mut source = LaborPool::new(2, 3, 4);
        let mut destination = LaborPool::default();
        assert!(source.transfer_low_skill_first(&mut destination, 4));
        assert_eq!(source, LaborPool::new(0, 1, 4));
        assert_eq!(destination, LaborPool::new(2, 2, 0));

        assert!(!source.transfer_high_skill_first(&mut destination, 8));
        assert_eq!(source, LaborPool::default());
        assert_eq!(destination, LaborPool::new(2, 3, 4));
    }

    #[test]
    fn initializes_all_population_bands() {
        let mut state = population();
        state.set_population(4, 2, 3);
        assert_eq!(state.baseline_labor, LaborPool::new(4, 2, 3));
        assert_eq!(state.production_labor, state.baseline_labor);
        assert_eq!(state.pending_labor_delta, LaborPool::default());
        assert_eq!(state.strength, 20);
        assert_eq!(state.count, 9);
        assert_eq!(state.count_float(), f32::from(state.count));
        assert_eq!(state.strike_phase, crate::StrikePhase::default());
    }

    #[test]
    fn uses_recovered_growth_thresholds_and_signed_penalties() {
        let mut state = population();
        state.count = 9;
        assert_eq!(state.growth_rate(0).to_bits(), 1.2_f32.to_bits());
        assert_eq!(state.growth_rate(19).to_bits(), 1_067_190_322);
        assert_eq!(state.growth_rate(20).to_bits(), 1.22_f32.to_bits());
        state.count = 399;
        assert_eq!(state.growth_rate(0).to_bits(), 1.005_f32.to_bits());
        state.count = 400;
        assert_eq!(state.growth_rate(19).to_bits(), 1.0_f32.to_bits());
    }

    #[test]
    fn refreshes_only_the_retail_predicted_need_slots() {
        let mut state = population();
        state.refresh_predicted_needs(2);
        assert_eq!(state.predicted_need_by_resource[ResourceKind::Clothing], 0);
        assert_eq!(state.predicted_need_by_resource[ResourceKind::Furniture], 0);
        assert_eq!(state.predicted_need_by_resource[ResourceKind::Hardware], 0);
        assert_eq!(state.predicted_need_by_resource[ResourceKind::Grain], 5);
        assert_eq!(state.predicted_need_by_resource[ResourceKind::Fruit], 2);
        assert_eq!(state.predicted_need_by_resource[ResourceKind::Livestock], 2);
        assert_eq!(state.predicted_need_by_resource[ResourceKind::Arms], 9);
    }

    #[test]
    fn removes_population_across_skill_bands() {
        let mut state = population();
        state.remove_population(SkillBand::Low, 5);
        assert_eq!(state.baseline_labor, LaborPool::new(0, 1, 1));
        assert_eq!(state.production_labor, state.baseline_labor);
        assert_eq!(state.strength, 9);
        assert_eq!(state.count, 2);
        assert_eq!(state.count_float(), 2.0);
    }

    #[test]
    fn availability_and_additions_update_only_retail_fields() {
        let mut state = population();
        state.make_unavailable(SkillBand::Medium, 1);
        state.add_untrained(2);
        state.add_expert(1);
        assert_eq!(state.baseline_labor, LaborPool::new(6, 2, 2));
        assert_eq!(state.production_labor, LaborPool::new(6, 1, 2));
        assert_eq!(state.count, 10);
        assert_eq!(state.count_float(), 7.0);
        assert_eq!(state.strength, 14);
    }

    #[test]
    fn consumes_each_required_food_without_substitution() {
        let mut state = city();
        stock_food(&mut state, 2, 4, 2, 1, 0);
        assert_eq!(state.consume_population_food(), FoodOutcome::default());
        assert_eq!(state.stockpile[ResourceKind::Food], 2);
        assert_eq!(state.stockpile[ResourceKind::Grain], 0);
        assert_eq!(state.stockpile[ResourceKind::Fruit], 0);
        assert_eq!(state.stockpile[ResourceKind::Fish], 0);
        assert_eq!(state.stockpile[ResourceKind::Livestock], 0);
        assert_eq!(state.population.count, 7);
    }

    #[test]
    fn spends_canned_food_before_reassigning_workers() {
        let mut state = city();
        stock_food(&mut state, 2, 3, 2, 1, 0);
        assert_eq!(state.consume_population_food(), FoodOutcome::default());
        assert_eq!(state.stockpile[ResourceKind::Food], 1);
        assert_eq!(
            state.population.production_labor,
            state.population.baseline_labor
        );
        assert_eq!(state.population.pending_labor_delta, LaborPool::default());
    }

    #[test]
    fn substitutes_surplus_food_and_moves_low_skill_workers() {
        let mut state = city();
        stock_food(&mut state, 0, 3, 3, 1, 0);
        assert_eq!(
            state.consume_population_food(),
            FoodOutcome {
                substitution_count: 1,
                starvation_count: 0,
            }
        );
        assert_eq!(state.food_substitution_count, 1);
        assert_eq!(state.population.production_labor, LaborPool::new(3, 2, 1));
        assert_eq!(
            state.population.pending_labor_delta,
            LaborPool::new(1, 0, 0)
        );
    }

    #[test]
    fn starvation_removes_population_low_skill_first() {
        let mut state = city();
        assert_eq!(
            state.consume_population_food(),
            FoodOutcome {
                substitution_count: 0,
                starvation_count: 7,
            }
        );
        assert_eq!(state.starvation_population_loss, 7);
        assert_eq!(state.population.count, 0);
        assert_eq!(state.population.count_float(), 0.0);
        assert_eq!(state.population.baseline_labor, LaborPool::default());
        assert_eq!(state.population.production_labor, LaborPool::default());
    }

    #[test]
    fn forecasts_food_without_mutating_city_or_population() {
        let mut state = city();
        stock_food(&mut state, 0, 99, 99, 99, 99);
        let before = state.clone();
        let mut targets = ResourceTable::default();
        targets[ResourceKind::Grain] = 3;
        targets[ResourceKind::Fruit] = 3;
        targets[ResourceKind::Fish] = 1;
        assert_eq!(
            state.forecast_population_food(&targets),
            FoodOutcome {
                substitution_count: 1,
                starvation_count: 0,
            }
        );
        assert_eq!(state, before);
    }

    #[test]
    fn start_phase_recomputes_strength_after_food_reassignment() {
        let mut state = city();
        state.population.production_labor = LaborPool::new(99, 99, 99);
        state.population.pending_labor_delta = LaborPool::new(1, 0, 0);
        state.population.strength = -1;
        stock_food(&mut state, 0, 4, 2, 1, 0);
        state.start_production_phase();
        assert_eq!(
            state.population.production_labor,
            state.population.baseline_labor
        );
        assert_eq!(state.population.strength, 12);
        assert_eq!(state.population.extra, 0);
    }

    #[test]
    fn strike_rotates_skilled_consumption_and_reports_shortage() {
        let mut state = city();
        state.population.baseline_labor = LaborPool::new(0, 20, 0);
        state.population.strike_phase = crate::StrikePhase::Hardware;
        state.stockpile[ResourceKind::Hardware] = 1;
        state.stockpile[ResourceKind::Clothing] = 1;
        state.stockpile[ResourceKind::Furniture] = 0;
        assert!(state.apply_population_strike());
        assert_eq!(state.population.strike_phase, crate::StrikePhase::default());
        assert_eq!(state.stockpile[ResourceKind::Hardware], 1);
        assert_eq!(state.stockpile[ResourceKind::Clothing], 1);
        assert_eq!(state.stockpile[ResourceKind::Furniture], 0);
    }
}
