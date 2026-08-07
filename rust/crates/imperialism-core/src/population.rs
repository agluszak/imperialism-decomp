use crate::{CityState, PopulationState};
use std::error::Error;
use std::fmt;

const PREDICTED_NEED_RESOURCE_COUNT: usize = 23;
const STRIKE_RESOURCE_IDS: [usize; 3] = [15, 13, 14];
const GRAIN_RESOURCE_ID: usize = 17;
const FRUIT_RESOURCE_ID: usize = 18;
const ANIMAL_FOOD_RESOURCE_ID: usize = 20;
const CANNED_FOOD_RESOURCE_ID: usize = 7;
const FISH_RESOURCE_ID: usize = 19;
const LIVESTOCK_RESOURCE_ID: usize = 20;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LaborPool {
    pub low: i16,
    pub medium: i16,
    pub high: i16,
}

impl LaborPool {
    pub const fn new(low: i16, medium: i16, high: i16) -> Self {
        Self { low, medium, high }
    }

    pub fn strength(self) -> i16 {
        self.low.wrapping_add(
            self.medium
                .wrapping_add(self.high.wrapping_mul(2))
                .wrapping_mul(2),
        )
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
    fn from(value: [i16; 3]) -> Self {
        Self::new(value[0], value[1], value[2])
    }
}

impl From<LaborPool> for [i16; 3] {
    fn from(value: LaborPool) -> Self {
        [value.low, value.medium, value.high]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i16)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PopulationError {
    MissingLaborPool(&'static str),
    InvalidPredictedNeedCount { actual: usize },
    InvalidStockCount { actual: usize },
    InvalidStrikePhase { phase: i16 },
}

impl fmt::Display for PopulationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLaborPool(name) => write!(formatter, "population is missing its {name}"),
            Self::InvalidPredictedNeedCount { actual } => write!(
                formatter,
                "population has {actual} predicted-need slots, expected {PREDICTED_NEED_RESOURCE_COUNT}"
            ),
            Self::InvalidStockCount { actual } => write!(
                formatter,
                "city has {actual} resource slots, expected {PREDICTED_NEED_RESOURCE_COUNT}"
            ),
            Self::InvalidStrikePhase { phase } => {
                write!(formatter, "population has invalid strike phase {phase}")
            }
        }
    }
}

impl Error for PopulationError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FoodOutcome {
    pub substitution_count: i16,
    pub starvation_count: i16,
}

impl CityState {
    /// Mirrors `TPopulationMgr::Eat` and records the two city summary fields
    /// updated by the original routine.
    pub fn consume_population_food(&mut self) -> Result<FoodOutcome, PopulationError> {
        validate_resource_slots(&self.stock_by_type)?;
        let outcome = self.population.consume_food(&mut self.stock_by_type)?;
        self.food_substitution_count = outcome.substitution_count;
        self.starvation_population_loss = outcome.starvation_count;
        Ok(outcome)
    }

    /// Mirrors `TPopulationMgr::StartProductionPhase`.
    pub fn start_production_phase(&mut self) -> Result<FoodOutcome, PopulationError> {
        let baseline = *self.population.baseline()?;
        *self.population.production_mut()? = baseline;
        let outcome = self.consume_population_food()?;
        self.population.strength = self.population.production()?.strength();
        self.population.extra = 0;
        Ok(outcome)
    }

    /// Mirrors `TPopulationMgr::PretendToEat` without mutating either input.
    pub fn forecast_population_food(
        &self,
        nation_need_targets: &[i16],
    ) -> Result<FoodOutcome, PopulationError> {
        validate_resource_slots(nation_need_targets)?;
        validate_resource_slots(&self.stock_by_type)?;
        Ok(self.population.forecast_food(
            nation_need_targets,
            self.stock_by_type[CANNED_FOOD_RESOURCE_ID],
        ))
    }

    /// Mirrors `TPopulationMgr::Strike` and returns whether any of the three
    /// rotated resources was short.
    pub fn apply_population_strike(&mut self) -> Result<bool, PopulationError> {
        validate_resource_slots(&self.stock_by_type)?;
        let baseline = *self.population.baseline()?;
        let skilled = i32::from(baseline.medium) + i32::from(baseline.high);
        let mut cycles = (skilled / 10) as i16;
        let mut consumption = [0_i16; 4];

        while cycles != 0 {
            let phase = usize::try_from(self.population.phase_value).map_err(|_| {
                PopulationError::InvalidStrikePhase {
                    phase: self.population.phase_value,
                }
            })?;
            let amount = consumption
                .get_mut(phase)
                .ok_or(PopulationError::InvalidStrikePhase {
                    phase: self.population.phase_value,
                })?;
            *amount = amount.wrapping_add(1);
            self.population.phase_value = if self.population.phase_value == 3 {
                0
            } else {
                self.population.phase_value.wrapping_add(1)
            };
            cycles = cycles.wrapping_sub(1);
        }

        let mut shortage = false;
        for (resource, amount) in STRIKE_RESOURCE_IDS.into_iter().zip(consumption) {
            if self.stock_by_type[resource] < amount {
                self.stock_by_type[resource] = 0;
                verify_stocks(&mut self.stock_by_type);
                shortage = true;
            } else {
                self.stock_by_type[resource] = self.stock_by_type[resource].wrapping_sub(amount);
                verify_stocks(&mut self.stock_by_type);
            }
        }
        Ok(shortage)
    }
}

impl PopulationState {
    pub fn count_float(&self) -> f32 {
        f32::from_bits(self.count_float_bits)
    }

    /// Mirrors the one-argument `TPopulationMgr::SetPopulation` overload. The
    /// original only replaces the low-skill bands and leaves the others alone.
    pub fn set_untrained_population(&mut self, count: i16) -> Result<(), PopulationError> {
        self.baseline_mut()?.low = count;
        self.production_mut()?.low = count;
        self.strength = count;
        self.count = count;
        self.count_float_bits = f32::from(count).to_bits();
        *self.pending_mut()? = LaborPool::default();
        self.phase_value = 0;
        Ok(())
    }

    /// Mirrors the three-argument `TPopulationMgr::SetPopulation` overload.
    pub fn set_population(
        &mut self,
        low: i16,
        medium: i16,
        high: i16,
    ) -> Result<(), PopulationError> {
        let labor = LaborPool::new(low, medium, high);
        *self.baseline_mut()? = labor;
        *self.production_mut()? = labor;
        self.strength = labor.strength();
        self.count = medium.wrapping_add(high).wrapping_add(low);
        self.count_float_bits = f32::from(self.count).to_bits();
        *self.pending_mut()? = LaborPool::default();
        self.phase_value = 0;
        Ok(())
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
    pub fn refresh_predicted_needs(
        &mut self,
        order_quantity: i16,
    ) -> Result<&[i16], PopulationError> {
        if self.predicted_need_by_resource.len() != PREDICTED_NEED_RESOURCE_COUNT {
            return Err(PopulationError::InvalidPredictedNeedCount {
                actual: self.predicted_need_by_resource.len(),
            });
        }
        for resource in STRIKE_RESOURCE_IDS {
            self.predicted_need_by_resource[resource] = 0;
        }
        let supported = self.count.wrapping_add(order_quantity);
        self.predicted_need_by_resource[GRAIN_RESOURCE_ID] =
            ((i32::from(supported) + 1) / 2) as i16;
        self.predicted_need_by_resource[FRUIT_RESOURCE_ID] =
            ((i32::from(supported) + 2) / 4) as i16;
        self.predicted_need_by_resource[ANIMAL_FOOD_RESOURCE_ID] = supported / 4;
        Ok(&self.predicted_need_by_resource)
    }

    /// Mirrors `TPopulationMgr::RemovePopulation`, including its unusual use
    /// of the post-band remainder in the overflow strength adjustments.
    pub fn remove_population(
        &mut self,
        starting_band: SkillBand,
        amount: i16,
    ) -> Result<(), PopulationError> {
        let mut remaining = amount;
        let mut band = Some(starting_band);

        while let Some(current) = band {
            let available = self.baseline()?.band(current);
            if remaining <= available {
                *self.baseline_mut()?.band_mut(current) = available.wrapping_sub(remaining);
                let production = self.production_mut()?.band_mut(current);
                *production = production.wrapping_sub(remaining);
                self.strength = self
                    .strength
                    .wrapping_sub(remaining.wrapping_mul(current.weight()));
                remaining = 0;
                break;
            }

            remaining = remaining.wrapping_sub(available);
            *self.baseline_mut()?.band_mut(current) = 0;
            *self.production_mut()?.band_mut(current) = 0;
            self.strength = self
                .strength
                .wrapping_sub(remaining.wrapping_mul(current.weight()));
            band = match current {
                SkillBand::Low => Some(SkillBand::Medium),
                SkillBand::Medium => Some(SkillBand::High),
                SkillBand::High => None,
            };
        }

        let removed = amount.wrapping_sub(remaining);
        self.count = self.count.wrapping_sub(removed);
        self.count_float_bits = (self.count_float() - f32::from(removed)).to_bits();
        Ok(())
    }

    pub fn make_unavailable(
        &mut self,
        band: SkillBand,
        amount: i16,
    ) -> Result<(), PopulationError> {
        let production = self.production_mut()?.band_mut(band);
        *production = production.wrapping_sub(amount);
        self.strength = self
            .strength
            .wrapping_sub(amount.wrapping_mul(band.weight()));
        Ok(())
    }

    pub fn add_untrained(&mut self, count: i16) -> Result<(), PopulationError> {
        let baseline = &mut self.baseline_mut()?.low;
        *baseline = baseline.wrapping_add(count);
        let production = &mut self.production_mut()?.low;
        *production = production.wrapping_add(count);
        self.count = self.count.wrapping_add(count);
        Ok(())
    }

    pub fn add_expert(&mut self, count: i16) -> Result<(), PopulationError> {
        let baseline = &mut self.baseline_mut()?.high;
        *baseline = baseline.wrapping_add(count);
        let production = &mut self.production_mut()?.high;
        *production = production.wrapping_add(count);
        self.count = self.count.wrapping_add(count);
        self.strength = self.strength.wrapping_add(count.wrapping_mul(4));
        Ok(())
    }

    fn consume_food(&mut self, stocks: &mut [i16]) -> Result<FoodOutcome, PopulationError> {
        validate_resource_slots(stocks)?;
        self.require_labor_pools()?;
        let pending = *self.pending()?;
        let production = self.production_mut()?;
        production.low = production.low.wrapping_add(pending.low);
        production.medium = production.medium.wrapping_add(pending.medium);
        production.high = production.high.wrapping_add(pending.high);

        let mut food = FoodRemainders::from_city_stocks(stocks);
        let mut unmet = food.consume_normal_needs(self.count);
        let mut substituted = 0;

        if unmet != 0 {
            let canned = &mut stocks[CANNED_FOOD_RESOURCE_ID];
            if unmet < *canned {
                *canned = canned.wrapping_sub(unmet);
                verify_stocks(stocks);
                unmet = 0;
            } else {
                unmet = unmet.wrapping_sub(*canned);
                *canned = 0;
                verify_stocks(stocks);
            }

            if unmet != 0 {
                let before = unmet;
                food.substitute_surpluses(&mut unmet);
                substituted = before.wrapping_sub(unmet);
            }
        }

        food.write_back(stocks);

        let starvation = if unmet != 0 {
            let mut lost = LaborPool::default();
            self.baseline_mut()?
                .transfer_low_skill_first(&mut lost, unmet);
            self.count = self.count.wrapping_sub(unmet);
            self.count_float_bits = (self.count_float() - f32::from(unmet)).to_bits();
            unmet.max(0)
        } else {
            0
        };

        let baseline = *self.baseline()?;
        *self.production_mut()? = baseline;
        if substituted != 0 {
            let production = self
                .production_labor
                .as_mut()
                .expect("labor-pool presence was checked above");
            let pending = self
                .pending_labor_delta
                .as_mut()
                .expect("labor-pool presence was checked above");
            production.transfer_low_skill_first(pending, substituted);
        }

        Ok(FoodOutcome {
            substitution_count: substituted,
            starvation_count: starvation,
        })
    }

    fn forecast_food(&self, available: &[i16], canned_food: i16) -> FoodOutcome {
        let mut food = FoodRemainders {
            grain: available[GRAIN_RESOURCE_ID],
            fruit: available[FRUIT_RESOURCE_ID],
            animal: available[FISH_RESOURCE_ID].wrapping_add(available[LIVESTOCK_RESOURCE_ID]),
            original_fish: available[FISH_RESOURCE_ID],
            original_livestock: available[LIVESTOCK_RESOURCE_ID],
        };
        let mut unmet = food.consume_normal_needs(self.count);
        let mut substitution = 0;

        if unmet != 0 {
            if unmet < canned_food {
                unmet = 0;
            } else {
                unmet = unmet.wrapping_sub(canned_food);
            }
            if unmet != 0 {
                let before = unmet;
                food.substitute_surpluses(&mut unmet);
                substitution = before.wrapping_sub(unmet);
            }
        }

        FoodOutcome {
            substitution_count: substitution,
            starvation_count: unmet.max(0),
        }
    }

    fn baseline(&self) -> Result<&LaborPool, PopulationError> {
        self.baseline_labor
            .as_ref()
            .ok_or(PopulationError::MissingLaborPool("baseline labor pool"))
    }

    fn baseline_mut(&mut self) -> Result<&mut LaborPool, PopulationError> {
        self.baseline_labor
            .as_mut()
            .ok_or(PopulationError::MissingLaborPool("baseline labor pool"))
    }

    fn production_mut(&mut self) -> Result<&mut LaborPool, PopulationError> {
        self.production_labor
            .as_mut()
            .ok_or(PopulationError::MissingLaborPool("production labor pool"))
    }

    fn production(&self) -> Result<&LaborPool, PopulationError> {
        self.production_labor
            .as_ref()
            .ok_or(PopulationError::MissingLaborPool("production labor pool"))
    }

    fn pending_mut(&mut self) -> Result<&mut LaborPool, PopulationError> {
        self.pending_labor_delta
            .as_mut()
            .ok_or(PopulationError::MissingLaborPool("pending labor pool"))
    }

    fn pending(&self) -> Result<&LaborPool, PopulationError> {
        self.pending_labor_delta
            .as_ref()
            .ok_or(PopulationError::MissingLaborPool("pending labor pool"))
    }

    fn require_labor_pools(&self) -> Result<(), PopulationError> {
        self.baseline()?;
        self.production()?;
        self.pending()?;
        Ok(())
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
    fn from_city_stocks(stocks: &[i16]) -> Self {
        Self {
            grain: stocks[GRAIN_RESOURCE_ID],
            fruit: stocks[FRUIT_RESOURCE_ID],
            animal: stocks[FISH_RESOURCE_ID].wrapping_add(stocks[LIVESTOCK_RESOURCE_ID]),
            original_fish: stocks[FISH_RESOURCE_ID],
            original_livestock: stocks[LIVESTOCK_RESOURCE_ID],
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

    fn write_back(self, stocks: &mut [i16]) {
        stocks[GRAIN_RESOURCE_ID] = self.grain;
        verify_stocks(stocks);
        stocks[FRUIT_RESOURCE_ID] = self.fruit;
        verify_stocks(stocks);

        if self.animal == 0 {
            stocks[LIVESTOCK_RESOURCE_ID] = 0;
            verify_stocks(stocks);
            stocks[FISH_RESOURCE_ID] = 0;
            verify_stocks(stocks);
            return;
        }

        let mut livestock = if self.animal & 1 != 0 {
            self.animal / 2 + 1
        } else {
            self.animal / 2
        };
        let mut fish = if self.animal & 1 != 0 {
            livestock.wrapping_sub(1)
        } else {
            livestock
        };
        if self.original_livestock < livestock {
            let shift = livestock.wrapping_sub(self.original_livestock);
            livestock = livestock.wrapping_sub(shift);
            fish = fish.wrapping_add(shift);
        } else if self.original_fish < fish {
            let shift = fish.wrapping_sub(self.original_fish);
            fish = fish.wrapping_sub(shift);
            livestock = livestock.wrapping_add(shift);
        }
        stocks[LIVESTOCK_RESOURCE_ID] = livestock;
        verify_stocks(stocks);
        stocks[FISH_RESOURCE_ID] = fish;
        verify_stocks(stocks);
    }
}

fn validate_resource_slots(slots: &[i16]) -> Result<(), PopulationError> {
    if slots.len() == PREDICTED_NEED_RESOURCE_COUNT {
        Ok(())
    } else {
        Err(PopulationError::InvalidStockCount {
            actual: slots.len(),
        })
    }
}

fn verify_stocks(stocks: &mut [i16]) {
    for stock in stocks {
        if *stock < 0 {
            *stock = 0;
        }
    }
}

fn consume_need(remaining: &mut i16, need: i16, unmet: &mut i16) {
    if *remaining < need {
        *unmet = unmet.wrapping_add(need.wrapping_sub(*remaining));
        *remaining = 0;
    } else {
        *remaining = remaining.wrapping_sub(need);
    }
}

fn consume_surplus(remaining: &mut i16, unmet: &mut i16) {
    if *remaining < *unmet {
        *unmet = unmet.wrapping_sub(*remaining);
        *remaining = 0;
    } else {
        *remaining = remaining.wrapping_sub(*unmet);
        *unmet = 0;
    }
}

fn transfer_band(source: &mut i16, destination: &mut i16, remaining: &mut i16) {
    let moved = if *source < *remaining {
        *source
    } else {
        *remaining
    };
    *source = source.wrapping_sub(moved);
    *destination = destination.wrapping_add(moved);
    *remaining = remaining.wrapping_sub(moved);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NationId;

    fn population() -> PopulationState {
        PopulationState {
            count: 7,
            count_float_bits: 7.0_f32.to_bits(),
            strength: 12,
            extra: 5,
            phase_value: 3,
            baseline_labor: Some(LaborPool::new(4, 2, 1)),
            production_labor: Some(LaborPool::new(4, 2, 1)),
            pending_labor_delta: Some(LaborPool::new(1, -1, 2)),
            predicted_need_by_resource: vec![9; PREDICTED_NEED_RESOURCE_COUNT],
        }
    }

    fn city() -> CityState {
        let mut population = population();
        population.extra = 5;
        population.phase_value = 0;
        population.pending_labor_delta = Some(LaborPool::default());
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
            reserved_by_type: vec![0; PREDICTED_NEED_RESOURCE_COUNT],
            home_town_tile: 1,
            power_available: 0,
            stock_by_type: vec![0; PREDICTED_NEED_RESOURCE_COUNT],
            production_orders: vec![0; 16],
            production_accum: vec![0; 16],
            production_flags: vec![0; 16],
            production_current: vec![0; 16],
            production_progress: vec![0; 16],
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: vec![0; PREDICTED_NEED_RESOURCE_COUNT],
            consumed_production_input_by_type: vec![0; PREDICTED_NEED_RESOURCE_COUNT],
            population,
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
        city.stock_by_type[CANNED_FOOD_RESOURCE_ID] = canned;
        city.stock_by_type[GRAIN_RESOURCE_ID] = grain;
        city.stock_by_type[FRUIT_RESOURCE_ID] = fruit;
        city.stock_by_type[FISH_RESOURCE_ID] = fish;
        city.stock_by_type[LIVESTOCK_RESOURCE_ID] = livestock;
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
    fn initializes_all_population_bands_with_retail_short_arithmetic() {
        let mut state = population();
        state.set_population(i16::MAX, 2, 3).unwrap();
        assert_eq!(state.baseline_labor, Some(LaborPool::new(i16::MAX, 2, 3)));
        assert_eq!(state.production_labor, state.baseline_labor);
        assert_eq!(state.pending_labor_delta, Some(LaborPool::default()));
        assert_eq!(state.strength, i16::MIN.wrapping_add(15));
        assert_eq!(state.count, i16::MIN.wrapping_add(4));
        assert_eq!(state.count_float(), f32::from(state.count));
        assert_eq!(state.phase_value, 0);
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
        state.refresh_predicted_needs(2).unwrap();
        assert_eq!(state.predicted_need_by_resource[13], 0);
        assert_eq!(state.predicted_need_by_resource[14], 0);
        assert_eq!(state.predicted_need_by_resource[15], 0);
        assert_eq!(state.predicted_need_by_resource[17], 5);
        assert_eq!(state.predicted_need_by_resource[18], 2);
        assert_eq!(state.predicted_need_by_resource[20], 2);
        assert_eq!(state.predicted_need_by_resource[16], 9);
    }

    #[test]
    fn preserves_remove_population_overflow_branch_semantics() {
        let mut state = population();
        state.remove_population(SkillBand::Low, 5).unwrap();
        assert_eq!(state.baseline_labor, Some(LaborPool::new(0, 1, 1)));
        assert_eq!(state.production_labor, state.baseline_labor);
        assert_eq!(state.strength, 9);
        assert_eq!(state.count, 2);
        assert_eq!(state.count_float(), 2.0);
    }

    #[test]
    fn availability_and_additions_update_only_retail_fields() {
        let mut state = population();
        state.make_unavailable(SkillBand::Medium, 1).unwrap();
        state.add_untrained(2).unwrap();
        state.add_expert(1).unwrap();
        assert_eq!(state.baseline_labor, Some(LaborPool::new(6, 2, 2)));
        assert_eq!(state.production_labor, Some(LaborPool::new(6, 1, 2)));
        assert_eq!(state.count, 10);
        assert_eq!(state.count_float(), 7.0);
        assert_eq!(state.strength, 14);
    }

    #[test]
    fn consumes_each_required_food_without_substitution() {
        let mut state = city();
        stock_food(&mut state, 2, 4, 2, 1, 0);
        assert_eq!(
            state.consume_population_food().unwrap(),
            FoodOutcome::default()
        );
        assert_eq!(state.stock_by_type[CANNED_FOOD_RESOURCE_ID], 2);
        assert_eq!(state.stock_by_type[GRAIN_RESOURCE_ID], 0);
        assert_eq!(state.stock_by_type[FRUIT_RESOURCE_ID], 0);
        assert_eq!(state.stock_by_type[FISH_RESOURCE_ID], 0);
        assert_eq!(state.stock_by_type[LIVESTOCK_RESOURCE_ID], 0);
        assert_eq!(state.population.count, 7);
    }

    #[test]
    fn spends_canned_food_before_reassigning_workers() {
        let mut state = city();
        stock_food(&mut state, 2, 3, 2, 1, 0);
        assert_eq!(
            state.consume_population_food().unwrap(),
            FoodOutcome::default()
        );
        assert_eq!(state.stock_by_type[CANNED_FOOD_RESOURCE_ID], 1);
        assert_eq!(
            state.population.production_labor,
            state.population.baseline_labor
        );
        assert_eq!(
            state.population.pending_labor_delta,
            Some(LaborPool::default())
        );
    }

    #[test]
    fn substitutes_surplus_food_and_moves_low_skill_workers() {
        let mut state = city();
        stock_food(&mut state, 0, 3, 3, 1, 0);
        assert_eq!(
            state.consume_population_food().unwrap(),
            FoodOutcome {
                substitution_count: 1,
                starvation_count: 0,
            }
        );
        assert_eq!(state.food_substitution_count, 1);
        assert_eq!(
            state.population.production_labor,
            Some(LaborPool::new(3, 2, 1))
        );
        assert_eq!(
            state.population.pending_labor_delta,
            Some(LaborPool::new(1, 0, 0))
        );
    }

    #[test]
    fn starvation_removes_population_low_skill_first() {
        let mut state = city();
        assert_eq!(
            state.consume_population_food().unwrap(),
            FoodOutcome {
                substitution_count: 0,
                starvation_count: 7,
            }
        );
        assert_eq!(state.starvation_population_loss, 7);
        assert_eq!(state.population.count, 0);
        assert_eq!(state.population.count_float(), 0.0);
        assert_eq!(state.population.baseline_labor, Some(LaborPool::default()));
        assert_eq!(
            state.population.production_labor,
            Some(LaborPool::default())
        );
    }

    #[test]
    fn forecasts_food_without_mutating_city_or_population() {
        let mut state = city();
        stock_food(&mut state, 0, 99, 99, 99, 99);
        let before = state.clone();
        let mut targets = vec![0; PREDICTED_NEED_RESOURCE_COUNT];
        targets[GRAIN_RESOURCE_ID] = 3;
        targets[FRUIT_RESOURCE_ID] = 3;
        targets[FISH_RESOURCE_ID] = 1;
        assert_eq!(
            state.forecast_population_food(&targets).unwrap(),
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
        state.population.production_labor = Some(LaborPool::new(99, 99, 99));
        state.population.pending_labor_delta = Some(LaborPool::new(1, 0, 0));
        state.population.strength = -1;
        stock_food(&mut state, 0, 4, 2, 1, 0);
        state.start_production_phase().unwrap();
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
        state.population.baseline_labor = Some(LaborPool::new(0, 20, 0));
        state.population.phase_value = 2;
        state.stock_by_type[15] = 1;
        state.stock_by_type[13] = 1;
        state.stock_by_type[14] = 0;
        assert!(state.apply_population_strike().unwrap());
        assert_eq!(state.population.phase_value, 0);
        assert_eq!(state.stock_by_type[15], 1);
        assert_eq!(state.stock_by_type[13], 1);
        assert_eq!(state.stock_by_type[14], 0);
    }
}
