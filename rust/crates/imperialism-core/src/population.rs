use crate::PopulationState;
use std::error::Error;
use std::fmt;

const PREDICTED_NEED_RESOURCE_COUNT: usize = 23;
const STRIKE_RESOURCE_IDS: [usize; 3] = [15, 13, 14];
const GRAIN_RESOURCE_ID: usize = 17;
const FRUIT_RESOURCE_ID: usize = 18;
const ANIMAL_FOOD_RESOURCE_ID: usize = 20;

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
}

impl fmt::Display for PopulationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLaborPool(name) => write!(formatter, "population is missing its {name}"),
            Self::InvalidPredictedNeedCount { actual } => write!(
                formatter,
                "population has {actual} predicted-need slots, expected {PREDICTED_NEED_RESOURCE_COUNT}"
            ),
        }
    }
}

impl Error for PopulationError {}

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

    fn pending_mut(&mut self) -> Result<&mut LaborPool, PopulationError> {
        self.pending_labor_delta
            .as_mut()
            .ok_or(PopulationError::MissingLaborPool("pending labor pool"))
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
}
