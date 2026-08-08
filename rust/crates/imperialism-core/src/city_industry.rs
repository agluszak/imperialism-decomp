use crate::{CityState, RngState};

const INDUSTRY_ACTION_COUNT: usize = 14;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IndustryActionSlot(u8);

impl IndustryActionSlot {
    pub const COUNT: usize = INDUSTRY_ACTION_COUNT;
    pub const ALL: [Self; Self::COUNT] = [
        Self(0),
        Self(1),
        Self(2),
        Self(3),
        Self(4),
        Self(5),
        Self(6),
        Self(7),
        Self(8),
        Self(9),
        Self(10),
        Self(11),
        Self(12),
        Self(13),
    ];

    pub const fn new(value: u8) -> Option<Self> {
        if (value as usize) < Self::COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IndustryActionWeights {
    random_draw_block: i16,
    allocation: i16,
    average: i16,
}

// Columns 0, 5, and 7 from g_NavyOrderResourceDescriptorTable. These are the
// only columns read by TCity's 14-slot weighted-resource methods.
const ACTION_WEIGHTS: [IndustryActionWeights; INDUSTRY_ACTION_COUNT] = [
    weights(0, 0, 0),
    weights(0, 2, 1),
    weights(0, 4, 1),
    weights(300, 0, 3),
    weights(600, 0, 2),
    weights(0, 8, 1),
    weights(0, 4, 1),
    weights(300, 0, 5),
    weights(500, 0, 3),
    weights(1000, 0, 4),
    weights(0, 16, 1),
    weights(600, 0, 6),
    weights(2000, 0, 5),
    weights(1800, 0, 6),
];

const fn weights(random_draw_block: i16, allocation: i16, average: i16) -> IndustryActionWeights {
    IndustryActionWeights {
        random_draw_block,
        allocation,
        average,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CityIndustryError {
    #[error("{field} has {actual} entries, expected {INDUSTRY_ACTION_COUNT}")]
    InvalidActionCount { field: &'static str, actual: usize },
    #[error("positive action total has no selectable action")]
    NoSelectableAction,
}

impl CityState {
    pub fn average_descriptor_weight_times_ten(&self) -> Result<i32, CityIndustryError> {
        self.weighted_average_times_ten(false)
    }

    pub fn average_allocation_weight_times_ten(&self) -> Result<i32, CityIndustryError> {
        self.weighted_average_times_ten(true)
    }

    pub fn allocate_random_resource_counts(
        &mut self,
        max_weight: i16,
        output_counts: &mut [i16],
        rng: &mut RngState,
    ) -> Result<i32, CityIndustryError> {
        validate_action_table("city industry action counts", &self.order_count_by_type)?;
        validate_action_table("allocated industry action counts", output_counts)?;

        let mut allocated_weight = 0_i32;
        let mut remaining = 0_i16;
        for slot in IndustryActionSlot::ALL {
            if action_weights(slot).random_draw_block == 0 {
                remaining = remaining.wrapping_add(self.order_count_by_type[slot.index()]);
            }
        }

        while remaining > 0 && (allocated_weight as i16) < max_weight {
            let mut roll = rng.next_crt_rand() % i32::from(remaining) + 1;
            let mut selected = None;
            for slot in IndustryActionSlot::ALL {
                if action_weights(slot).random_draw_block == 0 {
                    roll -= i32::from(self.order_count_by_type[slot.index()]);
                    if roll < 1 {
                        selected = Some(slot);
                        break;
                    }
                }
            }
            let selected = selected.ok_or(CityIndustryError::NoSelectableAction)?;
            let weight = action_weights(selected).allocation;
            if max_weight < weight
                && i32::from(weight) - 1 < rng.next_crt_rand() % i32::from(max_weight)
            {
                break;
            }

            let index = selected.index();
            output_counts[index] = output_counts[index].wrapping_add(1);
            self.order_count_by_type[index] = self.order_count_by_type[index].wrapping_sub(1);
            allocated_weight = allocated_weight.wrapping_add(i32::from(weight));
            remaining = remaining.wrapping_sub(1);
        }

        if (allocated_weight as i16) >= max_weight {
            Ok(i32::from(max_weight))
        } else {
            Ok(allocated_weight)
        }
    }

    fn weighted_average_times_ten(
        &self,
        allocation_column: bool,
    ) -> Result<i32, CityIndustryError> {
        validate_action_table("city industry action counts", &self.order_count_by_type)?;
        let mut weighted_sum = 0_i32;
        let mut total_count = 0_i32;
        for slot in IndustryActionSlot::ALL {
            let count = self.order_count_by_type[slot.index()];
            let weights = action_weights(slot);
            let weight = if allocation_column {
                weights.allocation
            } else {
                weights.average
            };
            weighted_sum = weighted_sum.wrapping_add(i32::from(weight) * i32::from(count));
            total_count = total_count.wrapping_add(i32::from(count));
        }

        if total_count == 0 {
            return Ok(i32::from(allocation_column));
        }
        let scaled = weighted_sum.wrapping_mul(10);
        if allocation_column {
            Ok(scaled.wrapping_add(total_count / 2) / total_count)
        } else {
            Ok(scaled / total_count)
        }
    }
}

const fn action_weights(slot: IndustryActionSlot) -> IndustryActionWeights {
    ACTION_WEIGHTS[slot.index()]
}

fn validate_action_table<T>(field: &'static str, values: &[T]) -> Result<(), CityIndustryError> {
    if values.len() == INDUSTRY_ACTION_COUNT {
        Ok(())
    } else {
        Err(CityIndustryError::InvalidActionCount {
            field,
            actual: values.len(),
        })
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
            order_count_by_type: [0; IndustryActionSlot::COUNT],
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

    #[test]
    fn validates_the_retail_industry_action_range() {
        assert_eq!(IndustryActionSlot::new(0).unwrap().get(), 0);
        assert_eq!(IndustryActionSlot::new(13).unwrap().get(), 13);
        assert_eq!(IndustryActionSlot::new(14), None);
        assert_eq!(IndustryActionSlot::ALL.len(), IndustryActionSlot::COUNT);
    }

    #[test]
    fn computes_both_retail_weighted_average_variants() {
        let mut state = city();
        assert_eq!(state.average_descriptor_weight_times_ten().unwrap(), 0);
        assert_eq!(state.average_allocation_weight_times_ten().unwrap(), 1);

        state.order_count_by_type[1] = 1;
        state.order_count_by_type[2] = 2;
        assert_eq!(state.average_descriptor_weight_times_ten().unwrap(), 10);
        assert_eq!(state.average_allocation_weight_times_ten().unwrap(), 33);
    }

    #[test]
    fn allocation_skips_blocked_rows_and_consumes_the_exact_crt_stream() {
        let mut state = city();
        state.order_count_by_type[1] = 3;
        state.order_count_by_type[3] = 100;
        let mut output = [0_i16; IndustryActionSlot::COUNT];
        let mut rng = RngState {
            crt_rand: 1,
            map_generation: 2,
            zone_status: 3,
        };

        assert_eq!(
            state
                .allocate_random_resource_counts(5, &mut output, &mut rng)
                .unwrap(),
            5
        );
        assert_eq!(output[1], 3);
        assert_eq!(output[3], 0);
        assert_eq!(state.order_count_by_type[1], 0);
        assert_eq!(state.order_count_by_type[3], 100);
        assert_eq!(rng.crt_rand, 415_139_642);
        assert_eq!(rng.map_generation, 2);
        assert_eq!(rng.zone_status, 3);
    }

    #[test]
    fn zero_budget_leaves_counts_and_rng_untouched() {
        let mut state = city();
        state.order_count_by_type[1] = 1;
        let mut output = [0_i16; IndustryActionSlot::COUNT];
        let mut rng = RngState {
            crt_rand: 1,
            map_generation: 2,
            zone_status: 3,
        };
        assert_eq!(
            state
                .allocate_random_resource_counts(0, &mut output, &mut rng)
                .unwrap(),
            0
        );
        assert_eq!(state.order_count_by_type[1], 1);
        assert_eq!(rng.crt_rand, 1);
    }
}
