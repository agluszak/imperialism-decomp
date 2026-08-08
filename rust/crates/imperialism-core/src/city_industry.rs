use crate::{CityState, IndustryActionTable, RngState};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IndustryActionWeights {
    random_draw_block: i16,
    allocation: i16,
    average: i16,
}

// Columns 0, 5, and 7 from g_NavyOrderResourceDescriptorTable. These are the
// only columns read by TCity's 14-slot weighted-resource methods.
const ACTION_WEIGHTS: IndustryActionTable<IndustryActionWeights> =
    IndustryActionTable::from_array([
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
    ]);

const fn weights(random_draw_block: i16, allocation: i16, average: i16) -> IndustryActionWeights {
    IndustryActionWeights {
        random_draw_block,
        allocation,
        average,
    }
}

impl CityState {
    pub(crate) fn merchant_capacity(&self) -> i16 {
        ACTION_WEIGHTS
            .iter()
            .map(|(slot, weights)| weights.allocation * self.order_count_by_type[slot])
            .sum()
    }

    pub fn average_descriptor_weight_times_ten(&self) -> i32 {
        self.weighted_average_times_ten(false)
    }

    pub fn average_allocation_weight_times_ten(&self) -> i32 {
        self.weighted_average_times_ten(true)
    }

    pub fn allocate_random_resource_counts(
        &mut self,
        max_weight: i16,
        output_counts: &mut IndustryActionTable<i16>,
        rng: &mut RngState,
    ) -> i32 {
        let mut allocated_weight = 0_i32;
        let mut remaining: i32 = ACTION_WEIGHTS
            .iter()
            .filter(|(_, weights)| weights.random_draw_block == 0)
            .map(|(slot, _)| i32::from(self.order_count_by_type[slot]))
            .sum();
        let max_weight = i32::from(max_weight);

        while remaining > 0 && allocated_weight < max_weight {
            let mut roll = rng.next_crt_rand() % remaining + 1;
            let selected = ACTION_WEIGHTS
                .iter()
                .find_map(|(slot, weights)| {
                    if weights.random_draw_block != 0 {
                        return None;
                    }
                    roll -= i32::from(self.order_count_by_type[slot]);
                    (roll < 1).then_some(slot)
                })
                .expect("positive unblocked action count selects a slot");
            let weight = i32::from(ACTION_WEIGHTS[selected].allocation);
            if max_weight < weight && weight - 1 < rng.next_crt_rand() % max_weight {
                break;
            }

            output_counts[selected] += 1;
            self.order_count_by_type[selected] -= 1;
            allocated_weight += weight;
            remaining -= 1;
        }

        if allocated_weight >= max_weight {
            max_weight
        } else {
            allocated_weight
        }
    }

    fn weighted_average_times_ten(&self, allocation_column: bool) -> i32 {
        let mut weighted_sum = 0_i32;
        let mut total_count = 0_i32;
        for (slot, weights) in ACTION_WEIGHTS.iter() {
            let count = self.order_count_by_type[slot];
            let weight = if allocation_column {
                weights.allocation
            } else {
                weights.average
            };
            weighted_sum += i32::from(weight) * i32::from(count);
            total_count += i32::from(count);
        }

        if total_count == 0 {
            return i32::from(allocation_column);
        }
        let scaled = weighted_sum * 10;
        if allocation_column {
            (scaled + total_count / 2) / total_count
        } else {
            scaled / total_count
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RetailCrtRng, RetailLcg};

    fn city() -> CityState {
        crate::test_support::city()
    }

    #[test]
    fn computes_both_retail_weighted_average_variants() {
        let mut state = city();
        assert_eq!(state.average_descriptor_weight_times_ten(), 0);
        assert_eq!(state.average_allocation_weight_times_ten(), 1);

        state.order_count_by_type[1] = 1;
        state.order_count_by_type[2] = 2;
        assert_eq!(state.average_descriptor_weight_times_ten(), 10);
        assert_eq!(state.average_allocation_weight_times_ten(), 33);
    }

    #[test]
    fn allocation_skips_blocked_rows_and_consumes_the_exact_crt_stream() {
        let mut state = city();
        state.order_count_by_type[1] = 3;
        state.order_count_by_type[3] = 100;
        let mut output = IndustryActionTable::default();
        let mut rng = RngState {
            crt_rand: RetailCrtRng::from_state(1),
            map_generation: RetailLcg::from_state(2),
            zone_status: RetailLcg::from_state(3),
        };

        assert_eq!(
            state.allocate_random_resource_counts(5, &mut output, &mut rng),
            5
        );
        assert_eq!(output[1], 3);
        assert_eq!(output[3], 0);
        assert_eq!(state.order_count_by_type[1], 0);
        assert_eq!(state.order_count_by_type[3], 100);
        assert_eq!(rng.crt_rand, RetailCrtRng::from_state(415_139_642));
        assert_eq!(rng.map_generation, RetailLcg::from_state(2));
        assert_eq!(rng.zone_status, RetailLcg::from_state(3));
    }

    #[test]
    fn zero_budget_leaves_counts_and_rng_untouched() {
        let mut state = city();
        state.order_count_by_type[1] = 1;
        let mut output = IndustryActionTable::default();
        let mut rng = RngState {
            crt_rand: RetailCrtRng::from_state(1),
            map_generation: RetailLcg::from_state(2),
            zone_status: RetailLcg::from_state(3),
        };
        assert_eq!(
            state.allocate_random_resource_counts(0, &mut output, &mut rng),
            0
        );
        assert_eq!(state.order_count_by_type[1], 1);
        assert_eq!(rng.crt_rand, RetailCrtRng::from_state(1));
    }
}
