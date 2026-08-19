use crate::{CityState, RngState, ShipTypeTable};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ShipTypeWeights {
    random_draw_block: i32,
    allocation: i32,
    average: i32,
}

// Columns 0, 5, and 7 from g_NavyOrderResourceDescriptorTable. These are the
// only columns read by TCity's weighted ship-order methods.
const SHIP_TYPE_WEIGHTS: ShipTypeTable<ShipTypeWeights> = ShipTypeTable::from_array([
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

const fn weights(random_draw_block: i32, allocation: i32, average: i32) -> ShipTypeWeights {
    ShipTypeWeights {
        random_draw_block,
        allocation,
        average,
    }
}

impl CityState {
    pub(crate) fn merchant_capacity(&self) -> i32 {
        SHIP_TYPE_WEIGHTS
            .iter()
            .map(|(ship_type, weights)| {
                weights.allocation * self.ship_order_count_by_type[ship_type]
            })
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
        max_weight: i32,
        output_counts: &mut ShipTypeTable<i32>,
        rng: &mut RngState,
    ) -> i32 {
        let mut allocated_weight = 0_i32;
        let mut remaining: i32 = SHIP_TYPE_WEIGHTS
            .iter()
            .filter(|(_, weights)| weights.random_draw_block == 0)
            .map(|(ship_type, _)| i32::from(self.ship_order_count_by_type[ship_type]))
            .sum();
        let max_weight = i32::from(max_weight);

        while remaining > 0 && allocated_weight < max_weight {
            let mut roll = rng.next_crt_rand() % remaining + 1;
            let selected = SHIP_TYPE_WEIGHTS
                .iter()
                .find_map(|(ship_type, weights)| {
                    if weights.random_draw_block != 0 {
                        return None;
                    }
                    roll -= i32::from(self.ship_order_count_by_type[ship_type]);
                    (roll < 1).then_some(ship_type)
                })
                .expect("positive unblocked ship order count selects a ship type");
            let weight = i32::from(SHIP_TYPE_WEIGHTS[selected].allocation);
            if max_weight < weight && weight - 1 < rng.next_crt_rand() % max_weight {
                break;
            }

            output_counts[selected] += 1;
            self.ship_order_count_by_type[selected] -= 1;
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
        for (ship_type, weights) in SHIP_TYPE_WEIGHTS.iter() {
            let count = self.ship_order_count_by_type[ship_type];
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
    use crate::{RetailCrtRng, RetailLcg, ShipType, ShipTypeTable};

    fn city() -> CityState {
        crate::test_support::city()
    }

    #[test]
    fn computes_both_retail_weighted_average_variants() {
        let mut state = city();
        assert_eq!(state.average_descriptor_weight_times_ten(), 0);
        assert_eq!(state.average_allocation_weight_times_ten(), 1);

        state.ship_order_count_by_type[ShipType::Trader] = 1;
        state.ship_order_count_by_type[ShipType::Indiaman] = 2;
        assert_eq!(state.average_descriptor_weight_times_ten(), 10);
        assert_eq!(state.average_allocation_weight_times_ten(), 33);
    }

    #[test]
    fn allocation_skips_blocked_rows_and_consumes_the_exact_crt_stream() {
        let mut state = city();
        state.ship_order_count_by_type[ShipType::Trader] = 3;
        state.ship_order_count_by_type[ShipType::Frigate] = 100;
        let mut output = ShipTypeTable::default();
        let mut rng = RngState {
            crt_rand: RetailCrtRng::from_state(1),
            map_generation: RetailLcg::from_state(2),
            zone_status: RetailLcg::from_state(3),
        };

        assert_eq!(
            state.allocate_random_resource_counts(5, &mut output, &mut rng),
            5
        );
        assert_eq!(output[ShipType::Trader], 3);
        assert_eq!(output[ShipType::Frigate], 0);
        assert_eq!(state.ship_order_count_by_type[ShipType::Trader], 0);
        assert_eq!(state.ship_order_count_by_type[ShipType::Frigate], 100);
        assert_eq!(rng.crt_rand, RetailCrtRng::from_state(415_139_642));
        assert_eq!(rng.map_generation, RetailLcg::from_state(2));
        assert_eq!(rng.zone_status, RetailLcg::from_state(3));
    }

    #[test]
    fn zero_budget_leaves_counts_and_rng_untouched() {
        let mut state = city();
        state.ship_order_count_by_type[ShipType::Trader] = 1;
        let mut output = ShipTypeTable::default();
        let mut rng = RngState {
            crt_rand: RetailCrtRng::from_state(1),
            map_generation: RetailLcg::from_state(2),
            zone_status: RetailLcg::from_state(3),
        };
        assert_eq!(
            state.allocate_random_resource_counts(0, &mut output, &mut rng),
            0
        );
        assert_eq!(state.ship_order_count_by_type[ShipType::Trader], 1);
        assert_eq!(rng.crt_rand, RetailCrtRng::from_state(1));
    }
}
