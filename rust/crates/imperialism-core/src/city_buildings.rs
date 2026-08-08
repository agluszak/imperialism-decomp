use crate::{CityState, MajorNationState, PendingActionKind};

const PRODUCTION_SLOT_COUNT: usize = 16;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProductionSlot(u8);

impl ProductionSlot {
    pub const COUNT: usize = PRODUCTION_SLOT_COUNT;
    pub const TRANSPORT: Self = Self(14);
    pub const REGIONAL_POPULATION: Self = Self(15);

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
pub struct BuildingWindowState {
    pub flag: u8,
    pub current: i16,
    pub accumulated: i16,
}

impl CityState {
    pub fn set_building_window_state(&mut self, slot: ProductionSlot, state: BuildingWindowState) {
        self.production_flags[slot] = state.flag;
        self.production_current[slot] = state.current;
        self.production_progress[slot] = state.accumulated;
    }

    pub fn building_window_state(&self, slot: ProductionSlot) -> BuildingWindowState {
        BuildingWindowState {
            flag: self.production_flags[slot],
            current: self.production_current[slot],
            accumulated: self.production_progress[slot],
        }
    }

    pub const fn is_capacity_center(slot: ProductionSlot) -> bool {
        matches!(slot.index(), 0..=6 | 11)
    }

    pub fn max_building_capacity(
        &self,
        slot: ProductionSlot,
        owner: &MajorNationState,
        owned_region_count: i32,
    ) -> i16 {
        let index = slot.index();
        if slot == ProductionSlot::REGIONAL_POPULATION {
            return region_capacity(owner, owned_region_count);
        }

        let capacity = self.production_orders[slot];
        match index {
            0 | 2 | 4 | 6 => match capacity {
                0 => 2,
                2 => 4,
                4 => 8,
                _ => capacity.wrapping_add(8),
            },
            1 | 3 | 5 => match capacity {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => capacity.wrapping_add(4),
            },
            _ => capacity.wrapping_add(1),
        }
    }

    pub fn next_building_level(
        &self,
        slot: ProductionSlot,
        owner: &MajorNationState,
        owned_region_count: i32,
    ) -> u8 {
        let capacity = self.max_building_capacity(slot, owner, owned_region_count);
        if matches!(slot.index(), 1 | 3 | 5) {
            if capacity < 4 {
                1
            } else if capacity < 8 {
                2
            } else {
                u8::from(capacity > 15) + 3
            }
        } else if capacity < 8 {
            1
        } else if capacity < 16 {
            2
        } else {
            u8::from(capacity > 31) + 3
        }
    }

    pub fn building_type(
        &self,
        slot: ProductionSlot,
        owner: &MajorNationState,
        owned_region_count: i32,
    ) -> i16 {
        if slot == ProductionSlot::REGIONAL_POPULATION {
            region_capacity(owner, owned_region_count)
        } else {
            self.production_orders[slot]
        }
    }

    pub fn next_building_type(
        &self,
        slot: ProductionSlot,
        owner: &MajorNationState,
        owned_region_count: i32,
        active_nation_has_technology_15: bool,
    ) -> i16 {
        let building_type = self.building_type(slot, owner, owned_region_count);
        let status = &owner.pending_action_status;
        match slot.index() {
            0 | 2 | 4 => {
                if building_type == 0 {
                    0
                } else if building_type < 16 {
                    1
                } else {
                    i16::from(building_type >= 32) + 2
                }
            }
            1 | 3 | 5 => {
                if building_type == 0 {
                    0
                } else if building_type < 8 {
                    1
                } else {
                    i16::from(building_type >= 16) + 2
                }
            }
            6 | 11 => i16::from(building_type != 0),
            7 => i16::from(active_nation_has_technology_15) + 1,
            8 => {
                if status[PendingActionKind::ConquestMonumentArmory] == b'3' as i8 {
                    3
                } else {
                    i16::from(
                        status[PendingActionKind::ConqueredCapitalArmoryUpgrade] == b'3' as i8,
                    ) + 1
                }
            }
            10 => {
                if status[PendingActionKind::UniversityExpansion] < b'3' as i8 {
                    1
                } else {
                    i16::from(status[PendingActionKind::UniversityExpansion] != b'3' as i8) + 2
                }
            }
            14 => i16::from(status[PendingActionKind::RailyardExpansion] >= b'3' as i8) + 1,
            15 => {
                i16::from(
                    status[PendingActionKind::AnnexedGreatPowerCapitalExpansion] >= b'3' as i8,
                ) + 1
            }
            _ => 0,
        }
    }

    pub fn set_power_plant_upgrade(&mut self, treasury: &mut i32, enabled: bool) {
        if enabled && !self.power_plant_upgrade_queued {
            *treasury = treasury.wrapping_sub(5_000);
            self.power_plant_upgrade_queued = true;
        } else if !enabled && self.power_plant_upgrade_queued {
            *treasury = treasury.wrapping_add(5_000);
            self.power_plant_upgrade_queued = false;
        }
    }
}

fn region_capacity(owner: &MajorNationState, owned_region_count: i32) -> i16 {
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
            metrics_0e: [0; 30],
            metrics_4a: [0; 9],
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

    #[test]
    fn validates_the_retail_production_slot_range() {
        assert_eq!(ProductionSlot::new(0).unwrap().get(), 0);
        assert_eq!(ProductionSlot::new(15).unwrap().get(), 15);
        assert_eq!(ProductionSlot::new(16), None);
    }

    #[test]
    fn round_trips_building_window_state() {
        let mut state = city();
        let expected = BuildingWindowState {
            flag: 3,
            current: -2,
            accumulated: 17,
        };
        state.set_building_window_state(slot(11), expected);
        assert_eq!(state.building_window_state(slot(11)), expected);
    }

    #[test]
    fn identifies_only_the_retail_capacity_center_slots() {
        let actual: Vec<u8> = (0..ProductionSlot::COUNT as u8)
            .filter(|value| CityState::is_capacity_center(slot(*value)))
            .collect();
        assert_eq!(actual, vec![0, 1, 2, 3, 4, 5, 6, 11]);
    }

    #[test]
    fn advances_even_odd_and_linear_capacity_ladders() {
        let mut state = city();
        let owner = nation();

        for (current, expected) in [(0, 2), (2, 4), (4, 8), (5, 13)] {
            state.production_orders[slot(0)] = current;
            assert_eq!(state.max_building_capacity(slot(0), &owner, 0), expected);
        }
        for (current, expected) in [(0, 1), (1, 2), (2, 4), (3, 7)] {
            state.production_orders[slot(1)] = current;
            assert_eq!(state.max_building_capacity(slot(1), &owner, 0), expected);
        }
        state.production_orders[slot(9)] = 12;
        assert_eq!(state.max_building_capacity(slot(9), &owner, 0), 13);
    }

    #[test]
    fn derives_region_capacity_from_the_retail_status_threshold() {
        let state = city();
        let mut owner = nation();
        owner.pending_action_status[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
            b'2' as i8;
        assert_eq!(state.max_building_capacity(slot(15), &owner, 12), 3);
        owner.pending_action_status[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
            b'3' as i8;
        assert_eq!(state.max_building_capacity(slot(15), &owner, 12), 4);
        assert_eq!(state.max_building_capacity(slot(15), &owner, 2), 1);
    }

    #[test]
    fn classifies_next_building_levels_at_retail_boundaries() {
        let mut state = city();
        let owner = nation();
        for (current, expected) in [(0, 1), (4, 2), (8, 3), (24, 4)] {
            state.production_orders[slot(0)] = current;
            assert_eq!(state.next_building_level(slot(0), &owner, 0), expected);
        }
        for (current, expected) in [(0, 1), (2, 2), (4, 3), (12, 4)] {
            state.production_orders[slot(1)] = current;
            assert_eq!(state.next_building_level(slot(1), &owner, 0), expected);
        }
    }

    #[test]
    fn projects_building_types_from_orders_technology_and_action_status() {
        let mut state = city();
        let mut owner = nation();
        state.production_orders[slot(0)] = 32;
        state.production_orders[slot(1)] = 8;
        state.production_orders[slot(6)] = 1;
        assert_eq!(state.next_building_type(slot(0), &owner, 0, false), 3);
        assert_eq!(state.next_building_type(slot(1), &owner, 0, false), 2);
        assert_eq!(state.next_building_type(slot(6), &owner, 0, false), 1);
        assert_eq!(state.next_building_type(slot(7), &owner, 0, true), 2);

        owner.pending_action_status[PendingActionKind::ConquestMonumentArmory] = b'3' as i8;
        owner.pending_action_status[PendingActionKind::UniversityExpansion] = b'4' as i8;
        owner.pending_action_status[PendingActionKind::RailyardExpansion] = b'3' as i8;
        owner.pending_action_status[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
            b'3' as i8;
        assert_eq!(state.next_building_type(slot(8), &owner, 0, false), 3);
        assert_eq!(state.next_building_type(slot(10), &owner, 0, false), 3);
        assert_eq!(state.next_building_type(slot(14), &owner, 0, false), 2);
        assert_eq!(state.next_building_type(slot(15), &owner, 9, false), 2);
    }

    #[test]
    fn power_plant_upgrade_charges_and_refunds_only_on_transitions() {
        let mut state = city();
        let mut treasury = 10_000;
        state.set_power_plant_upgrade(&mut treasury, true);
        state.set_power_plant_upgrade(&mut treasury, true);
        assert_eq!(treasury, 5_000);
        assert!(state.power_plant_upgrade_queued);
        state.set_power_plant_upgrade(&mut treasury, false);
        state.set_power_plant_upgrade(&mut treasury, false);
        assert_eq!(treasury, 10_000);
        assert!(!state.power_plant_upgrade_queued);
    }
}
