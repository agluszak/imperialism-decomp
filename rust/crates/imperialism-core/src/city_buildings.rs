use crate::*;
use serde::{Deserialize, Serialize};

/// A fixed building position on the city production screen.
///
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum ProductionSlot {
    TextileMill,
    ClothingFactory,
    SteelMill,
    Metalworks,
    LumberMill,
    FurnitureFactory,
    OilRefinery,
    Shipyard,
    Armory,
    TradeSchool,
    University,
    PowerPlant,
    FoodProcessing,
    Warehouse,
    Transport,
    RegionalPopulation,
}

impl ProductionSlot {
    pub const COUNT: usize = 16;

    #[cfg(test)]
    pub(crate) const fn from_index(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::TextileMill),
            1 => Some(Self::ClothingFactory),
            2 => Some(Self::SteelMill),
            3 => Some(Self::Metalworks),
            4 => Some(Self::LumberMill),
            5 => Some(Self::FurnitureFactory),
            6 => Some(Self::OilRefinery),
            7 => Some(Self::Shipyard),
            8 => Some(Self::Armory),
            9 => Some(Self::TradeSchool),
            10 => Some(Self::University),
            11 => Some(Self::PowerPlant),
            12 => Some(Self::FoodProcessing),
            13 => Some(Self::Warehouse),
            14 => Some(Self::Transport),
            15 => Some(Self::RegionalPopulation),
            _ => None,
        }
    }

    pub(crate) const fn index(self) -> usize {
        self as usize
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
        matches!(
            slot,
            ProductionSlot::TextileMill
                | ProductionSlot::ClothingFactory
                | ProductionSlot::SteelMill
                | ProductionSlot::Metalworks
                | ProductionSlot::LumberMill
                | ProductionSlot::FurnitureFactory
                | ProductionSlot::OilRefinery
                | ProductionSlot::PowerPlant
        )
    }

    pub fn max_building_capacity(
        &self,
        slot: ProductionSlot,
        owner: &GreatPowerState,
        owned_region_count: i32,
    ) -> i16 {
        if slot == ProductionSlot::RegionalPopulation {
            return region_capacity(owner, owned_region_count);
        }

        let capacity = self.production_orders[slot];
        match slot {
            ProductionSlot::TextileMill
            | ProductionSlot::SteelMill
            | ProductionSlot::LumberMill
            | ProductionSlot::OilRefinery => match capacity {
                0 => 2,
                2 => 4,
                4 => 8,
                _ => capacity + 8,
            },
            ProductionSlot::ClothingFactory
            | ProductionSlot::Metalworks
            | ProductionSlot::FurnitureFactory => match capacity {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => capacity + 4,
            },
            _ => capacity + 1,
        }
    }

    pub fn next_building_level(
        &self,
        slot: ProductionSlot,
        owner: &GreatPowerState,
        owned_region_count: i32,
    ) -> u8 {
        let capacity = self.max_building_capacity(slot, owner, owned_region_count);
        if matches!(
            slot,
            ProductionSlot::ClothingFactory
                | ProductionSlot::Metalworks
                | ProductionSlot::FurnitureFactory
        ) {
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
        owner: &GreatPowerState,
        owned_region_count: i32,
    ) -> i16 {
        if slot == ProductionSlot::RegionalPopulation {
            region_capacity(owner, owned_region_count)
        } else {
            self.production_orders[slot]
        }
    }

    pub fn next_building_type(
        &self,
        slot: ProductionSlot,
        owner: &GreatPowerState,
        owned_region_count: i32,
        active_nation_has_technology_15: bool,
    ) -> i16 {
        let building_type = self.building_type(slot, owner, owned_region_count);
        let status = &owner.pending_actions;
        match slot {
            ProductionSlot::TextileMill
            | ProductionSlot::SteelMill
            | ProductionSlot::LumberMill => {
                if building_type == 0 {
                    0
                } else if building_type < 16 {
                    1
                } else {
                    i16::from(building_type >= 32) + 2
                }
            }
            ProductionSlot::ClothingFactory
            | ProductionSlot::Metalworks
            | ProductionSlot::FurnitureFactory => {
                if building_type == 0 {
                    0
                } else if building_type < 8 {
                    1
                } else {
                    i16::from(building_type >= 16) + 2
                }
            }
            ProductionSlot::OilRefinery | ProductionSlot::PowerPlant => {
                i16::from(building_type != 0)
            }
            ProductionSlot::Shipyard => i16::from(active_nation_has_technology_15) + 1,
            ProductionSlot::Armory => {
                if status[PendingActionKind::ConquestMonumentArmory].status()
                    == crate::PendingActionStatus::Level3
                {
                    3
                } else {
                    i16::from(
                        status[PendingActionKind::ConqueredCapitalArmoryUpgrade].status()
                            == crate::PendingActionStatus::Level3,
                    ) + 1
                }
            }
            ProductionSlot::University => {
                if status[PendingActionKind::UniversityExpansion].status()
                    < crate::PendingActionStatus::Level3
                {
                    1
                } else {
                    i16::from(
                        status[PendingActionKind::UniversityExpansion].status()
                            != crate::PendingActionStatus::Level3,
                    ) + 2
                }
            }
            ProductionSlot::Transport => {
                i16::from(
                    status[PendingActionKind::RailyardExpansion]
                        .status()
                        .has_reached(crate::PendingActionStatus::Level3),
                ) + 1
            }
            ProductionSlot::RegionalPopulation => {
                i16::from(
                    status[PendingActionKind::AnnexedGreatPowerCapitalExpansion]
                        .status()
                        .has_reached(crate::PendingActionStatus::Level3),
                ) + 1
            }
            _ => 0,
        }
    }

    pub(crate) fn set_power_plant_upgrade(&mut self, treasury: &mut i32, enabled: bool) {
        if enabled && !self.power_plant_upgrade_queued {
            *treasury -= 5_000;
            self.power_plant_upgrade_queued = true;
        } else if !enabled && self.power_plant_upgrade_queued {
            *treasury += 5_000;
            self.power_plant_upgrade_queued = false;
        }
    }
}

impl GameState {
    /// Records the retail building-window presence and client origin for one city.
    pub fn set_city_building_window_state(
        &mut self,
        nation: MajorNationId,
        slot: ProductionSlot,
        state: BuildingWindowState,
    ) {
        self.nations
            .city_mut(nation)
            .set_building_window_state(slot, state);
    }
}

fn region_capacity(owner: &GreatPowerState, owned_region_count: i32) -> i16 {
    let divisor = if owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion]
        .status()
        .has_reached(crate::PendingActionStatus::Level3)
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

    fn slot(value: u8) -> ProductionSlot {
        ProductionSlot::from_index(value).unwrap()
    }

    fn city() -> CityState {
        crate::test_support::city()
    }

    fn nation() -> GreatPowerState {
        crate::test_support::great_power_state()
    }

    #[test]
    fn validates_the_retail_production_slot_range() {
        assert_eq!(
            ProductionSlot::from_index(0),
            Some(ProductionSlot::TextileMill)
        );
        assert_eq!(
            ProductionSlot::from_index(15),
            Some(ProductionSlot::RegionalPopulation)
        );
        assert_eq!(ProductionSlot::from_index(16), None);
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
        owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
            crate::PendingActionState::new(crate::PendingActionStatus::Queued, None);
        assert_eq!(state.max_building_capacity(slot(15), &owner, 12), 3);
        owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
            crate::PendingActionState::new(crate::PendingActionStatus::Level3, None);
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

        owner.pending_actions[PendingActionKind::ConquestMonumentArmory] =
            crate::PendingActionState::new(crate::PendingActionStatus::Level3, None);
        owner.pending_actions[PendingActionKind::UniversityExpansion] =
            crate::PendingActionState::new(crate::PendingActionStatus::Level4, None);
        owner.pending_actions[PendingActionKind::RailyardExpansion] =
            crate::PendingActionState::new(crate::PendingActionStatus::Level3, None);
        owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
            crate::PendingActionState::new(crate::PendingActionStatus::Level3, None);
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
