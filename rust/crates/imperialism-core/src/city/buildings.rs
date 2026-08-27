use crate::*;
use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Serialize};

/// A fixed building position on the city production screen.
///
#[derive(
    Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum CityFacilitySlot {
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

/// The fourteen city facilities represented by retail's industry-capability array.
#[derive(Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, PartialEq, Serialize)]
#[repr(u8)]
pub enum IndustryCapabilitySlot {
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
}

pub type IndustryCapabilityTable<T> = EnumMap<IndustryCapabilitySlot, T>;

impl IndustryCapabilitySlot {
    pub const ALL: [Self; 14] = [
        Self::TextileMill,
        Self::ClothingFactory,
        Self::SteelMill,
        Self::Metalworks,
        Self::LumberMill,
        Self::FurnitureFactory,
        Self::OilRefinery,
        Self::Shipyard,
        Self::Armory,
        Self::TradeSchool,
        Self::University,
        Self::PowerPlant,
        Self::FoodProcessing,
        Self::Warehouse,
    ];

    pub const fn facility(self) -> CityFacilitySlot {
        match self {
            Self::TextileMill => CityFacilitySlot::TextileMill,
            Self::ClothingFactory => CityFacilitySlot::ClothingFactory,
            Self::SteelMill => CityFacilitySlot::SteelMill,
            Self::Metalworks => CityFacilitySlot::Metalworks,
            Self::LumberMill => CityFacilitySlot::LumberMill,
            Self::FurnitureFactory => CityFacilitySlot::FurnitureFactory,
            Self::OilRefinery => CityFacilitySlot::OilRefinery,
            Self::Shipyard => CityFacilitySlot::Shipyard,
            Self::Armory => CityFacilitySlot::Armory,
            Self::TradeSchool => CityFacilitySlot::TradeSchool,
            Self::University => CityFacilitySlot::University,
            Self::PowerPlant => CityFacilitySlot::PowerPlant,
            Self::FoodProcessing => CityFacilitySlot::FoodProcessing,
            Self::Warehouse => CityFacilitySlot::Warehouse,
        }
    }

    pub const fn retail(self) -> u8 {
        self as u8
    }
}

impl CityFacilitySlot {
    pub const COUNT: usize = enum_map::enum_len::<Self>();

    pub const fn retail(self) -> u8 {
        self as u8
    }

    pub fn from_index(value: u8) -> Option<Self> {
        let index = usize::from(value);
        (index < Self::COUNT).then(|| Self::from_usize(index))
    }

    pub const fn is_capacity_center(self) -> bool {
        matches!(
            self,
            Self::TextileMill
                | Self::ClothingFactory
                | Self::SteelMill
                | Self::Metalworks
                | Self::LumberMill
                | Self::FurnitureFactory
                | Self::OilRefinery
                | Self::PowerPlant
        )
    }
}

impl CityState {
    pub fn max_building_capacity(
        &self,
        slot: CityFacilitySlot,
        owner: &GreatPowerState,
        owned_region_count: usize,
    ) -> i16 {
        if slot == CityFacilitySlot::RegionalPopulation {
            return region_capacity(owner, owned_region_count);
        }

        let capacity = self.production_orders[slot];
        match slot {
            CityFacilitySlot::TextileMill
            | CityFacilitySlot::SteelMill
            | CityFacilitySlot::LumberMill
            | CityFacilitySlot::OilRefinery => match capacity {
                0 => 2,
                2 => 4,
                4 => 8,
                _ => capacity + 8,
            },
            CityFacilitySlot::ClothingFactory
            | CityFacilitySlot::Metalworks
            | CityFacilitySlot::FurnitureFactory => match capacity {
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
        slot: CityFacilitySlot,
        owner: &GreatPowerState,
        owned_region_count: usize,
    ) -> u8 {
        let capacity = self.max_building_capacity(slot, owner, owned_region_count);
        if matches!(
            slot,
            CityFacilitySlot::ClothingFactory
                | CityFacilitySlot::Metalworks
                | CityFacilitySlot::FurnitureFactory
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
        slot: CityFacilitySlot,
        owner: &GreatPowerState,
        owned_region_count: usize,
    ) -> i16 {
        if slot == CityFacilitySlot::RegionalPopulation {
            region_capacity(owner, owned_region_count)
        } else {
            self.production_orders[slot]
        }
    }

    pub fn next_building_type(
        &self,
        slot: CityFacilitySlot,
        owner: &GreatPowerState,
        owned_region_count: usize,
        active_nation_has_technology_15: bool,
    ) -> i16 {
        let building_type = self.building_type(slot, owner, owned_region_count);
        let status = &owner.pending_actions;
        match slot {
            CityFacilitySlot::TextileMill
            | CityFacilitySlot::SteelMill
            | CityFacilitySlot::LumberMill => {
                if building_type == 0 {
                    0
                } else if building_type < 16 {
                    1
                } else {
                    i16::from(building_type >= 32) + 2
                }
            }
            CityFacilitySlot::ClothingFactory
            | CityFacilitySlot::Metalworks
            | CityFacilitySlot::FurnitureFactory => {
                if building_type == 0 {
                    0
                } else if building_type < 8 {
                    1
                } else {
                    i16::from(building_type >= 16) + 2
                }
            }
            CityFacilitySlot::OilRefinery | CityFacilitySlot::PowerPlant => {
                i16::from(building_type != 0)
            }
            CityFacilitySlot::Shipyard => i16::from(active_nation_has_technology_15) + 1,
            CityFacilitySlot::Armory => {
                if status[PendingActionKind::ConquestMonumentArmory].status()
                    == crate::PendingActionStatus::HANDLED
                {
                    3
                } else {
                    i16::from(
                        status[PendingActionKind::ConqueredCapitalArmoryUpgrade].status()
                            == crate::PendingActionStatus::HANDLED,
                    ) + 1
                }
            }
            CityFacilitySlot::University => {
                if status[PendingActionKind::UniversityExpansion].status()
                    < crate::PendingActionStatus::HANDLED
                {
                    1
                } else {
                    i16::from(
                        status[PendingActionKind::UniversityExpansion].status()
                            != crate::PendingActionStatus::HANDLED,
                    ) + 2
                }
            }
            CityFacilitySlot::Transport => {
                i16::from(
                    status[PendingActionKind::RailyardExpansion]
                        .status()
                        .has_reached(crate::PendingActionStatus::HANDLED),
                ) + 1
            }
            CityFacilitySlot::RegionalPopulation => {
                i16::from(
                    status[PendingActionKind::AnnexedGreatPowerCapitalExpansion]
                        .status()
                        .has_reached(crate::PendingActionStatus::HANDLED),
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

fn region_capacity(owner: &GreatPowerState, owned_region_count: usize) -> i16 {
    let divisor = if owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion]
        .status()
        .has_reached(crate::PendingActionStatus::HANDLED)
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

    fn slot(value: u8) -> CityFacilitySlot {
        CityFacilitySlot::from_index(value).unwrap()
    }

    fn city() -> CityState {
        crate::test_support::city()
    }

    fn nation() -> GreatPowerState {
        crate::test_support::great_power_state()
    }

    #[test]
    fn identifies_only_the_retail_capacity_center_slots() {
        let actual: Vec<CityFacilitySlot> = (0..CityFacilitySlot::COUNT)
            .map(CityFacilitySlot::from_usize)
            .filter(|slot| slot.is_capacity_center())
            .collect();
        assert_eq!(
            actual,
            [
                CityFacilitySlot::TextileMill,
                CityFacilitySlot::ClothingFactory,
                CityFacilitySlot::SteelMill,
                CityFacilitySlot::Metalworks,
                CityFacilitySlot::LumberMill,
                CityFacilitySlot::FurnitureFactory,
                CityFacilitySlot::OilRefinery,
                CityFacilitySlot::PowerPlant,
            ]
        );
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
            crate::PendingActionState::new(crate::PendingActionStatus::QUEUED, None);
        assert_eq!(state.max_building_capacity(slot(15), &owner, 12), 3);
        owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
            crate::PendingActionState::new(crate::PendingActionStatus::HANDLED, None);
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
            crate::PendingActionState::new(crate::PendingActionStatus::HANDLED, None);
        owner.pending_actions[PendingActionKind::UniversityExpansion] =
            crate::PendingActionState::new(crate::PendingActionStatus::from_retail(0x34), None);
        owner.pending_actions[PendingActionKind::RailyardExpansion] =
            crate::PendingActionState::new(crate::PendingActionStatus::HANDLED, None);
        owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
            crate::PendingActionState::new(crate::PendingActionStatus::HANDLED, None);
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
