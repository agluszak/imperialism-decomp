use crate::{MajorNationId, NationId, ProductionSlot};
use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Serialize};
use std::ops::{Index, IndexMut};

pub const NATION_COUNT: usize = 23;
pub const MAJOR_NATION_COUNT: usize = 7;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct NationTable<T>([T; NATION_COUNT]);

impl<T> NationTable<T> {
    pub const fn from_array(values: [T; NATION_COUNT]) -> Self {
        Self(values)
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.0
    }

    pub fn get(&self, nation: NationId) -> Option<&T> {
        self.0.get(usize::from(nation.get()))
    }

    pub fn get_mut(&mut self, nation: NationId) -> Option<&mut T> {
        self.0.get_mut(usize::from(nation.get()))
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &T> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = &mut T> {
        self.0.iter_mut()
    }
}

impl<T: Default> Default for NationTable<T> {
    fn default() -> Self {
        Self(std::array::from_fn(|_| T::default()))
    }
}

impl<T> Index<NationId> for NationTable<T> {
    type Output = T;

    fn index(&self, nation: NationId) -> &Self::Output {
        &self.0[usize::from(nation.get())]
    }
}

impl<T> IndexMut<NationId> for NationTable<T> {
    fn index_mut(&mut self, nation: NationId) -> &mut Self::Output {
        &mut self.0[usize::from(nation.get())]
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MajorNationTable<T>([T; MAJOR_NATION_COUNT]);

impl<T> MajorNationTable<T> {
    pub const fn from_array(values: [T; MAJOR_NATION_COUNT]) -> Self {
        Self(values)
    }

    pub fn from_fn(mut function: impl FnMut(MajorNationId) -> T) -> Self {
        Self(std::array::from_fn(|index| {
            function(MajorNationId::new(index as u8))
        }))
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &T> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = &mut T> {
        self.0.iter_mut()
    }

    pub fn get(&self, nation: MajorNationId) -> Option<&T> {
        self.0.get(usize::from(nation.get()))
    }

    pub fn get_mut(&mut self, nation: MajorNationId) -> Option<&mut T> {
        self.0.get_mut(usize::from(nation.get()))
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<T> Index<MajorNationId> for MajorNationTable<T> {
    type Output = T;

    fn index(&self, nation: MajorNationId) -> &Self::Output {
        &self.0[usize::from(nation.get())]
    }
}

impl<T> IndexMut<MajorNationId> for MajorNationTable<T> {
    fn index_mut(&mut self, nation: MajorNationId) -> &mut Self::Output {
        &mut self.0[usize::from(nation.get())]
    }
}

impl<T: Default> Default for MajorNationTable<T> {
    fn default() -> Self {
        Self(std::array::from_fn(|_| T::default()))
    }
}

/// Zero-based entries in the retail reward-prompt string group `0x273a`.
#[derive(
    Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PendingActionKind {
    NavyGrowthReward,
    ArmyGrowthReward,
    OverseasDeveloperReward,
    VillageDevelopment,
    TownDevelopment,
    ShipyardIronworkingUpgrade,
    ConqueredCapitalArmoryUpgrade,
    UniversityExpansion,
    RailyardExpansion,
    AnnexedGreatPowerCapitalExpansion,
    ColonyMonumentMerchantCapacity,
    CouncilLeadMonument,
    ConquestMonumentArmory,
}

pub const PENDING_ACTION_COUNT: usize = PendingActionKind::LENGTH;
pub type PendingActionTable<T> = EnumMap<PendingActionKind, T>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProductionTable<T>([T; ProductionSlot::COUNT]);

impl<T> ProductionTable<T> {
    pub const fn from_array(values: [T; ProductionSlot::COUNT]) -> Self {
        Self(values)
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn fill(&mut self, value: T)
    where
        T: Clone,
    {
        self.0.fill(value);
    }
}

impl<T: Default> Default for ProductionTable<T> {
    fn default() -> Self {
        Self(std::array::from_fn(|_| T::default()))
    }
}

impl<T> Index<ProductionSlot> for ProductionTable<T> {
    type Output = T;

    fn index(&self, slot: ProductionSlot) -> &Self::Output {
        &self.0[slot.index()]
    }
}

impl<T> IndexMut<ProductionSlot> for ProductionTable<T> {
    fn index_mut(&mut self, slot: ProductionSlot) -> &mut Self::Output {
        &mut self.0[slot.index()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_keyed_by_domain_ids() {
        let mut nations = NationTable::default();
        nations[NationId::new(6)] = 7_i16;
        assert_eq!(nations[NationId::new(6)], 7);

        let mut production = ProductionTable::default();
        let slot = ProductionSlot::new(3).unwrap();
        production[slot] = 11_i16;
        assert_eq!(production[slot], 11);

        let mut pending = PendingActionTable::default();
        pending[PendingActionKind::UniversityExpansion] = 3_i16;
        assert_eq!(pending[PendingActionKind::UniversityExpansion], 3);

        let mut major_nations = MajorNationTable::from_fn(|nation| nation.get());
        major_nations[MajorNationId::new(6)] = 9;
        assert_eq!(major_nations[MajorNationId::new(6)], 9);
    }
}
