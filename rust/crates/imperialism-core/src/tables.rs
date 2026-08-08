use crate::{MajorNationId, MinorNationId, NationId, ProductionSlot};
use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Deserializer, Serialize, de};
use std::ops::{Index, IndexMut};

pub const NATION_COUNT: usize = NationId::COUNT as usize;
pub const MAJOR_NATION_COUNT: usize = MajorNationId::COUNT as usize;
pub const MINOR_NATION_COUNT: usize = MinorNationId::COUNT as usize;

pub const INDUSTRY_ACTION_SLOT_COUNT: usize = 14;

/// Fixed 14-slot industry-action counts. Slot names are not yet recovered.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct IndustryActionTable<T>([T; INDUSTRY_ACTION_SLOT_COUNT]);

impl<T> IndustryActionTable<T> {
    pub const fn from_array(values: [T; INDUSTRY_ACTION_SLOT_COUNT]) -> Self {
        Self(values)
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = (usize, &T)> {
        self.0.iter().enumerate()
    }

    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = (usize, &mut T)> {
        self.0.iter_mut().enumerate()
    }
}

impl<T: Default> Default for IndustryActionTable<T> {
    fn default() -> Self {
        Self(std::array::from_fn(|_| T::default()))
    }
}

impl<T> Index<usize> for IndustryActionTable<T> {
    type Output = T;

    fn index(&self, slot: usize) -> &Self::Output {
        &self.0[slot]
    }
}

impl<T> IndexMut<usize> for IndustryActionTable<T> {
    fn index_mut(&mut self, slot: usize) -> &mut Self::Output {
        &mut self.0[slot]
    }
}

/// Fixed capacities maintained for every major nation.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NationCapacities {
    pub available_merchant: i16,
    pub trade_offer: i16,
    pub transport: i16,
    pub reserved_transport: i16,
}

impl NationCapacities {
    pub const fn from_array(values: [i16; 4]) -> Self {
        Self {
            available_merchant: values[0],
            trade_offer: values[1],
            transport: values[2],
            reserved_transport: values[3],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct NationTable<T>([T; NATION_COUNT]);

impl<'de, T> Deserialize<'de> for NationTable<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Serde's generated fixed-array visitor keeps every decoded nation on
        // the call stack. NationState is intentionally substantial, so decode
        // the same JSON sequence into its natural heap-backed staging form.
        let values: [T; NATION_COUNT] =
            Vec::<T>::deserialize(deserializer)?
                .try_into()
                .map_err(|values: Vec<T>| {
                    de::Error::invalid_length(values.len(), &"a 23-entry nation table")
                })?;
        Ok(Self(values))
    }
}

impl<T> NationTable<T> {
    pub const fn from_array(values: [T; NATION_COUNT]) -> Self {
        Self(values)
    }

    pub fn from_fn(mut function: impl FnMut(NationId) -> T) -> Self {
        let mut ids = NationId::all();
        Self(std::array::from_fn(|_| {
            function(ids.next().expect("nation ID count matches table length"))
        }))
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.0
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &T> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = &mut T> {
        self.0.iter_mut()
    }

    pub fn iter_enumerated(&self) -> impl ExactSizeIterator<Item = (NationId, &T)> {
        self.0
            .iter()
            .enumerate()
            .map(|(index, value)| (NationId::new(index as u8), value))
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MajorNationTable<T>([T; MAJOR_NATION_COUNT]);

impl<T> MajorNationTable<T> {
    pub const fn from_array(values: [T; MAJOR_NATION_COUNT]) -> Self {
        Self(values)
    }

    pub fn from_fn(mut function: impl FnMut(MajorNationId) -> T) -> Self {
        let mut ids = MajorNationId::all();
        Self(std::array::from_fn(|_| {
            function(
                ids.next()
                    .expect("major-nation ID count matches table length"),
            )
        }))
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &T> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = &mut T> {
        self.0.iter_mut()
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn iter_enumerated(&self) -> impl ExactSizeIterator<Item = (MajorNationId, &T)> {
        self.0
            .iter()
            .enumerate()
            .map(|(index, value)| (MajorNationId::new(index as u8), value))
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MinorNationTable<T>([T; MINOR_NATION_COUNT]);

impl<T> MinorNationTable<T> {
    pub const fn from_array(values: [T; MINOR_NATION_COUNT]) -> Self {
        Self(values)
    }

    pub fn from_fn(mut function: impl FnMut(MinorNationId) -> T) -> Self {
        let mut ids = MinorNationId::all();
        Self(std::array::from_fn(|_| {
            function(
                ids.next()
                    .expect("minor-nation ID count matches table length"),
            )
        }))
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &T> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = &mut T> {
        self.0.iter_mut()
    }

    pub fn iter_enumerated(&self) -> impl ExactSizeIterator<Item = (MinorNationId, &T)> {
        self.0.iter().enumerate().map(|(index, value)| {
            (
                MinorNationId::new(MinorNationId::FIRST + index as u8),
                value,
            )
        })
    }
}

impl<T: Default> Default for MinorNationTable<T> {
    fn default() -> Self {
        Self(std::array::from_fn(|_| T::default()))
    }
}

impl<T> Index<MinorNationId> for MinorNationTable<T> {
    type Output = T;

    fn index(&self, nation: MinorNationId) -> &Self::Output {
        &self.0[nation.table_index()]
    }
}

impl<T> IndexMut<MinorNationId> for MinorNationTable<T> {
    fn index_mut(&mut self, nation: MinorNationId) -> &mut Self::Output {
        &mut self.0[nation.table_index()]
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

        let mut capacities = NationCapacities::from_array([0_i16, 0, 15, 11]);
        capacities.reserved_transport += 1;
        assert_eq!(capacities.reserved_transport, 12);

        let mut major_nations = MajorNationTable::from_fn(|nation| nation.get());
        major_nations[MajorNationId::new(6)] = 9;
        assert_eq!(major_nations[MajorNationId::new(6)], 9);

        let mut actions = IndustryActionTable::default();
        actions[1] = 4_i16;
        assert_eq!(actions[1], 4);
    }
}
