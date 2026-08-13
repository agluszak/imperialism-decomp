use crate::{CityFacilitySlot, MajorNationId, MinorNationId, NationId, ProvinceId, TileId};
use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Index, IndexMut};

pub const NATION_COUNT: usize = NationId::COUNT;
pub const MAJOR_NATION_COUNT: usize = MajorNationId::COUNT;
pub const MINOR_NATION_COUNT: usize = MinorNationId::COUNT;
pub const PROVINCE_COUNT: usize = ProvinceId::COUNT;

/// The fourteen entries in the retail shipyard descriptor table.
///
/// Their order is the zero-based index into the retail ship-name string group
/// `0x2716`; the first entry deliberately denotes no ship.
#[derive(
    Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ShipType {
    NoShip,
    Trader,
    Indiaman,
    Frigate,
    ShipOfTheLine,
    Paddlewheeler,
    Clipper,
    Raider,
    Ironclad,
    AdvancedIronclad,
    Freighter,
    ArmoredCruiser,
    Dreadnought,
    Battlecruiser,
}

impl ShipType {
    pub const LENGTH: usize = enum_map::enum_len::<Self>();

    pub fn from_index(index: u8) -> Option<Self> {
        (usize::from(index) < Self::LENGTH).then(|| Self::from_usize(usize::from(index)))
    }
}

pub type ShipTypeTable<T> = EnumMap<ShipType, T>;

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct NationTable<T>([T; NATION_COUNT]);

impl<T> NationTable<T> {
    pub const fn from_array(values: [T; NATION_COUNT]) -> Self {
        Self(values)
    }

    pub fn from_fn(mut function: impl FnMut(NationId) -> T) -> Self {
        Self(std::array::from_fn(|index| function(NationId::new(index))))
    }

    pub const fn as_array(&self) -> &[T; NATION_COUNT] {
        &self.0
    }

    pub fn enumerate(&self) -> impl Iterator<Item = (NationId, &T)> {
        self.0
            .iter()
            .enumerate()
            .map(|(index, value)| (NationId::new(index), value))
    }

    pub fn enumerate_mut(&mut self) -> impl Iterator<Item = (NationId, &mut T)> {
        self.0
            .iter_mut()
            .enumerate()
            .map(|(index, value)| (NationId::new(index), value))
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
        &self.0[nation.index()]
    }
}

impl<T> IndexMut<NationId> for NationTable<T> {
    fn index_mut(&mut self, nation: NationId) -> &mut Self::Output {
        &mut self.0[nation.index()]
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
        Self(std::array::from_fn(|index| {
            function(MajorNationId::new(index))
        }))
    }

    pub const fn as_array(&self) -> &[T; MAJOR_NATION_COUNT] {
        &self.0
    }

    pub fn enumerate(&self) -> impl Iterator<Item = (MajorNationId, &T)> {
        self.0
            .iter()
            .enumerate()
            .map(|(index, value)| (MajorNationId::new(index), value))
    }

    pub fn enumerate_mut(&mut self) -> impl Iterator<Item = (MajorNationId, &mut T)> {
        self.0
            .iter_mut()
            .enumerate()
            .map(|(index, value)| (MajorNationId::new(index), value))
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &T> {
        self.0.iter()
    }

    pub(crate) fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = &mut T> {
        self.0.iter_mut()
    }
}

impl<T> Index<MajorNationId> for MajorNationTable<T> {
    type Output = T;

    fn index(&self, nation: MajorNationId) -> &Self::Output {
        &self.0[nation.index()]
    }
}

impl<T> IndexMut<MajorNationId> for MajorNationTable<T> {
    fn index_mut(&mut self, nation: MajorNationId) -> &mut Self::Output {
        &mut self.0[nation.index()]
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

    pub(crate) fn from_fn(mut function: impl FnMut(MinorNationId) -> T) -> Self {
        Self(std::array::from_fn(|index| {
            function(MinorNationId::new(MinorNationId::FIRST + index))
        }))
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &T> {
        self.0.iter()
    }

    pub const fn as_array(&self) -> &[T; MINOR_NATION_COUNT] {
        &self.0
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

/// Fixed values stored in retail province-table order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvinceTable<T>(Box<[T; PROVINCE_COUNT]>);

impl<T> ProvinceTable<T> {
    pub fn from_array(values: [T; PROVINCE_COUNT]) -> Self {
        Self(Box::new(values))
    }

    pub fn from_fn(mut function: impl FnMut(ProvinceId) -> T) -> Self {
        Self::from_array(std::array::from_fn(|index| {
            function(ProvinceId::new(index))
        }))
    }

    pub fn as_array(&self) -> &[T; PROVINCE_COUNT] {
        &self.0
    }

    pub(crate) fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = &mut T> {
        self.0.iter_mut()
    }
}

impl<T: Default> Default for ProvinceTable<T> {
    fn default() -> Self {
        Self::from_array(std::array::from_fn(|_| T::default()))
    }
}

impl<T> Index<ProvinceId> for ProvinceTable<T> {
    type Output = T;

    fn index(&self, province: ProvinceId) -> &Self::Output {
        &self.0[province.index()]
    }
}

impl<T> IndexMut<ProvinceId> for ProvinceTable<T> {
    fn index_mut(&mut self, province: ProvinceId) -> &mut Self::Output {
        &mut self.0[province.index()]
    }
}

impl<T: Serialize> Serialize for ProvinceTable<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.0.iter())
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for ProvinceTable<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<T>::deserialize(deserializer)?;
        let actual = values.len();
        let values: [T; PROVINCE_COUNT] = values.try_into().map_err(|_| {
            serde::de::Error::invalid_length(actual, &"exactly 384 province entries")
        })?;
        Ok(Self::from_array(values))
    }
}

/// Fixed values stored in retail strategic-tile order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TileTable<T>(Box<[T; TileId::COUNT]>);

impl<T> TileTable<T> {
    pub fn from_vec(values: Vec<T>) -> Self {
        Self::from_boxed_slice(values.into_boxed_slice())
    }

    pub fn from_boxed_slice(values: Box<[T]>) -> Self {
        let actual = values.len();
        let values: Box<[T; TileId::COUNT]> = values.try_into().unwrap_or_else(|_| {
            panic!(
                "strategic map must have {} tiles, got {actual}",
                TileId::COUNT
            )
        });
        Self(values)
    }

    pub fn from_fn(function: impl FnMut(TileId) -> T) -> Self {
        Self::from_vec(TileId::all().map(function).collect())
    }

    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
        self.0.iter_mut()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }

    pub fn enumerate(&self) -> impl DoubleEndedIterator<Item = (TileId, &T)> + ExactSizeIterator {
        self.0
            .iter()
            .enumerate()
            .map(|(index, value)| (TileId::from_index_unchecked(index), value))
    }

    pub fn enumerate_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<Item = (TileId, &mut T)> + ExactSizeIterator {
        self.0
            .iter_mut()
            .enumerate()
            .map(|(index, value)| (TileId::from_index_unchecked(index), value))
    }
}

impl<T> From<Vec<T>> for TileTable<T> {
    fn from(values: Vec<T>) -> Self {
        Self::from_vec(values)
    }
}

impl<T> From<Box<[T]>> for TileTable<T> {
    fn from(values: Box<[T]>) -> Self {
        Self::from_boxed_slice(values)
    }
}

impl<T: Default> Default for TileTable<T> {
    fn default() -> Self {
        Self::from_fn(|_| T::default())
    }
}

impl<T> Index<TileId> for TileTable<T> {
    type Output = T;

    fn index(&self, tile: TileId) -> &Self::Output {
        &self.0[tile.index()]
    }
}

impl<T> IndexMut<TileId> for TileTable<T> {
    fn index_mut(&mut self, tile: TileId) -> &mut Self::Output {
        &mut self.0[tile.index()]
    }
}

impl<'a, T> IntoIterator for &'a TileTable<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut TileTable<T> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<T: Serialize> Serialize for TileTable<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.0.iter())
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for TileTable<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<T>::deserialize(deserializer)?;
        let actual = values.len();
        if actual != TileId::COUNT {
            return Err(serde::de::Error::invalid_length(
                actual,
                &"exactly 6480 strategic tile entries",
            ));
        }
        Ok(Self::from_vec(values))
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
impl PendingActionKind {
    pub const LENGTH: usize = enum_map::enum_len::<Self>();
}
pub const PENDING_ACTION_COUNT: usize = PendingActionKind::LENGTH;
pub type PendingActionTable<T> = EnumMap<PendingActionKind, T>;

pub type ProductionTable<T> = EnumMap<CityFacilitySlot, T>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ship_type_table_uses_the_retail_shipyard_order() {
        let indexes = ShipTypeTable::from_array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
        assert_eq!(indexes[ShipType::NoShip], 0);
        assert_eq!(indexes[ShipType::Trader], 1);
        assert_eq!(indexes[ShipType::Indiaman], 2);
        assert_eq!(indexes[ShipType::Frigate], 3);
        assert_eq!(indexes[ShipType::ShipOfTheLine], 4);
        assert_eq!(indexes[ShipType::Paddlewheeler], 5);
        assert_eq!(indexes[ShipType::Clipper], 6);
        assert_eq!(indexes[ShipType::Raider], 7);
        assert_eq!(indexes[ShipType::Ironclad], 8);
        assert_eq!(indexes[ShipType::AdvancedIronclad], 9);
        assert_eq!(indexes[ShipType::Freighter], 10);
        assert_eq!(indexes[ShipType::ArmoredCruiser], 11);
        assert_eq!(indexes[ShipType::Dreadnought], 12);
        assert_eq!(indexes[ShipType::Battlecruiser], 13);
    }
}
