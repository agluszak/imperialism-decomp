use crate::{CityFacilitySlot, MajorNationId, MinorNationId, NationId, ProvinceId};
use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Index, IndexMut};

pub const NATION_COUNT: usize = NationId::COUNT as usize;
pub const MAJOR_NATION_COUNT: usize = MajorNationId::COUNT as usize;
pub const MINOR_NATION_COUNT: usize = MinorNationId::COUNT as usize;
pub const PROVINCE_COUNT: usize = ProvinceId::COUNT as usize;

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

    pub const fn as_array(&self) -> &[T; NATION_COUNT] {
        &self.0
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
        Self(std::array::from_fn(|index| {
            function(MajorNationId::new(index as u8))
        }))
    }

    pub const fn as_array(&self) -> &[T; MAJOR_NATION_COUNT] {
        &self.0
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

    pub(crate) fn from_fn(mut function: impl FnMut(MinorNationId) -> T) -> Self {
        Self(std::array::from_fn(|index| {
            function(MinorNationId::new(MinorNationId::FIRST + index as u8))
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

    pub fn as_array(&self) -> &[T; PROVINCE_COUNT] {
        &self.0
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
        &self.0[usize::from(province.get())]
    }
}

impl<T> IndexMut<ProvinceId> for ProvinceTable<T> {
    fn index_mut(&mut self, province: ProvinceId) -> &mut Self::Output {
        &mut self.0[usize::from(province.get())]
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
