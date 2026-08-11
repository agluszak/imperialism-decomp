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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProductionTable<T>([T; CityFacilitySlot::COUNT]);

impl<T> ProductionTable<T> {
    pub const fn from_array(values: [T; CityFacilitySlot::COUNT]) -> Self {
        Self(values)
    }
}

impl<T: Default> Default for ProductionTable<T> {
    fn default() -> Self {
        Self(std::array::from_fn(|_| T::default()))
    }
}

impl<T> Index<CityFacilitySlot> for ProductionTable<T> {
    type Output = T;

    fn index(&self, slot: CityFacilitySlot) -> &Self::Output {
        &self.0[slot.index()]
    }
}

impl<T> IndexMut<CityFacilitySlot> for ProductionTable<T> {
    fn index_mut(&mut self, slot: CityFacilitySlot) -> &mut Self::Output {
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
        production[CityFacilitySlot::Metalworks] = 11_i16;
        assert_eq!(production[CityFacilitySlot::Metalworks], 11);

        let mut pending = PendingActionTable::default();
        pending[PendingActionKind::UniversityExpansion] = 3_i16;
        assert_eq!(pending[PendingActionKind::UniversityExpansion], 3);

        let mut capacities = NationCapacities::from_array([0_i16, 0, 15, 11]);
        capacities.reserved_transport += 1;
        assert_eq!(capacities.reserved_transport, 12);

        let mut major_nations = MajorNationTable::from_fn(|nation| nation.get());
        major_nations[MajorNationId::new(6)] = 9;
        assert_eq!(major_nations[MajorNationId::new(6)], 9);
    }

    #[test]
    fn nation_table_deserialization_requires_exact_length() {
        let too_short = serde_json::to_string(&vec![0_u8; NATION_COUNT - 1]).unwrap();
        let too_long = serde_json::to_string(&vec![0_u8; NATION_COUNT + 1]).unwrap();

        assert!(serde_json::from_str::<NationTable<u8>>(&too_short).is_err());
        assert!(serde_json::from_str::<NationTable<u8>>(&too_long).is_err());
    }

    #[test]
    fn province_table_deserialization_requires_exact_retail_length() {
        let too_short = serde_json::to_string(&vec![0_u8; PROVINCE_COUNT - 1]).unwrap();
        let exact = serde_json::to_string(&vec![0_u8; PROVINCE_COUNT]).unwrap();
        let too_long = serde_json::to_string(&vec![0_u8; PROVINCE_COUNT + 1]).unwrap();

        assert!(serde_json::from_str::<ProvinceTable<u8>>(&too_short).is_err());
        assert!(serde_json::from_str::<ProvinceTable<u8>>(&exact).is_ok());
        assert!(serde_json::from_str::<ProvinceTable<u8>>(&too_long).is_err());
    }

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
