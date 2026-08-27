use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, Debug, Enum, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Cotton = 0,
    Wool = 1,
    Timber = 2,
    Coal = 3,
    Iron = 4,
    Horses = 5,
    Oil = 6,
    Food = 7,
    Fabric = 8,
    Lumber = 9,
    Paper = 10,
    Steel = 11,
    Fuel = 12,
    Clothing = 13,
    Furniture = 14,
    Hardware = 15,
    Arms = 16,
    Grain = 17,
    Fruit = 18,
    Fish = 19,
    Livestock = 20,
    Gems = 21,
    Gold = 22,
}

pub type ResourceTable<T> = EnumMap<ResourceKind, T>;

impl ResourceKind {
    pub const LENGTH: usize = enum_map::enum_len::<Self>();

    pub const CITY_PRODUCTION: [Self; 10] = [
        Self::Food,
        Self::Fabric,
        Self::Lumber,
        Self::Paper,
        Self::Steel,
        Self::Fuel,
        Self::Clothing,
        Self::Furniture,
        Self::Hardware,
        Self::Arms,
    ];

    pub const INDUSTRIAL_RAW: [Self; 5] = [
        Self::Timber,
        Self::Coal,
        Self::Iron,
        Self::Horses,
        Self::Oil,
    ];

    pub fn from_index(index: u8) -> Option<Self> {
        (usize::from(index) < Self::LENGTH).then(|| Self::from_usize(usize::from(index)))
    }

    pub const fn retail(self) -> u8 {
        self as u8
    }
}

pub(crate) fn all_resources() -> impl ExactSizeIterator<Item = ResourceKind> {
    (0..ResourceKind::LENGTH).map(ResourceKind::from_usize)
}
