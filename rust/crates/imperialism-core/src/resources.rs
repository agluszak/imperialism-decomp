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
        match self {
            Self::Cotton => 0,
            Self::Wool => 1,
            Self::Timber => 2,
            Self::Coal => 3,
            Self::Iron => 4,
            Self::Horses => 5,
            Self::Oil => 6,
            Self::Food => 7,
            Self::Fabric => 8,
            Self::Lumber => 9,
            Self::Paper => 10,
            Self::Steel => 11,
            Self::Fuel => 12,
            Self::Clothing => 13,
            Self::Furniture => 14,
            Self::Hardware => 15,
            Self::Arms => 16,
            Self::Grain => 17,
            Self::Fruit => 18,
            Self::Fish => 19,
            Self::Livestock => 20,
            Self::Gems => 21,
            Self::Gold => 22,
        }
    }
}

pub(crate) fn all_resources() -> impl ExactSizeIterator<Item = ResourceKind> {
    (0..ResourceKind::LENGTH).map(ResourceKind::from_usize)
}
