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
    pub const PURCHASED_COUNT: usize = Self::Grain as usize;

    pub fn from_index(index: u8) -> Option<Self> {
        (usize::from(index) < Self::LENGTH).then(|| Self::from_usize(usize::from(index)))
    }
}

pub fn all_resources() -> impl ExactSizeIterator<Item = ResourceKind> {
    (0..ResourceKind::LENGTH).map(ResourceKind::from_usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_the_retail_resource_table_order() {
        assert_eq!(ResourceKind::Cotton.into_usize(), 0);
        assert_eq!(ResourceKind::Food.into_usize(), 7);
        assert_eq!(ResourceKind::Arms.into_usize(), 16);
        assert_eq!(ResourceKind::Grain.into_usize(), 17);
        assert_eq!(ResourceKind::Gold.into_usize(), 22);
        assert_eq!(ResourceKind::LENGTH, 23);
        assert!(
            all_resources()
                .enumerate()
                .all(|(index, resource)| resource.into_usize() == index)
        );
    }

    #[test]
    fn resource_tables_have_one_value_for_every_kind() {
        let mut table = ResourceTable::<i16>::default();
        table[ResourceKind::Steel] = 7;
        assert_eq!(table.len(), ResourceKind::LENGTH);
        assert_eq!(table[ResourceKind::Steel], 7);
    }
}
