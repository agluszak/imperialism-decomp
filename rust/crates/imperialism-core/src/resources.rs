#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
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

impl ResourceKind {
    pub const COUNT: usize = 23;
    pub const PURCHASED_COUNT: usize = Self::Grain as usize;

    pub const fn index(self) -> usize {
        self as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_the_retail_resource_table_order() {
        assert_eq!(ResourceKind::Cotton.index(), 0);
        assert_eq!(ResourceKind::Food.index(), 7);
        assert_eq!(ResourceKind::Arms.index(), 16);
        assert_eq!(ResourceKind::Grain.index(), 17);
        assert_eq!(ResourceKind::Gold.index(), 22);
        assert_eq!(ResourceKind::COUNT, 23);
    }
}
