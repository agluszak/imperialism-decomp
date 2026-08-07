use serde::{Deserialize, Serialize};

macro_rules! id_type {
    ($name:ident, $value:ty) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name($value);

        impl $name {
            pub const fn new(value: $value) -> Self {
                Self(value)
            }

            pub const fn get(self) -> $value {
                self.0
            }
        }
    };
}

id_type!(NationId, u8);
id_type!(TileId, u16);
id_type!(ProvinceId, u16);
id_type!(CityId, u16);
id_type!(ArmyId, u32);
id_type!(NavyId, u32);
id_type!(MissionId, u32);
id_type!(MilitaryUnitId, u32);
id_type!(CivilianUnitId, u32);
id_type!(ShipId, u32);
id_type!(TaskForceId, u32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_preserve_their_storage_widths() {
        assert_eq!(NationId::new(6).get(), 6);
        assert_eq!(TileId::new(6479).get(), 6479);
        assert_eq!(ArmyId::new(70_000).get(), 70_000);
    }
}
