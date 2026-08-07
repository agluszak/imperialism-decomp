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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MajorNationId(u8);

impl MajorNationId {
    pub const COUNT: u8 = 7;

    pub const fn new(value: u8) -> Self {
        assert!(value < Self::COUNT, "major-nation ID is out of range");
        Self(value)
    }

    pub const fn from_nation(nation: NationId) -> Option<Self> {
        if nation.get() < Self::COUNT {
            Some(Self(nation.get()))
        } else {
            None
        }
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub const fn nation(self) -> NationId {
        NationId::new(self.0)
    }
}

impl<'de> Deserialize<'de> for MajorNationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        if value < Self::COUNT {
            Ok(Self(value))
        } else {
            Err(serde::de::Error::custom(format_args!(
                "major-nation ID {value} is out of range"
            )))
        }
    }
}
id_type!(TileId, u16);
id_type!(ProvinceId, u16);
id_type!(CityId, u16);
id_type!(ArmyId, u32);
id_type!(NavyId, u32);
id_type!(MissionId, u32);
id_type!(MilitaryUnitId, i32);
id_type!(CivilianUnitId, i32);
id_type!(ShipId, u32);
id_type!(TaskForceId, u32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_preserve_their_storage_widths() {
        assert_eq!(NationId::new(6).get(), 6);
        assert_eq!(MajorNationId::new(6).get(), 6);
        assert_eq!(TileId::new(6479).get(), 6479);
        assert_eq!(ArmyId::new(70_000).get(), 70_000);
    }
}
