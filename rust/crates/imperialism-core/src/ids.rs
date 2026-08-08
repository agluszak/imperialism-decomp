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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct NationId(u8);

impl NationId {
    pub const COUNT: u8 = 23;

    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub fn from_retail_slot(value: i64) -> Option<Self> {
        let slot = u8::try_from(value).ok()?;
        (slot < Self::COUNT).then_some(Self(slot))
    }
}

impl<'de> Deserialize<'de> for NationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        Self::from_retail_slot(value).ok_or_else(|| {
            serde::de::Error::custom(format_args!(
                "nation ID {value} is outside the retail range 0..={}",
                Self::COUNT - 1
            ))
        })
    }
}

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

    pub fn from_retail_slot(value: i64) -> Option<Self> {
        NationId::from_retail_slot(value).and_then(Self::from_nation)
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
        let value = i64::deserialize(deserializer)?;
        Self::from_retail_slot(value).ok_or_else(|| {
            serde::de::Error::custom(format_args!("major-nation ID {value} is out of range"))
        })
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
