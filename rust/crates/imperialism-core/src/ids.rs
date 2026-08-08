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
        assert!(value < Self::COUNT, "nation ID is out of range");
        Self(value)
    }

    pub const fn try_new(value: u8) -> Option<Self> {
        if value < Self::COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub(crate) fn all() -> impl ExactSizeIterator<Item = Self> {
        (0..Self::COUNT).map(Self::new)
    }
}

impl TryFrom<u8> for NationId {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::try_new(value).ok_or(())
    }
}

impl<'de> Deserialize<'de> for NationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::try_new(value).ok_or_else(|| {
            serde::de::Error::custom(format_args!(
                "nation ID {value} is out of range 0..={}",
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

    pub const fn try_new(value: u8) -> Option<Self> {
        if value < Self::COUNT {
            Some(Self(value))
        } else {
            None
        }
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
        Self::try_new(value).ok_or_else(|| {
            serde::de::Error::custom(format_args!("major-nation ID {value} is out of range"))
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MinorNationId(u8);

impl MinorNationId {
    pub(crate) const FIRST: u8 = MajorNationId::COUNT;
    pub const COUNT: u8 = NationId::COUNT - Self::FIRST;

    pub const fn new(value: u8) -> Self {
        assert!(
            value >= Self::FIRST && value < NationId::COUNT,
            "minor-nation ID is out of range"
        );
        Self(value)
    }

    pub const fn try_new(value: u8) -> Option<Self> {
        if value >= Self::FIRST && value < NationId::COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn nation(self) -> NationId {
        NationId::new(self.0)
    }

    pub(crate) const fn table_index(self) -> usize {
        (self.0 - Self::FIRST) as usize
    }
}

impl<'de> Deserialize<'de> for MinorNationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::try_new(value).ok_or_else(|| {
            serde::de::Error::custom(format_args!(
                "minor-nation ID {value} is out of range {}..={}",
                Self::FIRST,
                NationId::COUNT - 1
            ))
        })
    }
}

id_type!(TileId, u16);
// A strategic-tile ownership context. Values above the nation range identify
// non-nation map contexts, so this deliberately is not a NationId.
id_type!(TileOwnerTag, u8);
id_type!(ProvinceId, u16);
id_type!(CityId, u16);
id_type!(ArmyId, u32);
id_type!(NavyId, u32);
id_type!(MissionId, u32);
id_type!(MilitaryUnitId, i32);
id_type!(CivilianUnitId, i32);
id_type!(ShipId, u32);
id_type!(TaskForceId, u32);
