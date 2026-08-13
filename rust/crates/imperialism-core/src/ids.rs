use serde::{Deserialize, Serialize};

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

    pub fn all() -> impl ExactSizeIterator<Item = Self> {
        (0..Self::COUNT).map(Self::new)
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

    const fn try_new(value: u8) -> Option<Self> {
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

    pub fn all() -> impl ExactSizeIterator<Item = Self> {
        (0..Self::COUNT).map(Self::new)
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

    const fn try_new(value: u8) -> Option<Self> {
        if value >= Self::FIRST && value < NationId::COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn nation(self) -> NationId {
        NationId::new(self.0)
    }

    pub const fn get(self) -> u8 {
        self.0
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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TileId(u16);

impl TileId {
    pub const COUNT: u16 = 6_480;

    pub const fn new(value: u16) -> Self {
        assert!(value < Self::COUNT, "strategic tile ID is out of range");
        Self(value)
    }

    pub const fn try_new(value: u16) -> Option<Self> {
        if value < Self::COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }

    pub(crate) const fn from_index_unchecked(value: u16) -> Self {
        Self(value)
    }
}

impl<'de> Deserialize<'de> for TileId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::try_new(value).ok_or_else(|| {
            serde::de::Error::custom(format_args!("strategic tile ID {value} is out of range"))
        })
    }
}
// A strategic-tile ownership context. Values above the nation range identify
// non-nation map contexts, so this deliberately is not a NationId.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TileOwnerTag(u8);

impl TileOwnerTag {
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub const fn from_nation(nation: NationId) -> Self {
        Self(nation.get())
    }

    pub const fn nation(self) -> Option<NationId> {
        NationId::try_new(self.0)
    }

    pub const fn is_claimed_nation(self) -> bool {
        self.0 < NationId::COUNT
    }
}
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProvinceId(u16);

impl ProvinceId {
    pub const COUNT: u16 = 0x180;

    pub const fn new(value: u16) -> Self {
        assert!(value < Self::COUNT, "province ID is out of range");
        Self(value)
    }

    pub const fn try_new(value: u16) -> Option<Self> {
        if value < Self::COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for ProvinceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::try_new(value).ok_or_else(|| {
            serde::de::Error::custom(format_args!("province ID {value} is out of range"))
        })
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MilitaryUnitId(i32);

impl MilitaryUnitId {
    /// Rehydrates the persistent identity retained by a serialized game state.
    pub const fn from_serialized(value: i32) -> Self {
        Self(value)
    }

    pub(crate) const fn new(value: i32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> i32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CivilianUnitId(i32);

impl CivilianUnitId {
    /// Rehydrates the persistent identity retained by a serialized game state.
    pub const fn from_serialized(value: i32) -> Self {
        Self(value)
    }

    pub(crate) const fn new(value: i32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> i32 {
        self.0
    }
}

/// Zero-based ordinal in the retail ocean manager's shared sea/port-zone table.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OceanZoneId(u16);

impl OceanZoneId {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Snapshot-local position in the authoritative ship-list order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShipId(u32);

impl ShipId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Snapshot-local position in the authoritative task-force queue order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TaskForceId(u32);

impl TaskForceId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}
