use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct NationId(usize);

impl NationId {
    pub const COUNT: usize = 23;

    pub const fn new(value: usize) -> Self {
        assert!(value < Self::COUNT, "nation ID is out of range");
        Self(value)
    }

    pub const fn try_new(value: usize) -> Option<Self> {
        if value < Self::COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn index(self) -> usize {
        self.0
    }

    pub fn all() -> impl DoubleEndedIterator<Item = Self> + ExactSizeIterator {
        (0..Self::COUNT).map(Self::new)
    }
}

impl<'de> Deserialize<'de> for NationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = usize::deserialize(deserializer)?;
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
pub struct MajorNationId(usize);

impl MajorNationId {
    pub const COUNT: usize = 7;

    pub const fn new(value: usize) -> Self {
        assert!(value < Self::COUNT, "major-nation ID is out of range");
        Self(value)
    }

    const fn try_new(value: usize) -> Option<Self> {
        if value < Self::COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn from_nation(nation: NationId) -> Option<Self> {
        Self::try_new(nation.index())
    }

    pub const fn index(self) -> usize {
        self.0
    }

    pub const fn nation(self) -> NationId {
        NationId::new(self.0)
    }

    pub fn all() -> impl DoubleEndedIterator<Item = Self> + ExactSizeIterator {
        (0..Self::COUNT).map(Self::new)
    }
}

impl<'de> Deserialize<'de> for MajorNationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = usize::deserialize(deserializer)?;
        Self::try_new(value).ok_or_else(|| {
            serde::de::Error::custom(format_args!("major-nation ID {value} is out of range"))
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MinorNationId(usize);

impl MinorNationId {
    pub(crate) const FIRST: usize = MajorNationId::COUNT;
    pub const COUNT: usize = NationId::COUNT - Self::FIRST;

    pub const fn new(value: usize) -> Self {
        assert!(
            value >= Self::FIRST && value < NationId::COUNT,
            "minor-nation ID is out of range"
        );
        Self(value)
    }

    const fn try_new(value: usize) -> Option<Self> {
        if value >= Self::FIRST && value < NationId::COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn from_nation(nation: NationId) -> Option<Self> {
        Self::try_new(nation.index())
    }

    pub const fn nation(self) -> NationId {
        NationId::new(self.0)
    }

    pub const fn index(self) -> usize {
        self.0
    }

    pub fn all() -> impl DoubleEndedIterator<Item = Self> + ExactSizeIterator {
        (Self::FIRST..NationId::COUNT).map(Self::new)
    }

    pub(crate) const fn table_index(self) -> usize {
        self.0 - Self::FIRST
    }
}

impl<'de> Deserialize<'de> for MinorNationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = usize::deserialize(deserializer)?;
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
pub struct TileId(usize);

impl TileId {
    pub const COUNT: usize = 6_480;

    pub const fn new(value: usize) -> Self {
        assert!(value < Self::COUNT, "strategic tile ID is out of range");
        Self(value)
    }

    pub const fn try_new(value: usize) -> Option<Self> {
        if value < Self::COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn index(self) -> usize {
        self.0
    }

    pub(crate) const fn from_index_unchecked(value: usize) -> Self {
        Self(value)
    }

    pub fn all() -> impl DoubleEndedIterator<Item = Self> + ExactSizeIterator {
        (0..Self::COUNT).map(Self::new)
    }
}

impl<'de> Deserialize<'de> for TileId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = usize::deserialize(deserializer)?;
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
        Self(nation.index() as u8)
    }

    pub const fn nation(self) -> Option<NationId> {
        NationId::try_new(self.0 as usize)
    }

    pub const fn is_claimed_nation(self) -> bool {
        self.nation().is_some()
    }

    pub const fn is_major_nation(self) -> bool {
        match self.nation() {
            Some(nation) => MajorNationId::from_nation(nation).is_some(),
            None => false,
        }
    }

    pub const fn is_minor_nation(self) -> bool {
        match self.nation() {
            Some(nation) => MinorNationId::from_nation(nation).is_some(),
            None => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProvinceId(usize);

impl ProvinceId {
    pub const COUNT: usize = 0x180;

    pub const fn new(value: usize) -> Self {
        assert!(value < Self::COUNT, "province ID is out of range");
        Self(value)
    }

    pub const fn try_new(value: usize) -> Option<Self> {
        if value < Self::COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn index(self) -> usize {
        self.0
    }

    pub fn all() -> impl DoubleEndedIterator<Item = Self> + ExactSizeIterator {
        (0..Self::COUNT).map(Self::new)
    }
}

impl<'de> Deserialize<'de> for ProvinceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = usize::deserialize(deserializer)?;
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
pub struct OceanZoneId(usize);

impl OceanZoneId {
    pub const fn new(value: usize) -> Self {
        Self(value)
    }

    pub const fn index(self) -> usize {
        self.0
    }
}

/// Snapshot-local position in the authoritative ship-list order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShipId(usize);

impl ShipId {
    pub const fn new(value: usize) -> Self {
        Self(value)
    }

    pub const fn index(self) -> usize {
        self.0
    }
}

/// Snapshot-local position in the authoritative task-force queue order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TaskForceId(usize);

impl TaskForceId {
    pub const fn new(value: usize) -> Self {
        Self(value)
    }

    pub const fn index(self) -> usize {
        self.0
    }
}
