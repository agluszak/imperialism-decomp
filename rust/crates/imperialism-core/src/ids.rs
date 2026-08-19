use serde::{Deserialize, Serialize};

macro_rules! dense_id {
    ($name:ident, $count:expr, $label:literal) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(usize);

        impl $name {
            pub const COUNT: usize = $count;

            pub const fn new(value: usize) -> Self {
                assert!(value < Self::COUNT, concat!($label, " is out of range"));
                Self(value)
            }

            pub const fn try_new(value: usize) -> Option<Self> {
                if value < Self::COUNT {
                    Some(Self(value))
                } else {
                    None
                }
            }

            pub const fn get(self) -> usize {
                self.0
            }

            pub fn all() -> impl DoubleEndedIterator<Item = Self> + ExactSizeIterator {
                (0..Self::COUNT).map(Self::new)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = usize::deserialize(deserializer)?;
                Self::try_new(value).ok_or_else(|| {
                    serde::de::Error::custom(format_args!(
                        concat!($label, " {} is out of range"),
                        value
                    ))
                })
            }
        }
    };
}

dense_id!(MajorNationId, 7, "major-nation ID");
dense_id!(MinorNationId, 16, "minor-nation ID");
dense_id!(TileId, 6_480, "strategic tile ID");
dense_id!(ProvinceId, 0x180, "province ID");

impl From<MajorNationId> for NationId {
    fn from(id: MajorNationId) -> Self {
        Self::Major(id)
    }
}

impl From<MinorNationId> for NationId {
    fn from(id: MinorNationId) -> Self {
        Self::Minor(id)
    }
}

impl MajorNationId {
    pub const fn nation(self) -> NationId {
        NationId::Major(self)
    }
}

impl MinorNationId {
    pub const fn nation(self) -> NationId {
        NationId::Minor(self)
    }
}

impl TileId {
    pub(crate) const fn from_index_unchecked(value: usize) -> Self {
        Self(value)
    }
}

/// Semantic nation identity. Major and minor IDs are independently zero-based.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum NationId {
    Major(MajorNationId),
    Minor(MinorNationId),
}

impl NationId {
    pub const COUNT: usize = MajorNationId::COUNT + MinorNationId::COUNT;

    pub const fn as_major(self) -> Option<MajorNationId> {
        match self {
            Self::Major(id) => Some(id),
            Self::Minor(_) => None,
        }
    }

    pub const fn as_minor(self) -> Option<MinorNationId> {
        match self {
            Self::Minor(id) => Some(id),
            Self::Major(_) => None,
        }
    }

    pub fn expect_minor(self) -> MinorNationId {
        self.as_minor().expect("nation must be a minor")
    }

    pub fn majors() -> [Self; MajorNationId::COUNT] {
        std::array::from_fn(|index| Self::Major(MajorNationId::new(index)))
    }

    pub fn minors() -> [Self; MinorNationId::COUNT] {
        std::array::from_fn(|index| Self::Minor(MinorNationId::new(index)))
    }

    pub fn all() -> impl DoubleEndedIterator<Item = Self> {
        Self::majors().into_iter().chain(Self::minors())
    }

    /// Retail combined slot `0..23`. Format/oracle boundary only.
    pub const fn from_retail_slot(slot: u8) -> Option<Self> {
        let index = slot as usize;
        if index < MajorNationId::COUNT {
            Some(Self::Major(MajorNationId::new(index)))
        } else if index < Self::COUNT {
            Some(Self::Minor(MinorNationId::new(
                index - MajorNationId::COUNT,
            )))
        } else {
            None
        }
    }

    /// Retail combined slot `0..23`. Format/oracle boundary only.
    pub const fn retail_slot(self) -> u8 {
        match self {
            Self::Major(id) => id.get() as u8,
            Self::Minor(id) => (MajorNationId::COUNT + id.get()) as u8,
        }
    }
}

/// Ownership or map context of a strategic tile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum TileContext {
    Nation(NationId),
    Ocean(OceanZoneId),
    Unknown(i32),
}

impl From<NationId> for TileContext {
    fn from(nation: NationId) -> Self {
        Self::Nation(nation)
    }
}

impl From<MajorNationId> for TileContext {
    fn from(id: MajorNationId) -> Self {
        Self::Nation(id.nation())
    }
}

impl From<MinorNationId> for TileContext {
    fn from(id: MinorNationId) -> Self {
        Self::Nation(id.nation())
    }
}

impl TileContext {
    /// Retail owner byte: `0..23` is a nation, `23 + zone` is an ocean zone.
    pub const fn from_retail_tag(tag: u8) -> Self {
        match NationId::from_retail_slot(tag) {
            Some(nation) => Self::Nation(nation),
            None => Self::Ocean(OceanZoneId(tag as usize - NationId::COUNT)),
        }
    }

    /// Retail owner byte used by v62 saves and map generation traces.
    pub const fn to_retail_tag(self) -> u8 {
        match self {
            Self::Nation(nation) => nation.retail_slot(),
            Self::Ocean(zone) => (NationId::COUNT + zone.0) as u8,
            Self::Unknown(value) => value as u8,
        }
    }

    pub const fn nation(self) -> Option<NationId> {
        match self {
            Self::Nation(nation) => Some(nation),
            Self::Ocean(_) | Self::Unknown(_) => None,
        }
    }

    pub const fn ocean(self) -> Option<OceanZoneId> {
        match self {
            Self::Ocean(zone) => Some(zone),
            Self::Nation(_) | Self::Unknown(_) => None,
        }
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

/// Identity of an entry in the ocean manager's shared sea/port-zone table.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OceanZoneId(usize);

impl OceanZoneId {
    pub const fn new(value: usize) -> Self {
        Self(value)
    }

    pub const fn get(self) -> usize {
        self.0
    }
}

/// Stable identity of a ship. Retail ordinals are translated at the save boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShipId(pub(crate) u32);

impl ShipId {
    #[doc(hidden)]
    pub const fn new(value: usize) -> Self {
        Self(value as u32)
    }
}

/// Stable identity of a task force, independent of retail processing order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TaskForceId(pub(crate) u32);

impl TaskForceId {
    #[doc(hidden)]
    pub const fn new(value: usize) -> Self {
        Self(value as u32)
    }
}

/// Stable identity of an admiral object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AdmiralId(pub(crate) u32);

/// Stable identity of a mission object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MissionId(pub(crate) u32);
