use serde::{Deserialize, Serialize};

macro_rules! bounded_id {
    ($(#[$meta:meta])* $name:ident, $inner:ty, $count:expr, $label:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name($inner);

        impl $name {
            pub const COUNT: $inner = $count;

            pub const fn new(value: $inner) -> Self {
                assert!(value < Self::COUNT, concat!($label, " is out of range"));
                Self(value)
            }

            pub const fn try_new(value: $inner) -> Option<Self> {
                if value < Self::COUNT {
                    Some(Self(value))
                } else {
                    None
                }
            }

            pub const fn get(self) -> $inner {
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
                let value = <$inner>::deserialize(deserializer)?;
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

bounded_id!(NationId, u8, 23, "nation ID");
bounded_id!(
    /// One of the seven stable major-nation slots.
    ///
    /// This identifies a slot only; it does not prove that the slot currently
    /// contains a live [`crate::MajorNation`]. Eliminated major nations retain
    /// their slot ID while their entry in [`crate::Nations`] is absent.
    MajorNationId,
    u8,
    7,
    "major-nation ID"
);
bounded_id!(TileId, u16, 6_480, "strategic tile ID");
bounded_id!(ProvinceId, u16, 0x180, "province ID");

impl MajorNationId {
    /// Converts a nation ID in the major-slot range.
    ///
    /// The result identifies a slot and does not establish that a live major
    /// nation occupies it.
    pub const fn from_nation(nation: NationId) -> Option<Self> {
        if nation.get() < Self::COUNT {
            Some(Self(nation.get()))
        } else {
            None
        }
    }

    pub const fn nation(self) -> NationId {
        NationId::new(self.0)
    }
}

impl TileId {
    pub(crate) const fn from_index_unchecked(value: u16) -> Self {
        Self(value)
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

    pub fn all() -> impl DoubleEndedIterator<Item = Self> + ExactSizeIterator {
        (Self::FIRST..NationId::COUNT).map(Self::new)
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
