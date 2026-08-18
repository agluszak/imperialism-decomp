use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Serialize};

/// Random-game difficulty selected by `dif0` through `dif4`.
#[derive(
    Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum Difficulty {
    Introductory,
    Easy,
    Normal,
    Hard,
    NighOnImpossible,
}

pub type DifficultyTable<T> = EnumMap<Difficulty, T>;

impl TryFrom<u8> for Difficulty {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Introductory),
            1 => Ok(Self::Easy),
            2 => Ok(Self::Normal),
            3 => Ok(Self::Hard),
            4 => Ok(Self::NighOnImpossible),
            _ => Err(()),
        }
    }
}

impl Difficulty {
    pub const fn retail(self) -> u8 {
        match self {
            Self::Introductory => 0,
            Self::Easy => 1,
            Self::Normal => 2,
            Self::Hard => 3,
            Self::NighOnImpossible => 4,
        }
    }
}
