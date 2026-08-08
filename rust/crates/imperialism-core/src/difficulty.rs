use serde::{Deserialize, Serialize};

/// Retail random-game / new-game difficulty control values (`dif0`..=`dif4`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Difficulty {
    Introductory = 0,
    Easy = 1,
    Normal = 2,
    Hard = 3,
    NighOnImpossible = 4,
}

impl Difficulty {
    pub const COUNT: u8 = 5;

    pub const fn from_retail_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Introductory),
            1 => Some(Self::Easy),
            2 => Some(Self::Normal),
            3 => Some(Self::Hard),
            4 => Some(Self::NighOnImpossible),
            _ => None,
        }
    }

    pub const fn retail_byte(self) -> u8 {
        self as u8
    }

    pub const fn index(self) -> usize {
        self as usize
    }
}

impl Serialize for Difficulty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.retail_byte().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Difficulty {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        u8::try_from(value)
            .ok()
            .and_then(Self::from_retail_byte)
            .ok_or_else(|| {
                serde::de::Error::custom(format_args!(
                    "difficulty {value} is outside the retail range 0..=4"
                ))
            })
    }
}
