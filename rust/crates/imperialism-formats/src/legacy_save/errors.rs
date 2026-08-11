use super::*;
use crate::legacy_stream::StreamError;

#[derive(Debug, thiserror::Error)]
pub enum LegacySaveError {
    #[error(
        "legacy save ended at offset {offset:#x}: requested {requested} bytes, {remaining} remain"
    )]
    Truncated {
        offset: usize,
        requested: usize,
        remaining: usize,
    },
    #[error("invalid Imperialism save magic {0:?}")]
    InvalidMagic([u8; 4]),
    #[error(
        "unsupported Imperialism save version {0:#x}; the current decoder requires {CURRENT_RETAIL_VERSION:#x}"
    )]
    UnsupportedVersion(u32),
    #[error(
        "multiplayer save role {0} requires the game-flow manager DTO before the simulation suffix can be located"
    )]
    UnsupportedMultiplayerRole(i32),
    #[error("{context} contains {count} MFC polymorphic object(s) at {offset:#x}")]
    UnsupportedPolymorphicObjects {
        context: &'static str,
        count: u32,
        offset: usize,
    },
    #[error("invalid MFC object at {offset:#x}: {detail}")]
    InvalidMfcObject { offset: usize, detail: String },
    #[error(
        "nation {nation} has unsupported retail diplomacy-grant flags for target {target}: {entry:#06x}"
    )]
    UnsupportedDiplomacyGrantFlags {
        nation: i16,
        target: usize,
        entry: i16,
    },
    #[error(
        "nation {nation} has unsupported retail diplomacy policy for target {target}: {entry:#06x}"
    )]
    UnsupportedDiplomacyPolicy {
        nation: i16,
        target: usize,
        entry: i16,
    },
    #[error("tile {tile} has unsupported {field} bits {bits:#04x}")]
    UnsupportedTileTransportLinkBits {
        tile: usize,
        field: &'static str,
        bits: u8,
    },
    #[error("{0}")]
    StateProjection(String),
    #[error("city order {order}: {detail}")]
    InvalidCityOrder { order: &'static str, detail: String },
    #[error("{context}: invalid count {value}; maximum is {maximum}")]
    InvalidCount {
        context: &'static str,
        value: i64,
        maximum: usize,
    },
    #[error("{context}: declared count {declared} does not match availability flags ({available})")]
    CountAvailabilityMismatch {
        context: &'static str,
        declared: usize,
        available: usize,
    },
    #[error("{context}: nation slot {slot} is outside the expected range")]
    InvalidNationSlot { context: &'static str, slot: i16 },
    #[error("{context} entry {index} has invalid retail value {value}")]
    InvalidDiplomacyValue {
        context: &'static str,
        index: usize,
        value: i16,
    },
    #[error("{context} has invalid retail boolean value {value}")]
    InvalidBoolean { context: &'static str, value: u8 },
    #[error(
        "trade commodity {commodity} maximum offer for minor nation slot {nation} is negative: {value}"
    )]
    NegativeTradeOfferMaximum {
        commodity: usize,
        nation: usize,
        value: i16,
    },
    #[error(
        "legacy save ends at offset {end_offset:#x} but input length is {length:#x}; trailing bytes are not represented"
    )]
    TrailingData { end_offset: usize, length: usize },
    #[error("MFC Unicode CString marker at offset {offset:#x} is not supported")]
    UnsupportedUnicodeString { offset: usize },
}

impl From<StreamError> for LegacySaveError {
    fn from(error: StreamError) -> Self {
        match error {
            StreamError::Truncated {
                offset,
                requested,
                remaining,
            } => Self::Truncated {
                offset,
                requested,
                remaining,
            },
            StreamError::UnsupportedUnicodeString { offset } => {
                Self::UnsupportedUnicodeString { offset }
            }
            StreamError::InvalidCount {
                context,
                value,
                maximum,
            } => Self::InvalidCount {
                context,
                value,
                maximum,
            },
        }
    }
}

pub(super) fn bounded_count(
    value: i32,
    maximum: usize,
    context: &'static str,
) -> Result<usize, LegacySaveError> {
    let Ok(count) = usize::try_from(value) else {
        return Err(LegacySaveError::InvalidCount {
            context,
            value: i64::from(value),
            maximum,
        });
    };
    if count > maximum {
        return Err(LegacySaveError::InvalidCount {
            context,
            value: i64::from(value),
            maximum,
        });
    }
    Ok(count)
}

pub(super) fn bounded_u32(
    value: u32,
    maximum: usize,
    context: &'static str,
) -> Result<usize, LegacySaveError> {
    let count = value as usize;
    if count > maximum {
        return Err(LegacySaveError::InvalidCount {
            context,
            value: i64::from(value),
            maximum,
        });
    }
    Ok(count)
}

pub(super) fn validate_nation_slot(
    slot: i16,
    expected: std::ops::Range<i16>,
    context: &'static str,
) -> Result<(), LegacySaveError> {
    if !expected.contains(&slot) {
        return Err(LegacySaveError::InvalidNationSlot { context, slot });
    }
    Ok(())
}
