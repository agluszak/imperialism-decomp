use super::errors::*;
use imperialism_core::*;

pub(super) fn river_segment_from_retail_sprite(
    mut sprite: u8,
    tile: usize,
) -> Result<Option<RiverSegment>, LegacySaveError> {
    const FLOW_CONNECTIONS: [u8; 16] = [1, 2, 3, 3, 4, 4, 5, 5, 5, 5, 6, 6, 7, 7, 8, 9];

    if sprite == 0 {
        return Ok(None);
    }
    if (0x1b..=0x2a).contains(&sprite) {
        sprite -= 0x10;
    }
    let connection_code = if (0x0b..=0x1a).contains(&sprite) {
        FLOW_CONNECTIONS[usize::from(sprite - 0x0b)]
    } else {
        match sprite {
            0x2b => 0x0a,
            0x2c | 0x2d => 0x0b,
            0x2e => 0x0c,
            0x2f => 0x0d,
            0x30 | 0x31 => 0x0e,
            0x32 => 0x0f,
            0x33 => 0x13,
            0x34 | 0x35 => 0x14,
            0x36 => 0x15,
            0x37 => 0x10,
            0x38 | 0x39 => 0x11,
            0x3a => 0x12,
            _ => {
                return Err(LegacySaveError::StateProjection(format!(
                    "tile {tile} has invalid river sprite {sprite:#04x}"
                )));
            }
        }
    };
    Ok(RiverSegment::from_connection_code(connection_code))
}

pub(super) fn optional_region_id(value: i8) -> Result<Option<RegionId>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    u8::try_from(value)
        .map(RegionId::new)
        .map(Some)
        .map_err(|_| LegacySaveError::StateProjection(format!("region ID {value} is invalid")))
}

pub(super) fn optional_resource_kind(
    value: i8,
    tile: usize,
) -> Result<Option<ResourceKind>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    u8::try_from(value)
        .ok()
        .and_then(ResourceKind::from_index)
        .map(Some)
        .ok_or_else(|| {
            LegacySaveError::StateProjection(format!(
                "tile {tile} has invalid edge resource {value}"
            ))
        })
}

pub(super) fn decode_tile_transport_links(
    tile: usize,
    field: &'static str,
    bits: u8,
) -> Result<TileTransportLinks, LegacySaveError> {
    TileTransportLinks::from_bits(bits).ok_or(LegacySaveError::UnsupportedTileTransportLinkBits {
        tile,
        field,
        bits: bits & !TileTransportLinks::all().bits(),
    })
}

pub(super) fn optional_tile_owner_tag(value: i8) -> Result<Option<TileOwnerTag>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    u8::try_from(value)
        .map(TileOwnerTag::new)
        .map(Some)
        .map_err(|_| LegacySaveError::StateProjection(format!("tile owner tag {value} is invalid")))
}

pub(super) fn optional_major_nation_id(
    value: i8,
    tile: usize,
) -> Result<Option<MajorNationId>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    let raw = value;
    u8::try_from(value)
        .ok()
        .filter(|value| *value < MajorNationId::COUNT)
        .map(MajorNationId::new)
        .map(Some)
        .ok_or_else(|| {
            LegacySaveError::StateProjection(format!(
                "tile {tile} has invalid secondary major-nation owner {raw}"
            ))
        })
}

pub(super) fn optional_province_id(value: i16) -> Result<Option<ProvinceId>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    u16::try_from(value)
        .ok()
        .and_then(ProvinceId::try_new)
        .map(Some)
        .ok_or_else(|| {
            LegacySaveError::StateProjection(format!("province ID {value} is out of range"))
        })
}

pub(super) fn optional_province_array(
    values: [i16; 3],
) -> Result<[Option<ProvinceId>; 3], LegacySaveError> {
    Ok([
        optional_province_id(values[0])?,
        optional_province_id(values[1])?,
        optional_province_id(values[2])?,
    ])
}

pub(super) fn optional_ocean_zone_id(value: i16) -> Result<Option<OceanZoneId>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    u16::try_from(value)
        .map(OceanZoneId::new)
        .map(Some)
        .map_err(|_| {
            LegacySaveError::StateProjection(format!(
                "ocean-zone ordinal {value} is negative and not the absent sentinel"
            ))
        })
}

pub(super) fn optional_nation_id(value: i16) -> Result<Option<NationId>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    nation_id_from_retail_i16(value).map(Some)
}

pub(super) fn optional_tile_id(value: i32) -> Result<Option<TileId>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    u16::try_from(value)
        .ok()
        .and_then(TileId::try_new)
        .map(Some)
        .ok_or_else(|| {
            LegacySaveError::StateProjection(format!("strategic tile ID {value} is out of range"))
        })
}

pub(super) fn civilian_work_order(
    value: i32,
    tile: Option<TileId>,
    target: Option<TileId>,
    remaining: i16,
    topology: MapTopology,
) -> Result<CivilianWorkOrder, LegacySaveError> {
    let turns = || {
        TurnsRemaining::try_new(remaining).ok_or_else(|| {
            LegacySaveError::StateProjection(format!(
                "civilian order {value} has invalid remaining-turn count {remaining}"
            ))
        })
    };
    let required_tile = || {
        tile.ok_or_else(|| {
            LegacySaveError::StateProjection(format!("civilian order {value} has no tile"))
        })
    };
    let order = match value {
        0 => CivilianWorkOrder::Idle,
        1 => CivilianWorkOrder::Redeploy {
            destination: target.ok_or_else(|| {
                LegacySaveError::StateProjection("redeploy order has no destination".into())
            })?,
            turns: turns()?,
        },
        2 => CivilianWorkOrder::Sleep,
        5 => CivilianWorkOrder::LayRail {
            segment: RailSegment::between(
                topology,
                target.ok_or_else(|| {
                    LegacySaveError::StateProjection("rail order has no source".into())
                })?,
                required_tile()?,
            )
            .ok_or_else(|| {
                LegacySaveError::StateProjection("rail order tiles are not adjacent".into())
            })?,
            turns: turns()?,
        },
        6 => {
            required_tile()?;
            CivilianWorkOrder::BuildDepot { turns: turns()? }
        }
        7 => {
            required_tile()?;
            CivilianWorkOrder::BuildPort { turns: turns()? }
        }
        8 => {
            required_tile()?;
            CivilianWorkOrder::Prospect { turns: turns()? }
        }
        10 => {
            required_tile()?;
            CivilianWorkOrder::DevelopResource { turns: turns()? }
        }
        12 => {
            required_tile()?;
            CivilianWorkOrder::BuildFort { turns: turns()? }
        }
        13 => {
            required_tile()?;
            CivilianWorkOrder::PurchaseLand { turns: turns()? }
        }
        _ => {
            return Err(LegacySaveError::StateProjection(format!(
                "unrecovered civilian work order {value}"
            )));
        }
    };
    Ok(order)
}

pub(super) fn required_state<T>(value: Option<T>, name: &str) -> Result<T, LegacySaveError> {
    value.ok_or_else(|| LegacySaveError::StateProjection(format!("missing {name}")))
}

pub(super) fn retail_boolean(value: u8, context: &'static str) -> Result<bool, LegacySaveError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(LegacySaveError::InvalidBoolean { context, value }),
    }
}

pub(super) fn nation_id_from_retail_i16(value: i16) -> Result<NationId, LegacySaveError> {
    u8::try_from(value)
        .ok()
        .and_then(NationId::try_new)
        .ok_or_else(|| {
            LegacySaveError::StateProjection(format!(
                "nation slot {value} is outside the retail range 0..={}",
                NATION_COUNT - 1
            ))
        })
}

pub(super) fn minor_nation_id_from_retail_i16(
    value: i16,
) -> Result<MinorNationId, LegacySaveError> {
    let nation = nation_id_from_retail_i16(value)?;
    if nation.get() < MAJOR_NATION_COUNT as u8 {
        return Err(LegacySaveError::InvalidNationSlot {
            context: "minor consortium member",
            slot: value,
        });
    }
    Ok(MinorNationId::new(nation.get()))
}

pub(super) fn fixed_text(bytes: &[u8]) -> String {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    lossy_text(&bytes[..length])
}

/// Decodes save-string bytes.
///
/// Retail ANSI `CString` payloads use a Windows code page selected by the build's
/// localization; `language_code` is retained on the simulation prefix for that mapping.
/// Until localized retail fixtures establish the per-language code pages, bytes are
/// decoded as UTF-8 with lossy replacement so English fixtures keep loading.
pub(super) fn lossy_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Mirrors the live, language-table-loaded `NormalizeRuntimeCredentialNameToken`
/// pass used by the Diplomacy map on `TCountry::identitySharedString1`.
pub(super) fn normalize_nation_display_name(raw: &str) -> String {
    let mut characters = raw.chars();
    let Some(first) = characters.next() else {
        return String::new();
    };
    if first == '(' || first.is_ascii_uppercase() {
        raw.to_owned()
    } else {
        characters.as_str().to_owned()
    }
}
