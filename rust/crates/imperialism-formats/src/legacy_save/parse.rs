use super::PROVINCE_COUNT;
use super::errors::*;
use super::model::*;
use super::normalize::*;
use super::*;
use crate::legacy_stream::{LegacyStream, StreamError};
use imperialism_core::*;

impl LegacySaveV62 {
    pub fn parse(bytes: &[u8]) -> Result<Self, LegacySaveError> {
        let mut stream = LegacyStream::new(bytes);
        let magic: [u8; 4] = stream.read_bytes(4)?.try_into().unwrap();
        if magic != SAVE_MAGIC {
            return Err(LegacySaveError::InvalidMagic(magic));
        }
        let format_version = stream.read_le_u32()?;
        if format_version != CURRENT_RETAIL_VERSION {
            return Err(LegacySaveError::UnsupportedVersion(format_version));
        }
        let saved_session_slot = stream.read_le_i32()?;
        let save_label = fixed_text(stream.read_bytes(SAVE_LABEL_LENGTH)?);
        let preview_owner_nation_by_tile = (0..STRATEGIC_TILE_COUNT)
            .map(|_| stream.read_i8())
            .collect::<Result<Vec<_>, _>>()?;
        let preview_economic_year_offset = stream.read_le_i16()?;
        let preview_difficulty = stream.read_u8()?;
        let preview_active_nation = stream.read_u8()?;
        let preview_active_nation_name = fixed_text(stream.read_bytes(ACTIVE_NATION_NAME_LENGTH)?);
        let header = LegacySaveHeader {
            format_version,
            saved_session_slot,
            save_label,
            preview_owner_nation_by_tile,
            preview_economic_year_offset,
            preview_difficulty,
            preview_active_nation,
            preview_active_nation_name,
        };

        let language_code = stream.read_le_u32()?;
        let economic_turn = stream.read_le_i16()?;
        let active_nation = stream.read_le_i16()?;
        let turn_state_code = stream.read_le_i16()?;
        let mode = stream.read_le_i16()?;
        let previous_turn_state_code = stream.read_le_i16()?;
        let previous_mode = stream.read_le_i16()?;
        stream.skip(1)?;
        let nation_count_raw = stream.read_le_i32()?;
        let minor_nation_count_raw = stream.read_le_i32()?;
        let nation_count = bounded_count(
            nation_count_raw,
            MAJOR_NATION_COUNT,
            "simulation major nation_count",
        )?;
        let minor_nation_count = bounded_count(
            minor_nation_count_raw,
            MINOR_NATION_COUNT,
            "simulation minor_nation_count",
        )?;
        let turn_flow_status_flags = stream.read_le_u32()?;
        let difficulty = stream.read_u8()?;
        let game_setup = read_game_setup(&mut stream)?;
        let persistent_unit_id_counter = stream.read_le_i32()?;
        let nation_availability: [u8; NATION_COUNT] =
            stream.read_bytes(NATION_COUNT)?.try_into().unwrap();
        let available_majors = nation_availability[..MAJOR_NATION_COUNT]
            .iter()
            .filter(|&&flag| flag != 0)
            .count();
        let available_minors = nation_availability[MAJOR_NATION_COUNT..]
            .iter()
            .filter(|&&flag| flag != 0)
            .count();
        if nation_count != available_majors {
            return Err(LegacySaveError::CountAvailabilityMismatch {
                context: "simulation major nation_count",
                declared: nation_count,
                available: available_majors,
            });
        }
        if minor_nation_count != available_minors {
            return Err(LegacySaveError::CountAvailabilityMismatch {
                context: "simulation minor_nation_count",
                declared: minor_nation_count,
                available: available_minors,
            });
        }
        let saved_multiplayer_role = stream.read_le_i32()?;
        if saved_multiplayer_role != 0 {
            return Err(LegacySaveError::UnsupportedMultiplayerRole(
                saved_multiplayer_role,
            ));
        }
        let preference_slot_10 = stream.read_le_i16()?;
        let selected_asset_set = stream.read_le_i16()?;
        let diplomacy_year_term_raw = stream.read_le_i16()?;
        let phase_state_by_decade = stream.read_bytes(12)?.try_into().unwrap();
        let nation_names = (0..NATION_COUNT)
            .map(|_| stream.read_mfc_string().map(|bytes| lossy_text(&bytes)))
            .collect::<Result<Vec<_>, _>>()?;
        let simulation = LegacySimulationPrefix {
            language_code,
            economic_turn,
            active_nation,
            turn_state_code,
            mode,
            previous_turn_state_code,
            previous_mode,
            nation_count: nation_count_raw,
            minor_nation_count: minor_nation_count_raw,
            turn_flow_status_flags,
            difficulty,
            game_setup,
            persistent_unit_id_counter,
            nation_availability,
            saved_multiplayer_role,
            preference_slot_10,
            selected_asset_set,
            diplomacy_year_term_raw,
            phase_state_by_decade,
            nation_names,
        };
        let animator_idle_frequency = stream.read_le_i32()?;
        let market = read_trade_market(&mut stream)?;
        let diplomacy_start = stream.position();
        let diplomacy = read_diplomacy_state(&mut stream)?;
        debug_assert_eq!(
            stream.position() - diplomacy_start,
            DIPLOMACY_SERIALIZED_SIZE_V62
        );
        let technology = read_technology_state(&mut stream)?;
        let map = read_map(&mut stream)?;
        let ocean = read_ocean(&mut stream)?;
        let navy = read_navy(&mut stream)?;
        let army_report_count = skip_army_reports(&mut stream)?;
        let remaining_manager_chain_offset = stream.position();

        let mut archive = LegacyMfcArchiveState::default();
        let mut nation_offset = remaining_manager_chain_offset;
        let mut major_nations = Vec::with_capacity(nation_count);
        for nation in 0..MAJOR_NATION_COUNT {
            if simulation.nation_availability[nation] == 0 {
                continue;
            }
            let foreign_policy_id = simulation.game_setup.foreign_minister_policy_ids[nation];
            if simulation.game_setup.nation_control_modes[nation] == 2 {
                let (major, next_offset) = parse_auto_great_power_record_at(
                    bytes,
                    nation_offset,
                    foreign_policy_id,
                    &mut archive,
                )?;
                validate_nation_slot(
                    major.great_power.country.nation_slot,
                    0..MAJOR_NATION_COUNT as i16,
                    "major nation record",
                )?;
                if major.great_power.country.nation_slot as usize != nation {
                    return Err(LegacySaveError::InvalidNationSlot {
                        context: "major nation record slot does not match availability walk",
                        slot: major.great_power.country.nation_slot,
                    });
                }
                major_nations.push(LegacyMajorNationState::Auto(Box::new(major)));
                nation_offset = next_offset;
            } else {
                let (major, next_offset) =
                    parse_great_power_record_at(bytes, nation_offset, foreign_policy_id)?;
                validate_nation_slot(
                    major.country.nation_slot,
                    0..MAJOR_NATION_COUNT as i16,
                    "major nation record",
                )?;
                if major.country.nation_slot as usize != nation {
                    return Err(LegacySaveError::InvalidNationSlot {
                        context: "major nation record slot does not match availability walk",
                        slot: major.country.nation_slot,
                    });
                }
                major_nations.push(LegacyMajorNationState::Other(Box::new(major)));
                nation_offset = next_offset;
            }
        }

        let mut minor_nations = Vec::with_capacity(minor_nation_count);
        for nation in MAJOR_NATION_COUNT..NATION_COUNT {
            if simulation.nation_availability[nation] == 0 {
                continue;
            }
            let (minor, next_offset) = parse_minor_record_at(bytes, nation_offset)?;
            validate_nation_slot(
                minor.country.nation_slot,
                MAJOR_NATION_COUNT as i16..NATION_COUNT as i16,
                "minor nation record",
            )?;
            if minor.country.nation_slot as usize != nation {
                return Err(LegacySaveError::InvalidNationSlot {
                    context: "minor nation record slot does not match availability walk",
                    slot: minor.country.nation_slot,
                });
            }
            minor_nations.push(minor);
            nation_offset = next_offset;
        }

        // TViewMgr, TMacViewMgr, and TNewsMgr persist no fields beyond TObject.
        let (help, end_offset) = parse_help_manager_at(bytes, nation_offset)?;
        if end_offset != bytes.len() {
            return Err(LegacySaveError::TrailingData {
                end_offset,
                length: bytes.len(),
            });
        }
        Ok(Self {
            header,
            simulation,
            animator_idle_frequency,
            market,
            diplomacy,
            technology,
            map,
            ocean,
            navy,
            army_report_count,
            remaining_manager_chain_offset,
            major_nations,
            minor_nations,
            help,
            end_offset,
        })
    }
}

/// Decodes the common `TCountry` prefix at an already-located nation record.
///
/// The returned offset is the first byte of the derived `TGreatPower` or `TMinor`
/// suffix. Keeping location separate from decoding lets the manager-chain parser
/// choose the concrete retail nation class without embedding C++ layout in the DTO.
pub(super) fn parse_country_base_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyCountryBase, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let country = read_country_base(&mut stream)?;
    Ok((country, offset + stream.position()))
}

/// Decodes the fixed portion of a `TGreatPower` derived record.
///
/// The returned offset points just after the minister-presence byte, at the first
/// optional minister or city payload. It includes the two turn/proposal queues and
/// 17 diplomacy lists serialized as fixed-size `TSortedPtrList` records.
pub(super) fn parse_great_power_prefix_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyGreatPowerPrefix, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let prefix = read_great_power_prefix(&mut stream)?;
    Ok((prefix, offset + stream.position()))
}

/// Decodes the complete current-format `TCity` payload at an already-located city.
pub(super) fn parse_city_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyCityState, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let city = read_city(&mut stream)?;
    Ok((city, offset + stream.position()))
}

/// Decodes the optional minister payload selected by `TGreatPower`'s presence mask.
/// The foreign policy ID matters only for Bill's one-byte derived suffix.
pub(super) fn parse_great_power_ministers_at(
    bytes: &[u8],
    offset: usize,
    presence_mask: u8,
    foreign_policy_id: i16,
) -> Result<(LegacyGreatPowerMinisters, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let ministers = read_great_power_ministers(&mut stream, presence_mask, foreign_policy_id)?;
    Ok((ministers, offset + stream.position()))
}

pub(super) fn parse_great_power_post_city_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyGreatPowerPostCity, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let post_city = read_great_power_post_city(&mut stream, offset)?;
    Ok((post_city, offset + stream.position()))
}

pub(super) fn parse_auto_great_power_prefix_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyAutoGreatPowerPrefix, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let prefix = read_auto_great_power_prefix(&mut stream)?;
    Ok((prefix, offset + stream.position()))
}

/// Decodes a mission queue written through MFC `CArchive::WriteObject`.
///
/// `archive` is intentionally supplied by the caller because its class/object map
/// spans the complete save stream rather than resetting at each nation.
pub(super) fn parse_missions_at(
    bytes: &[u8],
    offset: usize,
    count: u32,
    archive: &mut LegacyMfcArchiveState,
) -> Result<(Vec<LegacyMission>, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let count = bounded_u32(count, MAX_MISSIONS, "AI mission queue")?;
    let mut missions = Vec::with_capacity(count);
    for _ in 0..count {
        missions.push(read_mfc_mission(&mut stream, offset, archive)?);
    }
    Ok((missions, offset + stream.position()))
}

/// Decodes the complete common `TGreatPower` record, stopping before any
/// controller-specific derived suffix.
pub(super) fn parse_great_power_record_at(
    bytes: &[u8],
    offset: usize,
    foreign_policy_id: i16,
) -> Result<(LegacyGreatPowerState, usize), LegacySaveError> {
    let (country, prefix_offset) = parse_country_base_at(bytes, offset)?;
    let (prefix, optional_offset) = parse_great_power_prefix_at(bytes, prefix_offset)?;
    let (ministers, city_offset) = parse_great_power_ministers_at(
        bytes,
        optional_offset,
        prefix.minister_presence_mask,
        foreign_policy_id,
    )?;
    let (city, post_city_offset) = if prefix.minister_presence_mask & 8 != 0 {
        let (city, next) = parse_city_at(bytes, city_offset)?;
        (Some(city), next)
    } else {
        (None, city_offset)
    };
    let (post_city, next_offset) = parse_great_power_post_city_at(bytes, post_city_offset)?;
    Ok((
        LegacyGreatPowerState {
            country,
            prefix,
            ministers,
            city,
            post_city,
        },
        next_offset,
    ))
}

/// Decodes one AI-controlled major nation and advances the shared MFC object map.
pub(super) fn parse_auto_great_power_record_at(
    bytes: &[u8],
    offset: usize,
    foreign_policy_id: i16,
    archive: &mut LegacyMfcArchiveState,
) -> Result<(LegacyAutoGreatPowerState, usize), LegacySaveError> {
    let (great_power, auto_offset) = parse_great_power_record_at(bytes, offset, foreign_policy_id)?;
    let (auto_prefix, mission_offset) = parse_auto_great_power_prefix_at(bytes, auto_offset)?;
    let (missions, next_offset) =
        parse_missions_at(bytes, mission_offset, auto_prefix.mission_count, archive)?;
    Ok((
        LegacyAutoGreatPowerState {
            great_power,
            auto_prefix,
            missions,
        },
        next_offset,
    ))
}

/// Decodes one v62 `TMinor` record including its current-format diplomacy extension.
pub(super) fn parse_minor_record_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyMinorState, usize), LegacySaveError> {
    let (country, suffix_offset) = parse_country_base_at(bytes, offset)?;
    let remaining = bytes.get(suffix_offset..).ok_or(StreamError::Truncated {
        offset: suffix_offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let minor = LegacyMinorState {
        country,
        need_current_by_type: read_be_short_array(&mut stream)?,
        trade_offers_by_resource: read_be_short_array(&mut stream)?,
        grant_amounts_by_resource: read_be_short_array(&mut stream)?,
        diplomacy_thresholds: read_short_array(&mut stream)?,
        diplomacy_policy_fields: read_short_array(&mut stream)?,
        diplomacy_save_fields: read_be_short_array(&mut stream)?,
        diplomacy_save_extension: read_be_short_array(&mut stream)?,
    };
    Ok((minor, suffix_offset + stream.position()))
}

pub(super) fn parse_help_manager_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyHelpState, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let help = LegacyHelpState {
        index_records: read_fixed_record_list(&mut stream)?,
        civilian_completion_counters: read_be_short_array(&mut stream)?,
        help_index_ready: stream.read_le_i16()?,
    };
    Ok((help, offset + stream.position()))
}

pub(super) fn read_diplomacy_state(
    stream: &mut LegacyStream<'_>,
) -> Result<DiplomacyState, LegacySaveError> {
    const NATION_PAIR_COUNT: usize = NATION_COUNT * NATION_COUNT;

    let start = stream.position();
    let standings = nation_pair_table(read_be_short_array::<NATION_PAIR_COUNT>(stream)?);
    let relationships = read_be_short_array::<NATION_PAIR_COUNT>(stream)?
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            DiplomaticRelationship::try_from_retail(value).ok_or(
                LegacySaveError::InvalidDiplomacyValue {
                    context: "diplomacy relationships",
                    index,
                    value,
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .expect("one relationship per nation pair");
    let relationships = nation_pair_table(relationships);
    let relationship_turns = read_be_short_array::<NATION_PAIR_COUNT>(stream)?
        .into_iter()
        .enumerate()
        .map(|(index, value)| match value {
            -1 => Ok(None),
            0..=i16::MAX => Ok(Some(value)),
            _ => Err(LegacySaveError::InvalidDiplomacyValue {
                context: "diplomacy relationship turns",
                index,
                value,
            }),
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .expect("one turn stamp per nation pair");
    let relationship_turns = nation_pair_table(relationship_turns);

    let influence_thresholds =
        ProvinceTable::from_array(read_be_short_array::<PROVINCE_COUNT>(stream)?);
    let influence_sides = (0..PROVINCE_COUNT)
        .map(|index| {
            let value = i16::from(stream.read_i8()?);
            optional_major_nation(value, "diplomacy influence sides", index)
        })
        .collect::<Result<Vec<_>, LegacySaveError>>()?
        .try_into()
        .expect("one influence side per province");
    let influence_sides = ProvinceTable::from_array(influence_sides);
    let last_diplomatic_effort_turn = stream.read_le_i16()?;

    let mission_levels = read_be_short_array::<NATION_PAIR_COUNT>(stream)?
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            DiplomaticMissionLevel::try_from_retail(value).ok_or(
                LegacySaveError::InvalidDiplomacyValue {
                    context: "diplomacy mission levels",
                    index,
                    value,
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .expect("one mission level per nation pair");
    let mission_levels = nation_pair_table(mission_levels);

    let chairman = optional_major_nation(stream.read_be_i16()?, "diplomatic congress chairman", 0)?;
    let counterpart =
        optional_major_nation(stream.read_be_i16()?, "diplomatic congress counterpart", 0)?;
    let congress = DiplomaticCongressState {
        chairman,
        counterpart,
        chairman_support: stream.read_be_i16()?,
        counterpart_support: stream.read_be_i16()?,
        neutral_support: stream.read_be_i16()?,
    };

    let special_relation_sources =
        read_optional_major_nation_table(stream, "diplomacy special-relation sources")?;
    let special_relation_targets =
        read_optional_major_nation_table(stream, "diplomacy special-relation targets")?;

    assert_eq!(
        stream.position() - start,
        DIPLOMACY_SERIALIZED_SIZE_V62,
        "recovered v62 diplomacy payload layout must remain exact"
    );
    Ok(DiplomacyState {
        standings,
        relationships,
        relationship_turns,
        influence_thresholds,
        influence_sides,
        last_diplomatic_effort_turn,
        mission_levels,
        congress,
        special_relation_sources,
        special_relation_targets,
        // The retail constructor restores both values before ReadFrom consumes the payload.
        last_processed_nation: None,
        proposal_mode_raw: 0,
    })
}

pub(super) fn nation_pair_table<T: Copy>(
    values: [T; NATION_COUNT * NATION_COUNT],
) -> NationTable<NationTable<T>> {
    NationTable::from_array(std::array::from_fn(|source| {
        NationTable::from_array(std::array::from_fn(|target| {
            values[source * NATION_COUNT + target]
        }))
    }))
}

pub(super) fn optional_major_nation(
    value: i16,
    context: &'static str,
    index: usize,
) -> Result<Option<MajorNationId>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    if (0..MAJOR_NATION_COUNT as i16).contains(&value) {
        return Ok(Some(MajorNationId::new(value as u8)));
    }
    Err(LegacySaveError::InvalidDiplomacyValue {
        context,
        index,
        value,
    })
}

pub(super) fn read_optional_major_nation_table(
    stream: &mut LegacyStream<'_>,
    context: &'static str,
) -> Result<MinorNationTable<Option<MajorNationId>>, LegacySaveError> {
    let values = (0..MINOR_NATION_COUNT)
        .map(|index| optional_major_nation(stream.read_be_i16()?, context, index))
        .collect::<Result<Vec<_>, LegacySaveError>>()?
        .try_into()
        .expect("one special-relation value per minor nation");
    Ok(MinorNationTable::from_array(values))
}

pub(super) fn read_trade_market(
    stream: &mut LegacyStream<'_>,
) -> Result<TradeMarketState, LegacySaveError> {
    let rows = (0..TRADE_CATEGORY_COUNT)
        .map(|commodity| read_trade_market_row(stream, commodity))
        .collect::<Result<Vec<_>, _>>()?;
    let rows: [TradeMarketRow; TRADE_CATEGORY_COUNT] =
        rows.try_into().expect("one market row per trade commodity");
    for _ in 0..TRADE_CATEGORY_COUNT {
        let record_size = usize::from(stream.read_le_u16()?);
        let record_count = bounded_u32(
            stream.read_le_u32()?,
            MAX_TRADE_HISTORY_RECORDS,
            "trade history",
        )?;
        let byte_len = record_size * record_count;
        stream.skip(byte_len)?;
    }
    Ok(TradeMarketState {
        rows: TradeCommodityTable::from_array(rows),
    })
}

pub(super) fn read_trade_market_row(
    stream: &mut LegacyStream<'_>,
    commodity: usize,
) -> Result<TradeMarketRow, LegacySaveError> {
    let previous_price = i32::from(stream.read_le_i16()?);
    let price = i32::from(stream.read_le_i16()?);
    let request_count = i32::from(stream.read_le_i16()?);
    let offer_count = i32::from(stream.read_le_i16()?);
    let adjusted_offer_count = f64::from_le_bytes(stream.read_bytes(8)?.try_into().unwrap());
    let amount_offered = i32::from(stream.read_le_i16()?);
    let base_price = i32::from(stream.read_le_i16()?);
    // The first two per-nation sub-rows are transient current and accumulated offers.
    stream.skip(2 * NATION_COUNT * std::mem::size_of::<i16>())?;
    let mut maximum_offer_by_nation = [0; NATION_COUNT];
    for (nation, maximum) in maximum_offer_by_nation.iter_mut().enumerate() {
        let value = stream.read_be_i16()?;
        if value < 0 {
            return Err(LegacySaveError::NegativeTradeOfferMaximum {
                commodity,
                nation,
                value,
            });
        }
        *maximum = value;
    }
    Ok(TradeMarketRow {
        previous_price,
        price,
        base_price,
        request_count,
        offer_count,
        amount_offered,
        adjusted_offer_count,
        maximum_offer_by_nation: NationTable::from_array(maximum_offer_by_nation),
    })
}

pub(super) fn read_technology_state(
    stream: &mut LegacyStream<'_>,
) -> Result<TechnologyState, LegacySaveError> {
    let bytes = stream.read_bytes(TECH_SERIALIZED_SIZE_V62)?;
    let mut scheduled_unlock_turn_by_technology = [0; TECHNOLOGY_COUNT];
    for (technology, turn) in scheduled_unlock_turn_by_technology.iter_mut().enumerate() {
        let offset = TECH_PRIORITY_SLOTS_OFFSET_V62 + technology * std::mem::size_of::<i16>();
        *turn = i16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    }
    let mut global_unlocks_by_technology = [false; TECHNOLOGY_COUNT];
    for (technology, unlocked) in global_unlocks_by_technology.iter_mut().enumerate() {
        *unlocked = retail_boolean(
            bytes[TECH_GLOBAL_UNLOCK_FLAGS_OFFSET_V62 + technology],
            "technology global unlock flag",
        )?;
    }
    let status = |nation: usize, technology: usize| {
        let offset = TECH_ORDER_CAP_ROWS_OFFSET_V62 + nation * TECH_ORDER_CAP_ROW_SIZE + technology;
        let value = bytes[offset];
        if value <= 2 {
            Ok(value)
        } else {
            Err(LegacySaveError::StateProjection(format!(
                "major nation {nation} technology {technology} status {value} is invalid"
            )))
        }
    };
    let researched = |nation: usize, technology: usize| {
        Ok::<bool, LegacySaveError>(status(nation, technology)? == 2)
    };
    let mut industry_enabled_by_slot = [false; 14];
    for (slot, enabled) in industry_enabled_by_slot.iter_mut().enumerate() {
        *enabled = retail_boolean(
            bytes[TECH_INDUSTRY_ENABLED_OFFSET_V62 + slot],
            "technology industry enabled flag",
        )?;
    }
    let mut military_unit_ability_active_by_nation =
        std::array::from_fn(|_| MilitaryUnitTable::default());
    let mut research_status_by_nation =
        [[TechnologyResearchStatus::NotStarted; TECHNOLOGY_COUNT]; MAJOR_NATION_COUNT];
    let mut city_capabilities_by_nation =
        std::array::from_fn(|_| CityTechnologyCapabilities::default());
    for (nation, capabilities) in city_capabilities_by_nation.iter_mut().enumerate() {
        for (technology, research_status) in
            research_status_by_nation[nation].iter_mut().enumerate()
        {
            *research_status = match status(nation, technology)? {
                0 => TechnologyResearchStatus::NotStarted,
                1 => TechnologyResearchStatus::Pending,
                2 => TechnologyResearchStatus::Researched,
                _ => unreachable!("technology status was validated above"),
            };
        }
        let mut active_by_unit_type = [false; TECH_ABILITY_ACTIVE_ROW_SIZE];
        for (unit_type, active) in active_by_unit_type.iter_mut().enumerate() {
            let offset = TECH_ABILITY_ACTIVE_ROWS_OFFSET_V62
                + nation * TECH_ABILITY_ACTIVE_ROW_SIZE
                + unit_type;
            *active = retail_boolean(
                bytes[offset],
                "technology military unit ability active flag",
            )?;
        }
        military_unit_ability_active_by_nation[nation] =
            MilitaryUnitTable::from_array(active_by_unit_type);

        capabilities.advanced_iron_working = researched(nation, TECH_ADVANCED_IRON_WORKING_ID)?;
        capabilities.oil_drilling = researched(nation, TECH_OIL_DRILLING_ID)?;
        capabilities.primary_civilian_distance_terrain = CivilianTerrainAccess {
            hills: researched(nation, 12)?,
            mountain: researched(nation, 23)?,
            swamp: researched(nation, 6)?,
        };
        capabilities.secondary_civilian_hills = researched(nation, 11)?;
        capabilities.secondary_civilian_swamp = researched(nation, 5)?;
        capabilities.fort_level_cap = if status(nation, 22)? != 0 {
            FortLevelCap::THREE
        } else if status(nation, 11)? != 0 {
            FortLevelCap::TWO
        } else {
            FortLevelCap::ONE
        };

        let mut available = [false; TECH_UNIVERSITY_AVAILABILITY_ROW_SIZE];
        for (category, value) in available.iter_mut().enumerate() {
            let offset = TECH_UNIVERSITY_AVAILABILITY_OFFSET_V62
                + nation * TECH_UNIVERSITY_AVAILABILITY_ROW_SIZE
                + category;
            *value = retail_boolean(bytes[offset], "university recruitment availability")?;
        }

        let mut requirement_levels = [0; RESOURCE_KIND_COUNT];
        for (resource, value) in requirement_levels.iter_mut().enumerate() {
            let offset = TECH_FINAL_REQUIREMENT_LEVELS_OFFSET_V62
                + nation * TECH_REQUIREMENT_LEVELS_ROW_SIZE
                + resource * std::mem::size_of::<i16>();
            let raw = i16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            *value = u8::try_from(raw).map_err(|_| {
                LegacySaveError::StateProjection(format!(
                    "major nation {nation} university requirement level {raw} for resource {resource} is invalid"
                ))
            })?;
            if *value > 3 {
                return Err(LegacySaveError::StateProjection(format!(
                    "major nation {nation} university requirement level {raw} for resource {resource} is invalid"
                )));
            }
        }
        capabilities.university = UniversityTechnologyState {
            available: CivilianUnitTable::from_array(available),
            requirement_levels: ResourceTable::from_array(requirement_levels),
        };
    }
    Ok(TechnologyState {
        advanced_iron_working: retail_boolean(
            bytes[TECH_ADVANCED_IRON_WORKING_OFFSET_V62],
            "technology advanced iron working",
        )?,
        marine_engineering: retail_boolean(
            bytes[TECH_MARINE_ENGINEERING_OFFSET_V62],
            "technology marine engineering",
        )?,
        scheduled_unlock_turn_by_technology,
        global_unlocks_by_technology,
        research_status_by_nation: MajorNationTable::from_array(research_status_by_nation),
        industry_enabled_by_slot,
        military_unit_ability_active_by_nation: MajorNationTable::from_array(
            military_unit_ability_active_by_nation,
        ),
        city_capabilities_by_nation: MajorNationTable::from_array(city_capabilities_by_nation),
    })
}

pub(super) fn read_map(stream: &mut LegacyStream<'_>) -> Result<LegacyMapState, StreamError> {
    let view_origin_tile = stream.read_le_i16()?;
    let map_data_ready = stream.read_u8()?;
    let recruit_search_active = stream.read_u8()?;
    let city_score_total = stream.read_le_i32()?;
    let scenario_tag = lossy_text(&stream.read_mfc_string()?);
    let no_horizontal_wrap = stream.read_u8()?;
    let tiles = (0..STRATEGIC_TILE_COUNT)
        .map(|_| read_terrain_tile(stream))
        .collect::<Result<Vec<_>, _>>()?;
    let provinces = (0..PROVINCE_COUNT)
        .map(|_| read_province(stream))
        .collect::<Result<Vec<_>, _>>()?;
    let pending_river_mouth_tile = stream.read_le_i16()?;
    Ok(LegacyMapState {
        view_origin_tile,
        map_data_ready,
        recruit_search_active,
        city_score_total,
        scenario_tag,
        no_horizontal_wrap,
        tiles,
        provinces,
        pending_river_mouth_tile,
    })
}

pub(super) fn read_ocean(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyOceanState, LegacySaveError> {
    let zone_count = bounded_u32(
        u32::from(stream.read_le_u16()?),
        MAX_OCEAN_ZONES,
        "ocean zones",
    )?;
    let zones = (0..zone_count)
        .map(|_| read_zone(stream, false))
        .collect::<Result<Vec<_>, _>>()?;
    let port_zone_count = bounded_u32(
        u32::from(stream.read_le_u16()?),
        MAX_OCEAN_ZONES,
        "ocean port zones",
    )?;
    let port_zones = (0..port_zone_count)
        .map(|_| read_zone(stream, true))
        .collect::<Result<Vec<_>, _>>()?;
    let route_count = bounded_u32(
        u32::from(stream.read_le_u16()?),
        MAX_OCEAN_ROUTES,
        "ocean routes",
    )?;
    let route_segments = (0..route_count)
        .map(|_| {
            Ok([
                stream.read_le_i32()?,
                stream.read_le_i32()?,
                stream.read_le_i32()?,
                stream.read_le_i32()?,
            ])
        })
        .collect::<Result<Vec<_>, StreamError>>()?;
    Ok(LegacyOceanState {
        zones,
        port_zones,
        route_segments,
    })
}

pub(super) fn read_zone(
    stream: &mut LegacyStream<'_>,
    port: bool,
) -> Result<LegacyZone, StreamError> {
    let display_name = lossy_text(&stream.read_mfc_string()?);
    let status_code = stream.read_le_i16()?;
    let tile_or_terrain_id = stream.read_le_i32()?;
    let seed_nation_id = stream.read_le_i16()?;
    let active_tile_index = stream.read_le_i16()?;
    let context_ordinal = stream.read_le_i16()?;
    let port_tile_index = port.then(|| stream.read_le_i16()).transpose()?;
    Ok(LegacyZone {
        display_name,
        status_code,
        tile_or_terrain_id,
        seed_nation_id,
        active_tile_index,
        context_ordinal,
        port_tile_index,
    })
}

pub(super) fn read_navy(stream: &mut LegacyStream<'_>) -> Result<LegacyNavyState, LegacySaveError> {
    let ship_count = bounded_u32(u32::from(stream.read_le_u16()?), MAX_SHIPS, "navy ships")?;
    let mut ships = (0..ship_count)
        .map(|_| read_ship(stream))
        .collect::<Result<Vec<_>, _>>()?;
    ships.reverse();
    let admiral_count = bounded_u32(
        u32::from(stream.read_le_u16()?),
        MAX_ADMIRALS,
        "navy admirals",
    )?;
    let admirals = (0..admiral_count)
        .map(|_| read_admiral(stream))
        .collect::<Result<Vec<_>, _>>()?;
    let task_force_count = bounded_u32(
        u32::from(stream.read_le_u16()?),
        MAX_TASK_FORCES,
        "navy task forces",
    )?;
    let task_forces = (0..task_force_count)
        .map(|_| read_task_force(stream))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LegacyNavyState {
        ships,
        admirals,
        task_forces,
    })
}

pub(super) fn read_ship(stream: &mut LegacyStream<'_>) -> Result<LegacyShip, StreamError> {
    Ok(LegacyShip {
        ship_type: stream.read_le_i16()?,
        aggression: stream.read_le_i32()?,
        nation: stream.read_le_i16()?,
        name: lossy_text(&stream.read_mfc_string()?),
        strength: stream.read_le_i16()?,
        selection: stream.read_le_i32()?,
        experience: stream.read_le_i16()?,
        zone_ordinal: stream.read_le_i16()?,
    })
}

pub(super) fn read_admiral(stream: &mut LegacyStream<'_>) -> Result<LegacyAdmiral, StreamError> {
    Ok(LegacyAdmiral {
        nation: stream.read_le_i16()?,
        name: lossy_text(&stream.read_mfc_string()?),
        experience: stream.read_le_i16()?,
        ship_index: stream.read_le_i16()?,
    })
}

pub(super) fn read_task_force(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyTaskForce, LegacySaveError> {
    let aggression = stream.read_le_i32()?;
    let order = stream.read_le_i32()?;
    let target_ordinal = stream.read_le_i16()?;
    let location_ordinal = stream.read_le_i16()?;
    let nation = stream.read_le_i16()?;
    let defeated = stream.read_u8()?;
    let ingot_tile = stream.read_le_i16()?;
    let child_count = bounded_u32(
        u32::from(stream.read_le_u16()?),
        MAX_TASK_FORCE_CHILDREN,
        "task force ships",
    )?;
    let ships = (0..child_count)
        .map(|_| Ok([stream.read_le_i16()?, stream.read_le_i16()?]))
        .collect::<Result<Vec<_>, StreamError>>()?;
    Ok(LegacyTaskForce {
        aggression,
        order,
        target_ordinal,
        location_ordinal,
        nation,
        defeated,
        ingot_tile,
        ships,
    })
}

pub(super) fn skip_army_reports(stream: &mut LegacyStream<'_>) -> Result<u16, LegacySaveError> {
    let report_count = stream.read_le_u16()?;
    bounded_u32(u32::from(report_count), MAX_ARMY_REPORTS, "army reports")?;
    for _ in 0..report_count {
        stream.skip(8)?;
        for _ in 0..2 {
            stream.skip(1 + 0x20 + 0xff)?;
            let child_count = bounded_u32(
                u32::from(stream.read_le_u16()?),
                MAX_MILITARY_UNITS,
                "army report children",
            )?;
            let byte_len = child_count * 42;
            stream.skip(byte_len)?;
        }
    }
    Ok(report_count)
}

pub(super) fn read_country_base(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyCountryBase, LegacySaveError> {
    let identity = lossy_text(&stream.read_mfc_string()?);
    let alternate_identity = lossy_text(&stream.read_mfc_string()?);
    let nation_slot = stream.read_le_i16()?;
    let status = super::project::country_status_from_retail(stream.read_le_i16()?)?;
    let unit_name_ordinal_by_type = read_be_short_array(stream)?;
    let unit_name_counter = stream.read_le_i16()?;
    let treasury = stream.read_le_i32()?;
    let home_tile = stream.read_le_i32()?;
    let overlay_anchor_tile = stream.read_le_i32()?;
    let need_level_by_nation = read_be_short_array(stream)?;

    // TSortedList::ReadFrom is a retail no-op; the count follows immediately.
    let military_unit_count = bounded_u32(
        stream.read_le_u32()?,
        MAX_MILITARY_UNITS,
        "country military units",
    )?;
    let military_units = (0..military_unit_count)
        .map(|_| read_military_unit(stream))
        .collect::<Result<Vec<_>, _>>()?;

    // TLongintList::NoOpReadFrom is likewise a no-op.
    let owned_region_count = bounded_u32(
        stream.read_le_u32()?,
        MAX_OWNED_REGIONS,
        "country owned regions",
    )?;
    let owned_regions = (0..owned_region_count)
        .map(|_| stream.read_le_i32())
        .collect::<Result<Vec<_>, _>>()?;

    Ok(LegacyCountryBase {
        identity,
        alternate_identity,
        nation_slot,
        status,
        unit_name_ordinal_by_type,
        unit_name_counter,
        treasury,
        home_tile,
        overlay_anchor_tile,
        need_level_by_nation,
        military_units,
        owned_regions,
    })
}

pub(super) fn read_military_unit(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyMilitaryUnit, StreamError> {
    Ok(LegacyMilitaryUnit {
        unit_type: stream.read_le_i16()?,
        stationed_province: stream.read_le_i16()?,
        order_target: stream.read_le_i16()?,
        owner_nation: stream.read_le_i16()?,
        roster_id: stream.read_le_i16()?,
        registered: stream.read_u8()?,
        order: stream.read_le_i32()?,
        persistent_id: stream.read_le_i32()?,
        name: lossy_text(&stream.read_mfc_string()?),
        order_target_tiles: read_be_short_array(stream)?,
        order_target_mirrors: read_be_short_array(stream)?,
        strength: stream.read_le_i16()?,
        era: stream.read_le_i16()?,
        experience: stream.read_le_i16()?,
        battle_flags: stream.read_le_i16()?,
    })
}

pub(super) fn read_great_power_prefix(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyGreatPowerPrefix, LegacySaveError> {
    let diplomacy_eligible = stream.read_u8()?;
    let capacities = read_short_array(stream)?;
    let grant_total_cost = stream.read_le_i32()?;
    let unfilled_trade_offer_count = stream.read_le_i16()?;
    let diplomacy_policy_by_nation = read_be_short_array(stream)?;
    let diplomacy_grant_by_nation = read_be_short_array(stream)?;
    let need_current_by_type = read_be_short_array(stream)?;
    let need_target_by_type = read_be_short_array(stream)?;
    let relation_delta_current = read_be_short_array(stream)?;
    let purchased_items_by_resource = read_be_short_array(stream)?;
    let item_potentials = read_be_short_array(stream)?;
    let unfilled_trade_turns_by_resource = read_be_short_array(stream)?;
    let transported_items_by_resource = read_be_short_array(stream)?;
    let remembered_trade_offers_by_resource = read_be_short_array(stream)?;
    let budget_pool_base = stream.read_le_i32()?;
    let budget_pool_delta = stream.read_le_i32()?;
    let mut aid_allocation_by_minor_nation = [[0; RESOURCE_KIND_COUNT]; MINOR_NATION_COUNT];
    for resource_values in &mut aid_allocation_by_minor_nation {
        for value in resource_values {
            *value = stream.read_be_i32()?;
        }
    }
    let mut pending_action_status = [0; PENDING_ACTION_COUNT];
    for value in &mut pending_action_status {
        *value = stream.read_i8()?;
    }
    let pending_action_payload_by_action: [i16; PENDING_ACTION_COUNT] =
        read_be_short_array(stream)?;
    let mut pending_action_values = [PendingActionState::default(); PENDING_ACTION_COUNT];
    for (index, slot) in pending_action_values.iter_mut().enumerate() {
        *slot = super::project::pending_action_from_retail(
            pending_action_status[index],
            pending_action_payload_by_action[index],
        )?;
    }
    let pending_actions =
        PendingActionTable::from_fn(|action| pending_action_values[action as usize]);

    // These are TSortedByRelationshipList/TSortedPtrList instances, unlike the
    // no-op TSortedList hooks used by object-owning lists elsewhere.
    let relationship_lists = (0..19)
        .map(|_| read_fixed_record_list(stream))
        .collect::<Result<Vec<_>, _>>()?;
    let minister_presence_mask = stream.read_u8()?;

    Ok(LegacyGreatPowerPrefix {
        diplomacy_eligible,
        capacities,
        grant_total_cost,
        unfilled_trade_offer_count,
        diplomacy_policy_by_nation,
        diplomacy_grant_by_nation,
        need_current_by_type,
        need_target_by_type,
        relation_delta_current,
        purchased_items_by_resource,
        item_potentials,
        unfilled_trade_turns_by_resource,
        transported_items_by_resource,
        remembered_trade_offers_by_resource,
        budget_pool_base,
        budget_pool_delta,
        aid_allocation_by_minor_nation,
        pending_actions,
        relationship_lists,
        minister_presence_mask,
    })
}

pub(super) fn read_fixed_record_list(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyFixedRecordList, StreamError> {
    let record_size = stream.read_le_u16()?;
    let record_count = stream.read_le_u32()? as usize;
    let records = (0..record_count)
        .map(|_| Ok(stream.read_bytes(usize::from(record_size))?.to_vec()))
        .collect::<Result<Vec<_>, StreamError>>()?;
    Ok(LegacyFixedRecordList {
        record_size,
        records,
    })
}

pub(super) fn read_great_power_ministers(
    stream: &mut LegacyStream<'_>,
    presence_mask: u8,
    foreign_policy_id: i16,
) -> Result<LegacyGreatPowerMinisters, StreamError> {
    let foreign = (presence_mask & 1 != 0)
        .then(|| read_foreign_minister(stream, foreign_policy_id))
        .transpose()?;
    let interior = (presence_mask & 2 != 0)
        .then(|| read_interior_minister(stream))
        .transpose()?;
    let defense = (presence_mask & 4 != 0)
        .then(|| read_defense_minister(stream))
        .transpose()?;
    Ok(LegacyGreatPowerMinisters {
        foreign,
        interior,
        defense,
    })
}

pub(super) fn read_foreign_minister(
    stream: &mut LegacyStream<'_>,
    foreign_policy_id: i16,
) -> Result<LegacyForeignMinisterState, StreamError> {
    let skill_index = stream.read_le_i16()?;
    let scalar_fields = read_short_array(stream)?;
    let purchase_priority_by_resource = read_be_short_array(stream)?;
    let preferred_resource_slots = read_be_short_array(stream)?;
    let status_flag = stream.read_u8()?;
    let trade_partner_enabled = stream.read_bytes(7)?.try_into().unwrap();
    let development_grant_by_nation = read_be_short_array(stream)?;
    let bill_order_flag = (foreign_policy_id == 4)
        .then(|| stream.read_u8())
        .transpose()?;
    Ok(LegacyForeignMinisterState {
        skill_index,
        scalar_fields,
        purchase_priority_by_resource,
        preferred_resource_slots,
        status_flag,
        trade_partner_enabled,
        development_grant_by_nation,
        bill_order_flag,
    })
}

pub(super) fn read_interior_minister(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyInteriorMinisterState, StreamError> {
    let skill_index = stream.read_le_i16()?;
    let scalar_prefix = read_short_array(stream)?;
    let trailing_table = read_be_short_array(stream)?;
    let order_scalars = read_short_array(stream)?;
    let order_metrics = read_be_short_array(stream)?;
    let deferred_labor_shortfall = stream.read_le_i16()?;
    let order_short_table = read_be_short_array(stream)?;
    let order_type_tables = [
        read_be_short_array(stream)?,
        read_be_short_array(stream)?,
        read_be_short_array(stream)?,
    ];
    let temporarily_reserved_ship_arms = stream.read_le_i16()?;
    let integer_lists = [
        read_longint_list(stream)?,
        read_longint_list(stream)?,
        read_longint_list(stream)?,
    ];
    let civilian_order_demand_by_resource = read_be_short_array(stream)?;
    Ok(LegacyInteriorMinisterState {
        skill_index,
        scalar_prefix,
        trailing_table,
        order_scalars,
        order_metrics,
        deferred_labor_shortfall,
        order_short_table,
        order_type_tables,
        temporarily_reserved_ship_arms,
        integer_lists,
        civilian_order_demand_by_resource,
    })
}

pub(super) fn read_defense_minister(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyDefenseMinisterState, StreamError> {
    Ok(LegacyDefenseMinisterState {
        skill_index: stream.read_le_i16()?,
        scalar_fields: read_short_array(stream)?,
        recruit_order_count_by_type: read_be_short_array(stream)?,
        order_weight_by_type: read_be_short_array(stream)?,
        thresholds: read_short_array(stream)?,
    })
}

pub(super) fn read_longint_list(stream: &mut LegacyStream<'_>) -> Result<Vec<i32>, StreamError> {
    let count = stream.read_le_u32()? as usize;
    if count > MAX_LONGINT_LIST {
        return Err(StreamError::InvalidCount {
            context: "longint list",
            value: count as i64,
            maximum: MAX_LONGINT_LIST,
        });
    }
    (0..count)
        .map(|_| stream.read_le_i32())
        .collect::<Result<Vec<_>, _>>()
}

pub(super) fn read_city(stream: &mut LegacyStream<'_>) -> Result<LegacyCityState, LegacySaveError> {
    let power_plant_upgrade_queued = stream.read_u8()?;
    let low_production = stream.read_u8()?;
    let low_stock = stream.read_u8()?;
    let production_flags = stream
        .read_bytes(CITY_PRODUCTION_SLOT_COUNT)?
        .try_into()
        .unwrap();
    let food_substitution_count = stream.read_le_i16()?;
    let starvation_population_loss = stream.read_le_i16()?;
    let serialized_state = stream.read_le_i16()?;
    let phase_counter = stream.read_le_i16()?;
    let power_available = stream.read_le_i16()?;
    let military_recruit_count_by_kind = read_be_short_array(stream)?;
    let civilian_recruit_count_by_kind = read_be_short_array(stream)?;
    let order_count_by_type = read_be_short_array(stream)?;
    let stockpile = read_be_short_array(stream)?;
    let production_orders = read_be_short_array(stream)?;
    let production_accum = read_be_short_array(stream)?;
    let unmet_resource_retries = read_be_short_array(stream)?;
    let reserved_by_type = read_be_short_array(stream)?;
    let production_current = read_be_short_array(stream)?;
    let production_progress = read_be_short_array(stream)?;
    let consumed_production_input_by_type = read_be_short_array(stream)?;
    let rolling_item_production_score = stream.read_le_i32()?;
    let population = read_population(stream)?;
    let orders = read_city_orders(stream)?;

    // TTaskList's inherited TSortedList stream hook is a no-op.
    let task_count = stream.read_le_u32()? as usize;
    if task_count > MAX_CITY_TASKS {
        return Err(LegacySaveError::InvalidCount {
            context: "city tasks",
            value: task_count as i64,
            maximum: MAX_CITY_TASKS,
        });
    }
    let tasks = (0..task_count)
        .map(|_| {
            let kind = stream.read_u8()?;
            let payload_size = if kind == 1 { 8 } else { 12 };
            Ok(LegacyCityTask {
                kind,
                payload: stream.read_bytes(payload_size)?.to_vec(),
            })
        })
        .collect::<Result<Vec<_>, StreamError>>()?;
    let transport_requests = read_fixed_record_list(stream)?;

    Ok(LegacyCityState {
        power_plant_upgrade_queued,
        low_production,
        low_stock,
        production_flags,
        food_substitution_count,
        starvation_population_loss,
        serialized_state,
        phase_counter,
        power_available,
        military_recruit_count_by_kind,
        civilian_recruit_count_by_kind,
        order_count_by_type,
        stockpile,
        production_orders,
        production_accum,
        unmet_resource_retries,
        reserved_by_type,
        production_current,
        production_progress,
        consumed_production_input_by_type,
        rolling_item_production_score,
        population,
        orders,
        tasks,
        transport_requests,
    })
}

pub(super) struct LegacyRequestedCityOrder {
    product: i16,
    state: RequestedCityOrderState,
    primary_input: i16,
    secondary_input: i16,
    production_slot: i16,
}

pub(super) struct LegacyRecruitOrder {
    product: i16,
    progress: ProductionProgress,
    primary_input: i16,
    secondary_input: i16,
    primary_per_unit: i16,
    secondary_per_unit: i16,
    cash_per_unit: i16,
    workforce: i16,
    specialist: u8,
}

pub(super) fn read_city_orders(
    stream: &mut LegacyStream<'_>,
) -> Result<CityOrders, LegacySaveError> {
    // TCity owns a fixed but untagged 61-pointer registry. Only these 47 entries
    // are constructed, so their concrete type is established by ICity's slot map.
    let food_processing = read_plain_city_order(stream, "slot 7 food processing", 7)?;

    let mut items = ResourceTable::default();
    for output in ManufacturedItem::ALL {
        items[output.resource()] = Some(read_item_order(stream, output)?);
    }

    let training = TrainingOrderTable::from_array([
        read_plain_city_order(stream, "slot 23 medium training", 1)?,
        read_plain_city_order(stream, "slot 24 high training", 2)?,
    ]);

    let military_recruitment = MilitaryRecruitOrderTable::from_array([
        read_military_recruit_order(
            stream,
            "slot 25 light infantry",
            MilitaryRecruitmentCategory::LightInfantry,
        )?,
        read_military_recruit_order(
            stream,
            "slot 26 regular infantry",
            MilitaryRecruitmentCategory::RegularInfantry,
        )?,
        read_military_recruit_order(
            stream,
            "slot 27 heavy infantry",
            MilitaryRecruitmentCategory::HeavyInfantry,
        )?,
        read_military_recruit_order(
            stream,
            "slot 28 light cavalry",
            MilitaryRecruitmentCategory::LightCavalry,
        )?,
        read_military_recruit_order(
            stream,
            "slot 29 heavy cavalry",
            MilitaryRecruitmentCategory::HeavyCavalry,
        )?,
        read_military_recruit_order(
            stream,
            "slot 30 light artillery",
            MilitaryRecruitmentCategory::LightArtillery,
        )?,
        read_military_recruit_order(
            stream,
            "slot 31 heavy artillery",
            MilitaryRecruitmentCategory::HeavyArtillery,
        )?,
        read_military_recruit_order(
            stream,
            "slot 32 combat engineers",
            MilitaryRecruitmentCategory::Demolitionist,
        )?,
    ]);

    let civilian_recruitment = CivilianUnitTable::from_array([
        read_civilian_recruit_order(stream, CivilianUnitKind::Miner)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Prospector)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Farmer)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Forester)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Engineer)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Rancher)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Fisherman)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Developer)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Driller)?,
    ]);

    let ships = ShipOrderTable::from_array([
        read_ship_order(
            stream,
            "slot 43 early merchant primary",
            ShipOrderSlot::MerchantEarlyPrimary,
        )?,
        read_ship_order(
            stream,
            "slot 44 early merchant secondary",
            ShipOrderSlot::MerchantEarlySecondary,
        )?,
        read_ship_order(
            stream,
            "slot 45 advanced merchant primary",
            ShipOrderSlot::MerchantAdvancedPrimary,
        )?,
        read_ship_order(
            stream,
            "slot 46 advanced merchant secondary",
            ShipOrderSlot::MerchantAdvancedSecondary,
        )?,
        read_ship_order(
            stream,
            "slot 47 early warship primary",
            ShipOrderSlot::WarshipEarlyPrimary,
        )?,
        read_ship_order(
            stream,
            "slot 48 early warship secondary",
            ShipOrderSlot::WarshipEarlySecondary,
        )?,
        read_ship_order(
            stream,
            "slot 49 advanced warship primary",
            ShipOrderSlot::WarshipAdvancedPrimary,
        )?,
        read_ship_order(
            stream,
            "slot 50 advanced warship secondary",
            ShipOrderSlot::WarshipAdvancedSecondary,
        )?,
    ]);

    let transport_capacity = read_transport_capacity_order(stream)?;
    let power_plant = read_power_plant_order(stream)?;

    let mut expansions = ProductionTable::default();
    for target in ExpandableFacility::ALL {
        expansions[target.slot()] = Some(read_expansion_order(stream, target)?);
    }

    let population_growth = read_plain_city_order(stream, "slot 60 population growth", 1)?;

    Ok(CityOrders {
        items,
        civilian_recruitment,
        military_recruitment,
        ships,
        training,
        expansions,
        food_processing,
        power_plant,
        transport_capacity,
        population_growth,
    })
}

pub(super) fn read_order_progress(
    stream: &mut LegacyStream<'_>,
    order: &'static str,
) -> Result<(i16, ProductionProgress), LegacySaveError> {
    let _constructor_product = stream.read_le_i16()?;
    let quantity = stream.read_le_i16()?;
    let limiting_constraint = match stream.read_le_i16()? {
        0 => ProductionConstraint::Resources,
        1 => ProductionConstraint::Workforce,
        2 => ProductionConstraint::Capacity,
        3 => ProductionConstraint::Treasury,
        value => {
            return Err(invalid_city_order(
                order,
                format!("limiting constraint {value} is outside 0..=3"),
            ));
        }
    };
    // TProductionOrder::ReadFrom overwrites the constructor product with this
    // second serialized word. The first word is not authoritative live state.
    let product = stream.read_le_i16()?;
    let tracking_by_resource = ResourceTable::from_array(read_short_array(stream)?);
    let accumulated_value = stream.read_le_i32()?;
    Ok((
        product,
        ProductionProgress {
            quantity,
            tracking_by_resource,
            // TProductionOrder::ReadFrom does not persist or reconstruct this field.
            reserved_workforce: 0,
            limiting_constraint,
            accumulated_value,
        },
    ))
}

pub(super) fn read_plain_city_order(
    stream: &mut LegacyStream<'_>,
    order: &'static str,
    expected_product: i16,
) -> Result<ProductionProgress, LegacySaveError> {
    let (product, progress) = read_order_progress(stream, order)?;
    require_city_order_value(order, "product", product, expected_product)?;
    Ok(progress)
}

pub(super) fn read_requested_city_order(
    stream: &mut LegacyStream<'_>,
    order: &'static str,
) -> Result<LegacyRequestedCityOrder, LegacySaveError> {
    let (product, progress) = read_order_progress(stream, order)?;
    let requested_quantity = stream.read_le_i16()?;
    Ok(LegacyRequestedCityOrder {
        product,
        state: RequestedCityOrderState {
            progress,
            requested_quantity,
        },
        primary_input: stream.read_le_i16()?,
        secondary_input: stream.read_le_i16()?,
        production_slot: stream.read_le_i16()?,
    })
}

pub(super) fn read_item_order(
    stream: &mut LegacyStream<'_>,
    output: ManufacturedItem,
) -> Result<RequestedCityOrderState, LegacySaveError> {
    let order = "slots 8..=16 item production";
    let raw = read_requested_city_order(stream, order)?;
    let spec = item_order_spec(output);
    let (primary_input, secondary_input) = match spec.inputs {
        ItemInputs::Double(primary) => (primary as i16, -1),
        ItemInputs::Both(primary, secondary) | ItemInputs::Either(primary, secondary) => {
            (primary as i16, secondary as i16)
        }
    };
    require_city_order_value(order, "product", raw.product, output.resource() as i16)?;
    require_city_order_value(order, "primary input", raw.primary_input, primary_input)?;
    require_city_order_value(
        order,
        "secondary input",
        raw.secondary_input,
        secondary_input,
    )?;
    require_city_order_value(
        order,
        "production slot",
        raw.production_slot,
        spec.production_slot as i16,
    )?;
    Ok(raw.state)
}

pub(super) fn read_transport_capacity_order(
    stream: &mut LegacyStream<'_>,
) -> Result<RequestedCityOrderState, LegacySaveError> {
    let order = "slot 51 transport capacity";
    let raw = read_requested_city_order(stream, order)?;
    let spec = transport_capacity_order_spec();
    require_city_order_value(
        order,
        "product",
        raw.product,
        CityFacilitySlot::Transport as i16,
    )?;
    require_city_order_value(
        order,
        "primary input",
        raw.primary_input,
        spec.primary as i16,
    )?;
    require_city_order_value(
        order,
        "secondary input",
        raw.secondary_input,
        spec.secondary as i16,
    )?;
    require_city_order_value(
        order,
        "production slot",
        raw.production_slot,
        spec.production_slot as i16,
    )?;
    Ok(raw.state)
}

pub(super) fn read_expansion_order(
    stream: &mut LegacyStream<'_>,
    target: ExpandableFacility,
) -> Result<RequestedCityOrderState, LegacySaveError> {
    let order = "slots 53..=59 industry expansion";
    let raw = read_requested_city_order(stream, order)?;
    let spec = expansion_order_spec(target);
    require_city_order_value(order, "product", raw.product, target.slot() as i16)?;
    require_city_order_value(
        order,
        "primary input",
        raw.primary_input,
        spec.primary as i16,
    )?;
    require_city_order_value(
        order,
        "secondary input",
        raw.secondary_input,
        spec.secondary as i16,
    )?;
    require_city_order_value(
        order,
        "production slot",
        raw.production_slot,
        spec.production_slot as i16,
    )?;
    Ok(raw.state)
}

pub(super) fn read_recruit_order(
    stream: &mut LegacyStream<'_>,
    order: &'static str,
) -> Result<LegacyRecruitOrder, LegacySaveError> {
    let (product, progress) = read_order_progress(stream, order)?;
    let raw = LegacyRecruitOrder {
        product,
        progress,
        primary_input: stream.read_le_i16()?,
        secondary_input: stream.read_le_i16()?,
        primary_per_unit: stream.read_le_i16()?,
        secondary_per_unit: stream.read_le_i16()?,
        cash_per_unit: stream.read_le_i16()?,
        workforce: stream.read_le_i16()?,
        specialist: stream.read_u8()?,
    };
    Ok(raw)
}

pub(super) fn read_military_recruit_order(
    stream: &mut LegacyStream<'_>,
    order: &'static str,
    category: MilitaryRecruitmentCategory,
) -> Result<MilitaryRecruitOrderState, LegacySaveError> {
    let raw = read_recruit_order(stream, order)?;
    require_city_order_value(order, "specialist flag", i16::from(raw.specialist), 1)?;
    let unit_kind = u8::try_from(raw.product)
        .ok()
        .and_then(MilitaryUnitKind::from_index)
        .ok_or_else(|| {
            invalid_city_order(order, format!("invalid military unit type {}", raw.product))
        })?;
    if military_recruitment_category(unit_kind) != Some(category) {
        return Err(invalid_city_order(
            order,
            format!("{unit_kind:?} does not belong to the {category:?} armory category"),
        ));
    }
    let spec = military_recruitment_spec(unit_kind).ok_or_else(|| {
        invalid_city_order(
            order,
            format!("{unit_kind:?} has no retail recruitment recipe"),
        )
    })?;
    validate_recruit_order_spec(order, &raw, spec)?;
    Ok(MilitaryRecruitOrderState {
        unit_kind,
        progress: raw.progress,
    })
}

pub(super) fn read_civilian_recruit_order(
    stream: &mut LegacyStream<'_>,
    kind: CivilianUnitKind,
) -> Result<ProductionProgress, LegacySaveError> {
    let order = "slots 34..=42 civilian recruitment";
    let raw = read_recruit_order(stream, order)?;
    require_city_order_value(order, "product", raw.product, kind as i16)?;
    require_city_order_value(order, "specialist flag", i16::from(raw.specialist), 0)?;
    let spec = civilian_recruitment_spec(kind);
    validate_recruit_order_spec(order, &raw, spec)?;
    Ok(raw.progress)
}

pub(super) fn read_ship_order(
    stream: &mut LegacyStream<'_>,
    order: &'static str,
    slot: ShipOrderSlot,
) -> Result<ShipOrderState, LegacySaveError> {
    let (product, progress) = read_order_progress(stream, order)?;
    let ship_type = ship_type_from_retail(order, product)?;
    if !ship_type_is_valid_for_order_slot(slot, ship_type) {
        return Err(invalid_city_order(
            order,
            format!("{ship_type:?} is not valid for {slot:?}"),
        ));
    }
    Ok(ShipOrderState {
        ship_type,
        progress,
    })
}

pub(super) fn read_power_plant_order(
    stream: &mut LegacyStream<'_>,
) -> Result<PowerPlantOrderState, LegacySaveError> {
    let order = "slot 52 power plant";
    let (product, progress) = read_order_progress(stream, order)?;
    require_city_order_value(order, "product", product, 0)?;
    let desired_quantity = stream.read_le_i16()?;
    Ok(PowerPlantOrderState {
        progress,
        desired_quantity,
    })
}

pub(super) fn validate_recruit_order_spec(
    order: &'static str,
    raw: &LegacyRecruitOrder,
    spec: RecruitmentOrderSpec,
) -> Result<(), LegacySaveError> {
    let (secondary_input, secondary_per_unit) = match spec.secondary {
        Some(cost) => (cost.resource as i16, cost.per_unit()),
        None => (-1, 0),
    };
    require_city_order_value(
        order,
        "primary input",
        raw.primary_input,
        spec.primary.resource as i16,
    )?;
    require_city_order_value(
        order,
        "primary per-unit cost",
        raw.primary_per_unit,
        spec.primary.per_unit(),
    )?;
    require_city_order_value(
        order,
        "secondary input",
        raw.secondary_input,
        secondary_input,
    )?;
    require_city_order_value(
        order,
        "secondary per-unit cost",
        raw.secondary_per_unit,
        secondary_per_unit,
    )?;
    require_city_order_value(order, "cash cost", raw.cash_per_unit, spec.cash_per_unit)?;
    require_city_order_value(
        order,
        "workforce mode",
        raw.workforce,
        spec.workforce as i16,
    )
}

pub(super) fn ship_type_from_retail(
    order: &'static str,
    value: i16,
) -> Result<ShipType, LegacySaveError> {
    let ship_type = match value {
        0 => ShipType::NoShip,
        1 => ShipType::Trader,
        2 => ShipType::Indiaman,
        3 => ShipType::Frigate,
        4 => ShipType::ShipOfTheLine,
        5 => ShipType::Paddlewheeler,
        6 => ShipType::Clipper,
        7 => ShipType::Raider,
        8 => ShipType::Ironclad,
        9 => ShipType::AdvancedIronclad,
        10 => ShipType::Freighter,
        11 => ShipType::ArmoredCruiser,
        12 => ShipType::Dreadnought,
        13 => ShipType::Battlecruiser,
        _ => {
            return Err(invalid_city_order(
                order,
                format!("ship type {value} is outside 0..=13"),
            ));
        }
    };
    Ok(ship_type)
}

pub(super) fn require_city_order_value(
    order: &'static str,
    field: &'static str,
    actual: i16,
    expected: i16,
) -> Result<(), LegacySaveError> {
    if actual != expected {
        return Err(invalid_city_order(
            order,
            format!("{field} is {actual}; expected {expected}"),
        ));
    }
    Ok(())
}

pub(super) fn invalid_city_order(order: &'static str, detail: String) -> LegacySaveError {
    LegacySaveError::InvalidCityOrder { order, detail }
}

pub(super) fn read_population(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyPopulationState, StreamError> {
    Ok(LegacyPopulationState {
        count: stream.read_le_i16()?,
        strength: stream.read_le_i16()?,
        extra: stream.read_le_i16()?,
        phase_value: stream.read_le_i16()?,
        // TPopulationMgr persists this block raw, unlike TCity's swapped arrays.
        predicted_need_by_resource: read_short_array(stream)?,
        count_float_bits: stream.read_le_u32()?,
        baseline_labor: read_short_array(stream)?,
        production_labor: read_short_array(stream)?,
        pending_labor_delta: read_short_array(stream)?,
    })
}

pub(super) fn read_great_power_post_city(
    stream: &mut LegacyStream<'_>,
    absolute_offset: usize,
) -> Result<LegacyGreatPowerPostCity, LegacySaveError> {
    let town_count = stream.read_le_u32()? as usize;
    let towns = (0..town_count)
        .map(|_| read_town(stream))
        .collect::<Result<Vec<_>, _>>()?;
    let civilian_count = stream.read_le_u32()? as usize;
    let civilian_units = (0..civilian_count)
        .map(|_| read_civilian_unit(stream))
        .collect::<Result<Vec<_>, _>>()?;
    let candidate_nation_flags = stream.read_bytes(NATION_COUNT)?.try_into().unwrap();
    let diplomacy_budget_base = stream.read_le_i32()?;
    let escalation_counter = stream.read_i8()?;
    let pending_commitment_cost = stream.read_le_i32()?;
    let pressure_counter = stream.read_i8()?;
    let army_movement_budget = stream.read_le_i32()?;
    let turn_finished_flag = stream.read_u8()?;

    let object_count_offset = absolute_offset + stream.position();
    let mission_node_count = stream.read_le_u32()?;
    if mission_node_count != 0 {
        return Err(LegacySaveError::UnsupportedPolymorphicObjects {
            context: "great-power turn-start queue",
            count: mission_node_count,
            offset: object_count_offset,
        });
    }

    let special_resource_trade_balance = stream.read_le_i32()?;
    let aid_allocation_total = stream.read_le_i32()?;
    let colony_boycott_flags = stream.read_bytes(NATION_COUNT)?.try_into().unwrap();
    let military_expenses = stream.read_le_i32()?;
    Ok(LegacyGreatPowerPostCity {
        towns,
        civilian_units,
        candidate_nation_flags,
        diplomacy_budget_base,
        escalation_counter,
        pending_commitment_cost,
        pressure_counter,
        army_movement_budget,
        turn_finished_flag,
        special_resource_trade_balance,
        aid_allocation_total,
        colony_boycott_flags,
        military_expenses,
    })
}

pub(super) fn read_town(stream: &mut LegacyStream<'_>) -> Result<LegacyTown, StreamError> {
    Ok(LegacyTown {
        name: fixed_text(stream.read_bytes(0x10)?),
        tile_index: stream.read_le_i16()?,
        opaque_fields: read_short_array(stream)?,
        created_turn: stream.read_le_i16()?,
        owner_nation: stream.read_le_i16()?,
        resource_yield_by_type: read_be_short_array(stream)?,
        transport_linked: stream.read_u8()?,
        enabled: stream.read_u8()?,
        has_adjacent_city: stream.read_u8()?,
        active: stream.read_u8()?,
    })
}

pub(super) fn read_civilian_unit(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyCivilianUnit, StreamError> {
    Ok(LegacyCivilianUnit {
        unit_type: stream.read_le_i16()?,
        tile_index: stream.read_le_i16()?,
        order_target: stream.read_le_i16()?,
        owner_nation: stream.read_le_i16()?,
        roster_id: stream.read_le_i16()?,
        registered: stream.read_u8()?,
        order: stream.read_le_i32()?,
        persistent_id: stream.read_le_i32()?,
        remaining_turns: stream.read_le_i16()?,
    })
}

pub(super) fn read_auto_great_power_prefix(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyAutoGreatPowerPrefix, StreamError> {
    Ok(LegacyAutoGreatPowerPrefix {
        action_metric_by_quarter: read_be_short_array(stream)?,
        map_node_state_flags: stream.read_bytes(0x180)?.try_into().unwrap(),
        port_zone_state_flags: stream.read_bytes(0x70)?.try_into().unwrap(),
        mission_count: stream.read_le_u32()?,
    })
}

pub(super) fn read_mfc_mission(
    stream: &mut LegacyStream<'_>,
    base_offset: usize,
    archive: &mut LegacyMfcArchiveState,
) -> Result<LegacyMission, LegacySaveError> {
    const NEW_CLASS_TAG: u16 = 0xffff;
    const CLASS_TAG: u16 = 0x8000;
    const BIG_TAG: u16 = 0x7fff;
    const BIG_CLASS_TAG: u32 = 0x8000_0000;

    let object_offset = base_offset + stream.position();
    let word_tag = stream.read_le_u16()?;
    let object_tag = if word_tag == BIG_TAG {
        stream.read_le_u32()?
    } else {
        (u32::from(word_tag & CLASS_TAG) << 16) | u32::from(word_tag & !CLASS_TAG)
    };
    if object_tag & BIG_CLASS_TAG == 0 {
        return Err(LegacySaveError::InvalidMfcObject {
            offset: object_offset,
            detail: format!("object reference tag {object_tag:#x} is not a new mission"),
        });
    }

    let class = if word_tag == NEW_CLASS_TAG {
        let schema = stream.read_le_u16()?;
        if schema != 1 {
            return Err(LegacySaveError::InvalidMfcObject {
                offset: object_offset,
                detail: format!("mission schema {schema} is not schema 1"),
            });
        }
        let name_length = usize::from(stream.read_le_u16()?);
        let name = lossy_text(stream.read_bytes(name_length)?);
        archive.entries.push(Some(name.clone()));
        name
    } else {
        let class_index = (object_tag & !BIG_CLASS_TAG) as usize;
        archive
            .entries
            .get(class_index)
            .and_then(Clone::clone)
            .ok_or_else(|| LegacySaveError::InvalidMfcObject {
                offset: object_offset,
                detail: format!("class tag references absent map index {class_index}"),
            })?
    };

    // ReadObject reserves the object index before invoking Serialize, allowing cycles.
    archive.entries.push(None);
    read_mission_payload(stream, class, object_offset)
}

pub(super) fn read_mission_payload(
    stream: &mut LegacyStream<'_>,
    class: String,
    object_offset: usize,
) -> Result<LegacyMission, LegacySaveError> {
    let source_nation = stream.read_le_i16()?;
    let state = stream.read_u8()?;
    let importance_bits = stream.read_le_u32()?;
    let flag = stream.read_u8()?;
    let path_marker = stream.read_le_i16()?;
    let marker = stream.read_u8()?;

    let mut mission = LegacyMission {
        class: class.clone(),
        source_nation,
        state,
        importance_bits,
        flag,
        path_marker,
        marker,
        army: None,
        navy: None,
        target_province: None,
        amassing_province: None,
        beachhead: None,
        blockade_port_zone: None,
    };

    match class.as_str() {
        "TDefendProvinceMission" => mission.army = Some(read_army_mission(stream)?),
        "TAttackProvinceMission" => {
            mission.army = Some(read_army_mission(stream)?);
            read_attack_mission(stream, &mut mission)?;
        }
        "TInvadeMission" => {
            mission.army = Some(read_army_mission(stream)?);
            read_attack_mission(stream, &mut mission)?;
            mission.beachhead = Some(read_navy_mission(stream)?);
        }
        "TControlSeaZoneMission"
        | "TEscortMission"
        | "TScatteredShipsMission"
        | "TBeachheadMission" => mission.navy = Some(read_navy_mission(stream)?),
        "TBlockadePortMission" => {
            mission.navy = Some(read_navy_mission(stream)?);
            mission.blockade_port_zone = Some(stream.read_le_i16()?);
        }
        _ => {
            return Err(LegacySaveError::InvalidMfcObject {
                offset: object_offset,
                detail: format!("unsupported mission runtime class {class}"),
            });
        }
    }

    Ok(mission)
}

pub(super) fn read_army_mission(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyArmyMission, LegacySaveError> {
    let present_location = stream.read_le_i16()?;
    let required_equipage_bits = read_be_u32_array(stream)?;
    let count = bounded_count(
        i32::from(stream.read_le_i16()?),
        MAX_MILITARY_UNITS,
        "army mission units",
    )?;
    let unit_ordinals = (0..count)
        .map(|_| stream.read_le_i16())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LegacyArmyMission {
        present_location,
        required_equipage_bits,
        unit_ordinals,
    })
}

pub(super) fn read_navy_mission(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyNavyMission, StreamError> {
    let target_zone = stream.read_le_i16()?;
    let resolved_port_zone = stream.read_le_i16()?;
    let required_equipage_bits = read_be_u32_array(stream)?;
    let mut ship_ordinals = Vec::new();
    loop {
        let ordinal = stream.read_le_i16()?;
        if ordinal < 0 {
            break;
        }
        ship_ordinals.push(ordinal);
    }
    let state = stream.read_le_i32()?;
    Ok(LegacyNavyMission {
        target_zone,
        resolved_port_zone,
        required_equipage_bits,
        ship_ordinals,
        state,
    })
}

pub(super) fn read_attack_mission(
    stream: &mut LegacyStream<'_>,
    mission: &mut LegacyMission,
) -> Result<(), StreamError> {
    mission.target_province = Some(stream.read_le_i16()?);
    mission.amassing_province = Some(stream.read_le_i16()?);
    Ok(())
}

pub(super) fn read_terrain_tile(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyTerrainTile, StreamError> {
    let bytes = stream.read_bytes(TERRAIN_TILE_SERIALIZED_SIZE)?;
    Ok(LegacyTerrainTile {
        terrain_kind: bytes[0] as i8,
        sprite_variant: bytes[1],
        river_sprite: bytes[2],
        former_owner_nation: bytes[3] as i8,
        owner_nation: bytes[4] as i8,
        secondary_owner_nation: bytes[0x18] as i8,
        owner_border_mask: bytes[7],
        city_border_mask: bytes[8],
        water_adjacency_mask: bytes[9],
        region: bytes[5] as i8,
        adjacency_bits: bytes[6],
        adjacency_mask_a: bytes[0x0a],
        adjacency_mask_b: bytes[0x0b],
        development_classes: bytes[0x0c] as i8,
        pending_development_visibility: bytes[0x0d],
        recruit_search_visited: bytes[0x0e],
        per_tile_visited: bytes[0x0f] as i8,
        marker_slot_index: bytes[0x10] as i8,
        edge_resources: [bytes[0x11] as i8, bytes[0x12] as i8],
        gate: bytes[0x13] as i8,
        city_record_index: i16::from_le_bytes(bytes[0x14..0x16].try_into().unwrap()),
        action_state: bytes[0x16] as i8,
        rail_flags: bytes[0x17],
        tile_action_ordinal: i16::from_le_bytes(bytes[0x1a..0x1c].try_into().unwrap()),
        active_flags: u16::from_le_bytes(bytes[0x1c..0x1e].try_into().unwrap()),
    })
}

pub(super) fn read_province(stream: &mut LegacyStream<'_>) -> Result<LegacyProvince, StreamError> {
    let bytes = stream.read_bytes(PROVINCE_FIXED_SERIALIZED_SIZE)?;
    let name = lossy_text(&stream.read_mfc_string()?);
    Ok(LegacyProvince {
        owner_nation: bytes[0] as i8,
        former_owner_nation: bytes[1] as i8,
        development_stage: bytes[2] as i8,
        fort_level: bytes[3] as i8,
        city_tile: i16::from_le_bytes(bytes[4..6].try_into().unwrap()),
        last_turn_tick: i16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        adjacent_region_count: bytes[8] as i8,
        adjacent_region_ids: std::array::from_fn(|index| {
            let offset = 0x0a + index * 2;
            i16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
        }),
        adjacent_region_anchor_tiles: std::array::from_fn(|index| {
            let offset = 0x22 + index * 2;
            i16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
        }),
        linked_region_count: bytes[0x3a] as i8,
        secondary_neighbor_tile: i16::from_le_bytes(bytes[0x3e..0x40].try_into().unwrap()),
        primary_neighbor_tile: i16::from_le_bytes(bytes[0x40..0x42].try_into().unwrap()),
        linked_tile_indices: std::array::from_fn(|index| {
            let offset = 0x42 + index * 2;
            i16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
        }),
        resource_development_by_type: std::array::from_fn(|index| {
            let offset = 0x82 + index * 2;
            i16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
        }),
        city_score: i32::from_le_bytes(bytes[0x9c..0xa0].try_into().unwrap()),
        navy_order_reachable: bytes[0xa0],
        explored_by_nation_mask: bytes[0xa1],
        resource_presence_mask: bytes[0xa2] as i8,
        region_class: bytes[0xa3] as i8,
        name,
    })
}

pub(super) fn read_game_setup(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyGameSetup, StreamError> {
    let multiplayer_game_active = stream.read_u8()?;
    stream.skip(1)?;
    let nation_control_modes = read_short_array(stream)?;
    let city_minister_policy_ids = read_short_array(stream)?;
    let foreign_minister_policy_ids = read_short_array(stream)?;
    let defense_minister_policy_ids = read_short_array(stream)?;
    let reload_political_map_state = stream.read_u8()?;
    stream.skip(1)?;
    let raw_scenario_map = stream.read_le_i16()?;
    let scenario_map =
        (raw_scenario_map > 0).then(|| ScenarioMapId::new((raw_scenario_map - 1) as u16));
    Ok(LegacyGameSetup {
        multiplayer_game_active,
        nation_control_modes,
        city_minister_policy_ids,
        foreign_minister_policy_ids,
        defense_minister_policy_ids,
        reload_political_map_state,
        scenario_map,
    })
}

pub(super) fn read_short_array<const N: usize>(
    stream: &mut LegacyStream<'_>,
) -> Result<[i16; N], StreamError> {
    let mut values = [0; N];
    for value in &mut values {
        *value = stream.read_le_i16()?;
    }
    Ok(values)
}

pub(super) fn read_be_short_array<const N: usize>(
    stream: &mut LegacyStream<'_>,
) -> Result<[i16; N], StreamError> {
    let mut values = [0; N];
    for value in &mut values {
        *value = stream.read_be_i16()?;
    }
    Ok(values)
}

pub(super) fn read_be_u32_array<const N: usize>(
    stream: &mut LegacyStream<'_>,
) -> Result<[u32; N], StreamError> {
    let mut values = [0; N];
    for value in &mut values {
        *value = u32::from_be_bytes(stream.read_bytes(4)?.try_into().unwrap());
    }
    Ok(values)
}
