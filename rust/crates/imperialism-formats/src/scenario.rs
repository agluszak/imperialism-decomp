use imperialism_core::*;
use std::fmt::Display;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioScriptError {
    offset: usize,
    detail: String,
}

impl Display for ScenarioScriptError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "scenario script byte {}: {}",
            self.offset, self.detail
        )
    }
}

impl std::error::Error for ScenarioScriptError {}

pub fn decode_scenario_script(
    bytes: &[u8],
) -> Result<Vec<ScenarioInstruction>, ScenarioScriptError> {
    let mut reader = ScenarioReader { bytes, offset: 0 };
    let mut instructions = Vec::new();
    while reader.offset < bytes.len() {
        let tag_offset = reader.offset;
        let tag = reader.read_array::<4>()?;
        if &tag == b"TERM" {
            break;
        }
        let instruction = match &tag {
            b"labo" => ScenarioInstruction::SetLabor {
                nation: reader.major()?,
                unskilled: reader.short()?,
                skilled: reader.short()?,
                professionals: reader.short()?,
            },
            b"capa" => ScenarioInstruction::SetProductionCapacity {
                nation: reader.major()?,
                slot: reader.short()? as u16,
                value: reader.short()?,
            },
            b"ware" => ScenarioInstruction::SetStockpile {
                nation: reader.major()?,
                resource: reader.resource()?,
                value: reader.short()?,
            },
            b"army" => ScenarioInstruction::CreateArmy {
                province: reader.province()?,
                kind: reader.military_kind()?,
                count: reader.dword()?,
            },
            b"civi" => ScenarioInstruction::CreateCivilian {
                kind: reader.civilian_kind()?,
                tile: reader.tile()?,
            },
            b"ship" => ScenarioInstruction::CreateShips {
                nation: reader.major()?,
                kind: reader.ship_type()?,
                zone: reader.short()? as u16,
                count: reader.dword()?,
            },
            b"tran" => ScenarioInstruction::SetTransportCapacity {
                nation: reader.major()?,
                value: reader.short()?,
            },
            b"deve" => ScenarioInstruction::SetDevelopment {
                tile: reader.tile()?,
                value: reader.dword()?.to_be_bytes()[3],
            },
            b"rail" => ScenarioInstruction::BuildDepot {
                tile: reader.tile()?,
            },
            b"port" => ScenarioInstruction::BuildPort {
                tile: reader.tile()?,
            },
            b"tech" => ScenarioInstruction::UnlockTechnology {
                nation: reader.major()?,
                technology: reader.technology()?,
            },
            b"pric" => ScenarioInstruction::SetMarketPrice {
                commodity: reader.commodity()?,
                value: reader.short()?,
            },
            b"emba" => ScenarioInstruction::SetMissionLevel {
                source: reader.nation()?,
                target: reader.nation()?,
                level: reader.mission_level()?,
            },
            b"subs" => ScenarioInstruction::SetTradePolicy {
                owner: reader.major()?,
                target: reader.short_nation()?,
                score: TradePolicyScore::new(i32::from(reader.short()?)),
            },
            b"trea" => ScenarioInstruction::SetTreaty {
                source: reader.nation()?,
                target: reader.nation()?,
                relationship: reader.relationship()?,
            },
            b"year" => ScenarioInstruction::SetYear(reader.short()?),
            b"prov" => ScenarioInstruction::SetProvinceOwner {
                province: reader.short_province()?,
                nation: reader.short_nation()?,
            },
            b"zone" => ScenarioInstruction::SetZoneName {
                zone: reader.short()? as u16,
                name: reader.name()?,
            },
            b"cnam" => ScenarioInstruction::SetCountryName {
                nation: reader.nation()?,
                name: reader.name()?,
            },
            b"rela" => ScenarioInstruction::SetStanding {
                source: reader.short_nation()?,
                target: reader.short_nation()?,
                value: reader.short()?,
            },
            b"pnam" => ScenarioInstruction::SetProvinceName {
                tile: reader.dword_tile()?,
                name: reader.name()?,
            },
            b"cash" => ScenarioInstruction::SetCash {
                nation: reader.major()?,
                value: reader.dword()? as i32,
            },
            b"flag" => ScenarioInstruction::SetFlag(reader.short()? as u16),
            b"tyer" => ScenarioInstruction::SetCapabilityTier {
                technology: reader.technology()?,
                value: reader.dword()? as i32,
            },
            b"tbar" => ScenarioInstruction::SetNeedTarget {
                nation: reader.major()?,
                resource: reader.dword_resource()?,
                value: reader.dword()? as i16,
            },
            b"tclr" => ScenarioInstruction::ClearNeedTargets {
                nation: reader.major()?,
            },
            b"coun" => ScenarioInstruction::SetCouncilState {
                decade: reader.dword()? as u8,
                state: reader.dword()? as u8,
            },
            _ => {
                return Err(ScenarioScriptError {
                    offset: tag_offset,
                    detail: format!(
                        "unknown instruction tag {:?}",
                        String::from_utf8_lossy(&tag)
                    ),
                });
            }
        };
        instructions.push(instruction);
    }
    Ok(instructions)
}

struct ScenarioReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl ScenarioReader<'_> {
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ScenarioScriptError> {
        let end = self.offset + N;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| ScenarioScriptError {
                offset: self.offset,
                detail: format!("truncated {N}-byte token"),
            })?;
        self.offset = end;
        Ok(bytes.try_into().expect("slice has requested fixed length"))
    }

    fn dword(&mut self) -> Result<u32, ScenarioScriptError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn short(&mut self) -> Result<i16, ScenarioScriptError> {
        Ok(i16::from_be_bytes(
            self.read_array::<4>()?[2..].try_into().unwrap(),
        ))
    }

    fn typed<T>(&self, value: Option<T>, what: &str, raw: u32) -> Result<T, ScenarioScriptError> {
        value.ok_or_else(|| ScenarioScriptError {
            offset: self.offset - 4,
            detail: format!("invalid {what} {raw}"),
        })
    }

    fn major(&mut self) -> Result<MajorNationId, ScenarioScriptError> {
        let raw = self.dword()?;
        self.typed(
            MajorNationId::try_new(raw as u8).filter(|_| raw <= u8::MAX.into()),
            "major nation",
            raw,
        )
    }

    fn nation(&mut self) -> Result<NationId, ScenarioScriptError> {
        let raw = self.dword()?;
        self.typed(
            NationId::try_new(raw as u8).filter(|_| raw <= u8::MAX.into()),
            "nation",
            raw,
        )
    }

    fn short_nation(&mut self) -> Result<NationId, ScenarioScriptError> {
        let raw = self.short()? as u16;
        self.typed(
            NationId::try_new(raw as u8).filter(|_| raw <= u8::MAX.into()),
            "nation",
            raw.into(),
        )
    }

    fn province(&mut self) -> Result<ProvinceId, ScenarioScriptError> {
        let raw = self.dword()?;
        self.typed(
            ProvinceId::try_new(raw as u16).filter(|_| raw <= u16::MAX.into()),
            "province",
            raw,
        )
    }

    fn short_province(&mut self) -> Result<ProvinceId, ScenarioScriptError> {
        let raw = self.short()? as u16;
        self.typed(ProvinceId::try_new(raw), "province", raw.into())
    }

    fn tile(&mut self) -> Result<TileId, ScenarioScriptError> {
        let raw = self.short()? as u16;
        self.typed(TileId::try_new(raw), "tile", raw.into())
    }

    fn dword_tile(&mut self) -> Result<TileId, ScenarioScriptError> {
        let raw = self.dword()?;
        self.typed(
            TileId::try_new(raw as u16).filter(|_| raw <= u16::MAX.into()),
            "tile",
            raw,
        )
    }

    fn resource(&mut self) -> Result<ResourceKind, ScenarioScriptError> {
        let raw = self.short()? as u16;
        self.typed(
            ResourceKind::from_index(raw as u8).filter(|_| raw <= u8::MAX.into()),
            "resource",
            raw.into(),
        )
    }

    fn dword_resource(&mut self) -> Result<ResourceKind, ScenarioScriptError> {
        let raw = self.dword()?;
        self.typed(
            ResourceKind::from_index(raw as u8).filter(|_| raw <= u8::MAX.into()),
            "resource",
            raw,
        )
    }

    fn military_kind(&mut self) -> Result<MilitaryUnitKind, ScenarioScriptError> {
        let raw = self.short()? as u16;
        self.typed(
            MilitaryUnitKind::from_index(raw as u8).filter(|_| raw <= u8::MAX.into()),
            "military unit kind",
            raw.into(),
        )
    }

    fn civilian_kind(&mut self) -> Result<CivilianUnitKind, ScenarioScriptError> {
        let raw = self.short()? as u16;
        self.typed(
            CivilianUnitKind::from_index(raw as u8).filter(|_| raw <= u8::MAX.into()),
            "civilian unit kind",
            raw.into(),
        )
    }

    fn ship_type(&mut self) -> Result<ShipType, ScenarioScriptError> {
        let raw = self.short()? as u16;
        self.typed(
            ShipType::from_index(raw as u8).filter(|_| raw <= u8::MAX.into()),
            "ship type",
            raw.into(),
        )
    }

    fn technology(&mut self) -> Result<Technology, ScenarioScriptError> {
        let raw = self.dword()?;
        self.typed(
            Technology::from_index(raw as u8).filter(|_| raw <= u8::MAX.into()),
            "technology",
            raw,
        )
    }

    fn commodity(&mut self) -> Result<TradeCommodity, ScenarioScriptError> {
        let raw = self.short()?;
        self.typed(
            TradeCommodity::from_retail(raw),
            "trade commodity",
            raw as u16 as u32,
        )
    }

    fn mission_level(&mut self) -> Result<DiplomaticMissionLevel, ScenarioScriptError> {
        let raw = self.short()?;
        self.typed(
            DiplomaticMissionLevel::try_from_retail(raw),
            "diplomatic mission level",
            raw as u16 as u32,
        )
    }

    fn relationship(&mut self) -> Result<DiplomaticRelationship, ScenarioScriptError> {
        let raw = self.dword()?;
        self.typed(
            DiplomaticRelationship::try_from_retail(raw as i16),
            "diplomatic relationship",
            raw,
        )
    }

    fn name(&mut self) -> Result<String, ScenarioScriptError> {
        let bytes = self.read_array::<64>()?;
        let end = bytes
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_big_endian_tokens_fixed_names_and_stops_at_term() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"labo");
        for value in [2_u32, 12, 7, 3] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(b"zone");
        bytes.extend_from_slice(&65_u32.to_be_bytes());
        let mut name = [0_u8; 64];
        name[..8].copy_from_slice(b"Atlantic");
        bytes.extend_from_slice(&name);
        bytes.extend_from_slice(b"TERMignored");

        assert_eq!(
            decode_scenario_script(&bytes).unwrap(),
            vec![
                ScenarioInstruction::SetLabor {
                    nation: MajorNationId::new(2),
                    unskilled: 12,
                    skilled: 7,
                    professionals: 3,
                },
                ScenarioInstruction::SetZoneName {
                    zone: 65,
                    name: "Atlantic".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn reports_unknown_and_truncated_instructions_at_the_retail_stream_offset() {
        assert_eq!(
            decode_scenario_script(b"nope").unwrap_err().to_string(),
            "scenario script byte 0: unknown instruction tag \"nope\""
        );
        assert_eq!(
            decode_scenario_script(b"cash\0\0").unwrap_err().to_string(),
            "scenario script byte 4: truncated 4-byte token"
        );
    }
}
