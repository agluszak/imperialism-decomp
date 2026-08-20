use crate::RetailAssetError;
use crate::legacy_save::model::{LegacyProvince, LegacyTerrainTile};
use crate::legacy_save::project::province_state;
use imperialism_core::*;
use std::fs;
use std::path::{Path, PathBuf};

const SCENARIO_SLOT_COUNT: u16 = 64;
const TILE_BYTES: usize = 0x24;
const PROVINCE_FIXED_BYTES: usize = 0xa4;
const PROVINCE_NAME_BYTES: usize = 0x20;
const PROVINCE_RECORD_BYTES: usize = PROVINCE_FIXED_BYTES + 2 + PROVINCE_NAME_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioMetadata {
    pub title: String,
    pub description: String,
    pub nation_descriptions: MajorNationTable<String>,
    pub difficulty_by_nation: MajorNationTable<Option<Difficulty>>,
    pub preview_nation: MajorNationId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioCatalogEntry {
    pub id: ScenarioMapId,
    pub metadata: ScenarioMetadata,
    root: PathBuf,
}

impl ScenarioCatalogEntry {
    pub fn load(&self) -> Result<ScenarioGameInput, RetailAssetError> {
        let index = self.id.index();
        let map_path = scenario_path(&self.root, index, "map");
        let script_path = scenario_path(&self.root, index, "scn");
        Ok(ScenarioGameInput {
            scenario: self.id,
            map: parse_map(&map_path, &read(&map_path)?)?,
            instructions: parse_script(&script_path, &read(&script_path)?)?,
        })
    }
}

pub fn read_scenario_catalog(root: &Path) -> Result<Vec<ScenarioCatalogEntry>, RetailAssetError> {
    let mut catalog = Vec::new();
    for index in 0..SCENARIO_SLOT_COUNT {
        let path = scenario_path(root, index, "inf");
        if !path.is_file() {
            continue;
        }
        let bytes = read(&path)?;
        catalog.push(ScenarioCatalogEntry {
            id: ScenarioMapId::new(index),
            metadata: parse_metadata(&path, &bytes)?,
            root: root.to_owned(),
        });
    }
    Ok(catalog)
}

fn scenario_path(root: &Path, index: u16, extension: &str) -> PathBuf {
    root.join("Scenario").join(format!("s{index}.{extension}"))
}

fn read(path: &Path) -> Result<Vec<u8>, RetailAssetError> {
    fs::read(path).map_err(|source| RetailAssetError::Io {
        path: path.to_owned(),
        source,
    })
}

fn parse_metadata(path: &Path, bytes: &[u8]) -> Result<ScenarioMetadata, RetailAssetError> {
    let text = String::from_utf8_lossy(bytes);
    let mut fields = text.split('#');
    let title = fields.next().unwrap_or_default().trim().to_owned();
    let description = metadata_text(fields.next().unwrap_or_default());
    let nation_descriptions =
        MajorNationTable::from_fn(|_| metadata_text(fields.next().unwrap_or_default()));
    let settings = fields.next().unwrap_or_default();
    let values = settings
        .split_ascii_whitespace()
        .map(str::parse::<i16>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| scenario_error(path, format!("invalid metadata settings: {error}")))?;
    if values.len() < 8 {
        return Err(scenario_error(
            path,
            format!("metadata has {} settings; expected 8", values.len()),
        ));
    }
    if let Some(value) = values[..7].iter().find(|&&value| value > 4) {
        return Err(scenario_error(
            path,
            format!("scenario difficulty {value} is outside -1..4"),
        ));
    }
    let difficulty_by_nation = MajorNationTable::from_fn(|nation| {
        let value = values[usize::from(nation.get())];
        (value >= 0)
            .then(|| Difficulty::try_from(value as u8).expect("scenario difficulty was validated"))
    });
    let preview_nation = u8::try_from(values[7])
        .ok()
        .and_then(MajorNationId::try_new)
        .ok_or_else(|| scenario_error(path, "preview nation is outside 0..7"))?;
    Ok(ScenarioMetadata {
        title,
        description,
        nation_descriptions,
        difficulty_by_nation,
        preview_nation,
    })
}

fn metadata_text(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\r' | '\n' => ' ',
            '^' => '\r',
            other => other,
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

fn parse_map(path: &Path, bytes: &[u8]) -> Result<MapMgr, RetailAssetError> {
    let expected = STRATEGIC_TILE_COUNT * TILE_BYTES + 0x180 * PROVINCE_RECORD_BYTES;
    if bytes.len() != expected {
        return Err(scenario_error(
            path,
            format!("map is {} bytes; expected {expected}", bytes.len()),
        ));
    }
    let tiles = bytes[..STRATEGIC_TILE_COUNT * TILE_BYTES]
        .chunks_exact(TILE_BYTES)
        .map(parse_tile)
        .map(|tile| tile.tile_state())
        .collect::<Vec<_>>();
    let province_bytes = &bytes[STRATEGIC_TILE_COUNT * TILE_BYTES..];
    let provinces = ProvinceTable::from_fn(|province| {
        let start = usize::from(province.get()) * PROVINCE_RECORD_BYTES;
        province_state(&parse_province(
            &province_bytes[start..start + PROVINCE_RECORD_BYTES],
        ))
    });
    let mut map = MapMgr::from_parts(MapTopology::Wrapping, tiles, provinces);
    map.map_data_ready = true;
    map.recruit_search_active = true;
    Ok(map)
}

fn parse_tile(bytes: &[u8]) -> LegacyTerrainTile {
    LegacyTerrainTile {
        terrain_kind: bytes[0] as i8,
        sprite_variant: bytes[1],
        river_sprite: bytes[2],
        former_owner_nation: bytes[3] as i8,
        owner_nation: bytes[4] as i8,
        region: bytes[5] as i8,
        adjacency_bits: bytes[6],
        owner_border_mask: bytes[7],
        city_border_mask: bytes[8],
        water_adjacency_mask: bytes[9],
        adjacency_mask_a: bytes[0x0a],
        adjacency_mask_b: bytes[0x0b],
        development_classes: bytes[0x0c] as i8,
        pending_development_visibility: bytes[0x0d],
        recruit_search_visited: bytes[0x0e],
        per_tile_visited: bytes[0x0f] as i8,
        marker_slot_index: bytes[0x10] as i8,
        edge_resources: [bytes[0x11] as i8, bytes[0x12] as i8],
        gate: bytes[0x13] as i8,
        city_record_index: be_i16(bytes, 0x14),
        action_state: bytes[0x16] as i8,
        rail_flags: bytes[0x17],
        secondary_owner_nation: bytes[0x18] as i8,
        tile_action_ordinal: be_i16(bytes, 0x1a),
        active_flags: be_u16(bytes, 0x1c),
    }
}

fn parse_province(bytes: &[u8]) -> LegacyProvince {
    let fixed = &bytes[..PROVINCE_FIXED_BYTES];
    let name = &bytes[PROVINCE_FIXED_BYTES + 2..];
    let name = String::from_utf8_lossy(name.split(|&byte| byte == 0).next().unwrap_or_default())
        .into_owned();
    LegacyProvince {
        owner_nation: fixed[0] as i8,
        former_owner_nation: fixed[1] as i8,
        development_stage: fixed[2] as i8,
        fort_level: fixed[3] as i8,
        city_tile: be_i16(fixed, 4),
        last_turn_tick: be_i16(fixed, 6),
        adjacent_region_count: fixed[8] as i8,
        adjacent_region_ids: std::array::from_fn(|index| be_i16(fixed, 0x0a + index * 2)),
        adjacent_region_anchor_tiles: std::array::from_fn(|index| be_i16(fixed, 0x22 + index * 2)),
        linked_region_count: fixed[0x3a] as i8,
        secondary_neighbor_tile: be_i16(fixed, 0x3e),
        primary_neighbor_tile: be_i16(fixed, 0x40),
        linked_tile_indices: std::array::from_fn(|index| be_i16(fixed, 0x42 + index * 2)),
        resource_development_by_type: std::array::from_fn(|index| be_i16(fixed, 0x82 + index * 2)),
        city_score: i32::from_le_bytes(fixed[0x9c..0xa0].try_into().unwrap()),
        navy_order_reachable: fixed[0xa0],
        explored_by_nation_mask: fixed[0xa1],
        resource_presence_mask: fixed[0xa2] as i8,
        region_class: fixed[0xa3] as i8,
        name,
    }
}

fn parse_script(path: &Path, bytes: &[u8]) -> Result<Vec<ScenarioInstruction>, RetailAssetError> {
    let mut cursor = ScriptCursor {
        path,
        bytes,
        offset: 0,
    };
    let mut instructions = Vec::new();
    loop {
        let tag = cursor.tag()?;
        let instruction = match tag.as_str() {
            "TERM" => break,
            "labo" => ScenarioInstruction::Labor {
                nation: cursor.nation32()?,
                counts: [cursor.i16_slot()?, cursor.i16_slot()?, cursor.i16_slot()?],
            },
            "capa" => ScenarioInstruction::Capacity {
                nation: cursor.major32()?,
                slot: cursor.i16_slot()?,
                value: cursor.i16_slot()?,
            },
            "ware" => ScenarioInstruction::Warehouse {
                nation: cursor.major32()?,
                resource: cursor.i16_slot()?,
                amount: cursor.i16_slot()?,
            },
            "army" => ScenarioInstruction::Army {
                province: cursor.province32()?,
                unit: cursor.i16_slot()?,
                count: cursor.i32_slot()?,
            },
            "civi" => ScenarioInstruction::Civilian {
                unit: cursor.i16_slot()?,
                tile: cursor.tile16()?,
            },
            "ship" => ScenarioInstruction::Ship {
                nation: cursor.major32()?,
                ship: cursor.i16_slot()?,
                zone: cursor.i16_slot()?,
                count: cursor.i32_slot()?,
            },
            "tran" => ScenarioInstruction::Transport {
                nation: cursor.major32()?,
                amount: cursor.i16_slot()?,
            },
            "deve" => ScenarioInstruction::Development {
                tile: cursor.tile16()?,
                level: cursor.byte_slot()?,
            },
            "rail" => ScenarioInstruction::Rail {
                tile: cursor.tile16()?,
            },
            "port" => ScenarioInstruction::Port {
                tile: cursor.tile16()?,
            },
            "tech" => ScenarioInstruction::Technology {
                nation: cursor.major32()?,
                technology: cursor.i32_slot()?,
            },
            "pric" => ScenarioInstruction::Price {
                resource: cursor.i16_slot()?,
                value: cursor.i16_slot()?,
            },
            "emba" => ScenarioInstruction::Embassy {
                first: cursor.nation32()?,
                second: cursor.nation32()?,
                level: cursor.i16_slot()?,
            },
            "subs" => ScenarioInstruction::Subsidy {
                owner: cursor.major32()?,
                target: cursor.nation16()?,
                level: cursor.i16_slot()?,
            },
            "trea" => ScenarioInstruction::Treaty {
                source: cursor.nation32()?,
                target: cursor.nation32()?,
                relationship: cursor.i32_slot()?,
            },
            "year" => ScenarioInstruction::Year(cursor.i16_slot()?),
            "prov" => ScenarioInstruction::ProvinceOwner {
                province: cursor.province16()?,
                nation: cursor.nation16()?,
            },
            "zone" => ScenarioInstruction::ZoneName {
                zone: cursor.i16_slot()?,
                name: cursor.fixed_name()?,
            },
            "cnam" => ScenarioInstruction::CountryName {
                nation: cursor.nation32()?,
                name: cursor.fixed_name()?,
            },
            "rela" => ScenarioInstruction::Standing {
                source: cursor.nation16()?,
                target: cursor.nation16()?,
                value: cursor.i16_slot()?,
            },
            "pnam" => ScenarioInstruction::ProvinceName {
                province: cursor.province32()?,
                name: cursor.fixed_name()?,
            },
            "cash" => ScenarioInstruction::Cash {
                nation: cursor.nation32()?,
                amount: cursor.i32_slot()?,
            },
            "flag" => ScenarioInstruction::Flag(cursor.i16_slot()?),
            "tyer" => ScenarioInstruction::CapabilityTier {
                slot: cursor.i32_slot()?,
                value: cursor.i32_slot()?,
            },
            "tbar" => ScenarioInstruction::NeedTarget {
                nation: cursor.major32()?,
                resource: cursor.i32_slot()?,
                value: cursor.i32_slot()?,
            },
            "tclr" => ScenarioInstruction::ClearNeedTargets {
                nation: cursor.major32()?,
            },
            "coun" => ScenarioInstruction::DecadeState {
                decade: cursor.i32_slot()?,
                state: cursor.i32_slot()?,
            },
            _ => return Err(cursor.error(format!("unknown scenario instruction {tag:?}"))),
        };
        instructions.push(instruction);
    }
    Ok(instructions)
}

struct ScriptCursor<'a> {
    path: &'a Path,
    bytes: &'a [u8],
    offset: usize,
}
impl ScriptCursor<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], RetailAssetError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| self.error("script offset overflow"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| self.error("truncated scenario instruction"))?;
        self.offset = end;
        Ok(bytes)
    }
    fn tag(&mut self) -> Result<String, RetailAssetError> {
        Ok(String::from_utf8_lossy(self.take(4)?).into_owned())
    }
    fn slot(&mut self) -> Result<[u8; 4], RetailAssetError> {
        Ok(self.take(4)?.try_into().unwrap())
    }
    fn i32_slot(&mut self) -> Result<i32, RetailAssetError> {
        Ok(i32::from_be_bytes(self.slot()?))
    }
    fn i16_slot(&mut self) -> Result<i16, RetailAssetError> {
        let slot = self.slot()?;
        Ok(i16::from_be_bytes([slot[2], slot[3]]))
    }
    fn byte_slot(&mut self) -> Result<u8, RetailAssetError> {
        Ok(self.slot()?[3])
    }
    fn nation32(&mut self) -> Result<NationId, RetailAssetError> {
        let value = self.i32_slot()?;
        u8::try_from(value)
            .ok()
            .and_then(NationId::try_new)
            .ok_or_else(|| self.error(format!("nation {value} is out of range")))
    }
    fn major32(&mut self) -> Result<MajorNationId, RetailAssetError> {
        let nation = self.nation32()?;
        MajorNationId::from_nation(nation)
            .ok_or_else(|| self.error(format!("nation {} is not a major", nation.get())))
    }
    fn nation16(&mut self) -> Result<NationId, RetailAssetError> {
        let value = self.i16_slot()?;
        u8::try_from(value)
            .ok()
            .and_then(NationId::try_new)
            .ok_or_else(|| self.error(format!("nation {value} is out of range")))
    }
    fn tile16(&mut self) -> Result<TileId, RetailAssetError> {
        let value = self.i16_slot()?;
        u16::try_from(value)
            .ok()
            .and_then(TileId::try_new)
            .ok_or_else(|| self.error(format!("tile {value} is out of range")))
    }
    fn province16(&mut self) -> Result<ProvinceId, RetailAssetError> {
        let value = self.i16_slot()?;
        u16::try_from(value)
            .ok()
            .and_then(ProvinceId::try_new)
            .ok_or_else(|| self.error(format!("province {value} is out of range")))
    }
    fn province32(&mut self) -> Result<ProvinceId, RetailAssetError> {
        let value = self.i32_slot()?;
        u16::try_from(value)
            .ok()
            .and_then(ProvinceId::try_new)
            .ok_or_else(|| self.error(format!("province {value} is out of range")))
    }
    fn fixed_name(&mut self) -> Result<String, RetailAssetError> {
        let bytes = self.take(64)?;
        Ok(
            String::from_utf8_lossy(bytes.split(|&byte| byte == 0).next().unwrap_or_default())
                .into_owned(),
        )
    }
    fn error(&self, detail: impl Into<String>) -> RetailAssetError {
        scenario_error(self.path, detail)
    }
}

fn be_i16(bytes: &[u8], offset: usize) -> i16 {
    i16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn be_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn scenario_error(path: &Path, detail: impl Into<String>) -> RetailAssetError {
    RetailAssetError::Scenario {
        path: path.to_owned(),
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_retail_metadata_fields_and_available_nations() {
        let bytes = b"Title\r#Description^Line#A#B#C#D#E#F#G# -1 1 2 3 4 -1 0 2";
        let metadata = parse_metadata(Path::new("s0.inf"), bytes).unwrap();
        assert_eq!(metadata.title, "Title");
        assert_eq!(metadata.description, "Description\rLine");
        assert_eq!(metadata.difficulty_by_nation[MajorNationId::new(0)], None);
        assert_eq!(
            metadata.difficulty_by_nation[MajorNationId::new(4)],
            Some(Difficulty::NighOnImpossible)
        );
        assert_eq!(metadata.preview_nation, MajorNationId::new(2));
    }

    #[test]
    fn script_stops_at_term_like_retail() {
        let bytes = [
            b'y', b'e', b'a', b'r', 0, 0, 0x07, 0x17, b'T', b'E', b'R', b'M', 1, 2, 3, 4,
        ];
        assert_eq!(
            parse_script(Path::new("s13.scn"), &bytes).unwrap(),
            vec![ScenarioInstruction::Year(1815)]
        );
    }
}
