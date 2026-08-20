use super::model::{LegacyProvince, LegacyTerrainTile};
use super::project::province_state;
use imperialism_core::{MapMgr, MapTopology, ProvinceTable, STRATEGIC_TILE_COUNT, TileState};

const TILE_BYTES: usize = 0x24;
const PROVINCE_BYTES: usize = 0xa4;
const PROVINCE_NAME_HEADER_BYTES: usize = 2;
const PROVINCE_NAME_BYTES: usize = 0x20;
const PROVINCE_COUNT: usize = 0x180;
const EXPECTED_BYTES: usize = STRATEGIC_TILE_COUNT * TILE_BYTES
    + PROVINCE_COUNT * (PROVINCE_BYTES + PROVINCE_NAME_HEADER_BYTES + PROVINCE_NAME_BYTES);

pub(crate) fn decode_scenario_map(bytes: &[u8]) -> Result<MapMgr, String> {
    if bytes.len() != EXPECTED_BYTES {
        return Err(format!(
            "scenario map has {} bytes; expected {EXPECTED_BYTES}",
            bytes.len()
        ));
    }

    let (tile_bytes, mut province_bytes) = bytes.split_at(STRATEGIC_TILE_COUNT * TILE_BYTES);
    let tiles: Vec<TileState> = tile_bytes
        .chunks_exact(TILE_BYTES)
        .map(scenario_tile)
        .map(|tile| tile.tile_state())
        .collect();
    let provinces = ProvinceTable::from_array(std::array::from_fn(|_| {
        let (record, rest) = province_bytes.split_at(PROVINCE_BYTES);
        let (_, rest) = rest.split_at(PROVINCE_NAME_HEADER_BYTES);
        let (name, rest) = rest.split_at(PROVINCE_NAME_BYTES);
        province_bytes = rest;
        province_state(&scenario_province(record, fixed_text(name)))
    }));
    Ok(MapMgr::from_parts(MapTopology::Wrapping, tiles, provinces))
}

fn scenario_tile(bytes: &[u8]) -> LegacyTerrainTile {
    LegacyTerrainTile {
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
        city_record_index: be_i16_at(bytes, 0x14),
        action_state: bytes[0x16] as i8,
        rail_flags: bytes[0x17],
        tile_action_ordinal: be_i16_at(bytes, 0x1a),
        active_flags: be_u16_at(bytes, 0x1c),
    }
}

fn scenario_province(bytes: &[u8], name: String) -> LegacyProvince {
    LegacyProvince {
        owner_nation: bytes[0] as i8,
        former_owner_nation: bytes[1] as i8,
        development_stage: bytes[2] as i8,
        fort_level: bytes[3] as i8,
        city_tile: be_i16_at(bytes, 4),
        last_turn_tick: be_i16_at(bytes, 6),
        adjacent_region_count: bytes[8] as i8,
        adjacent_region_ids: std::array::from_fn(|index| be_i16_at(bytes, 0x0a + index * 2)),
        adjacent_region_anchor_tiles: std::array::from_fn(|index| {
            be_i16_at(bytes, 0x22 + index * 2)
        }),
        linked_region_count: bytes[0x3a] as i8,
        secondary_neighbor_tile: be_i16_at(bytes, 0x3e),
        primary_neighbor_tile: be_i16_at(bytes, 0x40),
        linked_tile_indices: std::array::from_fn(|index| be_i16_at(bytes, 0x42 + index * 2)),
        resource_development_by_type: std::array::from_fn(|index| {
            be_i16_at(bytes, 0x82 + index * 2)
        }),
        city_score: i32::from_be_bytes(bytes[0x9c..0xa0].try_into().unwrap()),
        navy_order_reachable: bytes[0xa0],
        explored_by_nation_mask: bytes[0xa1],
        resource_presence_mask: bytes[0xa2] as i8,
        region_class: bytes[0xa3] as i8,
        name,
    }
}

fn be_i16_at(bytes: &[u8], offset: usize) -> i16 {
    i16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn be_u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn fixed_text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
