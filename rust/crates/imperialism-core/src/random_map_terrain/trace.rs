use crate::{MapTopology, RANDOM_MAP_CLASS_COUNT, RetailLcg};
use serde::{Deserialize, Serialize};

use super::{GeneratedTerrainTileScratch, RandomMapTuning, WATER, generate_random_map_impl};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandomMapTerrainAttemptTrace {
    pub coarse_generation: crate::random_map::CoarseMapTrace,
    pub after_expansion: RandomMapTerrainStageTrace,
    pub after_templates: RandomMapTerrainStageTrace,
    pub after_features: RandomMapTerrainStageTrace,
    pub after_rotation: RandomMapTerrainStageTrace,
    pub after_water_regions: RandomMapTerrainStageTrace,
    pub after_keyword: RandomMapTerrainStageTrace,
    pub map_lcg_after_validation: u32,
    pub rotation_column: usize,
    pub seed_candidate_tiles: [i32; RANDOM_MAP_CLASS_COUNT],
    pub accepted: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandomMapTerrainStageTrace {
    pub map_lcg: u32,
    pub tile_hash: u32,
    pub terrain_counts: [u32; 8],
    pub river_tile_count: u32,
}

/// Test-only stage record emitted by the native differential harness. Normal
/// generation returns [`GeneratedMap`] instead.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandomMapTerrainTrace {
    pub tuning: RandomMapTuning,
    pub initial_map_lcg: u32,
    pub attempts: Vec<RandomMapTerrainAttemptTrace>,
    pub final_map_lcg: u32,
}

pub fn trace_random_map_terrain(
    scenario_tag: &[u8],
    topology: MapTopology,
    rng: &mut RetailLcg,
) -> RandomMapTerrainTrace {
    let tuning = RandomMapTuning::from_scenario_tag(scenario_tag);
    let initial_map_lcg = rng.state();
    let mut attempts = Vec::new();
    let _map = generate_random_map_impl(scenario_tag, topology, tuning, rng, Some(&mut attempts));
    RandomMapTerrainTrace {
        tuning,
        initial_map_lcg,
        attempts,
        final_map_lcg: rng.state(),
    }
}

pub(super) fn summarize_stage(
    tiles: &[GeneratedTerrainTileScratch],
    map_lcg: u32,
) -> RandomMapTerrainStageTrace {
    summarize_stage_with_water_ownership(tiles, map_lcg, true)
}

pub(super) fn summarize_keyword_stage(
    tiles: &[GeneratedTerrainTileScratch],
    map_lcg: u32,
) -> RandomMapTerrainStageTrace {
    summarize_stage_with_water_ownership(tiles, map_lcg, false)
}

pub(super) fn summarize_stage_with_water_ownership(
    tiles: &[GeneratedTerrainTileScratch],
    map_lcg: u32,
    include_water_ownership: bool,
) -> RandomMapTerrainStageTrace {
    let mut tile_hash = 0x811c_9dc5_u32;
    let mut terrain_counts = [0_u32; 8];
    let mut river_tile_count = 0;
    for tile in tiles {
        let owner = if include_water_ownership || tile.terrain_kind != WATER {
            tile.owner_nation
        } else {
            -1
        };
        let province_index = if include_water_ownership || tile.terrain_kind != WATER {
            tile.province_index
        } else {
            -1
        };
        let province = province_index.to_le_bytes();
        for byte in [
            tile.terrain_kind as u8,
            tile.river_sprite_code,
            owner as u8,
            tile.gate_flag as u8,
            province[0],
            province[1],
        ] {
            tile_hash = (tile_hash ^ u32::from(byte)).wrapping_mul(0x0100_0193);
        }
        if let Ok(terrain) = usize::try_from(tile.terrain_kind)
            && let Some(count) = terrain_counts.get_mut(terrain)
        {
            *count += 1;
        }
        if tile.river_sprite_code != 0 {
            river_tile_count += 1;
        }
    }
    RandomMapTerrainStageTrace {
        map_lcg,
        tile_hash,
        terrain_counts,
        river_tile_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MapTopology, RetailLcg};

    #[test]
    fn trace_preserves_retail_stage_boundaries_when_requested() {
        let mut rng = RetailLcg::from_state(3_122_877_655);
        let trace = trace_random_map_terrain(b"ordinary", MapTopology::Wrapping, &mut rng);
        let final_attempt = trace.attempts.last().unwrap();
        assert_eq!(trace.initial_map_lcg, 0xba23_54d7);
        assert_eq!(trace.attempts.len(), 1);
        assert_eq!(
            final_attempt.after_keyword,
            RandomMapTerrainStageTrace {
                map_lcg: 0xd938_b2f4,
                tile_hash: 0x099d_e4c5,
                terrain_counts: [440, 252, 250, 156, 150, 4_538, 343, 351],
                river_tile_count: 72,
            }
        );
        assert!(final_attempt.accepted);
        assert_eq!(final_attempt.rotation_column, 26);
        assert_eq!(final_attempt.map_lcg_after_validation, 0x46a4_5026);
        assert_eq!(trace.final_map_lcg, 0x46a4_5026);
        assert_eq!(rng.state(), trace.final_map_lcg);
    }
}
