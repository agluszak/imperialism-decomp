//! Water-region border/merge/compact from `TMapMaker::AssignOrCompactCityRegionIdsAndRebuildBorders`
//! (mode 0), after `GenerateWaterRegionIds` and before keyword overrides.
//!
//! Ports:
//! - `BuildCityRegionBorderOverlaySegments` (0x0052c1a0)
//! - `BuildOverlaySpanRecordsFromQuadBorderLinks` (0x0052cae0)
//! - `MergeSmallCityRegionsAndCompactIds` (0x0052d750)

use crate::random_map_terrain::GeneratedTerrainTileScratch;
use crate::{HexDirection, MapGeometry, STRATEGIC_MAP_HEIGHT, STRATEGIC_MAP_WIDTH, TileId};

const WATER: i8 = 5;
const SEA_OWNER_BIAS: i32 = 0x17;
const OVERLAY_WIDTH: i32 = 0xd8;
const MERGE_SIZE_THRESHOLD: i32 = 0x20;
const TINY_REGION_FALLBACK: i32 = 7;

#[derive(Clone, Copy, Debug)]
struct Seapoint {
    coord: i32,
    lo: i32,
    hi: i32,
    side: i32,
}

#[derive(Clone, Copy, Debug)]
struct SeaSegment {
    x0: i16,
    y0: i16,
    x1: i16,
    y1: i16,
    coord0: i32,
    coord1: i32,
    region_a: i16,
    region_b: i16,
}

impl Seapoint {
    fn init_sorted(coord: i32, a: i32, b: i32, side: i32) -> Self {
        let (lo, hi) = if a > b { (b, a) } else { (a, b) };
        Self {
            coord,
            lo,
            hi,
            side,
        }
    }

    fn wrapped_delta_metric(self, other: Self) -> f64 {
        let mut row_delta = self.coord / OVERLAY_WIDTH - other.coord / OVERLAY_WIDTH;
        if row_delta < 0 {
            row_delta = -row_delta;
        }
        let mut col_delta = ((self.coord % OVERLAY_WIDTH - other.coord % OVERLAY_WIDTH)
            + OVERLAY_WIDTH)
            % OVERLAY_WIDTH;
        if col_delta > 0x6c {
            col_delta = 0xd7 - col_delta;
        }
        f64::from(col_delta * col_delta * row_delta * row_delta).sqrt()
    }
}

impl SeaSegment {
    fn init_from_points(p0: Seapoint, p1: Seapoint) -> Self {
        let mut x0 = (p0.coord % OVERLAY_WIDTH) as i16;
        let mut y0 = (p0.coord / OVERLAY_WIDTH) as i16;
        let mut x1 = (p1.coord % OVERLAY_WIDTH) as i16;
        let mut y1 = (p1.coord / OVERLAY_WIDTH) as i16;
        let mut coord0 = p0.coord;
        let mut coord1 = p1.coord;
        let region_a = p0.lo as i16;
        let region_b = p0.hi as i16;
        if y1 < y0 || (y0 == y1 && x1 < x0) {
            std::mem::swap(&mut x0, &mut x1);
            std::mem::swap(&mut y0, &mut y1);
            coord0 = i32::from(x0) + i32::from(y0) * OVERLAY_WIDTH;
            coord1 = i32::from(x1) + i32::from(y1) * OVERLAY_WIDTH;
        }
        Self {
            x0,
            y0,
            x1,
            y1,
            coord0,
            coord1,
            region_a,
            region_b,
        }
    }
}

/// Compact undersized water regions and rewrite `owner_nation` tags to the compacted id space.
///
/// Returns the post-merge city-region count (`cityRegionCount2a4`).
pub(crate) fn merge_small_water_regions(
    tiles: &mut [GeneratedTerrainTileScratch],
    geometry: MapGeometry,
) -> i32 {
    let mut region_count = city_region_count(tiles);
    if region_count <= 0 {
        return 0;
    }
    let quads = build_city_region_border_overlay_segments(tiles, geometry);
    let mut links = build_overlay_span_records_from_quad_border_links(&quads);

    let mut tile_counts = vec![0_i32; region_count as usize];
    let mut merged_flags = vec![0_u8; region_count as usize];
    for tile in tiles.iter() {
        let region = water_region_id(tile);
        if region >= 0 {
            tile_counts[region as usize] += 1;
        }
    }

    let mut region = region_count;
    loop {
        region -= 1;
        if region < 0 {
            return region_count;
        }
        let region_byte = i32::from(region as u8);

        if tile_counts[region as usize] > 0 && tile_counts[region as usize] < MERGE_SIZE_THRESHOLD {
            let mut merge_target = -1_i32;
            let mut best_score = -1_i32;
            let mut best_link = u32::MAX;

            for (li, link) in links.iter().enumerate() {
                let other = if i32::from(link.region_a) == region_byte {
                    i32::from(link.region_b)
                } else if i32::from(link.region_b) != region_byte {
                    0xfffe
                } else {
                    i32::from(link.region_a)
                };
                if (other as i16) < 0 {
                    continue;
                }
                let other_usize = other as usize;
                let mut bias = 0_i32;
                if tile_counts[other_usize] + tile_counts[region as usize] >= MERGE_SIZE_THRESHOLD {
                    bias = 0x2710;
                }
                if merged_flags[other_usize] == 0 {
                    bias += 0x1388;
                }
                let width = i32::from(link.x1) - i32::from(link.x0);
                let height = i32::from(link.y1) - i32::from(link.y0);
                let area_sq = width * width * height * height;
                // MSVC `_ftol` truncates toward zero; same for positive values via `as i32`.
                let score = (f64::from(area_sq).sqrt() * f64::from(tile_counts[other_usize])
                    + f64::from(bias)) as i32;
                if best_score < score {
                    best_score = score;
                    merge_target = other;
                    best_link = li as u32;
                }
            }

            let mut unresolved = false;
            if merge_target == -1 {
                if tile_counts[region as usize] < TINY_REGION_FALLBACK {
                    'tiles: for (tile_idx, tile) in tiles.iter().enumerate() {
                        if water_region_id(tile) != region {
                            continue;
                        }
                        let tile_id = TileId::new(tile_idx as u16);
                        for direction in HexDirection::ALL {
                            let Some(neighbor) = geometry.neighbor(tile_id, direction) else {
                                continue;
                            };
                            let neighbor_region =
                                water_region_id(&tiles[usize::from(neighbor.get())]);
                            if neighbor_region >= 0 && neighbor_region != region {
                                merge_target = neighbor_region;
                                break 'tiles;
                            }
                        }
                    }
                }
                unresolved = merge_target == -1;
            }

            if !unresolved && merge_target >= 0 {
                let merge_target_usize = merge_target as usize;
                tile_counts[merge_target_usize] += tile_counts[region as usize];
                tile_counts[region as usize] = 0;
                merged_flags[merge_target_usize] = 1;
                for tile in tiles.iter_mut() {
                    if water_region_id(tile) == region {
                        set_water_region_id(tile, merge_target);
                    }
                }
                if (best_link as i32) >= 0 {
                    let consumed = &mut links[best_link as usize];
                    consumed.x0 = 0;
                    consumed.y0 = 0;
                    consumed.x1 = 0;
                    consumed.y1 = 0;
                    consumed.region_a = -1;
                    consumed.region_b = -1;
                    consumed.coord0 = -1;
                    consumed.coord1 = -1;
                }
                for link in &mut links {
                    if i32::from(link.region_a) == region {
                        link.region_a = merge_target as i16;
                    }
                    if i32::from(link.region_b) == region {
                        link.region_b = merge_target as i16;
                    }
                }
            }
        }

        if tile_counts[region as usize] == 0 {
            let last = region_count - 1;
            region_count = last;
            tile_counts[region as usize] = tile_counts[last as usize];
            merged_flags[region as usize] = merged_flags[region_count as usize];
            for tile in tiles.iter_mut() {
                if water_region_id(tile) == region_count {
                    set_water_region_id(tile, region_byte);
                }
            }
            for link in &mut links {
                if i32::from(link.region_a) == region_count {
                    link.region_a = region_byte as i16;
                }
                if i32::from(link.region_b) == region_count {
                    link.region_b = region_byte as i16;
                }
            }
        }
    }
}

fn city_region_count(tiles: &[GeneratedTerrainTileScratch]) -> i32 {
    let mut max = -1_i32;
    for tile in tiles {
        max = max.max(water_region_id(tile));
    }
    max + 1
}

fn water_region_id(tile: &GeneratedTerrainTileScratch) -> i32 {
    if tile.terrain_kind != WATER {
        return -1;
    }
    i32::from(tile.owner_nation as u8) - SEA_OWNER_BIAS
}

fn set_water_region_id(tile: &mut GeneratedTerrainTileScratch, region: i32) {
    tile.owner_nation = (region + SEA_OWNER_BIAS) as i8;
}

fn region_at_tile(tiles: &[GeneratedTerrainTileScratch], tile_index: i32) -> i32 {
    if tile_index < 0 {
        return -1;
    }
    let index = tile_index as usize;
    if index >= tiles.len() {
        return -1;
    }
    water_region_id(&tiles[index])
}

fn hex_neighbor(geometry: MapGeometry, tile_index: i32, direction: usize) -> i32 {
    if tile_index < 0 {
        return -1;
    }
    let Some(neighbor) =
        geometry.neighbor(TileId::new(tile_index as u16), HexDirection::ALL[direction])
    else {
        return -1;
    };
    i32::from(neighbor.get())
}

fn overlay_coord_from_tile_side(tile_index: i32, side: i32) -> i32 {
    let mut row = tile_index / i32::from(STRATEGIC_MAP_WIDTH);
    let column = (row & 1) + (tile_index % i32::from(STRATEGIC_MAP_WIDTH)) * 2;
    let mut result = column;
    if side == 0 {
        result = column + 2;
        row += 1;
        if result >= OVERLAY_WIDTH {
            result -= OVERLAY_WIDTH;
        }
    }
    result + row * OVERLAY_WIDTH
}

fn append_border_quad(
    quads: &mut Vec<Seapoint>,
    tile_index: i32,
    region_a: i32,
    region_b: i32,
    side: i32,
) {
    quads.push(Seapoint::init_sorted(
        overlay_coord_from_tile_side(tile_index, 1),
        region_a,
        region_b,
        side,
    ));
}

fn emit_overlay_segment_from_tile_edge_sorted(
    quads: &mut Vec<Seapoint>,
    tile_index: i32,
    side: i32,
    a: i32,
    b: i32,
    extra: i32,
) {
    let coord = overlay_coord_from_tile_side(tile_index, side);
    let (lo, hi) = if a > b { (b, a) } else { (a, b) };
    quads.push(Seapoint {
        coord,
        lo,
        hi,
        side: extra,
    });
}

/// `TMapMaker::BuildCityRegionBorderOverlaySegments`.
fn build_city_region_border_overlay_segments(
    tiles: &[GeneratedTerrainTileScratch],
    geometry: MapGeometry,
) -> Vec<Seapoint> {
    let mut quads = Vec::new();
    let width = i32::from(STRATEGIC_MAP_WIDTH);
    let tile_count = (STRATEGIC_MAP_WIDTH as usize * STRATEGIC_MAP_HEIGHT as usize) as i32;

    // Phase 1: row 0 tiles, direction-4 edges.
    for tile_idx in 0..width {
        let region1 = region_at_tile(tiles, tile_idx);
        let region2 = region_at_tile(tiles, hex_neighbor(geometry, tile_idx, 4));
        if region1 != region2 && region1 != -1 && region2 != -1 {
            append_border_quad(&mut quads, tile_idx, region1, region2, 2);
        }
    }

    // Phase 2: remaining tiles, directions 4 and 5.
    for tile_idx in width..tile_count {
        let mut this_region = region_at_tile(tiles, tile_idx);
        let dir4_region = region_at_tile(tiles, hex_neighbor(geometry, tile_idx, 4));
        let dir5_region = region_at_tile(tiles, hex_neighbor(geometry, tile_idx, 5));

        let mut code_dir45 = 4;
        let mut code_this_dir4 = 2;
        let mut saved_dir5 = dir5_region;
        if this_region == -1 {
            code_dir45 = 2;
            saved_dir5 = -1;
            code_this_dir4 = 4;
            this_region = dir5_region;
        }
        let mut code_first = code_this_dir4;
        let mut code_second = 0;
        let mut other_dir5 = saved_dir5;
        let mut dir4 = dir4_region;
        if dir4 == -1 {
            other_dir5 = -1;
            code_first = 0;
            code_second = code_this_dir4;
            dir4 = saved_dir5;
        }
        if this_region != dir4 && this_region != other_dir5 && dir4 != other_dir5 {
            if other_dir5 == -1 {
                append_border_quad(&mut quads, tile_idx, this_region, dir4, code_first);
            } else {
                append_border_quad(&mut quads, tile_idx, this_region, dir4, code_first);
                append_border_quad(&mut quads, tile_idx, this_region, other_dir5, code_second);
                append_border_quad(&mut quads, tile_idx, dir4, other_dir5, code_dir45);
            }
        }
    }

    // Phase 3: directions 1 and 2, then direction-1-only sweep of the last rows.
    let mut t3 = 0_i32;
    loop {
        let mut r_this = region_at_tile(tiles, t3);
        let mut dir1_region = region_at_tile(tiles, hex_neighbor(geometry, t3, 1));
        let dir2_region = region_at_tile(tiles, hex_neighbor(geometry, t3, 2));

        let mut code_a = 1;
        let mut code_b = 3;
        let mut code_this_dir1 = 5;
        let mut saved_dir2 = dir2_region;
        if r_this == -1 {
            code_a = 5;
            saved_dir2 = -1;
            code_this_dir1 = 1;
            r_this = dir2_region;
        }
        let mut code_mid = code_this_dir1;
        let mut other_dir2 = saved_dir2;
        if dir1_region == -1 {
            other_dir2 = -1;
            code_mid = 3;
            dir1_region = saved_dir2;
            code_b = code_this_dir1;
        }
        if r_this != dir1_region && r_this != other_dir2 && dir1_region != other_dir2 {
            if other_dir2 != -1 {
                emit_overlay_segment_from_tile_edge_sorted(
                    &mut quads,
                    t3,
                    0,
                    r_this,
                    dir1_region,
                    code_mid,
                );
                emit_overlay_segment_from_tile_edge_sorted(
                    &mut quads, t3, 0, r_this, other_dir2, code_b,
                );
                r_this = dir1_region;
                dir1_region = other_dir2;
                code_mid = code_a;
            }
            emit_overlay_segment_from_tile_edge_sorted(
                &mut quads,
                t3,
                0,
                r_this,
                dir1_region,
                code_mid,
            );
        }
        t3 += 1;
        // retail: off3 += 0x24; if (0x3800f < off3) sweep remainder with direction 1.
        if t3 * 0x24 > 0x3800f {
            while t3 < tile_count {
                let r1 = region_at_tile(tiles, t3);
                let r2 = region_at_tile(tiles, hex_neighbor(geometry, t3, 1));
                if r1 != r2 && r1 != -1 && r2 != -1 {
                    emit_overlay_segment_from_tile_edge_sorted(&mut quads, t3, 0, r1, r2, 5);
                }
                t3 += 1;
            }
            break;
        }
    }
    quads
}

/// `TMapMaker::BuildOverlaySpanRecordsFromQuadBorderLinks`.
fn build_overlay_span_records_from_quad_border_links(quads_in: &[Seapoint]) -> Vec<SeaSegment> {
    let mut quads = quads_in.to_vec();
    let mut segments = Vec::new();
    if quads.is_empty() {
        return segments;
    }
    let mut i = 0_usize;
    while i < quads.len() {
        if quads[i].coord == -1 {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        let mut best_primary = u32::MAX;
        let mut best_secondary = u32::MAX;
        while j < quads.len() {
            let a = quads[i];
            let b = quads[j];
            let same_edge = a.lo == b.lo && a.hi == b.hi;
            if same_edge {
                let dir_delta = ((b.side - a.side) + 6) % 6;
                let is_primary = (2..=4).contains(&dir_delta);
                if is_primary {
                    if best_primary != u32::MAX {
                        let pa = quads[i];
                        let pb = quads[j];
                        let mut row_delta = pa.coord / OVERLAY_WIDTH - pb.coord / OVERLAY_WIDTH;
                        if row_delta < 0 {
                            row_delta = -row_delta;
                        }
                        let mut col_delta = ((pa.coord % OVERLAY_WIDTH - pb.coord % OVERLAY_WIDTH)
                            + OVERLAY_WIDTH)
                            % OVERLAY_WIDTH;
                        if col_delta > 0x6c {
                            col_delta = 0xd7 - col_delta;
                        }
                        let candidate_dist =
                            f64::from(col_delta * col_delta * row_delta * row_delta).sqrt() as f32;
                        if quads[best_primary as usize].wrapped_delta_metric(quads[i])
                            <= f64::from(candidate_dist)
                        {
                            j += 1;
                            continue;
                        }
                    }
                    best_primary = j as u32;
                } else if best_primary == u32::MAX {
                    if best_secondary != u32::MAX {
                        let candidate_dist = quads[j].wrapped_delta_metric(quads[i]) as f32;
                        if quads[best_secondary as usize].wrapped_delta_metric(quads[i])
                            <= f64::from(candidate_dist)
                        {
                            j += 1;
                            continue;
                        }
                    }
                    best_secondary = j as u32;
                }
            }
            j += 1;
        }
        if best_primary == u32::MAX {
            best_primary = best_secondary;
        }
        if best_primary == u32::MAX {
            quads[i].coord = -1;
            quads[i].hi = -1;
            quads[i].lo = -1;
        } else {
            segments.push(SeaSegment::init_from_points(
                quads[best_primary as usize],
                quads[i],
            ));
            quads[i].coord = -1;
            quads[i].hi = -1;
            quads[i].lo = -1;
            quads[best_primary as usize].coord = -1;
            quads[best_primary as usize].hi = -1;
            quads[best_primary as usize].lo = -1;
        }
        // When the current point was valid, retail leaves `i` unchanged; the next loop sees
        // coord==-1 and advances. Same effect as incrementing here after invalidation.
    }
    segments
}

#[cfg(test)]
mod tests {
    use super::*;

    fn water_tile(region: i32) -> GeneratedTerrainTileScratch {
        GeneratedTerrainTileScratch {
            terrain_kind: WATER,
            river_sprite_code: 0,
            river_flow_direction: None,
            owner_nation: (region + SEA_OWNER_BIAS) as i8,
            gate_flag: -1,
            province_index: -1,
        }
    }

    fn land_tile(owner: i8) -> GeneratedTerrainTileScratch {
        GeneratedTerrainTileScratch {
            terrain_kind: 0,
            river_sprite_code: 0,
            river_flow_direction: None,
            owner_nation: owner,
            gate_flag: -1,
            province_index: 0,
        }
    }

    #[test]
    fn merges_tiny_isolated_water_region_into_neighbor() {
        let width = STRATEGIC_MAP_WIDTH as usize;
        let height = STRATEGIC_MAP_HEIGHT as usize;
        let mut tiles = vec![land_tile(0); width * height];
        // Two adjacent water blobs on row 10: region 0 (large) and region 1 (tiny).
        for col in 10..40 {
            tiles[10 * width + col] = water_tile(0);
        }
        tiles[10 * width + 40] = water_tile(1);
        tiles[10 * width + 41] = water_tile(1);
        tiles[10 * width + 42] = water_tile(1);

        let before = city_region_count(&tiles);
        assert_eq!(before, 2);
        let after =
            merge_small_water_regions(&mut tiles, MapGeometry::new(crate::MapTopology::Wrapping));
        assert_eq!(after, 1);
        assert_eq!(water_region_id(&tiles[10 * width + 40]), 0);
        assert_eq!(water_region_id(&tiles[10 * width + 20]), 0);
    }
}
