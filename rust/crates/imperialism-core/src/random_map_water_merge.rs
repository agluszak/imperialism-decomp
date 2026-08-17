//! Water-region border/merge/compact from `TMapMaker::AssignOrCompactCityRegionIdsAndRebuildBorders`
//! (mode 0), after `GenerateWaterRegionIds` and before keyword overrides.
//!
//! Ports:
//! - `BuildCityRegionBorderOverlaySegments` (0x0052c1a0)
//! - `BuildOverlaySpanRecordsFromQuadBorderLinks` (0x0052cae0)
//! - `MergeSmallCityRegionsAndCompactIds` (0x0052d750)

use crate::random_map_terrain::GeneratedTerrainTileScratch;
use crate::{
    HexDirection, MapGeometry, OceanRoute, OceanZoneId, STRATEGIC_MAP_HEIGHT, STRATEGIC_MAP_WIDTH,
    TileId,
};

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
    direction: HexDirection,
}

#[derive(Clone, Copy, Debug)]
struct SeaSegment {
    x0: i16,
    y0: i16,
    x1: i16,
    y1: i16,
    region_a: u8,
    region_b: u8,
}

pub(crate) struct WaterMergeResult {
    pub(crate) region_count: i32,
    pub(crate) routes: Vec<OceanRoute>,
    pub(crate) zone_links: Vec<[OceanZoneId; 2]>,
}

impl Seapoint {
    fn init_sorted(coord: i32, a: i32, b: i32, direction: HexDirection) -> Self {
        let (lo, hi) = if a > b { (b, a) } else { (a, b) };
        Self {
            coord,
            lo,
            hi,
            direction,
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
        let region_a = p0.lo as u8;
        let region_b = p0.hi as u8;
        if y1 < y0 || (y0 == y1 && x1 < x0) {
            std::mem::swap(&mut x0, &mut x1);
            std::mem::swap(&mut y0, &mut y1);
        }
        Self {
            x0,
            y0,
            x1,
            y1,
            region_a,
            region_b,
        }
    }
}

/// Compact undersized water regions and rewrite `owner_nation` tags to the compacted id space.
///
/// Returns the post-merge city-region count and retained `TOcean` route records.
pub(crate) fn merge_small_water_regions(
    tiles: &mut [GeneratedTerrainTileScratch],
    geometry: MapGeometry,
) -> WaterMergeResult {
    let mut region_count = city_region_count(tiles);
    if region_count <= 0 {
        return WaterMergeResult {
            region_count: 0,
            routes: Vec::new(),
            zone_links: Vec::new(),
        };
    }
    let quads = build_city_region_border_overlay_segments(tiles, geometry);
    let mut links = build_overlay_span_records_from_quad_border_links(quads);

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
            let links = links
                .into_iter()
                .flatten()
                .filter(|link| {
                    link.region_a != link.region_b && (link.x0 != link.x1 || link.y0 != link.y1)
                })
                .collect::<Vec<_>>();
            let routes = links
                .iter()
                .map(|link| OceanRoute {
                    start_column: i32::from(link.x0),
                    start_row: i32::from(link.y0),
                    end_column: i32::from(link.x1),
                    end_row: i32::from(link.y1),
                })
                .collect();
            let zone_links = links
                .iter()
                .map(|link| {
                    [
                        OceanZoneId::new(u16::from(link.region_a)),
                        OceanZoneId::new(u16::from(link.region_b)),
                    ]
                })
                .collect();
            return WaterMergeResult {
                region_count,
                routes,
                zone_links,
            };
        }
        let region_byte = region as u8;

        if tile_counts[region as usize] > 0 && tile_counts[region as usize] < MERGE_SIZE_THRESHOLD {
            let mut merge_target = None;
            let mut best_score = -1_i32;
            let mut best_link = None;

            for (li, link) in links.iter().enumerate() {
                let Some(link) = link else {
                    continue;
                };
                let other = if link.region_a == region_byte {
                    usize::from(link.region_b)
                } else if link.region_b == region_byte {
                    usize::from(link.region_a)
                } else {
                    continue;
                };
                let mut bias = 0_i32;
                if tile_counts[other] + tile_counts[region as usize] >= MERGE_SIZE_THRESHOLD {
                    bias = 0x2710;
                }
                if merged_flags[other] == 0 {
                    bias += 0x1388;
                }
                let width = i32::from(link.x1) - i32::from(link.x0);
                let height = i32::from(link.y1) - i32::from(link.y0);
                let area_sq = width * width * height * height;
                // MSVC `_ftol` truncates toward zero; same for positive values via `as i32`.
                let score = (f64::from(area_sq).sqrt() * f64::from(tile_counts[other])
                    + f64::from(bias)) as i32;
                if best_score < score {
                    best_score = score;
                    merge_target = Some(other);
                    best_link = Some(li);
                }
            }

            if merge_target.is_none() && tile_counts[region as usize] < TINY_REGION_FALLBACK {
                'tiles: for (tile_idx, tile) in tiles.iter().enumerate() {
                    if water_region_id(tile) != region {
                        continue;
                    }
                    let tile_id = TileId::new(tile_idx as u16);
                    for direction in HexDirection::ALL {
                        let Some(neighbor) = geometry.neighbor(tile_id, direction) else {
                            continue;
                        };
                        let neighbor_region = water_region_id(&tiles[usize::from(neighbor.get())]);
                        if neighbor_region >= 0 && neighbor_region != region {
                            merge_target = Some(neighbor_region as usize);
                            break 'tiles;
                        }
                    }
                }
            }

            if let Some(merge_target) = merge_target {
                tile_counts[merge_target] += tile_counts[region as usize];
                tile_counts[region as usize] = 0;
                merged_flags[merge_target] = 1;
                for tile in tiles.iter_mut() {
                    if water_region_id(tile) == region {
                        set_water_region_id(tile, merge_target as i32);
                    }
                }
                if let Some(best_link) = best_link {
                    links[best_link] = None;
                }
                for link in links.iter_mut().flatten() {
                    if i32::from(link.region_a) == region {
                        link.region_a = merge_target as u8;
                    }
                    if i32::from(link.region_b) == region {
                        link.region_b = merge_target as u8;
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
                    set_water_region_id(tile, i32::from(region_byte));
                }
            }
            for link in links.iter_mut().flatten() {
                if i32::from(link.region_a) == region_count {
                    link.region_a = region_byte;
                }
                if i32::from(link.region_b) == region_count {
                    link.region_b = region_byte;
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

fn hex_neighbor(geometry: MapGeometry, tile_index: i32, direction: HexDirection) -> i32 {
    if tile_index < 0 {
        return -1;
    }
    let Some(neighbor) = geometry.neighbor(TileId::new(tile_index as u16), direction) else {
        return -1;
    };
    i32::from(neighbor.get())
}

fn overlay_coord_from_tile_edge(tile_index: i32, lower: bool) -> i32 {
    let mut row = tile_index / i32::from(STRATEGIC_MAP_WIDTH);
    let column = (row & 1) + (tile_index % i32::from(STRATEGIC_MAP_WIDTH)) * 2;
    let mut result = column;
    if lower {
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
    direction: HexDirection,
) {
    quads.push(Seapoint::init_sorted(
        overlay_coord_from_tile_edge(tile_index, false),
        region_a,
        region_b,
        direction,
    ));
}

fn emit_overlay_segment_from_tile_edge_sorted(
    quads: &mut Vec<Seapoint>,
    tile_index: i32,
    lower: bool,
    a: i32,
    b: i32,
    direction: HexDirection,
) {
    let coord = overlay_coord_from_tile_edge(tile_index, lower);
    let (lo, hi) = if a > b { (b, a) } else { (a, b) };
    quads.push(Seapoint {
        coord,
        lo,
        hi,
        direction,
    });
}

fn clockwise_delta(from: HexDirection, to: HexDirection) -> u8 {
    let mut direction = from;
    let mut delta = 0;
    while direction != to {
        direction = direction.next_clockwise();
        delta += 1;
    }
    delta
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
        let region2 = region_at_tile(tiles, hex_neighbor(geometry, tile_idx, HexDirection::West));
        if region1 != region2 && region1 != -1 && region2 != -1 {
            append_border_quad(
                &mut quads,
                tile_idx,
                region1,
                region2,
                HexDirection::SouthEast,
            );
        }
    }

    // Phase 2: remaining tiles, directions 4 and 5.
    for tile_idx in width..tile_count {
        let mut this_region = region_at_tile(tiles, tile_idx);
        let dir4_region =
            region_at_tile(tiles, hex_neighbor(geometry, tile_idx, HexDirection::West));
        let dir5_region = region_at_tile(
            tiles,
            hex_neighbor(geometry, tile_idx, HexDirection::NorthWest),
        );

        let mut code_dir45 = HexDirection::West;
        let mut code_this_dir4 = HexDirection::SouthEast;
        let mut saved_dir5 = dir5_region;
        if this_region == -1 {
            code_dir45 = HexDirection::SouthEast;
            saved_dir5 = -1;
            code_this_dir4 = HexDirection::West;
            this_region = dir5_region;
        }
        let mut code_first = code_this_dir4;
        let mut code_second = HexDirection::NorthEast;
        let mut other_dir5 = saved_dir5;
        let mut dir4 = dir4_region;
        if dir4 == -1 {
            other_dir5 = -1;
            code_first = HexDirection::NorthEast;
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
        let mut dir1_region = region_at_tile(tiles, hex_neighbor(geometry, t3, HexDirection::East));
        let dir2_region =
            region_at_tile(tiles, hex_neighbor(geometry, t3, HexDirection::SouthEast));

        let mut code_a = HexDirection::East;
        let mut code_b = HexDirection::SouthWest;
        let mut code_this_dir1 = HexDirection::NorthWest;
        let mut saved_dir2 = dir2_region;
        if r_this == -1 {
            code_a = HexDirection::NorthWest;
            saved_dir2 = -1;
            code_this_dir1 = HexDirection::East;
            r_this = dir2_region;
        }
        let mut code_mid = code_this_dir1;
        let mut other_dir2 = saved_dir2;
        if dir1_region == -1 {
            other_dir2 = -1;
            code_mid = HexDirection::SouthWest;
            dir1_region = saved_dir2;
            code_b = code_this_dir1;
        }
        if r_this != dir1_region && r_this != other_dir2 && dir1_region != other_dir2 {
            if other_dir2 != -1 {
                emit_overlay_segment_from_tile_edge_sorted(
                    &mut quads,
                    t3,
                    true,
                    r_this,
                    dir1_region,
                    code_mid,
                );
                emit_overlay_segment_from_tile_edge_sorted(
                    &mut quads, t3, true, r_this, other_dir2, code_b,
                );
                r_this = dir1_region;
                dir1_region = other_dir2;
                code_mid = code_a;
            }
            emit_overlay_segment_from_tile_edge_sorted(
                &mut quads,
                t3,
                true,
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
                let r2 = region_at_tile(tiles, hex_neighbor(geometry, t3, HexDirection::East));
                if r1 != r2 && r1 != -1 && r2 != -1 {
                    emit_overlay_segment_from_tile_edge_sorted(
                        &mut quads,
                        t3,
                        true,
                        r1,
                        r2,
                        HexDirection::NorthWest,
                    );
                }
                t3 += 1;
            }
            break;
        }
    }
    quads
}

/// `TMapMaker::BuildOverlaySpanRecordsFromQuadBorderLinks`.
fn build_overlay_span_records_from_quad_border_links(
    mut quads: Vec<Seapoint>,
) -> Vec<Option<SeaSegment>> {
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
        let mut best_primary: Option<usize> = None;
        let mut best_secondary: Option<usize> = None;
        while j < quads.len() {
            let a = quads[i];
            let b = quads[j];
            let same_edge = a.lo == b.lo && a.hi == b.hi;
            if same_edge {
                let dir_delta = clockwise_delta(a.direction, b.direction);
                let is_primary = (2..=4).contains(&dir_delta);
                if is_primary {
                    if let Some(best_primary) = best_primary {
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
                        if quads[best_primary].wrapped_delta_metric(quads[i])
                            <= f64::from(candidate_dist)
                        {
                            j += 1;
                            continue;
                        }
                    }
                    best_primary = Some(j);
                } else if best_primary.is_none() {
                    if let Some(best_secondary) = best_secondary {
                        let candidate_dist = quads[j].wrapped_delta_metric(quads[i]) as f32;
                        if quads[best_secondary].wrapped_delta_metric(quads[i])
                            <= f64::from(candidate_dist)
                        {
                            j += 1;
                            continue;
                        }
                    }
                    best_secondary = Some(j);
                }
            }
            j += 1;
        }
        if let Some(best_primary) = best_primary.or(best_secondary) {
            segments.push(Some(SeaSegment::init_from_points(
                quads[best_primary],
                quads[i],
            )));
            quads[best_primary].coord = -1;
            quads[best_primary].hi = -1;
            quads[best_primary].lo = -1;
        }
        quads[i].coord = -1;
        quads[i].hi = -1;
        quads[i].lo = -1;
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
            owner_nation: (region + SEA_OWNER_BIAS) as i8,
            gate_flag: -1,
            province_index: -1,
        }
    }

    fn land_tile(owner: i8) -> GeneratedTerrainTileScratch {
        GeneratedTerrainTileScratch {
            terrain_kind: 0,
            river_sprite_code: 0,
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
        assert_eq!(after.region_count, 1);
        assert_eq!(water_region_id(&tiles[10 * width + 40]), 0);
        assert_eq!(water_region_id(&tiles[10 * width + 20]), 0);
    }
}
