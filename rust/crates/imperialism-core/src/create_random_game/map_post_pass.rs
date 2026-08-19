use super::*;

/// `ComputeRepresentativeTileIndexForNation(..., wrapBias = 1)` followed by the
/// `TCitySiteView` owned-territory clamp and the base `TMapDialog` viewport clamp.
/// At the Normal+ start boundary the human nation has no home tile, so retail includes
/// every tile it owns in both the representative and CitySite bounds.
pub fn capital_selection_view_origin(world: &MapMgr, human_nation: MajorNationId) -> TileId {
    const VIEWPORT_TILE_SPAN: i32 = 9;

    let owner = TileContext::from_nation(human_nation.nation());
    let geometry = world.geometry();
    let mut column_sum = 0_u32;
    let mut row_sum = 0_u32;
    let mut tile_count = 0_u32;
    let mut west_count = 0_u32;
    let mut east_count = 0_u32;
    let mut min_column = i32::MAX;
    let mut max_column = i32::MIN;
    let mut min_row = i32::MAX;
    let mut max_row = i32::MIN;

    for tile in TileId::all() {
        if world[tile].owner_nation != Some(owner) {
            continue;
        }
        let MapPosition { row, column } = geometry.position(tile);
        let row = i32::from(row);
        let column = i32::from(column);
        column_sum += column as u32;
        row_sum += row as u32;
        tile_count += 1;
        west_count += u32::from(column < 0x19);
        east_count += u32::from(column > 0x53);
        min_column = min_column.min(column);
        max_column = max_column.max(column);
        min_row = min_row.min(row);
        max_row = max_row.max(row);
    }

    assert_ne!(
        tile_count, 0,
        "random-game human nation must own capital-selection territory"
    );
    if west_count != 0 && east_count != 0 {
        column_sum += west_count * STRATEGIC_MAP_WIDTH as u32;
    }
    let mut column = (column_sum / tile_count) as i32 % STRATEGIC_MAP_WIDTH;
    let mut row = (row_sum / tile_count) as i32;

    if column < min_column - 1 {
        column = min_column - 1;
    }
    if row < min_row - 1 {
        row = min_row - 1;
    }
    if column > max_column + 3 - VIEWPORT_TILE_SPAN {
        column = max_column + 3 - VIEWPORT_TILE_SPAN;
    }
    if row > max_row - 5 {
        row = max_row - 5;
    }

    if world.topology == MapTopology::Bounded {
        column = column.clamp(1, 0x6e - VIEWPORT_TILE_SPAN);
    }
    if column < 0 {
        column += STRATEGIC_MAP_WIDTH;
    } else if column >= STRATEGIC_MAP_WIDTH {
        column -= STRATEGIC_MAP_WIDTH;
    }
    row = row.clamp(0, 0x35);

    geometry
        .tile(MapPosition::new(row, column))
        .expect("capital-selection view origin is inside the strategic map")
}
pub(super) struct TilePostPassState {
    pub(super) tiles: Box<[TileState]>,
    pub(super) province_capitals: Vec<Option<TileId>>,
    pub(super) province_resource_presence_masks: Vec<i8>,
    pub(super) pending_river_mouth_tile: Option<TileId>,
}
/// Preview-time tile post-passes from `TMapMgr::BuildOrLoadGlobalMapStateForSession`:
/// icon-variant/edge-resource stamping, former-owner snapshot, province fallback capitals,
/// `GuaranteeResources`, and the final picture-assignment RNG pass.
pub(super) fn apply_tile_post_passes(
    map: &GeneratedMap,
    topology: MapTopology,
    map_lcg: &mut RetailLcg,
) -> TilePostPassState {
    let geometry = MapGeometry::new(topology);
    let mut tiles: Vec<TileState> = map
        .tiles()
        .iter()
        .copied()
        .map(tile_from_generated)
        .collect();
    for index in 0..tiles.len() {
        update_strategic_map_tile_icon_variant_state(&mut tiles, geometry, index, map_lcg);
    }

    // RebuildTileOwnerNeighborCachesAndFallbackAssignments snapshots this byte before its
    // fallback-capital normalization and before GuaranteeResources mutate tile resources.
    let province_resource_presence_masks = build_province_resource_presence_masks(&tiles);

    // Retail runs this between icon variants and GuaranteeResources; it advances the map
    // LCG once per occupied province and records its fallback capital.
    let province_capitals = assign_province_fallback_capitals(&mut tiles, geometry, map_lcg);

    guarantee_resources(&mut tiles, map_lcg);
    let mut river_connections: Vec<u8> = map
        .tiles()
        .iter()
        .map(|tile| tile.river.map_or(0, RiverSegment::connection_code))
        .collect();
    let pending_river_mouth_tile =
        assign_fresh_map_pictures(&mut tiles, &mut river_connections, geometry, map_lcg);
    TilePostPassState {
        tiles: tiles.into_boxed_slice(),
        province_capitals,
        province_resource_presence_masks,
        pending_river_mouth_tile,
    }
}

fn build_province_resource_presence_masks(tiles: &[TileState]) -> Vec<i8> {
    let province_count = tiles
        .iter()
        .filter_map(|tile| tile.province.map(|province| province.index() + 1))
        .max()
        .unwrap_or(0);
    let mut masks = vec![0_u8; province_count];
    for tile in tiles {
        if tile.terrain == TerrainKind::Water {
            continue;
        }
        let Some(province) = tile.province else {
            continue;
        };
        let mask = &mut masks[province.index()];
        for resource in tile.edge_resources.into_iter().flatten() {
            let resource = resource.retail();
            if resource < 8 {
                *mask |= 1 << resource;
            }
        }
    }
    masks.into_iter().map(|mask| mask as i8).collect()
}
/// Capital-tile pick + stamp from `TMapMgr::RebuildTileOwnerNeighborCachesAndFallbackAssignments`
/// (0x0050f860). Adjacent-province bookkeeping and transport-mask side effects that are not
/// represented on [`TileState`] are omitted.
pub(super) fn assign_province_fallback_capitals(
    tiles: &mut [TileState],
    geometry: MapGeometry,
    map_lcg: &mut RetailLcg,
) -> Vec<Option<TileId>> {
    let province_count = tiles
        .iter()
        .filter_map(|tile| tile.province.map(|province| province.index() + 1))
        .max()
        .unwrap_or(0);
    let mut linked_by_province: Vec<Vec<usize>> = vec![Vec::new(); province_count];
    let mut province_capitals = vec![None; province_count];
    for (index, tile) in tiles.iter().enumerate() {
        if tile.terrain == TerrainKind::Water {
            continue;
        }
        let Some(province) = tile.province else {
            continue;
        };
        linked_by_province[province.index()].push(index);
    }

    for (province_index, linked) in linked_by_province.iter().enumerate() {
        if linked.is_empty() {
            continue;
        }

        let mut interior = Vec::new();
        for &tile_index in linked {
            let tile_id = TileId::new(tile_index);
            let has_foreign_neighbor =
                geometry
                    .neighbors(tile_id)
                    .into_iter()
                    .flatten()
                    .any(|neighbor| {
                        let neighbor_tile = &tiles[usize::from(neighbor.get())];
                        match neighbor_tile.province {
                            Some(province) => province.index() != province_index,
                            None => false,
                        }
                    });
            if !has_foreign_neighbor {
                interior.push(tile_index);
            }
        }

        let chosen = if interior.is_empty() {
            let sample = map_lcg.next_sample_15() as usize;
            linked[sample % linked.len()]
        } else {
            let flat: Vec<usize> = interior
                .iter()
                .copied()
                .filter(|&index| {
                    matches!(
                        tiles[index].terrain,
                        TerrainKind::Plains | TerrainKind::Farmland
                    )
                })
                .collect();
            if !flat.is_empty() {
                let sample = map_lcg.next_sample_15() as usize;
                flat[sample % flat.len()]
            } else {
                let sample = map_lcg.next_sample_15() as usize;
                interior[sample % interior.len()]
            }
        };

        initialize_tile_neighbor_connection_mask_if_needed(tiles, chosen);
        tiles[chosen].flags = TileFlags::PROVINCE_ANCHOR_STATE;
        province_capitals[province_index] = Some(TileId::new(chosen));
    }
    province_capitals
}
/// `TMapMgr::InitializeTileNeighborConnectionMaskIfNeeded` (0x005107e0).
///
/// This preview-time call precedes picture assignment, so every neighboring transition mask is
/// still zero when retail tries to clear it.
pub(super) fn initialize_tile_neighbor_connection_mask_if_needed(
    tiles: &mut [TileState],
    index: usize,
) {
    if tiles[index].gate == 1 {
        return;
    }
    tiles[index].terrain = TerrainKind::Plains;
    tiles[index].edge_resources = [Some(ResourceKind::Grain), None];
    tiles[index].gate = resolve_region_tile_subtype_code(&tiles[index], index);
}
