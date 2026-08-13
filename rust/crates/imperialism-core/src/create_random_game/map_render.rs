use super::*;

pub(super) fn tile_from_generated(tile: GeneratedTerrainTile) -> TileState {
    let owner = tile.owner;
    TileState {
        terrain: tile.terrain,
        rendering: TileRendering::default(),
        owner_nation: owner,
        // Retail stamps former owners from the generation owners before Accept.
        former_owner_nation: owner,
        secondary_owner_nation: None,
        owner_border_mask: 0,
        city_border_mask: 0,
        water_adjacency_mask: 0,
        province: tile.province,
        gate: tile.gate.map_or(-1, |gate| gate.code()),
        recruit_search_visited: 0,
        per_tile_visited: 0,
        marker_slot_index: -1,
        tile_action_ordinal: -1,
        development: Default::default(),
        edge_resources: [None, None],
        transport_links: Default::default(),
        pending_rail_links: Default::default(),
        // Map tiles default to "no action" (-1) after generation.
        action: None,
        flags: TileFlags::empty(),
        region: None,
    }
}
/// `TMapMgr::UpdateStrategicMapTileIconVariantState` (0x00511610).
pub(super) fn update_strategic_map_tile_icon_variant_state(
    tiles: &mut [TileState],
    geometry: MapGeometry,
    index: usize,
    map_lcg: &mut RetailLcg,
) {
    let terrain = tiles[index].terrain;
    let major_owner = tiles[index]
        .owner_nation
        .and_then(TileOwnerTag::nation)
        .and_then(MajorNationId::from_nation)
        .is_some();
    match terrain {
        TerrainKind::Water => {
            let tile_id = TileId::new(index);
            let found_land = geometry
                .neighbors(tile_id)
                .into_iter()
                .filter_map(|(_, tile)| tile)
                .any(|neighbor| tiles[neighbor.index()].terrain != TerrainKind::Water);
            if found_land {
                tiles[index].edge_resources[0] = Some(ResourceKind::Fish);
            }
        }
        TerrainKind::Plains => {
            let roll = map_lcg.next_sample_15();
            if roll % 100 < 10 {
                tiles[index].edge_resources[0] = Some(ResourceKind::Cotton);
            } else {
                let roll = map_lcg.next_sample_15();
                if roll % 100 < 5 && major_owner {
                    tiles[index].edge_resources[0] = Some(ResourceKind::Horses);
                } else {
                    let roll = map_lcg.next_sample_15();
                    tiles[index].edge_resources[0] = Some(if roll % 100 < 0x24 {
                        ResourceKind::Livestock
                    } else {
                        ResourceKind::Grain
                    });
                }
            }
        }
        TerrainKind::Farmland => {
            let roll = map_lcg.next_sample_15();
            tiles[index].edge_resources[0] = Some(if roll % 100 < 0x37 {
                ResourceKind::Grain
            } else {
                ResourceKind::Fruit
            });
        }
        TerrainKind::Forest => {
            tiles[index].edge_resources[0] = Some(ResourceKind::Timber);
        }
        TerrainKind::Swamp | TerrainKind::Desert => {
            let roll = map_lcg.next_sample_15();
            if roll % 100 < 0xf {
                tiles[index].edge_resources[0] = Some(ResourceKind::Oil);
            }
        }
        TerrainKind::Hills => {
            let roll = map_lcg.next_sample_15();
            if roll % 100 < 0xc {
                tiles[index].edge_resources[0] = Some(ResourceKind::Wool);
            } else {
                let roll = map_lcg.next_sample_15();
                if roll % 100 < 0x14 {
                    let roll = map_lcg.next_sample_15();
                    tiles[index].edge_resources[0] = Some(if roll % 100 < 0x32 {
                        ResourceKind::Coal
                    } else {
                        ResourceKind::Iron
                    });
                }
            }
        }
        TerrainKind::Mountain => {
            let mut edge_index = 0usize;
            let roll = map_lcg.next_sample_15();
            if roll % 100 < 0x14 {
                let roll = map_lcg.next_sample_15();
                tiles[index].edge_resources[0] = Some(if roll % 100 < 0x32 {
                    ResourceKind::Coal
                } else {
                    ResourceKind::Iron
                });
                edge_index = 1;
            }
            if major_owner {
                let roll = map_lcg.next_sample_15();
                if roll % 100 < 0xf {
                    tiles[index].edge_resources[edge_index] = Some(ResourceKind::Gold);
                }
            } else {
                let roll = map_lcg.next_sample_15();
                if roll % 100 < 0xa {
                    tiles[index].edge_resources[edge_index] = Some(ResourceKind::Gems);
                } else {
                    let roll = map_lcg.next_sample_15();
                    if roll % 100 < 0xf {
                        tiles[index].edge_resources[edge_index] = Some(ResourceKind::Gold);
                    }
                }
            }
        }
    }
    tiles[index].gate = resolve_region_tile_subtype_code(&tiles[index], index);
}
/// `TMapMgr::ResolveRegionTileSubtypeCodeForTileIndex` (0x00514210).
pub(super) fn resolve_region_tile_subtype_code(tile: &TileState, index: usize) -> i8 {
    let edge0 = tile.edge_resources[0];
    match tile.terrain {
        TerrainKind::Plains => match edge0 {
            Some(ResourceKind::Cotton) => 2,
            Some(ResourceKind::Horses) => 4,
            Some(ResourceKind::Livestock) => 3,
            _ if tile.flags.contains(TileFlags::RECRUITMENT_RESERVED) => 0xe,
            _ => 1,
        },
        TerrainKind::Forest => {
            if tile.gate == -1 {
                0xd
            } else {
                tile.gate
            }
        }
        TerrainKind::Hills => i8::from(edge0 != Some(ResourceKind::Wool)) + 7,
        TerrainKind::Mountain => 9,
        TerrainKind::Swamp => 0xa,
        TerrainKind::Desert => {
            if tile.gate != -1 {
                tile.gate
            } else {
                let row = index / usize::from(STRATEGIC_MAP_WIDTH);
                if !(0xf..=0x2d).contains(&row) {
                    0xc
                } else {
                    0xb
                }
            }
        }
        TerrainKind::Farmland => i8::from(edge0 != Some(ResourceKind::Grain)) + 5,
        TerrainKind::Water => 0,
    }
}
/// `TMapMgr::GuaranteeResources` (0x00511a70).
pub(super) fn guarantee_resources(tiles: &mut [TileState], map_lcg: &mut RetailLcg) {
    for nation in MajorNationId::all() {
        let owner = TileOwnerTag::from_nation(nation.nation());
        let linked: Vec<usize> = tiles
            .iter()
            .enumerate()
            .filter_map(|(index, tile)| (tile.owner_nation == Some(owner)).then_some(index))
            .collect();
        if linked.is_empty() {
            continue;
        }

        let mut resource_tally: ResourceTable<i16> = ResourceTable::default();
        for &index in &linked {
            for edge in 0..2 {
                if let Some(resource) = tiles[index].edge_resources[edge] {
                    resource_tally[resource] += 1;
                }
            }
        }

        if resource_tally[ResourceKind::Coal] == 0 {
            place_guaranteed_resource(tiles, &linked, map_lcg, ResourceKind::Coal);
        }
        if resource_tally[ResourceKind::Iron] == 0 {
            let index = if let Some(index) = linked.iter().copied().find(|&index| {
                matches!(tiles[index].gate, 8 | 9) && tiles[index].edge_resources[0].is_none()
            }) {
                tiles[index].edge_resources[0] = Some(ResourceKind::Iron);
                if tiles[index].gate == 9 {
                    tiles[index].edge_resources[1] = None;
                    tiles[index].gate = resolve_region_tile_subtype_code(&tiles[index], index);
                    continue;
                }
                index
            } else {
                let mut picked;
                let mut gate_flag;
                loop {
                    loop {
                        let sample = map_lcg.next_sample_15();
                        picked = (sample as usize) % linked.len();
                        gate_flag = tiles[linked[picked]].gate;
                        if gate_flag != 8 {
                            break;
                        }
                    }
                    if gate_flag != 9 {
                        break;
                    }
                }
                let index = linked[picked];
                tiles[index].gate = 8;
                tiles[index].edge_resources[0] = Some(ResourceKind::Iron);
                index
            };
            tiles[index].edge_resources[1] = None;
            tiles[index].gate = resolve_region_tile_subtype_code(&tiles[index], index);
        }
    }
}
pub(super) fn place_guaranteed_resource(
    tiles: &mut [TileState],
    linked: &[usize],
    map_lcg: &mut RetailLcg,
    resource: ResourceKind,
) {
    let index = if let Some(index) = linked.iter().copied().find(|&index| {
        matches!(tiles[index].gate, 8 | 9) && tiles[index].edge_resources[0].is_none()
    }) {
        tiles[index].edge_resources[0] = Some(resource);
        index
    } else {
        let mut picked;
        loop {
            loop {
                let sample = map_lcg.next_sample_15();
                picked = (sample as usize) % linked.len();
                let gate_flag = tiles[linked[picked]].gate;
                if gate_flag != 8 {
                    break;
                }
            }
            if tiles[linked[picked]].gate != 9 {
                break;
            }
        }
        let index = linked[picked];
        tiles[index].gate = 8;
        tiles[index].edge_resources[0] = Some(resource);
        index
    };
    tiles[index].edge_resources[1] = None;
    tiles[index].gate = resolve_region_tile_subtype_code(&tiles[index], index);
}
/// Fresh-map `TMapMgr::AssignPictToTile` pass after `GuaranteeResources`.
///
/// `river_connections` carries generation-time connection codes until this pass writes the
/// authoritative picture sprites onto each tile. Finished tiles keep only those sprites.
pub(super) fn assign_fresh_map_pictures(
    tiles: &mut [TileState],
    river_connections: &mut [u8],
    geometry: MapGeometry,
    map_lcg: &mut RetailLcg,
) -> Option<TileId> {
    let mut sprite_variants = vec![0u8; tiles.len()];
    let mut pending_river_mouth_tile = None;

    for index in 0..tiles.len() {
        let selected_pending_tile = assign_picture_to_tile_for_rng(
            tiles,
            geometry,
            index,
            &mut sprite_variants,
            river_connections,
            map_lcg,
        );
        if selected_pending_tile && pending_river_mouth_tile.is_none() {
            pending_river_mouth_tile = Some(TileId::new(index));
        }
        let (transition_mask, coast_or_secondary_mask) =
            fresh_picture_masks(tiles, geometry, index);
        tiles[index].rendering = TileRendering::from_retail(
            sprite_variants[index],
            river_connections[index],
            transition_mask,
            coast_or_secondary_mask,
        )
        .expect("fresh-map picture assignment must produce valid rendering state");
        assert_eq!(
            tiles[index].river().is_some(),
            river_connections[index] != 0,
            "finished river sprite must derive the generation connection"
        );
    }
    pending_river_mouth_tile
}
pub(super) fn assign_picture_to_tile_for_rng(
    tiles: &[TileState],
    geometry: MapGeometry,
    index: usize,
    sprite_variants: &mut [u8],
    river_sprite_codes: &mut [u8],
    map_lcg: &mut RetailLcg,
) -> bool {
    if tiles[index].terrain != TerrainKind::Water {
        if tiles[index].terrain == TerrainKind::Mountain && map_lcg.next_sample_15() & 1 != 0 {
            sprite_variants[index] = 1;
        }

        if tiles[index].gate == 0x0b {
            let tile = TileId::new(index);
            let neighbors = geometry.neighbors(tile);
            for direction in HexDirection::ALL {
                let neighbor_has_profile = neighbors[direction]
                    .is_some_and(|neighbor| tiles[neighbor.index()].gate == 0x0b);
                if !neighbor_has_profile {
                    continue;
                }
                let previous_has_profile = neighbors[direction.wrapping_prev()]
                    .is_some_and(|neighbor| tiles[neighbor.index()].gate == 0x0b);
                let next_has_profile = neighbors[direction.wrapping_next()]
                    .is_some_and(|neighbor| tiles[neighbor.index()].gate == 0x0b);
                sprite_variants[index] = match (previous_has_profile, next_has_profile) {
                    (false, false) => 0,
                    (true, true) => 1,
                    (true, false) => 2,
                    (false, true) => 3,
                };
            }
        }

        if river_sprite_codes[index] != 0 {
            river_sprite_codes[index] =
                resolve_picture_river_sprite(tiles, index, river_sprite_codes, map_lcg);
            if (0x1b..0x2b).contains(&river_sprite_codes[index]) {
                river_sprite_codes[index] -= 0x10;
            }
        }
        return false;
    }

    let tile = TileId::new(index);
    let neighbors = geometry.neighbors(tile);
    let mut has_land_neighbor = false;
    for (direction, neighbor) in neighbors {
        if neighbor.is_some_and(|neighbor| tiles[neighbor.index()].terrain != TerrainKind::Water) {
            has_land_neighbor = true;
            if map_lcg.next_sample_15() & 1 != 0 {
                sprite_variants[index] |= 1 << direction as u8;
            }
        }
    }

    if has_land_neighbor {
        if river_sprite_codes[index] != 0 {
            river_sprite_codes[index] =
                resolve_picture_river_sprite(tiles, index, river_sprite_codes, map_lcg);
        }
        return false;
    }

    let west = neighbors[HexDirection::West].map(|tile| tile.index());
    let Some(west) = west else {
        return false;
    };
    if sprite_variants[west] != 0 {
        return false;
    }

    let north_west = neighbors[HexDirection::NorthWest].map(|tile| tile.index());
    let north_east = neighbors[HexDirection::NorthEast].map(|tile| tile.index());
    let north_west_variant = north_west.map_or(0, |neighbor| sprite_variants[neighbor]);
    let north_east_variant = north_east.map_or(0, |neighbor| sprite_variants[neighbor]);

    if north_west_variant == 0 && north_east_variant == 0 {
        if map_lcg.next_sample_15() % 100 <= 3 {
            sprite_variants[index] = (map_lcg.next_sample_15() & 3) as u8 + 1;
            return true;
        }
        return false;
    }

    if map_lcg.next_sample_15() % 100 > 7 {
        return false;
    }
    if north_west_variant != 0 {
        sprite_variants[index] = if north_west_variant < 4 {
            north_west_variant + 1
        } else {
            1
        };
    } else {
        sprite_variants[index] = if north_east_variant < 4 {
            north_east_variant + 1
        } else {
            1
        };
    }
    false
}
pub(super) fn fresh_picture_masks(
    tiles: &[TileState],
    geometry: MapGeometry,
    index: usize,
) -> (u8, u8) {
    let terrain = tiles[index].terrain;
    let mut transition_mask = 0;
    let mut coast_or_secondary_mask = 0;
    let tile = TileId::new(index);
    for (direction, neighbor) in geometry.neighbors(tile) {
        let Some(neighbor) = neighbor else {
            continue;
        };
        let neighbor = neighbor.index();
        let direction_bit = 1 << direction as u8;
        if terrain == TerrainKind::Water {
            if tiles[neighbor].terrain != TerrainKind::Water {
                coast_or_secondary_mask |= direction_bit;
            }
            continue;
        }
        if tiles[neighbor].gate == tiles[index].gate {
            transition_mask |= direction_bit;
        }
        match (terrain, tiles[neighbor].terrain) {
            (TerrainKind::Hills, TerrainKind::Hills) => transition_mask |= direction_bit,
            (TerrainKind::Hills, TerrainKind::Mountain)
            | (TerrainKind::Mountain, TerrainKind::Hills) => {
                coast_or_secondary_mask |= direction_bit;
            }
            _ => {}
        }
    }
    (transition_mask, coast_or_secondary_mask)
}
pub(super) fn resolve_picture_river_sprite(
    tiles: &[TileState],
    index: usize,
    river_sprite_codes: &[u8],
    map_lcg: &mut RetailLcg,
) -> u8 {
    let code = river_sprite_codes[index];
    let last_column =
        index % usize::from(STRATEGIC_MAP_WIDTH) == usize::from(STRATEGIC_MAP_WIDTH) - 1;
    let west_code = || {
        river_sprite_codes[index
            .checked_sub(1)
            .expect("fresh-map river does not cross the raw west boundary")]
    };
    let north_run_code = || {
        river_sprite_codes[index
            .checked_sub(usize::from(STRATEGIC_MAP_WIDTH) - 1)
            .expect("fresh-map river north-run lookup is in bounds")]
    };
    let random_bit = |rng: &mut RetailLcg| (rng.next_sample_15() & 1) as u8;

    if tiles[index].terrain == TerrainKind::Water {
        return match code {
            0x10 => 0x37,
            0x11 if variant_set_a(west_code()) => 0x38,
            0x11 if !variant_set_b(west_code()) => 0x38 + random_bit(map_lcg),
            0x11 => 0x39,
            0x12 => 0x3a,
            0x13 => 0x33,
            0x14 if !last_column => 0x35 - random_bit(map_lcg),
            0x14 if variant_set_c(north_run_code()) => 0x34,
            0x14 if variant_set_d(north_run_code()) => 0x35,
            0x14 => 0x34 + random_bit(map_lcg),
            0x15 => 0x36,
            _ => 0,
        };
    }

    match code {
        1 => 0x0b,
        2 => 0x0c,
        3 if variant_set_a(west_code()) => 0x0d,
        3 if !variant_set_b(west_code()) => 0x0d + random_bit(map_lcg),
        3 => 0x0e,
        4 if !last_column => 0x10 - random_bit(map_lcg),
        4 if variant_set_c(north_run_code()) => 0x0f,
        4 if variant_set_d(north_run_code()) => 0x10,
        4 => 0x0f + random_bit(map_lcg),
        5 if variant_set_a(west_code()) && !last_column => 0x12 - random_bit(map_lcg),
        5 if variant_set_a(west_code()) && variant_set_c(north_run_code()) => 0x11,
        5 if variant_set_a(west_code()) => 0x12,
        5 if !last_column => 0x14 - random_bit(map_lcg),
        5 if variant_set_c(north_run_code()) => 0x13,
        5 => 0x14,
        6 if !last_column => 0x16 - random_bit(map_lcg),
        6 if variant_set_c(north_run_code()) => 0x15,
        6 if variant_set_d(north_run_code()) => 0x16,
        6 => 0x15 + random_bit(map_lcg),
        7 if variant_set_a(west_code()) => 0x17,
        7 if !variant_set_b(west_code()) => 0x17 + random_bit(map_lcg),
        7 => 0x18,
        8 => 0x19,
        9 => 0x1a,
        0x0a => 0x2b,
        0x0b if !last_column => 0x2d - random_bit(map_lcg),
        0x0b if variant_set_c(north_run_code()) => 0x2c,
        0x0b if variant_set_d(north_run_code()) => 0x2d,
        0x0b => 0x2c + random_bit(map_lcg),
        0x0c => 0x2e,
        0x0d => 0x2f,
        0x0e if variant_set_a(west_code()) => 0x30,
        0x0e if !variant_set_b(west_code()) => 0x30 + random_bit(map_lcg),
        0x0e => 0x31,
        0x0f => 0x32,
        _ => 0,
    }
}
pub(super) const fn variant_set_a(code: u8) -> bool {
    matches!(
        code,
        0x0f | 0x1f | 0x11 | 0x21 | 0x13 | 0x23 | 0x15 | 0x25 | 0x2c | 0x34
    )
}
pub(super) const fn variant_set_b(code: u8) -> bool {
    matches!(
        code,
        0x10 | 0x20 | 0x12 | 0x22 | 0x14 | 0x24 | 0x16 | 0x26 | 0x2d | 0x35
    )
}
pub(super) const fn variant_set_c(code: u8) -> bool {
    matches!(
        code,
        0x0d | 0x1d | 0x11 | 0x21 | 0x12 | 0x22 | 0x17 | 0x27 | 0x30 | 0x38
    )
}
pub(super) const fn variant_set_d(code: u8) -> bool {
    matches!(
        code,
        0x0e | 0x1e | 0x13 | 0x23 | 0x14 | 0x24 | 0x18 | 0x28 | 0x31 | 0x39
    )
}
