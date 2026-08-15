use super::*;
use imperialism_core::*;

impl LegacyTerrainTile {
    fn tile_state(&self) -> TileState {
        let rendering = TileRendering::from_retail(
            self.sprite_variant,
            self.river_sprite,
            self.adjacency_mask_a,
            self.adjacency_mask_b,
        )
        .expect("retail tile rendering state");
        TileState {
            terrain: TerrainKind::from_retail(self.terrain_kind).expect("retail terrain kind"),
            rendering,
            owner_nation: optional_tile_owner_tag(self.owner_nation),
            former_owner_nation: optional_tile_owner_tag(self.former_owner_nation),
            secondary_owner_nation: optional_major_nation_id(self.secondary_owner_nation),
            owner_border_mask: self.owner_border_mask,
            city_border_mask: self.city_border_mask,
            water_adjacency_mask: self.water_adjacency_mask,
            province: optional_province_id(self.city_record_index),
            gate: self.gate,
            recruit_search_visited: self.recruit_search_visited,
            per_tile_visited: self.per_tile_visited,
            marker_slot_index: self.marker_slot_index,
            tile_action_ordinal: self.tile_action_ordinal,
            development: TileDevelopment {
                surface: DevelopmentLevel::new((self.development_classes as u8) & 0x0f),
                extractive: DevelopmentLevel::new((self.development_classes as u8) >> 4),
                resource_visible_to_majors: MajorNationTable::from_fn(|nation| {
                    self.pending_development_visibility & (1 << nation.get()) != 0
                }),
            },
            edge_resources: [
                optional_resource_kind(self.edge_resources[0]),
                optional_resource_kind(self.edge_resources[1]),
            ],
            transport_links: TileTransportLinks::from_bits_retain(self.adjacency_bits),
            pending_rail_links: TileTransportLinks::from_bits_retain(self.rail_flags),
            action: TileAction::try_from_retail(i16::from(self.action_state)),
            flags: TileFlags::from_bits_retain(self.active_flags),
            region: optional_region_id(self.region),
        }
    }
}

impl LegacyMapState {
    pub(super) const fn topology(&self) -> MapTopology {
        if self.no_horizontal_wrap == 0 {
            MapTopology::Wrapping
        } else {
            MapTopology::Bounded
        }
    }

    pub(super) fn map_mgr(&self) -> MapMgr {
        let mut map = MapMgr::from_parts(
            self.topology(),
            self.tiles
                .iter()
                .map(LegacyTerrainTile::tile_state)
                .collect::<Vec<_>>(),
            self.province_states(),
        );
        map.map_data_ready = self.map_data_ready != 0;
        map.recruit_search_active = self.recruit_search_active != 0;
        map.city_score_total = self.city_score_total;
        map.scenario_tag.clone_from(&self.scenario_tag);
        map.pending_river_mouth_tile = optional_tile_id(i32::from(self.pending_river_mouth_tile));
        map
    }

    fn province_states(&self) -> ProvinceTable<ProvinceState> {
        ProvinceTable::from_array(std::array::from_fn(|index| {
            province_state(&self.provinces[index])
        }))
    }
}

pub(super) fn owned_region_id_from_retail(value: i32) -> ProvinceId {
    ProvinceId::new(value as u16)
}

fn province_state(province: &LegacyProvince) -> ProvinceState {
    let count = province.adjacent_region_count as usize;
    let adjacency = province.adjacent_region_ids[..count]
        .iter()
        .copied()
        .map(|value| ProvinceId::new(value as u16))
        .collect();
    let adjacency_anchor_tiles = province.adjacent_region_anchor_tiles[..count]
        .iter()
        .copied()
        .map(|value| {
            optional_tile_id(i32::from(value)).expect("retail adjacency anchor tile is present")
        })
        .collect();
    let linked_count = province.linked_region_count as usize;
    let linked_tiles = province.linked_tile_indices[..linked_count]
        .iter()
        .copied()
        .map(|value| optional_tile_id(i32::from(value)).expect("retail linked tile is present"))
        .collect();

    let optional_owner = |value: i8| {
        if value == -1 {
            return None;
        }
        Some(NationId::new(value as u8))
    };
    let region_class = match province.region_class {
        -1 => None,
        value => Some(value as u8),
    };
    let mut resource_development_by_type = ResourceTable::default();
    for (offset, amount) in province
        .resource_development_by_type
        .iter()
        .copied()
        .enumerate()
    {
        let resource = ResourceKind::from_index((ResourceKind::Food as usize + offset) as u8)
            .expect("province resource-development table spans food through arms");
        resource_development_by_type[resource] = amount;
    }
    let explored_by_majors = MajorNationTable::from_fn(|nation| {
        province.explored_by_nation_mask & (1 << nation.get()) != 0
    });

    ProvinceState::new(
        optional_owner(province.owner_nation),
        optional_owner(province.former_owner_nation),
        province.development_stage,
        adjacency,
        adjacency_anchor_tiles,
        region_class,
        province.fort_level,
        optional_tile_id(i32::from(province.city_tile)),
        province.last_turn_tick,
        optional_tile_id(i32::from(province.secondary_neighbor_tile)),
        optional_tile_id(i32::from(province.primary_neighbor_tile)),
        linked_tiles,
        resource_development_by_type,
        explored_by_majors,
        province.city_score,
        province.navy_order_reachable != 0,
        province.resource_presence_mask,
        province.name.clone(),
    )
}

pub(super) fn ocean_state(ocean: &LegacyOceanState, map: &MapMgr) -> Ocean {
    let live_count = ocean.zones.len() + ocean.port_zones.len();
    let mut zones = vec![None; live_count];

    for context in &ocean.zones {
        let ordinal = context.context_ordinal as usize;
        zones[ordinal] = Some(ZoneKind::Zone(zone_state(context)));
    }
    for context in &ocean.port_zones {
        let ordinal = context.zone.context_ordinal as usize;
        let port_tile = optional_tile_id(i32::from(context.port_tile_index))
            .expect("retail port-zone tile is present");
        zones[ordinal] = Some(ZoneKind::PortZone(PortZone {
            zone: zone_state(&context.zone),
            port_tile,
        }));
    }

    let zones = zones
        .into_iter()
        .map(|zone| zone.expect("retail ocean context ordinals are contiguous"))
        .collect();
    let routes = ocean
        .route_segments
        .iter()
        .map(
            |&[start_row, start_column, end_row, end_column]| OceanRoute {
                start_column,
                start_row,
                end_column,
                end_row,
            },
        )
        .collect();
    let mut ocean = Ocean { zones, routes };
    rebuild_ocean_neighbors(&mut ocean, map);
    ocean
}

fn zone_state(context: &LegacyZone) -> Zone {
    let seed_owner = match context.seed_nation_id {
        -1 => None,
        value => Some(TileOwnerTag::new(value as u8)),
    };
    Zone {
        display_name: context.display_name.clone(),
        status_code: (context.status_code != -1).then_some(context.status_code),
        target_tile: optional_tile_id(context.tile_or_terrain_id),
        seed_owner,
        active_tile: optional_tile_id(i32::from(context.active_tile_index)),
        primary_neighbors: Vec::new(),
        secondary_neighbors: Vec::new(),
    }
}

fn rebuild_ocean_neighbors(ocean: &mut Ocean, map: &MapMgr) {
    let geometry = map.geometry();
    for tile in TileId::all() {
        let Some(zone_index) = ocean_zone_for_tile(ocean, map, tile) else {
            continue;
        };
        if matches!(ocean.zones[zone_index], ZoneKind::PortZone(_)) {
            let has_primary = match &ocean.zones[zone_index] {
                ZoneKind::PortZone(port) => !port.zone.primary_neighbors.is_empty(),
                ZoneKind::Zone(_) => unreachable!(),
            };
            if has_primary {
                continue;
            }
            let target_tile = match &ocean.zones[zone_index] {
                ZoneKind::PortZone(port) => port.zone.target_tile,
                ZoneKind::Zone(_) => unreachable!(),
            }
            .expect("retail port zone has a target tile");
            let owner = map[target_tile]
                .owner_nation
                .map(TileOwnerTag::get)
                .filter(|&owner| owner >= 0x17)
                .expect("retail port-zone target tile has a base ocean zone");
            let base_index = usize::from(owner - 0x17);
            let port_id = OceanZoneId::new(zone_index as u16);
            let base_id = OceanZoneId::new(base_index as u16);
            let ZoneKind::PortZone(port) = &mut ocean.zones[zone_index] else {
                unreachable!()
            };
            port.zone.primary_neighbors.push(base_id);
            let ZoneKind::Zone(base) = &mut ocean.zones[base_index] else {
                unreachable!()
            };
            base.primary_neighbors.push(port_id);
            continue;
        }

        for neighbor in geometry.neighbors(tile).into_iter().flatten() {
            if let Some(province) = map[neighbor].province {
                let ZoneKind::Zone(zone) = &mut ocean.zones[zone_index] else {
                    unreachable!()
                };
                if !zone.secondary_neighbors.contains(&province) {
                    zone.secondary_neighbors.push(province);
                }
                continue;
            }
            let Some(candidate) = ocean_zone_for_tile(ocean, map, neighbor) else {
                continue;
            };
            if candidate == zone_index || matches!(ocean.zones[candidate], ZoneKind::PortZone(_)) {
                continue;
            }
            let candidate = OceanZoneId::new(candidate as u16);
            let ZoneKind::Zone(zone) = &mut ocean.zones[zone_index] else {
                unreachable!()
            };
            if !zone.primary_neighbors.contains(&candidate) {
                zone.primary_neighbors.push(candidate);
            }
        }
    }
}

fn ocean_zone_for_tile(ocean: &Ocean, map: &MapMgr, tile: TileId) -> Option<usize> {
    if map[tile]
        .action
        .is_some_and(|action| matches!(action.retail(), 3 | 14))
    {
        return ocean
            .zones
            .iter()
            .enumerate()
            .rev()
            .find_map(|(ordinal, zone)| match zone {
                ZoneKind::PortZone(port)
                    if port.port_tile == tile
                        || port.zone.target_tile == Some(tile)
                        || port.zone.active_tile == Some(tile) =>
                {
                    Some(ordinal)
                }
                _ => None,
            });
    }
    let ordinal = map[tile]
        .owner_nation
        .map(TileOwnerTag::get)?
        .checked_sub(0x17)?;
    let ordinal = usize::from(ordinal);
    matches!(ocean.zones.get(ordinal), Some(ZoneKind::Zone(_))).then_some(ordinal)
}

pub(super) fn map_dto(map: &MapMgr, view_origin: TileId) -> LegacyMapState {
    LegacyMapState {
        view_origin_tile: view_origin.get() as i16,
        map_data_ready: u8::from(map.map_data_ready),
        recruit_search_active: u8::from(map.recruit_search_active),
        city_score_total: map.city_score_total,
        scenario_tag: map.scenario_tag.clone(),
        no_horizontal_wrap: u8::from(!map.topology.wraps_horizontally()),
        tiles: map.tiles.iter().map(tile_dto).collect(),
        provinces: map.provinces.as_array().iter().map(province_dto).collect(),
        pending_river_mouth_tile: option_i16(map.pending_river_mouth_tile.map(TileId::get)),
    }
}

fn tile_dto(tile: &TileState) -> LegacyTerrainTile {
    let mut visibility = 0_u8;
    for slot in 0..MAJOR_NATION_COUNT {
        if tile.development.resource_visible_to_majors[MajorNationId::new(slot as u8)] {
            visibility |= 1 << slot;
        }
    }
    LegacyTerrainTile {
        terrain_kind: tile.terrain.retail(),
        sprite_variant: tile.rendering.sprite_variant,
        river_sprite: tile
            .rendering
            .river_sprite
            .map(RiverSprite::retail)
            .unwrap_or(0),
        owner_nation: option_i8(tile.owner_nation.map(TileOwnerTag::get)),
        former_owner_nation: option_i8(tile.former_owner_nation.map(TileOwnerTag::get)),
        secondary_owner_nation: option_i8(tile.secondary_owner_nation.map(MajorNationId::get)),
        owner_border_mask: tile.owner_border_mask,
        city_border_mask: tile.city_border_mask,
        water_adjacency_mask: tile.water_adjacency_mask,
        region: option_i8(tile.region.map(RegionId::get)),
        adjacency_bits: tile.transport_links.bits(),
        adjacency_mask_a: tile.rendering.transition_mask,
        adjacency_mask_b: tile.rendering.coast_or_secondary_mask,
        city_record_index: option_i16(tile.province.map(ProvinceId::get)),
        development_classes: (tile.development.surface.get()
            | (tile.development.extractive.get() << 4)) as i8,
        pending_development_visibility: visibility,
        recruit_search_visited: tile.recruit_search_visited,
        per_tile_visited: tile.per_tile_visited,
        marker_slot_index: tile.marker_slot_index,
        edge_resources: tile
            .edge_resources
            .map(|resource| option_i8(resource.map(|kind| kind as u8))),
        gate: tile.gate,
        rail_flags: tile.pending_rail_links.bits(),
        action_state: tile
            .action
            .map(|action| action.retail() as i8)
            .unwrap_or(-1),
        tile_action_ordinal: tile.tile_action_ordinal,
        active_flags: tile.flags.bits(),
    }
}

fn province_dto(province: &ProvinceState) -> LegacyProvince {
    let mut adjacent_region_ids = [-1_i16; 12];
    let mut adjacent_region_anchor_tiles = [-1_i16; 12];
    for (index, (id, tile)) in province
        .adjacency()
        .iter()
        .zip(province.adjacency_anchor_tiles.iter())
        .enumerate()
    {
        adjacent_region_ids[index] = id.get() as i16;
        adjacent_region_anchor_tiles[index] = tile.get() as i16;
    }
    let mut linked_tile_indices = [-1_i16; 32];
    for (index, tile) in province.linked_tiles.iter().enumerate() {
        linked_tile_indices[index] = tile.get() as i16;
    }
    let resource_development_by_type = std::array::from_fn(|offset| {
        let resource = ResourceKind::from_index((ResourceKind::Food as usize + offset) as u8)
            .expect("province resource-development table spans food through arms");
        province.resource_development_by_type()[resource]
    });
    let mut explored_by_nation_mask = 0_u8;
    for slot in 0..MAJOR_NATION_COUNT {
        if province.explored_by_majors()[MajorNationId::new(slot as u8)] {
            explored_by_nation_mask |= 1 << slot;
        }
    }
    LegacyProvince {
        owner_nation: option_i8(province.owner().map(NationId::get)),
        former_owner_nation: option_i8(province.former_owner().map(NationId::get)),
        development_stage: province.development_stage(),
        fort_level: province.fort_level(),
        city_tile: option_i16(province.city_tile().map(TileId::get)),
        last_turn_tick: province.last_turn_tick,
        adjacent_region_count: province.adjacency().len() as i8,
        adjacent_region_ids,
        adjacent_region_anchor_tiles,
        linked_region_count: province.linked_tiles.len() as i8,
        secondary_neighbor_tile: option_i16(province.secondary_neighbor_tile.map(TileId::get)),
        primary_neighbor_tile: option_i16(province.primary_neighbor_tile.map(TileId::get)),
        linked_tile_indices,
        resource_development_by_type,
        city_score: province.city_score(),
        navy_order_reachable: u8::from(province.navy_order_reachable),
        explored_by_nation_mask,
        resource_presence_mask: province.resource_presence_mask,
        region_class: option_i8(province.region_class),
        name: province.name.clone(),
    }
}

pub(super) fn ocean_dto(ocean: &Ocean) -> LegacyOceanState {
    let mut zones = Vec::new();
    let mut port_zones = Vec::new();
    for (ordinal, zone) in ocean.zones.iter().enumerate() {
        match zone {
            ZoneKind::Zone(zone) => zones.push(zone_dto(zone, ordinal as i16)),
            ZoneKind::PortZone(port) => port_zones.push(LegacyPortZone {
                zone: zone_dto(&port.zone, ordinal as i16),
                port_tile_index: port.port_tile.get() as i16,
            }),
        }
    }
    LegacyOceanState {
        zones,
        port_zones,
        route_segments: ocean
            .routes
            .iter()
            .map(|route| {
                [
                    route.start_row,
                    route.start_column,
                    route.end_row,
                    route.end_column,
                ]
            })
            .collect(),
    }
}

fn zone_dto(zone: &Zone, ordinal: i16) -> LegacyZone {
    LegacyZone {
        display_name: zone.display_name.clone(),
        status_code: zone.status_code.unwrap_or(-1),
        tile_or_terrain_id: option_i32(zone.target_tile.map(TileId::get)),
        seed_nation_id: option_i16(zone.seed_owner.map(|tag| u16::from(tag.get()))),
        active_tile_index: option_i16(zone.active_tile.map(TileId::get)),
        context_ordinal: ordinal,
    }
}
