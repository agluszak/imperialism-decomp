use super::*;

/// Province adjacency lists used by the defend-province availability gate.
pub(super) fn build_province_adjacency(world: &MapMgr) -> Vec<Vec<ProvinceId>> {
    let province_count = world
        .tiles
        .iter()
        .filter_map(|tile| {
            tile.province
                .map(|province| usize::from(province.get()) + 1)
        })
        .max()
        .unwrap_or(0);
    let mut adjacency = vec![Vec::new(); province_count];
    let geometry = world.geometry();
    for (index, tile) in world.tiles.iter().enumerate() {
        let Some(province) = tile.province else {
            continue;
        };
        let province_index = usize::from(province.get());
        for neighbor in geometry
            .neighbors(TileId::new(index as u16))
            .into_iter()
            .flatten()
        {
            let Some(neighbor_province) = world[neighbor].province else {
                continue;
            };
            if neighbor_province == province {
                continue;
            }
            if !adjacency[province_index].contains(&neighbor_province) {
                adjacency[province_index].push(neighbor_province);
            }
        }
    }
    adjacency
}

fn build_province_adjacency_anchors(
    world: &MapMgr,
    province: ProvinceId,
    adjacency: &[ProvinceId],
) -> Vec<TileId> {
    let mut anchors = vec![None; adjacency.len()];
    let geometry = world.geometry();
    for (index, tile) in world.tiles.iter().enumerate() {
        if tile.province != Some(province) {
            continue;
        }
        for neighbor in geometry
            .neighbors(TileId::new(index as u16))
            .into_iter()
            .flatten()
        {
            let Some(neighbor_province) = world[neighbor].province else {
                continue;
            };
            if let Some(position) = adjacency
                .iter()
                .position(|&adjacent| adjacent == neighbor_province)
                && anchors[position].is_none()
            {
                anchors[position] = Some(neighbor);
            }
        }
    }
    anchors
        .into_iter()
        .map(|anchor| anchor.expect("generated adjacency retains its anchor tile"))
        .collect()
}
/// Materializes the fixed province table and each country's ordered region list.
/// Generated province IDs are already compact and are visited in ascending retail
/// table order, matching the append order used by map setup.
pub(super) fn build_province_state(
    map: &GeneratedMap,
    world: &MapMgr,
    province_capitals: &[Option<TileId>],
    resource_presence_masks: &[i8],
    nations: &mut Nations,
) -> ProvinceTable<ProvinceState> {
    let adjacency = build_province_adjacency(world);
    let mut provinces = ProvinceTable::default();
    for (index, generated) in map.provinces().iter().enumerate() {
        let province = ProvinceId::new(index as u16);
        let owner = generated
            .owner
            .nation()
            .expect("accepted generated provinces have nation owners");
        let fort_level = province_capitals[index]
            .is_some_and(|capital| {
                world[capital]
                    .flags
                    .contains(TileFlags::PROVINCE_CAPITAL_FORTIFICATION)
            })
            .into();
        let linked_tiles = world
            .tiles
            .iter()
            .enumerate()
            .filter_map(|(tile, state)| {
                (state.terrain != TerrainKind::Water && state.province == Some(province))
                    .then_some(TileId::new(tile as u16))
            })
            .collect::<Vec<_>>();
        let last_turn_tick = if linked_tiles.iter().any(|&tile| {
            world[tile].flags.contains(TileFlags::PROVINCE_ANCHOR_STATE)
                && world[tile].region.is_some()
        }) {
            0
        } else {
            999
        };
        let adjacency_anchor_tiles =
            build_province_adjacency_anchors(world, province, &adjacency[index]);
        let (primary_neighbor_tile, secondary_neighbor_tile) = world.province_neighbor_links(
            province,
            province_capitals[index].expect("generated province has a fallback capital"),
        );
        provinces[province] = ProvinceState::new(
            Some(owner),
            Some(owner),
            0,
            adjacency[index].clone(),
            adjacency_anchor_tiles,
            Some(generated.region_class),
            fort_level,
            province_capitals[index],
            last_turn_tick,
            Some(secondary_neighbor_tile),
            Some(primary_neighbor_tile),
            linked_tiles,
            ResourceTable::default(),
            MajorNationTable::default(),
            0,
            false,
            resource_presence_masks[index],
            String::new(),
        );
        nations.append_owned_region_during_construction(owner, province);
    }
    provinces
}
/// `IsNodeTypeLinkUnavailableAndNoActiveMapActionContext` for Accept-time owned provinces.
///
/// Without the sea-zone secondary-neighbor graph, coastal isolation falls back to "has any
/// adjacent province". The second-degree retail quirk (owned province with a neighbor that
/// itself has neighbors) is preserved.
pub(super) fn province_mission_available(
    province: ProvinceId,
    nation: TileOwnerTag,
    world: &MapMgr,
    province_capitals: &[Option<TileId>],
    adjacency: &[Vec<ProvinceId>],
) -> bool {
    let province_usize = usize::from(province.get());
    let neighbors = &adjacency[province_usize];
    for &adjacent in neighbors {
        let Some(capital) = province_capitals[usize::from(adjacent.get())] else {
            continue;
        };
        if world[capital].owner_nation == Some(nation) {
            return true;
        }
    }
    // CollectSecondDegreeLinksMatchingNodeType: if this owned province has any neighbor that
    // itself has neighbors, treat as available.
    if !neighbors.is_empty() {
        for &adjacent in neighbors {
            if !adjacency[usize::from(adjacent.get())].is_empty() {
                return true;
            }
        }
    }
    false
}
/// `TAutoGreatPower::QueueMapActionMissionsForPortZoneCandidates`.
pub(super) fn queue_map_action_missions_for_port_zone_candidates(
    world: &MapMgr,
    province_capitals: &[Option<TileId>],
    adjacency: &[Vec<ProvinceId>],
    ports: &PortZoneTable,
    nation: MajorNationId,
) -> Vec<MissionState> {
    let owner = TileOwnerTag::from_nation(nation.nation());
    let owned = owned_province_ids(world, province_capitals, owner);
    let mut missions = Vec::new();

    for &province in &owned {
        if !province_mission_available(province, owner, world, province_capitals, adjacency) {
            continue;
        }
        missions.push(mission_state(
            nation,
            MissionData::DefendProvince {
                province,
                army: ArmyMissionState {
                    required_equipage_bits: [0; 5],
                    units: Vec::new(),
                },
            },
            0,
        ));
    }

    let Some(port) = ports.find_first_port_for_nation(world, nation.nation()) else {
        return missions;
    };
    let Some(sea_or_neighbor) = port.primary_neighbor else {
        return missions;
    };

    // Factory: zone != nation's first port → ControlSeaZone; port itself → Escort.
    missions.push(mission_state(
        nation,
        MissionData::ControlSeaZone(empty_navy_mission(Some(sea_or_neighbor), None)),
        0,
    ));
    missions.push(mission_state(
        nation,
        MissionData::Escort(empty_navy_mission(Some(port.ordinal), Some(port.ordinal))),
        0,
    ));
    missions.push(mission_state(
        nation,
        MissionData::ScatteredShips(empty_navy_mission(None, None)),
        SCATTERED_SHIPS_IMPORTANCE_BITS,
    ));
    missions
}
pub(super) fn initialize_ai_targets(
    nations: &mut Nations,
    mission_queues: &MajorNationTable<Vec<MissionState>>,
    live_zone_count: u16,
) {
    for nation in (0..MajorNationId::COUNT).map(MajorNationId::new) {
        let economy = &mut nations.major_mut(nation).economy;
        let Some(zone_targets) = economy.ai_zone_targets.as_mut() else {
            continue;
        };
        zone_targets.resize(usize::from(live_zone_count), AiTargetState::Unmarked);
        for mission in &mission_queues[nation] {
            let target = match &mission.data {
                MissionData::ControlSeaZone(navy) | MissionData::Escort(navy) => navy.target_zone,
                _ => None,
            };
            if let Some(target) = target {
                zone_targets[usize::from(target.get())] = AiTargetState::MissionQueued;
            }
            if let MissionData::DefendProvince { province, .. } = &mission.data {
                economy
                    .ai_province_targets
                    .as_mut()
                    .expect("AI nation has province target state")[*province] =
                    AiTargetState::MissionQueued;
            }
        }
    }
}
pub(super) fn empty_navy_mission(
    target_zone: Option<OceanZoneId>,
    resolved_port_zone: Option<OceanZoneId>,
) -> NavyMissionState {
    NavyMissionState {
        target_zone,
        resolved_port_zone,
        selected_ship: None,
        task_force: None,
        state: 0,
        required_equipage_bits: [0; 4],
        ships: Vec::new(),
    }
}
pub(super) fn mission_state(
    nation: MajorNationId,
    data: MissionData,
    importance_bits: u32,
) -> MissionState {
    MissionState {
        nation: nation.nation(),
        data,
        path_nation: None,
        state: 2,
        importance_bits,
        held: false,
        marker: 0,
    }
}
pub(super) fn flatten_mission_queues(
    queues: &mut MajorNationTable<Vec<MissionState>>,
) -> Vec<MissionState> {
    let mut missions = Vec::new();
    for nation in (0..MajorNationId::COUNT).map(MajorNationId::new) {
        missions.append(&mut queues[nation]);
    }
    missions
}
