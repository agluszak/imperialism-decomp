//! First-turn civilian planning (`TSimMgr` phase 9).

use crate::*;

const TRANSPORT_NODE_FLAG: u16 = 0x10;
const DEPOT_SOURCE_FLAG: u16 = 0x04;
const FORT_BUILD_COST: [i32; 3] = [5_000, 7_500, 10_000];

#[derive(Clone, Copy, Debug)]
enum PlannedCivilianAssignment {
    LayRail {
        unit_index: usize,
        destination: TileId,
        segment: RailSegment,
    },
    BuildFort {
        unit_index: usize,
        destination: TileId,
    },
}

#[derive(Clone, Debug)]
struct AutomatedCivilianPlan {
    nation: MajorNationId,
    town_transport_linked: Vec<bool>,
    refresh_city_summary: bool,
    railhead_target: Option<TileId>,
    gold_priority: i16,
    assignment: PlannedCivilianAssignment,
}

#[derive(Debug)]
pub(crate) struct CivilianPhasePlan {
    automated: Vec<AutomatedCivilianPlan>,
}

impl GameState {
    /// Rebuilds one major nation's transportable resource supply from its
    /// currently linked city territory.
    ///
    /// Retail invokes this immediately before opening the Transport screen and
    /// again from city/transport turn resolution. Targets that no longer fit
    /// the rebuilt supply are reduced through the same reserved-capacity seam
    /// used by player allocation.
    pub fn rebuild_nation_resource_yields(&mut self, nation: MajorNationId) {
        let (_transport_influence, town_transport_linked) = self
            .transport_influence(nation)
            .expect("resource-yield rebuild requires the nation's home town marker");

        let mut influence = vec![0_u8; STRATEGIC_TILE_COUNT];
        let major = &self.nations.majors[nation];
        for (town, &linked) in major.towns.iter().zip(&town_transport_linked) {
            if !linked {
                continue;
            }
            let level = u8::from(town.enabled != 0) + 1;
            influence[usize::from(town.tile.get())] = level;
            let owner = Some(TileOwnerTag::from_nation(nation.nation()));
            for neighbor in self
                .map
                .geometry()
                .neighbors(town.tile)
                .into_iter()
                .flatten()
            {
                let tile = &self.map[neighbor];
                let entry = &mut influence[usize::from(neighbor.get())];
                if (tile.owner_nation == owner || tile.gate == 0) && *entry < level {
                    *entry = level;
                }
            }
        }

        let mut current = ResourceTable::<i16>::default();
        for (index, &level) in influence.iter().enumerate() {
            if level == 0 {
                continue;
            }
            let tile_id = TileId::new(index as u16);
            let tile = &self.map[tile_id];
            if tile.gate == 0 {
                if level == 2 {
                    current[ResourceKind::Fish] = current[ResourceKind::Fish].wrapping_add(1);
                }
                continue;
            }

            for resource in tile.edge_resources.into_iter().flatten() {
                let development = if matches!(
                    resource,
                    ResourceKind::Coal
                        | ResourceKind::Iron
                        | ResourceKind::Oil
                        | ResourceKind::Gems
                        | ResourceKind::Gold
                ) {
                    tile.development.extractive.get()
                } else {
                    tile.development.surface.get()
                };
                let contribution = resource_development_yield(resource, development);
                current[resource] = current[resource].wrapping_add(contribution);
            }

            if tile.river().is_some() && level == 2 {
                current[ResourceKind::Fish] = current[ResourceKind::Fish].wrapping_add(1);
            }
            if let Some(province) = tile.province
                && self.map.provinces[province].city_tile() == Some(tile_id)
            {
                for index in ResourceKind::Food as u8..=ResourceKind::Arms as u8 {
                    let resource = ResourceKind::from_index(index)
                        .expect("the manufactured resource range is semantic");
                    current[resource] = current[resource].wrapping_add(
                        self.map.provinces[province].resource_development_by_type()[resource],
                    );
                }
            }
        }

        let major = &mut self.nations.majors[nation];
        for (town, linked) in major.towns.iter_mut().zip(town_transport_linked) {
            town.transport_linked = linked;
        }
        major.economy.need_current_by_type = current;
        for resource in all_resources() {
            if major.economy.need_current_by_type[resource]
                < major.economy.need_target_by_type[resource]
            {
                major
                    .economy
                    .update_need_target(resource, major.economy.need_current_by_type[resource]);
            }
        }
        if major.kind == MajorNationKind::AutoGreatPower {
            let fish = major.economy.need_current_by_type[ResourceKind::Fish];
            major.economy.need_current_by_type[ResourceKind::Fish] = 0;
            major.economy.need_current_by_type[ResourceKind::Livestock] =
                major.economy.need_current_by_type[ResourceKind::Livestock].wrapping_add(fish);
        }
    }

    /// Builds the recovered Easy beginning-save civilian plan, or `None` for unrecovered branches.
    pub(crate) fn try_first_turn_civilian_phase(&self) -> Option<CivilianPhasePlan> {
        self.first_turn_civilian_plan()
    }

    /// Applies a previously validated civilian plan. The dispatcher owns phase advancement.
    pub(crate) fn apply_civilian_phase_plan(&mut self, plan: CivilianPhasePlan) {
        for plan in plan.automated {
            {
                let major = self.nations.major_mut(plan.nation);
                assert_eq!(
                    major.towns.len(),
                    plan.town_transport_linked.len(),
                    "civilian preflight preserves the ordered town list"
                );
                for (town, linked) in major.towns.iter_mut().zip(plan.town_transport_linked) {
                    town.transport_linked = linked;
                }
                major.economy.interior_civilian.railhead_target = plan.railhead_target;
                major
                    .economy
                    .interior_civilian
                    .railhead_priority_by_resource[ResourceKind::Gold] = plan.gold_priority;
                if plan.refresh_city_summary {
                    let quantity = major.city.orders.population_growth.quantity;
                    major.city.refresh_unreserved_city_needs(quantity);
                }
            }

            match plan.assignment {
                PlannedCivilianAssignment::LayRail {
                    unit_index,
                    destination,
                    segment,
                } => {
                    let unit = &mut self.civilian_units[unit_index];
                    unit.location = CivilianLocation::OnMap(destination);
                    unit.order = CivilianWorkOrder::LayRail {
                        segment,
                        turns: TurnsRemaining::try_new(1).expect("one turn is positive"),
                    };
                }
                PlannedCivilianAssignment::BuildFort {
                    unit_index,
                    destination,
                } => {
                    let unit = &mut self.civilian_units[unit_index];
                    unit.location = CivilianLocation::OnMap(destination);
                    unit.order = CivilianWorkOrder::BuildFort {
                        turns: TurnsRemaining::try_new(4).expect("four turns are positive"),
                    };
                }
            }
        }
    }

    fn first_turn_civilian_plan(&self) -> Option<CivilianPhasePlan> {
        let active = MajorNationId::from_nation(self.turn.active_nation)?;
        if self.turn.phase != PhaseCode::OFFER_SHEET
            || self.turn.economic_turn != 1
            || self.turn.difficulty != Difficulty::Easy
            || self.turn.scenario_map.is_some()
            || self.turn.selected_nation != self.turn.active_nation
            || self.map.topology != MapTopology::Wrapping
            // Sea reachability consults active type-3/4 naval orders. With no
            // ships, its runtime nation mask is exactly empty.
            || !self.ships.is_empty()
            || NationId::all().any(|nation| {
                !matches!(
                    self.nations.common(nation),
                    Some(common) if common.status() == CountryStatus::Independent
                ) || NationId::all().any(|target| {
                    self.diplomacy.relationships[nation][target] != DiplomaticRelationship::Peace
                })
            })
        {
            return None;
        }

        let mut engineer_by_nation = MajorNationTable::from_fn(|_| None);
        let mut count_by_nation = MajorNationTable::from_fn(|_| 0_u8);
        for (unit_index, unit) in self.civilian_units.iter().enumerate() {
            let nation = MajorNationId::from_nation(unit.nation)?;
            if unit.owner_nation != unit.nation
                || unit.registered
                || !matches!(unit.location, CivilianLocation::OnMap(_))
                || unit.order != CivilianWorkOrder::Idle
            {
                return None;
            }
            let expected = match count_by_nation[nation] {
                0 => CivilianUnitKind::Prospector,
                1 => CivilianUnitKind::Engineer,
                _ => return None,
            };
            if unit.unit_type != expected {
                return None;
            }
            if expected == CivilianUnitKind::Engineer {
                engineer_by_nation[nation] = Some(unit_index);
            }
            count_by_nation[nation] += 1;
        }

        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            let major = self.nations.major(nation);
            let interior = &major.economy.interior_civilian;
            let home_town = major.towns.first();
            if major.economy.controller.is_human() != (nation == active)
                || home_town.is_none()
                || major.common.home_tile != home_town.map(|town| town.tile)
                || count_by_nation[nation] != 2
                || engineer_by_nation[nation].is_none()
                || interior.pending_recruitment.is_some()
                || interior.railhead_target.is_some()
                || !resource_table_is_zero(&interior.resource_order_metrics)
                || !resource_table_is_zero(&interior.railhead_priority_by_resource)
                || !resource_table_is_zero(&interior.exterior_need_by_resource)
                || !resource_table_is_zero(&interior.historical_need_by_resource)
                || !resource_table_is_zero(&interior.civilian_order_demand_by_resource)
                || (nation == active && major.economy.ai_development_pressure.is_some())
                || (nation != active && major.economy.ai_development_pressure.is_none())
            {
                return None;
            }
        }

        let mut automated = Vec::with_capacity(usize::from(MajorNationId::COUNT - 1));
        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            if nation == active {
                continue;
            }
            automated.push(self.plan_automated_civilians(nation, engineer_by_nation[nation]?)?);
        }
        Some(CivilianPhasePlan { automated })
    }

    fn plan_automated_civilians(
        &self,
        nation: MajorNationId,
        engineer_index: usize,
    ) -> Option<AutomatedCivilianPlan> {
        let major = self.nations.major(nation);
        let home_tile = major.common.home_tile?;
        let home_town = major.towns.iter().position(|town| town.tile == home_tile)?;
        let owned_tiles = self.owned_tiles(nation);
        if owned_tiles.is_empty() || !owned_tiles.contains(&home_tile) {
            return None;
        }

        let (transport_influence, town_transport_linked) = self.transport_influence(nation)?;
        // Otherwise `SeekLostTowns` selects a separate continuation branch.
        if !town_transport_linked[home_town] {
            return None;
        }

        let technology = self.technology.city_capabilities_by_nation[nation];
        let primary_distance = self.distance_map(
            nation,
            &owned_tiles,
            technology.primary_civilian_distance_terrain,
            |tile| transport_influence[usize::from(tile.get())] != 0,
        );
        let secondary_terrain = technology.secondary_civilian_distance_terrain();
        let secondary_distance =
            self.distance_map(nation, &owned_tiles, secondary_terrain, |tile| {
                self.map[tile].region.is_none()
                    && terrain_is_allowed(self.map[tile].terrain, secondary_terrain)
                    && self.has_reachable_sea_outside_beginning_turn_mask(tile)
            });

        // With every persistent demand table zero, `SeekResources` clears no
        // additional state and installs only retail's unconditional gold weight.
        let mut priorities = ResourceTable::<i16>::default();
        priorities[ResourceKind::Gold] = 2;
        let (railhead_target, refresh_city_summary) = self.select_railhead_target(
            nation,
            &owned_tiles,
            &primary_distance,
            &secondary_distance,
            &priorities,
        )?;

        if let Some(target) = railhead_target {
            let (source, destination) =
                self.trace_supported_rail_segment(target, &primary_distance, &secondary_distance)?;
            let segment = RailSegment::between(self.map.topology, source, destination)?;
            return Some(AutomatedCivilianPlan {
                nation,
                town_transport_linked,
                refresh_city_summary,
                railhead_target: Some(target),
                gold_priority: 2,
                assignment: PlannedCivilianAssignment::LayRail {
                    unit_index: engineer_index,
                    destination,
                    segment,
                },
            });
        }

        let destination = self.select_fort_destination(nation, engineer_index)?;
        Some(AutomatedCivilianPlan {
            nation,
            town_transport_linked,
            refresh_city_summary,
            railhead_target: None,
            gold_priority: 0,
            assignment: PlannedCivilianAssignment::BuildFort {
                unit_index: engineer_index,
                destination,
            },
        })
    }

    fn owned_tiles(&self, nation: MajorNationId) -> Vec<TileId> {
        let owner = Some(TileOwnerTag::from_nation(nation.nation()));
        (0..STRATEGIC_TILE_COUNT)
            .map(|index| TileId::new(index as u16))
            .filter(|tile| self.map[*tile].owner_nation == owner)
            .collect()
    }

    /// Retail `TGreatPower::BuildTransportLinkedInfluenceMap` over the complete
    /// ordered `townMarkerList`.
    fn transport_influence(&self, nation: MajorNationId) -> Option<(Vec<u8>, Vec<bool>)> {
        let major = self.nations.major(nation);
        let home_tile = major.common.home_tile?;
        let home_town = major.towns.iter().position(|town| town.tile == home_tile)?;
        let unblocked_ports = major
            .towns
            .iter()
            .map(|town| {
                town.enabled != 0 && self.has_reachable_sea_outside_beginning_turn_mask(town.tile)
            })
            .collect::<Vec<_>>();
        let mut influence = vec![0_u8; STRATEGIC_TILE_COUNT];

        let mut home_linked = unblocked_ports[home_town];
        if !home_linked {
            self.mark_transport_component(nation, home_tile, &mut influence);
            for (town, &unblocked_port) in major.towns.iter().zip(&unblocked_ports) {
                if influence[usize::from(town.tile.get())] != 0 && unblocked_port {
                    home_linked = true;
                    break;
                }
            }
        }

        for (town, &unblocked_port) in major.towns.iter().zip(&unblocked_ports) {
            if unblocked_port
                && home_linked
                && town.active
                && influence[usize::from(town.tile.get())] == 0
            {
                self.mark_transport_component(nation, town.tile, &mut influence);
            }
        }

        let linked = major
            .towns
            .iter()
            .zip(&unblocked_ports)
            .map(|(town, &unblocked_port)| {
                !((influence[usize::from(town.tile.get())] == 0 || !town.active)
                    && (!unblocked_port || !home_linked))
            })
            .collect::<Vec<_>>();

        if home_linked {
            for (town, &unblocked_port) in major.towns.iter().zip(&unblocked_ports) {
                if unblocked_port {
                    influence[usize::from(town.tile.get())] = 1;
                }
            }
        }
        Some((influence, linked))
    }

    fn mark_transport_component(&self, nation: MajorNationId, start: TileId, influence: &mut [u8]) {
        let owner = Some(TileOwnerTag::from_nation(nation.nation()));
        let geometry = self.map.geometry();
        let mut pending = vec![start];
        while let Some(tile) = pending.pop() {
            let index = usize::from(tile.get());
            if influence[index] != 0 {
                continue;
            }
            influence[index] = 1;
            for direction in HexDirection::ALL.into_iter().rev() {
                if !self.map[tile]
                    .transport_links
                    .contains(TileTransportLinks::for_direction(direction))
                {
                    continue;
                }
                if let Some(neighbor) = geometry.neighbor(tile, direction)
                    && influence[usize::from(neighbor.get())] == 0
                    && self.map[neighbor].owner_nation == owner
                {
                    pending.push(neighbor);
                }
            }
        }
    }

    /// Retail fills these maps by repeated ascending scans. Writes made earlier
    /// in a scan are visible later in that same scan; established distances are
    /// never relaxed.
    fn distance_map(
        &self,
        _nation: MajorNationId,
        owned_tiles: &[TileId],
        terrain_access: CivilianTerrainAccess,
        mut is_seed: impl FnMut(TileId) -> bool,
    ) -> Vec<u8> {
        let mut distance = vec![0_u8; STRATEGIC_TILE_COUNT];
        for &tile in owned_tiles {
            if is_seed(tile) {
                distance[usize::from(tile.get())] = 1;
            }
        }

        let geometry = self.map.geometry();
        loop {
            let mut changed = false;
            for &tile in owned_tiles {
                let index = usize::from(tile.get());
                if distance[index] != 0
                    || !terrain_is_allowed(self.map[tile].terrain, terrain_access)
                {
                    continue;
                }
                let mut best_neighbor = 0_u8;
                for direction in HexDirection::ALL {
                    let Some(neighbor) = geometry.neighbor(tile, direction) else {
                        continue;
                    };
                    let candidate = distance[usize::from(neighbor.get())];
                    if candidate != 0 && (best_neighbor == 0 || candidate < best_neighbor) {
                        best_neighbor = candidate;
                    }
                }
                if best_neighbor != 0 {
                    distance[index] = best_neighbor.wrapping_add(1);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        distance
    }

    fn select_railhead_target(
        &self,
        nation: MajorNationId,
        owned_tiles: &[TileId],
        primary_distance: &[u8],
        secondary_distance: &[u8],
        priorities: &ResourceTable<i16>,
    ) -> Option<(Option<TileId>, bool)> {
        let geometry = self.map.geometry();
        let mut candidates = Vec::new();
        for &tile in owned_tiles {
            let index = usize::from(tile.get());
            if self.map[tile].region.is_some()
                || !((primary_distance[index] > 0 && primary_distance[index] < 9)
                    || self.can_build_port_at(tile)
                    || (secondary_distance[index] > 2 && secondary_distance[index] < 6))
                || HexDirection::ALL.into_iter().any(|direction| {
                    geometry.neighbor(tile, direction).is_some_and(|neighbor| {
                        self.map[neighbor].flags.bits() & TRANSPORT_NODE_FLAG != 0
                    })
                })
            {
                continue;
            }
            let yields = self.projected_town_resources(nation, tile)?;
            if yields[ResourceKind::Gold] != 0 {
                candidates.push((tile, yields));
            }
        }

        if candidates.is_empty() {
            return Some((None, false));
        }

        let major = self.nations.major(nation);
        let mut city = major.city.clone();
        let supported = city.orders.population_growth.quantity;
        let summary = *city.refresh_unreserved_city_needs(supported);
        let mut best_tile = None;
        let mut best_score = -1_i16;
        for (tile, yields) in candidates {
            let score = evaluate_projected_resources(
                &yields,
                priorities,
                &summary,
                &major.economy.need_current_by_type,
            );
            if score > best_score {
                best_score = score;
                best_tile = Some(tile);
            }
        }
        Some((best_tile, true))
    }

    /// `TTown::CalculateResources` for the transient enabled town used by
    /// `StartRailheadProject` and `EvaluateResources`.
    fn projected_town_resources(
        &self,
        nation: MajorNationId,
        town: TileId,
    ) -> Option<ResourceTable<i16>> {
        let owner = Some(TileOwnerTag::from_nation(nation.nation()));
        let town_region = self.map[town].region;
        let geometry = self.map.geometry();
        let mut yields = ResourceTable::<i16>::default();

        for harvest_tile in HexDirection::ALL
            .into_iter()
            .filter_map(|direction| geometry.neighbor(town, direction))
            .chain(std::iter::once(town))
        {
            let tile = &self.map[harvest_tile];
            if tile.owner_nation != owner || (tile.region != town_region && tile.region.is_some()) {
                continue;
            }

            for resource in tile.edge_resources.into_iter().flatten() {
                let extraction = matches!(
                    resource,
                    ResourceKind::Coal
                        | ResourceKind::Iron
                        | ResourceKind::Oil
                        | ResourceKind::Gems
                        | ResourceKind::Gold
                );
                let mut level = if extraction {
                    tile.development.extractive.get()
                } else {
                    tile.development.surface.get()
                };
                if extraction && level == 0 {
                    level = 1;
                }
                let value = resource_development_yield(resource, level);
                yields[resource] = yields[resource].wrapping_add(value);
            }

            // `AddAdjacentCityDevelopment` changes only manufactured yields.
            // They do not enter this phase's candidate predicate or score, but
            // retaining them keeps the transient town calculation complete.
            if let Some(province) = tile.province
                && self.map.provinces[province].city_tile() == Some(harvest_tile)
            {
                for index in ResourceKind::Food as u8..=ResourceKind::Arms as u8 {
                    let resource = ResourceKind::from_index(index)
                        .expect("the manufactured resource range is semantic");
                    yields[resource] = yields[resource].wrapping_add(
                        self.map.provinces[province].resource_development_by_type()[resource],
                    );
                }
            }
        }
        Some(yields)
    }

    /// Accepts only the observed primary-gradient `LayRail` continuation. Port
    /// and depot construction remain explicit unsupported branches.
    fn trace_supported_rail_segment(
        &self,
        target: TileId,
        primary_distance: &[u8],
        secondary_distance: &[u8],
    ) -> Option<(TileId, TileId)> {
        let index = usize::from(target.get());
        let primary = primary_distance[index];
        let can_build_port = self.can_build_port_at(target);

        if (primary == 0 || primary > 9) && !can_build_port {
            // Retail would trace the secondary map and try `BuildPort`.
            let _secondary = secondary_distance[index];
            return None;
        }
        if primary == 1 || (can_build_port && (primary == 0 || primary > 6)) {
            // Retail would build a depot or port directly at the target.
            return None;
        }

        let (source, previous) = self.trace_descending_gradient(target, primary_distance)?;
        let source_flags = self.map[source].flags.bits();
        if source_flags & DEPOT_SOURCE_FLAG != 0 && source_flags & TRANSPORT_NODE_FLAG == 0 {
            // Retail selects `BuildDepot` at this source.
            return None;
        }
        Some((source, previous))
    }

    fn trace_descending_gradient(
        &self,
        start: TileId,
        distance: &[u8],
    ) -> Option<(TileId, TileId)> {
        let geometry = self.map.geometry();
        let mut current = start;
        let mut previous = start;
        let mut score = distance[usize::from(current.get())];
        if score == 0 {
            return None;
        }
        while score != 1 {
            let desired = score.wrapping_sub(1);
            let next = HexDirection::ALL.into_iter().find_map(|direction| {
                let neighbor = geometry.neighbor(current, direction)?;
                (distance[usize::from(neighbor.get())] == desired).then_some(neighbor)
            })?;
            previous = current;
            current = next;
            score = desired;
        }
        Some((current, previous))
    }

    fn select_fort_destination(
        &self,
        nation: MajorNationId,
        engineer_index: usize,
    ) -> Option<TileId> {
        let major = self.nations.major(nation);
        let pressure = major.economy.ai_development_pressure?;
        let expansion = pressure.expansion_pressure_per_compatible_region();
        let mut average = pressure.average_unit_divergence_per_owned_region();
        // With zero expansion pressure and no war relationships (phase guard),
        // the unrecovered map-action compatibility predicate cannot affect the
        // score or the selected province.
        if expansion != 0.0 || !average.is_finite() {
            return None;
        }
        if average <= 0.0 {
            average = 1.0;
        }

        let fort_cap = self.technology.city_capabilities_by_nation[nation]
            .fort_level_cap
            .get();
        let mut best = None;
        let mut best_score = -1.0_f32;
        for &province_id in major.common.owned_regions() {
            let province = &self.map.provinces[province_id];
            if province.owner() != Some(nation.nation()) || province.fort_level() >= fort_cap {
                continue;
            }
            let mut city_score = province.city_score() as f32;
            if !province.adjacency().is_empty() {
                let same_owner = province
                    .adjacency()
                    .iter()
                    .filter(|adjacent| {
                        self.map.provinces[**adjacent].owner() == Some(nation.nation())
                    })
                    .count();
                city_score *= same_owner as f32 / province.adjacency().len() as f32 - (-1.0_f32);
            }
            let score = city_score / 5_000.0_f32 * average;
            if best.is_none() || score > best_score {
                best = Some(province_id);
                best_score = score;
            }
        }

        let province_id = best?;
        let province = &self.map.provinces[province_id];
        let fort_level = usize::try_from(province.fort_level()).ok()?;
        let cost = *FORT_BUILD_COST.get(fort_level)?;
        let destination = province.city_tile()?;
        if major.common.treasury < cost
            || self.map[destination].province != Some(province_id)
            || self.map[destination].owner_nation
                != Some(TileOwnerTag::from_nation(nation.nation()))
            || self.civilian_units.iter().enumerate().any(|(index, unit)| {
                index != engineer_index && unit.location == CivilianLocation::OnMap(destination)
            })
        {
            return None;
        }
        Some(destination)
    }

    fn has_reachable_sea_outside_beginning_turn_mask(&self, tile: TileId) -> bool {
        let origin_nation = self.map[tile]
            .owner_nation
            .and_then(TileOwnerTag::nation)
            .expect("a town marker must remain on nation-owned territory");
        for direction in HexDirection::ALL {
            let neighbor = civilian_sea_scan_neighbor(tile, direction);
            if self.map[neighbor].terrain == TerrainKind::Water {
                return self.sea_zone_allows_port_access(neighbor, origin_nation);
            }
        }
        if self.map[tile].river().is_none()
            || !river_reaches_sea_without_crossing_nation(&self.map, tile)
        {
            return false;
        }
        let sea_tile = trace_terrain_flow_to_nearest_sea_tile(&self.map, tile)
            .expect("a boundary-safe retail terrain flow must terminate at sea");
        self.sea_zone_allows_port_access(sea_tile, origin_nation)
    }

    /// `TZone::HasDiplomaticallyRelatedNationInActiveType3Or4OrderMask`.
    fn sea_zone_allows_port_access(&self, sea_tile: TileId, origin_nation: NationId) -> bool {
        const SEA_OWNER_BIAS: u8 = 0x17;

        let owner = self.map[sea_tile]
            .owner_nation
            .expect("reachable sea tile must name its ocean context")
            .get();
        let zone = OceanZoneId::new(u16::from(
            owner
                .checked_sub(SEA_OWNER_BIAS)
                .expect("sea owner tag must name a base ocean zone"),
        ));
        let mut active_nations = 0_u32;
        for ship in &self.ships {
            if ship.location != zone {
                continue;
            }
            let Some(task_force) = ship.task_force else {
                continue;
            };
            let task_force = &self.task_forces
                [usize::try_from(task_force.get()).expect("task-force ordinal fits this process")];
            if !task_force.defeated && matches!(task_force.order, 3 | 4) {
                active_nations |= 1_u32 << ship.nation.get();
            }
        }

        let origin_bit = 1_u32 << origin_nation.get();
        if active_nations & origin_bit != 0 {
            return true;
        }
        for candidate in (0..MajorNationId::COUNT).map(NationId::new) {
            if active_nations & (1_u32 << candidate.get()) == 0 {
                continue;
            }
            if self.diplomacy.relationships[candidate][origin_nation] == DiplomaticRelationship::War
                && self.diplomacy.relationship_turns[candidate][origin_nation]
                    .is_none_or(|turn| i32::from(turn) != self.turn.economic_turn)
            {
                return false;
            }
        }
        true
    }

    fn can_build_port_at(&self, tile: TileId) -> bool {
        if !matches!(
            self.map[tile].terrain,
            TerrainKind::Mountain | TerrainKind::Hills
        ) && HexDirection::ALL.into_iter().any(|direction| {
            self.map[civilian_sea_scan_neighbor(tile, direction)].terrain == TerrainKind::Water
        }) {
            return true;
        }
        self.map[tile].river().is_some()
            && river_reaches_sea_without_crossing_nation(&self.map, tile)
    }
}

fn resource_table_is_zero(table: &ResourceTable<i16>) -> bool {
    all_resources().all(|resource| table[resource] == 0)
}

fn terrain_is_allowed(terrain: TerrainKind, access: CivilianTerrainAccess) -> bool {
    match terrain {
        TerrainKind::Plains | TerrainKind::Forest | TerrainKind::Desert | TerrainKind::Farmland => {
            true
        }
        TerrainKind::Hills => access.hills,
        TerrainKind::Mountain => access.mountain,
        TerrainKind::Swamp => access.swamp,
        TerrainKind::Water => false,
    }
}

fn evaluate_projected_resources(
    yields: &ResourceTable<i16>,
    priorities: &ResourceTable<i16>,
    city_summary: &ResourceTable<i16>,
    need_current: &ResourceTable<i16>,
) -> i16 {
    let mut score = 0_i16;
    for index in ResourceKind::Cotton as u8..=ResourceKind::Oil as u8 {
        let resource = ResourceKind::from_index(index).expect("raw-resource range is semantic");
        score = score
            .wrapping_add((i32::from(yields[resource]) * i32::from(priorities[resource])) as i16);
    }

    let grain_shortage =
        city_summary[ResourceKind::Grain].wrapping_sub(need_current[ResourceKind::Grain]);
    if grain_shortage > 0 {
        score = score.wrapping_add(
            (i32::from(yields[ResourceKind::Grain]) * i32::from(grain_shortage)) as i16,
        );
    }
    let fruit_shortage =
        city_summary[ResourceKind::Fruit].wrapping_sub(need_current[ResourceKind::Fruit]);
    if fruit_shortage > 0 {
        score = score.wrapping_add(
            (i32::from(yields[ResourceKind::Fruit]) * i32::from(fruit_shortage)) as i16,
        );
    }
    let livestock_shortage = city_summary[ResourceKind::Livestock]
        .wrapping_sub(need_current[ResourceKind::Livestock])
        .wrapping_sub(need_current[ResourceKind::Fish]);
    if livestock_shortage > 0 {
        let yield_sum = yields[ResourceKind::Livestock].wrapping_add(yields[ResourceKind::Gems]);
        score = score.wrapping_add((i32::from(yield_sum) * i32::from(livestock_shortage)) as i16);
    }
    score
}

/// The port predicates inline a 217-wide doubled-column wrap and vertical
/// clamp instead of using the session topology helper.
fn civilian_sea_scan_neighbor(tile: TileId, direction: HexDirection) -> TileId {
    const COLUMN_X2_DELTAS: [i32; 6] = [1, 2, 1, -1, -2, -1];
    const ROW_DELTAS: [i32; 6] = [-1, 0, 1, 1, 0, -1];
    const RASTER_WIDTH: i32 = STRATEGIC_MAP_WIDTH as i32 * 2;

    let row = i32::from(tile.get() / STRATEGIC_MAP_WIDTH);
    let column = i32::from(tile.get() % STRATEGIC_MAP_WIDTH);
    let index = direction as usize;
    let mut column_x2 = row % 2 + column * 2 + COLUMN_X2_DELTAS[index];
    let row = (row + ROW_DELTAS[index]).clamp(0, i32::from(STRATEGIC_MAP_HEIGHT) - 1);
    if column_x2 >= RASTER_WIDTH {
        column_x2 -= RASTER_WIDTH + 1;
    } else if column_x2 < 0 {
        column_x2 += RASTER_WIDTH;
    }
    let index = column_x2 / 2 + row * i32::from(STRATEGIC_MAP_WIDTH);
    TileId::new(u16::try_from(index).expect("retail sea scan produced a valid tile"))
}

fn river_reaches_sea_without_crossing_nation(world: &MapMgr, start: TileId) -> bool {
    const FLOW_DIRECTIONS: [[HexDirection; 2]; 9] = [
        [HexDirection::NorthEast, HexDirection::SouthEast],
        [HexDirection::NorthEast, HexDirection::SouthWest],
        [HexDirection::NorthEast, HexDirection::West],
        [HexDirection::East, HexDirection::SouthWest],
        [HexDirection::East, HexDirection::West],
        [HexDirection::East, HexDirection::NorthWest],
        [HexDirection::SouthEast, HexDirection::West],
        [HexDirection::SouthEast, HexDirection::NorthWest],
        [HexDirection::SouthWest, HexDirection::NorthWest],
    ];

    let geometry = world.geometry();
    let start_owner = world[start].owner_nation;
    let flow_type = match world[start].river().and_then(|river| river.flow_type()) {
        Some(flow_type) => flow_type,
        None => return false,
    };
    for (attempt, mut direction) in FLOW_DIRECTIONS[flow_type].into_iter().enumerate() {
        let mut crossed_boundary = false;
        let mut current = start;
        for _ in 0..100 {
            let Some(next) = geometry.neighbor(current, direction) else {
                return !crossed_boundary;
            };
            current = next;
            let tile = &world[current];
            if tile.terrain == TerrainKind::Water {
                return !crossed_boundary;
            }
            let Some(next_flow_type) = tile.river().and_then(|river| river.flow_type()) else {
                break;
            };
            if tile.owner_nation != start_owner {
                if attempt != 0 {
                    return false;
                }
                crossed_boundary = true;
            }
            let incoming = direction.opposite();
            let pair = FLOW_DIRECTIONS[next_flow_type];
            direction = if pair[0] == incoming {
                pair[1]
            } else if pair[1] == incoming {
                pair[0]
            } else {
                break;
            };
        }
    }
    false
}

/// Retail `TraceTerrainFlowToNearestSeaTile`; unlike the boundary check above,
/// this walk ignores ownership and returns the sea context selected by flow variant order.
fn trace_terrain_flow_to_nearest_sea_tile(world: &MapMgr, start: TileId) -> Option<TileId> {
    const FLOW_DIRECTIONS: [[HexDirection; 2]; 9] = [
        [HexDirection::NorthEast, HexDirection::SouthEast],
        [HexDirection::NorthEast, HexDirection::SouthWest],
        [HexDirection::NorthEast, HexDirection::West],
        [HexDirection::East, HexDirection::SouthWest],
        [HexDirection::East, HexDirection::West],
        [HexDirection::East, HexDirection::NorthWest],
        [HexDirection::SouthEast, HexDirection::West],
        [HexDirection::SouthEast, HexDirection::NorthWest],
        [HexDirection::SouthWest, HexDirection::NorthWest],
    ];

    let geometry = world.geometry();
    let flow_type = world[start].river().and_then(RiverSegment::flow_type)?;
    for mut direction in FLOW_DIRECTIONS[flow_type] {
        let mut current = start;
        for _ in 0..100 {
            let Some(next) = geometry.neighbor(current, direction) else {
                break;
            };
            current = next;
            if world[current].terrain == TerrainKind::Water {
                return Some(current);
            }
            let Some(next_flow_type) = world[current].river().and_then(RiverSegment::flow_type)
            else {
                break;
            };
            let incoming = direction.opposite();
            let pair = FLOW_DIRECTIONS[next_flow_type];
            direction = if pair[0] == incoming {
                pair[1]
            } else if pair[1] == incoming {
                pair[0]
            } else {
                break;
            };
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_rebuild_updates_every_town_in_retail_list_order() {
        let mut state = crate::test_support::game_state();
        let nation = MajorNationId::new(0);
        let home = TileId::new(100);
        let second = state
            .map
            .geometry()
            .neighbor(home, HexDirection::East)
            .unwrap();
        let owner = Some(TileOwnerTag::from_nation(nation.nation()));
        state.map[home].owner_nation = owner;
        state.map[second].owner_nation = owner;
        state.map[home]
            .transport_links
            .insert(TileTransportLinks::for_direction(HexDirection::East));
        state.map[second]
            .transport_links
            .insert(TileTransportLinks::for_direction(HexDirection::West));

        let major = &mut state.nations.majors[nation];
        major.common.home_tile = Some(home);
        major.towns = vec![
            TownState::for_frog_city(home, nation.nation()),
            TownState {
                name: "Altown".to_owned(),
                tile: second,
                created_turn: 2,
                owner_nation: nation.nation(),
                resource_yield_by_type: ResourceTable::default(),
                transport_linked: false,
                enabled: 1,
                has_adjacent_city: 0,
                active: true,
            },
        ];

        state.rebuild_nation_resource_yields(nation);

        assert_eq!(
            state.nations.majors[nation]
                .towns
                .iter()
                .map(|town| town.transport_linked)
                .collect::<Vec<_>>(),
            [true, true]
        );
    }

    #[test]
    fn port_access_obeys_active_type_three_and_four_war_orders() {
        let mut state = crate::test_support::game_state();
        let home = TileId::new(2_210);
        let origin = NationId::new(6);
        state.map[home].owner_nation = Some(TileOwnerTag::from_nation(origin));
        for direction in HexDirection::ALL {
            let neighbor = civilian_sea_scan_neighbor(home, direction);
            state.map[neighbor].terrain = TerrainKind::Plains;
        }
        let sea = civilian_sea_scan_neighbor(home, HexDirection::NorthEast);
        state.map[sea].terrain = TerrainKind::Water;
        state.map[sea].owner_nation = Some(TileOwnerTag::new(0x17));

        state.turn.economic_turn = 10;
        let hostile = NationId::new(0);
        state.diplomacy.relationships[hostile][origin] = DiplomaticRelationship::War;
        state.diplomacy.relationship_turns[hostile][origin] = Some(9);
        state.task_forces.push(TaskForceState {
            aggression: 1,
            order: 3,
            target: TaskForceTarget::None,
            location: OceanZoneId::new(0),
            nation: hostile,
            ship_counts: [0; 4],
            defeated: false,
            ingot_tile: -1,
            flagship: None,
            ships: Vec::new(),
        });
        state.ships.push(ShipState {
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(0),
            task_force: Some(TaskForceId::new(0)),
            aggression: 1,
            nation: hostile,
            name: String::new(),
            strength: 1,
            experience: 0,
            selection: 0,
        });

        assert!(!state.has_reachable_sea_outside_beginning_turn_mask(home));

        state.diplomacy.relationship_turns[hostile][origin] = Some(10);
        assert!(state.has_reachable_sea_outside_beginning_turn_mask(home));

        state.diplomacy.relationship_turns[hostile][origin] = Some(9);
        state.task_forces[0].defeated = true;
        assert!(state.has_reachable_sea_outside_beginning_turn_mask(home));
    }
}
