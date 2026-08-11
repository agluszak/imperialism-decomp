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

#[derive(Clone, Copy, Debug)]
struct AutomatedCivilianPlan {
    nation: MajorNationId,
    town_transport_linked: bool,
    refresh_city_summary: bool,
    railhead_target: Option<TileId>,
    gold_priority: i16,
    assignment: PlannedCivilianAssignment,
}

#[derive(Debug)]
struct CivilianPhasePlan {
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
        let town = self.nations.majors[nation]
            .city
            .home_town
            .expect("resource-yield rebuild requires the nation's home town");
        let (_, town_transport_linked) = self
            .transport_influence(nation, town)
            .expect("the nation's home town must remain on owned territory");

        let mut influence = vec![0_u8; STRATEGIC_TILE_COUNT];
        if town_transport_linked {
            let level = u8::from(town.enabled) + 1;
            influence[usize::from(town.tile.get())] = level;
            let owner = Some(TileOwnerTag::from_nation(nation.nation()));
            for neighbor in self
                .world
                .geometry()
                .neighbors(town.tile)
                .into_iter()
                .flatten()
            {
                let tile = &self.world[neighbor];
                let entry = &mut influence[usize::from(neighbor.get())];
                if (tile.owner_nation == owner || tile.region_tile_subtype.retail() == 0)
                    && *entry < level
                {
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
            let tile = &self.world[tile_id];
            if tile.region_tile_subtype.retail() == 0 {
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
                && self.provinces[province].city_tile() == Some(tile_id)
            {
                for index in ResourceKind::Food as u8..=ResourceKind::Arms as u8 {
                    let resource = ResourceKind::from_index(index)
                        .expect("the manufactured resource range is semantic");
                    current[resource] = current[resource].wrapping_add(
                        self.provinces[province].resource_development_by_type()[resource],
                    );
                }
            }
        }

        let major = &mut self.nations.majors[nation];
        major
            .city
            .home_town
            .as_mut()
            .expect("resource-yield rebuild retains the home town")
            .transport_linked = town_transport_linked;
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
        if !major.economy.controller.is_human() {
            let fish = major.economy.need_current_by_type[ResourceKind::Fish];
            major.economy.need_current_by_type[ResourceKind::Fish] = 0;
            major.economy.need_current_by_type[ResourceKind::Livestock] =
                major.economy.need_current_by_type[ResourceKind::Livestock].wrapping_add(fish);
        }
    }

    /// Whether phase nine is the recovered Easy beginning-save civilian pass.
    pub(crate) fn supports_first_turn_civilian_phase(&self) -> bool {
        self.first_turn_civilian_plan().is_some()
    }

    /// Runs retail's six automated interior ministers after the human offer sheet.
    ///
    /// The dispatcher owns the phase-nine to phase-ten transition. Planning is
    /// completed for every automated nation before any authoritative state is
    /// changed, so an unrecovered branch cannot leave a partial phase result.
    pub(crate) fn run_civilian_phase(&mut self) {
        let plan = self
            .first_turn_civilian_plan()
            .expect("first-turn civilian phase contains an unrecovered branch");

        for plan in plan.automated {
            {
                let major = self.nations.major_mut(plan.nation);
                let town = major
                    .city
                    .home_town
                    .as_mut()
                    .expect("the preflight requires one home town");
                town.transport_linked = plan.town_transport_linked;
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
            || self.world.topology() != MapTopology::Wrapping
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
            if major.economy.controller.is_human() != (nation == active)
                || major.city.home_town.is_none()
                || major.common.home_tile != major.city.home_town.map(TownState::tile)
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
        let town = major.city.home_town?;
        let owned_tiles = self.owned_tiles(nation);
        if owned_tiles.is_empty() || !owned_tiles.contains(&town.tile) {
            return None;
        }

        let (transport_influence, town_transport_linked) =
            self.transport_influence(nation, town)?;
        // Otherwise `SeekLostTowns` selects a separate continuation branch.
        if !town_transport_linked {
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
                self.world[tile].region.is_none()
                    && terrain_is_allowed(self.world[tile].terrain, secondary_terrain)
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
            let segment = RailSegment::between(self.world.topology(), source, destination)?;
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
            .filter(|tile| self.world[*tile].owner_nation == owner)
            .collect()
    }

    /// `TGreatPower::BuildTransportLinkedInfluenceMap` for the one-town state
    /// admitted by the legacy projection.
    fn transport_influence(
        &self,
        nation: MajorNationId,
        town: TownState,
    ) -> Option<(Vec<u8>, bool)> {
        if self.world[town.tile].owner_nation != Some(TileOwnerTag::from_nation(nation.nation())) {
            return None;
        }

        let unblocked_port =
            town.enabled && self.has_reachable_sea_outside_beginning_turn_mask(town.tile);
        let mut influence = vec![0_u8; STRATEGIC_TILE_COUNT];
        if !unblocked_port || town.active {
            self.mark_transport_component(nation, town.tile, &mut influence);
        }

        let linked =
            !((influence[usize::from(town.tile.get())] == 0 || !town.active) && !unblocked_port);
        if unblocked_port {
            influence[usize::from(town.tile.get())] = 1;
        }
        Some((influence, linked))
    }

    fn mark_transport_component(&self, nation: MajorNationId, start: TileId, influence: &mut [u8]) {
        let owner = Some(TileOwnerTag::from_nation(nation.nation()));
        let geometry = self.world.geometry();
        let mut pending = vec![start];
        while let Some(tile) = pending.pop() {
            let index = usize::from(tile.get());
            if influence[index] != 0 || self.world[tile].owner_nation != owner {
                continue;
            }
            influence[index] = 1;
            for direction in HexDirection::ALL.into_iter().rev() {
                if !self.world[tile]
                    .transport_links
                    .contains(TileTransportLinks::for_direction(direction))
                {
                    continue;
                }
                if let Some(neighbor) = geometry.neighbor(tile, direction)
                    && influence[usize::from(neighbor.get())] == 0
                    && self.world[neighbor].owner_nation == owner
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

        let geometry = self.world.geometry();
        loop {
            let mut changed = false;
            for &tile in owned_tiles {
                let index = usize::from(tile.get());
                if distance[index] != 0
                    || !terrain_is_allowed(self.world[tile].terrain, terrain_access)
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
        let geometry = self.world.geometry();
        let mut candidates = Vec::new();
        for &tile in owned_tiles {
            let index = usize::from(tile.get());
            if self.world[tile].region.is_some()
                || !((primary_distance[index] > 0 && primary_distance[index] < 9)
                    || self.can_build_port_at(tile)
                    || (secondary_distance[index] > 2 && secondary_distance[index] < 6))
                || HexDirection::ALL.into_iter().any(|direction| {
                    geometry.neighbor(tile, direction).is_some_and(|neighbor| {
                        self.world[neighbor].flags.bits() & TRANSPORT_NODE_FLAG != 0
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
        let town_region = self.world[town].region;
        let geometry = self.world.geometry();
        let mut yields = ResourceTable::<i16>::default();

        for harvest_tile in HexDirection::ALL
            .into_iter()
            .filter_map(|direction| geometry.neighbor(town, direction))
            .chain(std::iter::once(town))
        {
            let tile = &self.world[harvest_tile];
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
                && self.provinces[province].city_tile() == Some(harvest_tile)
            {
                for index in ResourceKind::Food as u8..=ResourceKind::Arms as u8 {
                    let resource = ResourceKind::from_index(index)
                        .expect("the manufactured resource range is semantic");
                    yields[resource] = yields[resource].wrapping_add(
                        self.provinces[province].resource_development_by_type()[resource],
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
        let source_flags = self.world[source].flags.bits();
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
        let geometry = self.world.geometry();
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
            let province = &self.provinces[province_id];
            if province.owner() != Some(nation.nation()) || province.fort_level() >= fort_cap {
                continue;
            }
            let mut city_score = province.city_score() as f32;
            if !province.adjacency().is_empty() {
                let same_owner = province
                    .adjacency()
                    .iter()
                    .filter(|adjacent| self.provinces[**adjacent].owner() == Some(nation.nation()))
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
        let province = &self.provinces[province_id];
        let fort_level = usize::try_from(province.fort_level()).ok()?;
        let cost = *FORT_BUILD_COST.get(fort_level)?;
        let destination = province.city_tile()?;
        if major.common.treasury < cost
            || self.world[destination].province != Some(province_id)
            || self.world[destination].owner_nation
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
        for direction in HexDirection::ALL {
            let neighbor = civilian_sea_scan_neighbor(tile, direction);
            if self.world[neighbor].terrain == TerrainKind::Water {
                // The phase guard proves the naval-order mask is empty. Tile
                // action 3 is a sea-context anchor, not a type-3 ship order.
                return true;
            }
        }
        self.world[tile].river().is_some()
            && river_reaches_sea_without_crossing_nation(&self.world, tile)
    }

    fn can_build_port_at(&self, tile: TileId) -> bool {
        if !matches!(
            self.world[tile].terrain,
            TerrainKind::Mountain | TerrainKind::Hills
        ) && HexDirection::ALL.into_iter().any(|direction| {
            self.world[civilian_sea_scan_neighbor(tile, direction)].terrain == TerrainKind::Water
        }) {
            return true;
        }
        self.world[tile].river().is_some()
            && river_reaches_sea_without_crossing_nation(&self.world, tile)
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

fn river_reaches_sea_without_crossing_nation(world: &StrategicMap, start: TileId) -> bool {
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
