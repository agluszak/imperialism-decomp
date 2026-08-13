//! AI civilian assignment (`TCityInteriorMinister::ProcessUnitOrders`).

use crate::*;

const FORT_COST_BY_LEVEL: [i32; 5] = [5_000, 7_500, 10_000, 0, 0];
const WORK_ORDER_COST_BY_CLASS: [i32; 3] = [100, 1_000, 5_000];
const GATE_QUALIFIES: [u8; 24] = [
    0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

impl GameState {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn process_ai_civilian_orders(&mut self, nation: MajorNationId) {
        self.continue_civilian_orders(nation);

        let owned_tiles: Vec<TileId> = (0..STRATEGIC_TILE_COUNT)
            .map(|index| TileId::new(index as u16))
            .filter(|&tile| self.tile_owned_by(tile, nation))
            .collect();

        let primary = self.create_sea_distance_map(nation, &owned_tiles);
        let secondary = self.build_frog_city_distance_map(nation, &owned_tiles);
        self.seek_resources(nation, &owned_tiles, &primary);
        if self.nations.majors[nation]
            .economy
            .interior_civilian
            .railhead_target
            .is_none()
        {
            self.seek_lost_towns(nation, &primary, &secondary);
        }

        let mut selected = Some(ResourceKind::Cotton);
        while self.nations.majors[nation]
            .economy
            .interior_civilian
            .railhead_target
            .is_none()
            && selected.is_some()
        {
            selected = None;
            for resource in all_resources() {
                if !railhead_resource(resource) {
                    continue;
                }
                let priority = self.nations.majors[nation]
                    .economy
                    .interior_civilian
                    .railhead_priority_by_resource[resource];
                if priority == 0 {
                    continue;
                }
                if selected.is_none_or(|current| {
                    self.nations.majors[nation]
                        .economy
                        .interior_civilian
                        .railhead_priority_by_resource[current]
                        < priority
                }) {
                    selected = Some(resource);
                }
            }
            if let Some(resource) = selected {
                self.start_railhead_project(nation, resource, &owned_tiles, &primary, &secondary);
                if self.nations.majors[nation]
                    .economy
                    .interior_civilian
                    .railhead_target
                    .is_none()
                {
                    self.nations.majors[nation]
                        .economy
                        .interior_civilian
                        .railhead_priority_by_resource[resource] = 0;
                }
            }
        }

        match self.nations.majors[nation]
            .economy
            .interior_civilian
            .railhead_target
        {
            None => self.dispatch_builders(nation),
            Some(target) if !self.tile_owned_by(target, nation) => {
                self.nations.majors[nation]
                    .economy
                    .interior_civilian
                    .railhead_target = None;
            }
            Some(_) => {
                let mut has_engineer = false;
                let mut idle_engineer = None;
                for (index, unit) in self.civilian_units.iter().enumerate() {
                    if unit.nation != nation.nation()
                        || unit.unit_type != CivilianUnitKind::Engineer
                    {
                        continue;
                    }
                    has_engineer = true;
                    if matches!(unit.order, CivilianWorkOrder::Idle) {
                        idle_engineer = Some(index);
                        break;
                    }
                }
                if !has_engineer {
                    self.nations.majors[nation]
                        .economy
                        .interior_civilian
                        .pending_recruitment = Some(CivilianUnitKind::Engineer);
                }
                if let Some(engineer) = idle_engineer {
                    self.continue_railhead_project(nation, engineer, &primary, &secondary);
                }
            }
        }

        self.rebuild_map_tile_neighbor_buckets(nation);
        self.auto_assign_prospecting(nation);
    }

    fn tile_owned_by(&self, tile: TileId, nation: MajorNationId) -> bool {
        self.map[tile].owner_nation == Some(TileOwnerTag::from_nation(nation.nation()))
    }

    fn create_sea_distance_map(
        &mut self,
        nation: MajorNationId,
        owned_tiles: &[TileId],
    ) -> Vec<i8> {
        let allowed = primary_distance_terrain(
            self.technology.city_capabilities_by_nation[nation].primary_civilian_distance_terrain,
        );
        let transport = self
            .apply_town_transport_links(nation)
            .unwrap_or_else(|| vec![0; STRATEGIC_TILE_COUNT]);
        expand_distance_map(self, owned_tiles, allowed, |tile| {
            transport[tile_index(tile)] != 0
        })
    }

    fn build_frog_city_distance_map(
        &self,
        nation: MajorNationId,
        owned_tiles: &[TileId],
    ) -> Vec<i8> {
        let capabilities = self.technology.city_capabilities_by_nation[nation];
        let allowed = secondary_distance_terrain(capabilities);
        expand_distance_map(self, owned_tiles, allowed, |tile| {
            self.map[tile].region.is_none()
                && terrain_allowed(self.map[tile].terrain, allowed)
                && self.has_reachable_sea_outside_beginning_turn_mask(tile)
        })
    }

    fn seek_resources(&mut self, nation: MajorNationId, owned_tiles: &[TileId], primary: &[i8]) {
        let mut unclaimed = ResourceTable::<i16>::default();
        let mut work_delta = ResourceTable::<i16>::default();
        {
            let interior = self.nations.majors[nation]
                .economy
                .interior_civilian
                .as_mut();
            for resource in all_resources() {
                interior.civilian_order_demand_by_resource[resource] = 0;
                interior.exterior_need_by_resource[resource] = 0;
            }
        }

        for &tile in owned_tiles {
            if self.map[tile].region.is_some() {
                let developed_capability = self.max_resource_capability(tile, true, nation);
                let developed_cost = i16::from(self.map[tile].development.extractive.get());
                let current_capability = self.max_resource_capability(tile, false, nation);
                let current_cost = i16::from(self.map[tile].development.surface.get());
                for resource in self.map[tile].edge_resources.into_iter().flatten() {
                    let gain = if extractive_resource(resource) {
                        developed_capability - developed_cost
                    } else {
                        current_capability - current_cost
                    };
                    work_delta[resource] = work_delta[resource].wrapping_add(gain << 2);
                }
            } else {
                let distance = primary[tile_index(tile)];
                let mut reachable = true;
                if distance == 0 || distance < 9 || !self.can_build_port_at_tile(tile) {
                    reachable = false;
                    for direction in HexDirection::ALL {
                        let neighbor = civilian_sea_scan_neighbor(tile, direction);
                        let neighbor_distance = primary[tile_index(neighbor)];
                        if (neighbor_distance > 0 && neighbor_distance < 9)
                            || self.can_build_port_at_tile(neighbor)
                        {
                            reachable = true;
                            break;
                        }
                    }
                }
                if reachable {
                    for resource in self.map[tile].edge_resources.into_iter().flatten() {
                        unclaimed[resource] = unclaimed[resource].wrapping_add(1);
                    }
                }
            }
        }

        let interior = self.nations.majors[nation]
            .economy
            .interior_civilian
            .as_mut();
        for resource in all_resources() {
            if traded_resource(resource) && interior.resource_order_metrics[resource] != 0 {
                let demand = work_delta[resource];
                interior.civilian_order_demand_by_resource[resource] = demand;
                let need = interior.resource_order_metrics[resource];
                if need - demand > 2 {
                    if unclaimed[resource] == 0 {
                        interior.exterior_need_by_resource[resource] =
                            interior.exterior_need_by_resource[resource].wrapping_add(need);
                    } else {
                        interior.railhead_priority_by_resource[resource] = interior
                            .railhead_priority_by_resource[resource]
                            .wrapping_add(need - demand);
                    }
                }
                interior.resource_order_metrics[resource] = 0;
            }
            if interior.exterior_need_by_resource[resource] == 0 {
                interior.historical_need_by_resource[resource] = 0;
            } else {
                interior.historical_need_by_resource[resource] =
                    interior.historical_need_by_resource[resource].wrapping_add(1);
            }
        }
        interior.railhead_priority_by_resource[ResourceKind::Gold] = 2;
    }

    fn seek_lost_towns(&mut self, nation: MajorNationId, primary: &[i8], secondary: &[i8]) {
        let target = self.nations.major(nation).towns.iter().find_map(|town| {
            let primary_distance = primary[tile_index(town.tile)];
            let secondary_distance = secondary[tile_index(town.tile)];
            (!town.transport_linked
                && (primary_distance < 12 || (secondary_distance < 8 && secondary_distance > 2)))
                .then_some(town.tile)
        });
        self.nations.majors[nation]
            .economy
            .interior_civilian
            .railhead_target = target;
    }

    fn start_railhead_project(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
        owned_tiles: &[TileId],
        primary: &[i8],
        secondary: &[i8],
    ) {
        let mut candidates = Vec::new();
        for &tile in owned_tiles {
            if self.map[tile].region.is_some() {
                continue;
            }
            let primary_distance = primary[tile_index(tile)];
            let secondary_distance = secondary[tile_index(tile)];
            if !((primary_distance > 0 && primary_distance < 9)
                || self.can_build_port_at_tile(tile)
                || (secondary_distance > 2 && secondary_distance < 6))
            {
                continue;
            }
            if self.neighbor_has_depot(tile) {
                continue;
            }
            if self.projected_town_yield(nation, tile)[resource] != 0 {
                candidates.push(tile);
            }
        }
        let mut best_score = -1_i16;
        let mut best_tile = None;
        for tile in candidates {
            let score = self.evaluate_resources(nation, tile);
            if score > best_score {
                best_score = score;
                best_tile = Some(tile);
            }
        }
        if let Some(tile) = best_tile {
            self.nations.majors[nation]
                .economy
                .interior_civilian
                .railhead_target = Some(tile);
        }
    }

    fn evaluate_resources(&mut self, nation: MajorNationId, tile: TileId) -> i16 {
        let order_quantity = self.nations.city(nation).orders.population_growth.quantity;
        let summary = *self
            .nations
            .city_mut(nation)
            .refresh_unreserved_city_needs(order_quantity);
        let yields = self.projected_town_yield(nation, tile);
        let interior = &self.nations.majors[nation].economy.interior_civilian;
        let need_current = &self.nations.majors[nation].economy.need_current_by_type;
        let mut score = 0_i16;
        for resource in [
            ResourceKind::Cotton,
            ResourceKind::Wool,
            ResourceKind::Timber,
            ResourceKind::Coal,
            ResourceKind::Iron,
            ResourceKind::Horses,
            ResourceKind::Oil,
        ] {
            score = score.wrapping_add(
                yields[resource].wrapping_mul(interior.railhead_priority_by_resource[resource]),
            );
        }
        let grain_shortage = summary[ResourceKind::Grain] - need_current[ResourceKind::Grain];
        if grain_shortage > 0 {
            score = score.wrapping_add(yields[ResourceKind::Grain].wrapping_mul(grain_shortage));
        }
        let fruit_shortage = summary[ResourceKind::Fruit] - need_current[ResourceKind::Fruit];
        if fruit_shortage > 0 {
            score = score.wrapping_add(yields[ResourceKind::Fruit].wrapping_mul(fruit_shortage));
        }
        let livestock_shortage = summary[ResourceKind::Livestock]
            - need_current[ResourceKind::Livestock]
            - need_current[ResourceKind::Fish];
        if livestock_shortage > 0 {
            score = score.wrapping_add(
                (yields[ResourceKind::Livestock] + yields[ResourceKind::Gems])
                    .wrapping_mul(livestock_shortage),
            );
        }
        score
    }

    fn projected_town_yield(&self, nation: MajorNationId, tile: TileId) -> ResourceTable<i16> {
        let town_region = self.map[tile].region;
        let mut yields = ResourceTable::<i16>::default();
        let mut harvest = HexDirection::ALL
            .into_iter()
            .map(|direction| civilian_sea_scan_neighbor(tile, direction))
            .collect::<Vec<_>>();
        harvest.push(tile);
        for harvest_tile in harvest {
            if !self.tile_owned_by(harvest_tile, nation) {
                continue;
            }
            let region = self.map[harvest_tile].region;
            if region != town_region && region.is_some() {
                continue;
            }
            for (edge, resource) in self.map[harvest_tile]
                .edge_resources
                .into_iter()
                .flatten()
                .enumerate()
            {
                let mut level = if extractive_resource(resource) {
                    self.map[harvest_tile].development.extractive.get()
                } else {
                    self.map[harvest_tile].development.surface.get()
                };
                if extractive_resource(resource) && level == 0 {
                    level = 1;
                }
                let _ = edge;
                yields[resource] =
                    yields[resource].wrapping_add(resource_development_yield(resource, level));
            }
            if let Some(province) = self.map[harvest_tile].province
                && self.map.provinces[province].city_tile() == Some(harvest_tile)
            {
                for index in ResourceKind::Food as u8..=ResourceKind::Arms as u8 {
                    let resource =
                        ResourceKind::from_index(index).expect("manufactured resource index");
                    yields[resource] = yields[resource].wrapping_add(
                        self.map.provinces[province].resource_development_by_type()[resource],
                    );
                }
            }
        }
        yields
    }

    fn continue_railhead_project(
        &mut self,
        nation: MajorNationId,
        engineer: usize,
        primary: &[i8],
        secondary: &[i8],
    ) {
        let target = self.nations.majors[nation]
            .economy
            .interior_civilian
            .railhead_target
            .expect("railhead continuation requires a target");
        let primary_distance = primary[tile_index(target)];
        if (primary_distance == 0 || primary_distance > 9) && !self.can_build_port_at_tile(target) {
            if secondary[tile_index(target)] < 3 {
                self.nations.majors[nation]
                    .economy
                    .interior_civilian
                    .railhead_target = None;
                return;
            }
            let (source, _) = trace_descending(target, secondary);
            if self.owner_civilian_on_tile(source, nation).is_none() {
                self.move_civilian_to(engineer, source);
                self.set_civilian_work_order(
                    engineer,
                    CivilianWorkOrder::BuildPort { turns: turns(3) },
                );
            }
            return;
        }

        if primary_distance != 1
            && (!self.can_build_port_at_tile(target)
                || (primary_distance != 0 && primary_distance <= 6))
        {
            let (source, previous) = trace_descending(target, primary);
            let flags = self.map[source].flags;
            if flags.contains(TileFlags::PORT) && !flags.contains(TileFlags::DEPOT) {
                self.move_civilian_to(engineer, source);
                self.set_civilian_work_order(
                    engineer,
                    CivilianWorkOrder::BuildDepot { turns: turns(3) },
                );
            } else {
                self.move_civilian_to(engineer, previous);
                if let Some(segment) = RailSegment::between(MapTopology::Wrapping, source, previous)
                {
                    self.set_civilian_work_order(
                        engineer,
                        CivilianWorkOrder::LayRail {
                            segment,
                            turns: turns(1),
                        },
                    );
                }
            }
            return;
        }

        self.move_civilian_to(engineer, target);
        if primary_distance == 1 {
            self.set_civilian_work_order(
                engineer,
                CivilianWorkOrder::BuildDepot { turns: turns(3) },
            );
        } else {
            self.set_civilian_work_order(
                engineer,
                CivilianWorkOrder::BuildPort { turns: turns(3) },
            );
        }
        let yields = self.projected_town_yield(nation, target);
        let interior = self.nations.majors[nation]
            .economy
            .interior_civilian
            .as_mut();
        for resource in all_resources() {
            if harvested_or_raw_trade(resource) && yields[resource] != 0 {
                interior.railhead_priority_by_resource[resource] = 0;
            }
        }
        interior.railhead_target = None;
    }

    fn dispatch_builders(&mut self, nation: MajorNationId) {
        let Some(engineer) = self
            .civilian_units
            .iter()
            .enumerate()
            .find_map(|(index, unit)| {
                (unit.nation == nation.nation()
                    && unit.unit_type == CivilianUnitKind::Engineer
                    && matches!(unit.order, CivilianWorkOrder::Idle))
                .then_some(index)
            })
        else {
            return;
        };
        let Some(province) = self.best_fort_province(nation) else {
            return;
        };
        let Some(city_tile) = self.map.provinces[province].city_tile() else {
            return;
        };
        let occupant = self.chain_head_on_tile(city_tile);
        if occupant.is_some_and(|index| index != engineer) {
            return;
        }
        let fort_level = self.map.provinces[province].fort_level();
        let cost = FORT_COST_BY_LEVEL
            .get(usize::try_from(fort_level).unwrap_or(usize::MAX))
            .copied()
            .unwrap_or(0);
        if cost > self.nations.major(nation).common.treasury {
            return;
        }
        self.move_civilian_to(engineer, city_tile);
        self.set_civilian_work_order(engineer, CivilianWorkOrder::BuildFort { turns: turns(4) });
    }

    fn best_fort_province(&self, nation: MajorNationId) -> Option<ProvinceId> {
        if self.nations.major(nation).economy.controller.is_human() {
            return None;
        }
        let pressure = self.nations.major(nation).economy.ai_development_pressure;
        let mut average = pressure
            .map(|state| f32::from_bits(state.average_unit_divergence_per_owned_region_bits))
            .unwrap_or(0.0);
        #[allow(clippy::neg_cmp_op_on_partial_ord)]
        if !(average > 0.0) {
            average = 1.0;
        }
        let expansion = pressure
            .map(|state| f32::from_bits(state.expansion_pressure_per_compatible_region_bits))
            .unwrap_or(0.0);
        let cap = self.technology.city_capabilities_by_nation[nation]
            .fort_level_cap
            .get();
        let mut best_region = None;
        let mut best_score = -1.0_f32;
        for &province in self.nations.major(nation).common.owned_regions() {
            let record = &self.map.provinces[province];
            if record.fort_level() >= cap {
                continue;
            }
            let mut development_pressure = average;
            if self.province_is_compatible(province, nation) {
                development_pressure = expansion + average;
            }
            let mut city_score = record.city_score() as f32;
            if !record.adjacency().is_empty() {
                let same_owner = record
                    .adjacency()
                    .iter()
                    .filter(|&&adjacent| {
                        self.map.provinces[adjacent].owner() == Some(nation.nation())
                    })
                    .count();
                city_score *= (same_owner as f32) / (record.adjacency().len() as f32) - -1.0;
            }
            let score = city_score / 5000.0 * development_pressure;
            if score > best_score || best_region.is_none() {
                best_score = score;
                best_region = Some(province);
            }
        }
        best_region
    }

    fn province_is_compatible(&self, province: ProvinceId, nation: MajorNationId) -> bool {
        if let Some(home) = self.nations.major(nation).common.home_tile
            && self.map[home].province == Some(province)
        {
            return true;
        }
        let owner = self.map.provinces[province].owner();
        self.map.provinces[province]
            .adjacency()
            .iter()
            .any(|&adjacent| {
                let neighbor_owner = self.map.provinces[adjacent].owner();
                neighbor_owner.is_some_and(|candidate| {
                    MajorNationId::from_nation(candidate).is_some() && neighbor_owner != owner
                })
            })
    }

    #[allow(clippy::too_many_lines)]
    fn rebuild_map_tile_neighbor_buckets(&mut self, nation: MajorNationId) {
        self.request_missing_civilian_order_types(nation);

        let mut candidates = Vec::new();
        let towns: Vec<TileId> = self
            .nations
            .major(nation)
            .towns
            .iter()
            .map(|town| town.tile)
            .collect();
        for town_tile in towns {
            candidates.push(town_tile);
            let region = self.map[town_tile].region;
            for direction in HexDirection::ALL {
                let neighbor = civilian_sea_scan_neighbor(town_tile, direction);
                if self.map[neighbor].region == region && self.tile_owned_by(neighbor, nation) {
                    candidates.push(neighbor);
                }
            }
        }
        if let Some(railhead) = self.nations.majors[nation]
            .economy
            .interior_civilian
            .railhead_target
        {
            candidates.push(railhead);
            for direction in HexDirection::ALL {
                let neighbor = civilian_sea_scan_neighbor(railhead, direction);
                if self.tile_owned_by(neighbor, nation) {
                    candidates.push(neighbor);
                }
            }
        }
        for index in 0..STRATEGIC_TILE_COUNT {
            let tile = TileId::new(index as u16);
            if self.map[tile].secondary_owner_nation == Some(nation) {
                candidates.push(tile);
            }
        }

        let idle: Vec<usize> = self
            .civilian_units
            .iter()
            .enumerate()
            .filter(|(_, unit)| {
                unit.nation == nation.nation()
                    && unit.unit_type != CivilianUnitKind::Engineer
                    && matches!(unit.order, CivilianWorkOrder::Idle)
            })
            .map(|(index, _)| index)
            .collect();
        for unit_index in idle {
            let kind = self.civilian_units[unit_index].unit_type;
            let extractive = matches!(kind, CivilianUnitKind::Miner | CivilianUnitKind::Driller);
            for &tile in &candidates {
                if self.has_kind_with_develop(tile, kind) {
                    continue;
                }
                if !gate_qualifies(self.map[tile].gate) {
                    continue;
                }
                let mut assigned = false;
                for resource in self.map[tile].edge_resources.into_iter().flatten() {
                    if required_civilian_kind(resource) != Some(kind) {
                        continue;
                    }
                    if !always_qualifies(resource) && !self.tile_owned_by(tile, nation) {
                        continue;
                    }
                    let available = self.max_resource_capability(tile, extractive, nation);
                    let current = if extractive {
                        i16::from(self.map[tile].development.extractive.get())
                    } else {
                        i16::from(self.map[tile].development.surface.get())
                    };
                    if available > current {
                        self.move_civilian_to(unit_index, tile);
                        self.set_civilian_work_order(
                            unit_index,
                            CivilianWorkOrder::DevelopResource { turns: turns(3) },
                        );
                        let cost = if current == 0 {
                            0
                        } else {
                            WORK_ORDER_COST_BY_CLASS
                                .get(usize::try_from(current - 1).unwrap_or(usize::MAX))
                                .copied()
                                .unwrap_or(0)
                        };
                        self.nations.major_mut(nation).common.treasury -= cost;
                        assigned = true;
                        break;
                    }
                }
                if assigned {
                    break;
                }
            }
        }
    }

    fn request_missing_civilian_order_types(&mut self, nation: MajorNationId) {
        let mut has_kind = CivilianUnitTable::default();
        for unit in &self.civilian_units {
            if unit.nation == nation.nation() {
                has_kind[unit.unit_type] = true;
            }
        }
        has_kind[CivilianUnitKind::Prospector] = true;
        has_kind[CivilianUnitKind::Developer] = true;
        for kind in CivilianUnitKind::ALL.into_iter().rev() {
            if !self.technology.city_capabilities_by_nation[nation]
                .university
                .available[kind]
                || has_kind[kind]
            {
                continue;
            }
            let needed = all_resources().any(|resource| {
                required_civilian_kind(resource) == Some(kind)
                    && self.nations.majors[nation]
                        .economy
                        .interior_civilian
                        .civilian_order_demand_by_resource[resource]
                        != 0
            });
            if needed {
                self.nations.majors[nation]
                    .economy
                    .interior_civilian
                    .pending_recruitment = Some(kind);
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn auto_assign_prospecting(&mut self, nation: MajorNationId) {
        if self.turn.economic_turn < 4 {
            return;
        }

        let mut relation_scale = [0.0_f32; NATION_COUNT];
        for minor in MinorNationId::FIRST..NationId::COUNT {
            let minor_nation = NationId::new(minor);
            if self.nation_has_war(minor_nation) {
                continue;
            }
            let mut strongest = 0.1_f32;
            for major in 0..MajorNationId::COUNT {
                if major == nation.get() {
                    continue;
                }
                let standing =
                    f32::from(self.diplomacy.standings[NationId::new(major)][minor_nation]);
                if standing > strongest {
                    strongest = standing;
                }
            }
            relation_scale[usize::from(minor)] =
                f32::from(self.diplomacy.standings[nation.nation()][minor_nation]) / strongest;
        }

        let mut prospector_count = 0;
        let mut developer_count = 0;
        for unit in &self.civilian_units {
            if unit.nation != nation.nation() || !matches!(unit.order, CivilianWorkOrder::Idle) {
                continue;
            }
            match unit.unit_type {
                CivilianUnitKind::Prospector => prospector_count += 1,
                CivilianUnitKind::Developer => developer_count += 1,
                _ => {}
            }
        }

        let mut prospecting_tiles = vec![-1_i16; prospector_count];
        let mut prospecting_scores = vec![0.0_f32; prospector_count];
        let mut affordable = self
            .nations
            .major(nation)
            .economy
            .available_diplomacy_budget(self.nations.major(nation).common.treasury)
            / 2_000;
        if affordable < 0 {
            affordable = 0;
        }
        if affordable < developer_count as i32 {
            developer_count = affordable as usize;
        }
        let mut developer_tiles = vec![-1_i16; developer_count];
        let mut developer_scores = vec![0.0_f32; developer_count];

        let mut resource_weights = ResourceTable::<i32>::default();
        {
            let exterior = &self.nations.majors[nation]
                .economy
                .interior_civilian
                .exterior_need_by_resource;
            resource_weights[ResourceKind::Cotton] = i32::from(exterior[ResourceKind::Cotton]) + 1;
            resource_weights[ResourceKind::Wool] = i32::from(exterior[ResourceKind::Wool]) + 1;
            resource_weights[ResourceKind::Timber] = i32::from(exterior[ResourceKind::Timber]);
            resource_weights[ResourceKind::Coal] = i32::from(exterior[ResourceKind::Coal]) + 5;
            resource_weights[ResourceKind::Iron] = i32::from(exterior[ResourceKind::Iron]) + 5;
            if self.technology.city_capabilities_by_nation[nation].oil_drilling {
                resource_weights[ResourceKind::Oil] = i32::from(exterior[ResourceKind::Oil]) + 10;
            }
        }
        let oil = self.technology.city_capabilities_by_nation[nation].oil_drilling;

        for index in 0..STRATEGIC_TILE_COUNT {
            let tile = TileId::new(index as u16);
            let Some(owner) = self.map[tile].owner_nation.and_then(TileOwnerTag::nation) else {
                continue;
            };
            let Some(minor_id) =
                (owner.get() >= MinorNationId::FIRST).then(|| MinorNationId::new(owner.get()))
            else {
                continue;
            };
            let Some(minor) = self.nations.minors[minor_id].as_ref() else {
                continue;
            };
            if !matches!(minor.common.status(), CountryStatus::Independent)
                && !minor.common.status().is_colony_of(nation.nation())
            {
                continue;
            }
            if !gate_qualifies(self.map[tile].gate)
                || self.diplomacy.mission_levels[nation.nation()][owner]
                    != DiplomaticMissionLevel::Embassy
                || self.map[tile].secondary_owner_nation.is_some()
            {
                continue;
            }

            if prospectable_terrain(self.map[tile].terrain, oil) {
                let has_active_prospecting = self.civilian_units.iter().rev().any(|unit| {
                    unit.location.tile() == Some(tile)
                        && matches!(
                            unit.order,
                            CivilianWorkOrder::PurchaseLand { turns } if turns.get() == 8
                        )
                });
                let visible = self.map[tile].development.resource_visible_to_majors[nation];
                if !has_active_prospecting
                    && !visible
                    && prospector_count != 0
                    && relation_scale[usize::from(owner.get())] != 0.0
                {
                    insert_scored_candidate(
                        relation_scale[usize::from(owner.get())],
                        tile.get() as i16,
                        &mut prospecting_scores,
                        &mut prospecting_tiles,
                        &mut self.rng,
                    );
                }
            }

            if developer_count != 0 {
                let mut score = 0.0_f32;
                for resource in self.map[tile].edge_resources.into_iter().flatten() {
                    score += resource_weights[resource] as f32;
                }
                score *= relation_scale[usize::from(owner.get())];
                if score != 0.0 {
                    insert_scored_candidate(
                        score,
                        tile.get() as i16,
                        &mut developer_scores,
                        &mut developer_tiles,
                        &mut self.rng,
                    );
                }
            }
        }

        let mut prospecting_index = 0;
        let mut developer_index = 0;
        let assignment: Vec<usize> = self
            .civilian_units
            .iter()
            .enumerate()
            .filter(|(_, unit)| unit.nation == nation.nation())
            .map(|(index, _)| index)
            .collect();
        for unit_index in assignment {
            if !matches!(
                self.civilian_units[unit_index].order,
                CivilianWorkOrder::Idle
            ) {
                continue;
            }
            match self.civilian_units[unit_index].unit_type {
                CivilianUnitKind::Prospector
                    if prospecting_index < prospector_count
                        && prospecting_scores[prospecting_index] != 0.0 =>
                {
                    let tile = TileId::new(prospecting_tiles[prospecting_index] as u16);
                    prospecting_index += 1;
                    self.set_civilian_work_order(
                        unit_index,
                        CivilianWorkOrder::Prospect { turns: turns(1) },
                    );
                    self.move_civilian_to(unit_index, tile);
                }
                CivilianUnitKind::Developer
                    if developer_index < developer_count
                        && developer_scores[developer_index] != 0.0 =>
                {
                    let tile = TileId::new(developer_tiles[developer_index] as u16);
                    developer_index += 1;
                    self.set_civilian_work_order(
                        unit_index,
                        CivilianWorkOrder::PurchaseLand { turns: turns(1) },
                    );
                    self.move_civilian_to(unit_index, tile);
                    let cost = self.developer_tile_purchase_cost(tile);
                    self.nations.major_mut(nation).common.treasury -= cost;
                }
                _ => {}
            }
        }
    }

    fn max_resource_capability(
        &self,
        tile: TileId,
        extractive: bool,
        nation: MajorNationId,
    ) -> i16 {
        let mut max_value = 0_i16;
        for resource in self.map[tile].edge_resources.into_iter().flatten() {
            if extractive_resource(resource) != extractive {
                continue;
            }
            let value = i16::from(
                self.technology.city_capabilities_by_nation[nation]
                    .university
                    .requirement_levels[resource],
            );
            if value > max_value {
                max_value = value;
            }
        }
        max_value
    }

    fn neighbor_has_depot(&self, tile: TileId) -> bool {
        self.map
            .geometry()
            .neighbors(tile)
            .into_iter()
            .flatten()
            .any(|neighbor| self.map[neighbor].flags.contains(TileFlags::DEPOT))
    }

    fn has_kind_with_develop(&self, tile: TileId, kind: CivilianUnitKind) -> bool {
        self.civilian_units.iter().any(|unit| {
            unit.location.tile() == Some(tile)
                && unit.unit_type == kind
                && matches!(unit.order, CivilianWorkOrder::DevelopResource { .. })
        })
    }

    fn owner_civilian_on_tile(&self, tile: TileId, nation: MajorNationId) -> Option<usize> {
        self.civilian_units
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, unit)| {
                (unit.location.tile() == Some(tile) && unit.owner_nation == nation.nation())
                    .then_some(index)
            })
    }

    fn chain_head_on_tile(&self, tile: TileId) -> Option<usize> {
        self.civilian_units
            .iter()
            .enumerate()
            .rev()
            .find(|(_, unit)| unit.location.tile() == Some(tile))
            .map(|(index, _)| index)
    }

    fn nation_has_war(&self, nation: NationId) -> bool {
        NationId::all()
            .any(|other| self.diplomacy.relationships[nation][other] == DiplomaticRelationship::War)
    }
}

fn expand_distance_map(
    state: &GameState,
    owned_tiles: &[TileId],
    allowed: CivilianTerrainAccess,
    mut seed: impl FnMut(TileId) -> bool,
) -> Vec<i8> {
    let mut distance = vec![0_i8; STRATEGIC_TILE_COUNT];
    let mut remaining = owned_tiles.len() as i32;
    for &tile in owned_tiles {
        if seed(tile) {
            distance[tile_index(tile)] = 1;
            remaining -= 1;
        }
    }
    while remaining != 0 {
        let previous = remaining as i16;
        for &tile in owned_tiles {
            if distance[tile_index(tile)] != 0 || !terrain_allowed(state.map[tile].terrain, allowed)
            {
                continue;
            }
            let mut best = 0_i8;
            for neighbor in state.map.geometry().neighbors(tile).into_iter().flatten() {
                let neighbor_distance = distance[tile_index(neighbor)];
                if neighbor_distance != 0 && (best == 0 || neighbor_distance < best) {
                    best = neighbor_distance;
                }
            }
            if best != 0 {
                distance[tile_index(tile)] = best.wrapping_add(1);
                remaining -= 1;
            }
        }
        if previous == remaining as i16 {
            remaining = 0;
        }
    }
    distance
}

fn trace_descending(start: TileId, scores: &[i8]) -> (TileId, TileId) {
    let mut current = start;
    let mut previous = start;
    let mut score = scores[tile_index(current)];
    while score != 1 {
        let desired = score.wrapping_sub(1);
        let mut chosen = HexDirection::NorthWest;
        for direction in HexDirection::ALL {
            chosen = direction;
            score = scores[tile_index(civilian_sea_scan_neighbor(current, direction))];
            if score == desired {
                break;
            }
        }
        previous = current;
        current = civilian_sea_scan_neighbor(current, chosen);
    }
    (current, previous)
}

fn insert_scored_candidate(
    score: f32,
    tile: i16,
    scores: &mut [f32],
    tiles: &mut [i16],
    rng: &mut RngState,
) {
    let mut insertion = None;
    for (index, &current) in scores.iter().enumerate() {
        if score > current || (score == current && rng.next_crt_rand() & 1 != 0) {
            insertion = Some(index);
            break;
        }
    }
    let Some(insertion) = insertion else {
        return;
    };
    for shift in (insertion + 1..scores.len()).rev() {
        scores[shift] = scores[shift - 1];
        tiles[shift] = tiles[shift - 1];
    }
    scores[insertion] = score;
    tiles[insertion] = tile;
}

fn tile_index(tile: TileId) -> usize {
    usize::from(tile.get())
}

fn turns(value: i16) -> TurnsRemaining {
    TurnsRemaining::try_new(value).expect("work orders use a positive remaining-turn count")
}

fn extractive_resource(resource: ResourceKind) -> bool {
    matches!(
        resource,
        ResourceKind::Coal
            | ResourceKind::Iron
            | ResourceKind::Oil
            | ResourceKind::Gems
            | ResourceKind::Gold
    )
}

fn traded_resource(resource: ResourceKind) -> bool {
    (resource as u8) < ResourceKind::Food as u8
        || (resource as u8) > ResourceKind::Arms as u8
            && (resource as u8) < ResourceKind::LENGTH as u8
}

fn railhead_resource(resource: ResourceKind) -> bool {
    matches!(
        resource,
        ResourceKind::Cotton
            | ResourceKind::Wool
            | ResourceKind::Timber
            | ResourceKind::Coal
            | ResourceKind::Iron
            | ResourceKind::Horses
            | ResourceKind::Oil
            | ResourceKind::Grain
            | ResourceKind::Fruit
            | ResourceKind::Fish
            | ResourceKind::Livestock
            | ResourceKind::Gems
            | ResourceKind::Gold
    )
}

fn harvested_or_raw_trade(resource: ResourceKind) -> bool {
    matches!(
        resource,
        ResourceKind::Cotton
            | ResourceKind::Wool
            | ResourceKind::Timber
            | ResourceKind::Coal
            | ResourceKind::Iron
            | ResourceKind::Horses
            | ResourceKind::Oil
            | ResourceKind::Grain
            | ResourceKind::Fruit
            | ResourceKind::Fish
            | ResourceKind::Livestock
            | ResourceKind::Gems
            | ResourceKind::Gold
    )
}

fn required_civilian_kind(resource: ResourceKind) -> Option<CivilianUnitKind> {
    match resource {
        ResourceKind::Cotton | ResourceKind::Grain | ResourceKind::Fruit => {
            Some(CivilianUnitKind::Farmer)
        }
        ResourceKind::Wool | ResourceKind::Livestock => Some(CivilianUnitKind::Rancher),
        ResourceKind::Timber => Some(CivilianUnitKind::Forester),
        ResourceKind::Fish => Some(CivilianUnitKind::Fisherman),
        _ => None,
    }
}

fn always_qualifies(resource: ResourceKind) -> bool {
    matches!(
        resource,
        ResourceKind::Cotton
            | ResourceKind::Wool
            | ResourceKind::Timber
            | ResourceKind::Coal
            | ResourceKind::Iron
            | ResourceKind::Oil
            | ResourceKind::Gems
            | ResourceKind::Gold
    )
}

fn gate_qualifies(gate: i8) -> bool {
    let index = gate as u8 as usize;
    GATE_QUALIFIES.get(index).is_some_and(|flag| *flag != 0)
}

fn prospectable_terrain(terrain: TerrainKind, oil: bool) -> bool {
    match terrain {
        TerrainKind::Hills | TerrainKind::Mountain => true,
        TerrainKind::Swamp | TerrainKind::Desert => oil,
        _ => false,
    }
}

fn primary_distance_terrain(access: CivilianTerrainAccess) -> CivilianTerrainAccess {
    access
}

fn secondary_distance_terrain(capabilities: CityTechnologyCapabilities) -> CivilianTerrainAccess {
    CivilianTerrainAccess {
        hills: capabilities.secondary_civilian_hills,
        mountain: capabilities.oil_drilling,
        swamp: capabilities.secondary_civilian_swamp,
    }
}

fn terrain_allowed(terrain: TerrainKind, access: CivilianTerrainAccess) -> bool {
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
