//! First-turn military cleanup and AI replanning (`TSimMgr` phase `0x15`).

use crate::*;

const FIRST_TURN_AI_COUNT: usize = 6;
const FIRST_TURN_MISSIONS_PER_AI: usize = 11;
const FIRST_TURN_DEFEND_MISSIONS_PER_AI: usize = 8;
const FIRST_TURN_CONTROL_ZONE_BY_AI: [u16; FIRST_TURN_AI_COUNT] = [22, 42, 26, 21, 8, 11];
const FIRST_TURN_PORT_ZONE_BY_AI: [u16; FIRST_TURN_AI_COUNT] = [66, 65, 64, 63, 62, 61];
const FIRST_TURN_PRIMARY_SEA_ZONE_BY_PORT: [u16; NationId::COUNT as usize] = [
    24, 24, 15, 11, 27, 52, 20, 48, 13, 22, 25, 6, 20, 51, 52, 47, 22, 42, 26, 21, 8, 11, 36,
];
const WATER_OWNER_TAG_BASE: u8 = NationId::COUNT;
const UNIT_PROFILE_BASELINE: [i16; 5] = [40, 27, 0, 17, 16];
const UNIT_PROFILE_FORTIFIED: [i16; 5] = [40, 22, 0, 38, 0];
const NAVY_CONTROL_PROFILE: [i16; 4] = [40, 40, 20, 0];
const NAVY_ESCORT_PROFILE: [i16; 4] = [40, 30, 30, 0];
const MISSION_DISTANCE_WEIGHTS: [f32; 2] = [1.0, 0.8];

#[derive(Debug)]
pub(crate) struct MilitaryCleanupPlan {
    city_scores: ProvinceTable<i32>,
    pressure: MajorNationTable<Option<AiDevelopmentPressureState>>,
    missions: Vec<MissionState>,
    development_actions: MajorNationTable<Vec<PendingDevelopmentAction>>,
    crt_rand: RetailCrtRng,
}

impl GameState {
    /// Builds the recovered Easy beginning-save cleanup plan, or `None` for unrecovered branches.
    pub(crate) fn try_first_turn_military_cleanup_phase(&self) -> Option<MilitaryCleanupPlan> {
        self.first_turn_military_cleanup_plan()
    }

    /// Applies a previously validated cleanup plan. Phase advancement remains the turn driver's
    /// responsibility.
    pub(crate) fn apply_military_cleanup_plan(&mut self, plan: MilitaryCleanupPlan) {
        for slot in 0..ProvinceId::COUNT {
            let province = ProvinceId::new(slot);
            self.provinces[province].set_city_score(plan.city_scores[province]);
        }
        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            self.nations.majors[nation].economy.ai_development_pressure = plan.pressure[nation];
            self.nations.majors[nation]
                .economy
                .interior_civilian
                .pending_development_actions = plan.development_actions[nation].clone();
        }
        self.missions = plan.missions;
        self.rng.crt_rand = plan.crt_rand;

        // The final cleanup pass applies every major nation's phase-seven purchase ledger.
        for slot in 0..MajorNationId::COUNT {
            self.commit_purchased_items(MajorNationId::new(slot));
        }
    }

    fn first_turn_military_cleanup_plan(&self) -> Option<MilitaryCleanupPlan> {
        if self.turn.phase != PhaseCode::MILITARY_CLEANUP
            || self.turn.economic_turn != 1
            || self.turn.difficulty != Difficulty::Easy
            || self.turn.scenario_map.is_some()
            || self.turn.active_nation != MajorNationId::new(6).nation()
            || self.turn.selected_nation != self.turn.active_nation
            || !self.ships.is_empty()
            || !self.task_forces.is_empty()
            || self.missions.len() != FIRST_TURN_AI_COUNT * FIRST_TURN_MISSIONS_PER_AI
            || self.missions.iter().any(|mission| mission.marker != 0)
            || !self.first_turn_port_zones_are_supported()
            || !self.first_turn_mission_topology_is_supported()
            || !self.first_turn_ai_standings_are_supported()
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

        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            if self.nations.majors[nation].economy.controller.is_human()
                != (slot == FIRST_TURN_AI_COUNT as u8)
            {
                return None;
            }
        }

        let city_scores = self.first_turn_heatmap_plan()?;
        if (0..ProvinceId::COUNT).any(|slot| {
            let province = ProvinceId::new(slot);
            self.provinces[province].city_score() != city_scores[province]
        }) || !self.first_turn_cleanup_units_are_supported()
        {
            return None;
        }

        let pressure = self.first_turn_ai_pressure_plan()?;
        let mut missions = self.missions.clone();
        let mut assigned = vec![false; self.military_units.len()];
        self.seed_first_turn_militia(&mut missions, &mut assigned)?;
        self.reassess_first_turn_missions(&mut missions, &city_scores, &pressure)?;

        let mut crt_rand = self.rng.crt_rand;
        for nation_slot in 0..FIRST_TURN_AI_COUNT {
            let start = nation_slot * FIRST_TURN_MISSIONS_PER_AI;
            let end = start + FIRST_TURN_MISSIONS_PER_AI;
            quick_sort_missions(&mut missions[start..end], &mut crt_rand);
            missions[start..end]
                .iter_mut()
                .for_each(|mission| mission.held = false);
            self.assign_first_turn_units(&mut missions[start..end], &mut assigned)?;
        }

        if self
            .military_units
            .iter()
            .zip(&assigned)
            .any(|(unit, assigned)| *assigned != (unit.nation.get() < FIRST_TURN_AI_COUNT as u8))
        {
            return None;
        }
        let development_actions = self.first_turn_development_action_plan(&missions)?;

        Some(MilitaryCleanupPlan {
            city_scores,
            pressure,
            missions,
            development_actions,
            crt_rand,
        })
    }

    fn first_turn_cleanup_units_are_supported(&self) -> bool {
        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot).nation();
            let units: Vec<_> = self
                .military_units
                .iter()
                .filter(|unit| unit.nation == nation)
                .collect();
            if units.len() != 27
                || units.iter().any(|unit| {
                    !unit.registered
                        || unit.owner_nation != nation
                        || unit.stationed_province.is_none()
                        || unit.strength != 500
                        || unit.era != 0
                        || unit.experience != 0
                        || unit.battle_flags != 0
                        || primary_target(&unit.order).is_some()
                })
                || units
                    .iter()
                    .filter(|unit| unit.unit_type == MilitaryUnitKind::Minutemen)
                    .count()
                    != 24
                || units
                    .iter()
                    .filter(|unit| unit.unit_type == MilitaryUnitKind::Regulars)
                    .count()
                    != 2
                || units
                    .iter()
                    .filter(|unit| unit.unit_type == MilitaryUnitKind::Artillery)
                    .count()
                    != 1
            {
                return false;
            }
        }
        true
    }

    fn first_turn_port_zones_are_supported(&self) -> bool {
        if self.port_zone_owners.len() != NationId::COUNT as usize {
            return false;
        }
        self.port_zone_owners
            .iter()
            .enumerate()
            .all(|(index, port)| {
                let (owner, zone) = if index < MinorNationId::COUNT as usize {
                    (
                        NationId::new(NationId::COUNT - 1 - index as u8),
                        82 - index as u16,
                    )
                } else {
                    let major = index - MinorNationId::COUNT as usize;
                    (NationId::new(major as u8), 66 - major as u16)
                };
                port.former_owner == owner
                    && port.zone == OceanZoneId::new(zone)
                    && self.first_turn_primary_sea_zone(owner)
                        == Some(OceanZoneId::new(FIRST_TURN_PRIMARY_SEA_ZONE_BY_PORT[index]))
                    && self
                        .nations
                        .common(owner)
                        .and_then(|common| common.home_tile)
                        .and_then(|home| self.world[home].owner_nation)
                        .and_then(TileOwnerTag::nation)
                        == Some(owner)
            })
    }

    fn first_turn_mission_topology_is_supported(&self) -> bool {
        for slot in 0..FIRST_TURN_AI_COUNT {
            let nation = MajorNationId::new(slot as u8).nation();
            let start = slot * FIRST_TURN_MISSIONS_PER_AI;
            let missions = &self.missions[start..start + FIRST_TURN_MISSIONS_PER_AI];
            if missions.iter().any(|mission| mission.nation != nation) {
                return false;
            }
            for mission in &missions[..FIRST_TURN_DEFEND_MISSIONS_PER_AI] {
                let MissionData::DefendProvince { province, .. } = mission.data else {
                    return false;
                };
                if self.provinces[province].owner() != Some(nation) {
                    return false;
                }
            }

            let expected_control = OceanZoneId::new(FIRST_TURN_CONTROL_ZONE_BY_AI[slot]);
            let expected_port = OceanZoneId::new(FIRST_TURN_PORT_ZONE_BY_AI[slot]);
            let MissionData::ControlSeaZone(control) =
                &missions[FIRST_TURN_DEFEND_MISSIONS_PER_AI].data
            else {
                return false;
            };
            let MissionData::Escort(escort) = &missions[FIRST_TURN_DEFEND_MISSIONS_PER_AI + 1].data
            else {
                return false;
            };
            if control.target_zone != Some(expected_control)
                || control.resolved_port_zone != Some(expected_port)
                || escort.target_zone != Some(expected_port)
                || escort.resolved_port_zone != Some(expected_port)
                || !matches!(
                    missions[FIRST_TURN_DEFEND_MISSIONS_PER_AI + 2].data,
                    MissionData::ScatteredShips(_)
                )
            {
                return false;
            }
        }
        true
    }

    fn first_turn_ai_standings_are_supported(&self) -> bool {
        (0..FIRST_TURN_AI_COUNT).all(|source| {
            let source = MajorNationId::new(source as u8).nation();
            (0..MajorNationId::COUNT).all(|target| {
                let target = MajorNationId::new(target).nation();
                source == target || self.diplomacy.standings[source][target] < 100
            })
        })
    }

    fn first_turn_ai_pressure_plan(
        &self,
    ) -> Option<MajorNationTable<Option<AiDevelopmentPressureState>>> {
        let mut mobile_score = [0.0_f32; MajorNationId::COUNT as usize];
        let mut mobile_divergence = [0.0_f32; MajorNationId::COUNT as usize];
        let mut combined_divergence = [0.0_f32; MajorNationId::COUNT as usize];

        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot).nation();
            let mut mobile = [0.0_f32; 5];
            let mut combined = [0.0_f32; 5];
            for unit in self.military_units.iter().filter(|unit| {
                unit.nation == nation && unit.unit_type != MilitaryUnitKind::Minutemen
            }) {
                let contribution = first_turn_unit_contribution(unit, 1.0, 0.33)?;
                for index in 0..5 {
                    combined[index] += contribution[index];
                    mobile[index] += contribution[index];
                }
            }
            for unit in self.military_units.iter().filter(|unit| {
                unit.nation == nation && unit.unit_type == MilitaryUnitKind::Minutemen
            }) {
                let contribution = first_turn_unit_contribution(unit, 1.0, 0.33)?;
                for index in 0..5 {
                    combined[index] += contribution[index];
                }
            }
            let index = usize::from(slot);
            mobile_score[index] = normalize_unit_vector(mobile, [27, 36, 0, 17, 20]);
            mobile_divergence[index] = normalize_unit_vector(mobile, UNIT_PROFILE_BASELINE);
            combined_divergence[index] = normalize_unit_vector(combined, UNIT_PROFILE_BASELINE);
        }

        let mut pressure = MajorNationTable::default();
        for slot in 0..FIRST_TURN_AI_COUNT as u8 {
            let nation = MajorNationId::new(slot);
            let common = &self.nations.majors[nation].common;
            let total_regions = common.owned_regions().len();
            let compatible_regions = common
                .owned_regions()
                .iter()
                .filter(|&&province| self.first_turn_province_is_compatible(nation, province))
                .count();
            if total_regions == 0 || compatible_regions == 0 {
                return None;
            }

            let own_index = usize::from(slot);
            let own_unit_divergence = combined_divergence[own_index] - mobile_divergence[own_index];
            let average_unit_divergence = own_unit_divergence / total_regions as f32;
            let mut maximum_raw_military = 0.0_f32;
            let mut minimum_peer_combined = -1.0_f32;
            for peer_slot in 0..MajorNationId::COUNT {
                if peer_slot == slot {
                    continue;
                }
                let peer_index = usize::from(peer_slot);
                maximum_raw_military = maximum_raw_military.max(mobile_score[peer_index]);
                if minimum_peer_combined == -1.0
                    || combined_divergence[peer_index] < minimum_peer_combined
                {
                    minimum_peer_combined = combined_divergence[peer_index];
                }
            }

            let mut military_ratio =
                maximum_raw_military / (mobile_divergence[own_index] + average_unit_divergence);
            if military_ratio > 1.0 {
                military_ratio = 1.0;
            }
            let maximum_adjusted = (military_ratio - -1.0) * 0.5 * 1.1 * minimum_peer_combined;
            if maximum_adjusted <= maximum_raw_military {
                return None;
            }
            let mut expansion = maximum_adjusted - own_unit_divergence;
            if expansion < 0.0 {
                expansion = 1.0;
            }
            expansion /= compatible_regions as f32;

            pressure[nation] = Some(AiDevelopmentPressureState {
                expansion_pressure_per_compatible_region_bits: expansion.to_bits(),
                average_unit_divergence_per_owned_region_bits: average_unit_divergence.to_bits(),
                // With no ships, every nation's navy-order divergence is zero. Retail
                // divides that zero peer maximum by the one scattered-ships mission.
                active_mission_pressure_average_bits: 0.0_f32.to_bits(),
            });
        }
        Some(pressure)
    }

    fn first_turn_province_is_compatible(
        &self,
        nation: MajorNationId,
        province: ProvinceId,
    ) -> bool {
        let common = &self.nations.majors[nation].common;
        if common
            .home_tile
            .is_some_and(|home| self.world[home].province == Some(province))
        {
            return true;
        }
        self.provinces[province]
            .adjacency()
            .iter()
            .any(|&adjacent| {
                self.provinces[adjacent].owner().is_some_and(|owner| {
                    owner.get() < MajorNationId::COUNT && owner != nation.nation()
                })
            })
    }

    fn seed_first_turn_militia(
        &self,
        missions: &mut [MissionState],
        assigned: &mut [bool],
    ) -> Option<()> {
        if missions.iter().any(|mission| match &mission.data {
            MissionData::DefendProvince { army, .. } => !army.units.is_empty(),
            MissionData::ControlSeaZone(navy) => {
                !navy.ships.is_empty()
                    || navy.selected_ship.is_some()
                    || navy.task_force.is_some()
                    || navy.state != 0
                    || navy.target_zone.is_none()
                    || navy.resolved_port_zone.is_none()
            }
            MissionData::Escort(navy) => {
                !navy.ships.is_empty()
                    || navy.selected_ship.is_some()
                    || navy.task_force.is_some()
                    || navy.state != 0
                    || navy.target_zone.is_none()
                    || navy.target_zone != navy.resolved_port_zone
            }
            MissionData::ScatteredShips(navy) => {
                !navy.ships.is_empty()
                    || navy.selected_ship.is_some()
                    || navy.task_force.is_some()
                    || navy.state != 0
                    || navy.target_zone.is_some()
                    || navy.resolved_port_zone.is_some()
            }
            _ => true,
        }) {
            return None;
        }

        for (unit_index, unit) in self.military_units.iter().enumerate() {
            if unit.unit_type != MilitaryUnitKind::Minutemen
                || unit.nation.get() >= FIRST_TURN_AI_COUNT as u8
            {
                continue;
            }
            let province = unit.stationed_province?;
            let mission = missions.iter_mut().find(|mission| {
                mission.nation == unit.nation
                    && matches!(
                        mission.data,
                        MissionData::DefendProvince { province: target, .. } if target == province
                    )
            })?;
            let MissionData::DefendProvince { army, .. } = &mut mission.data else {
                unreachable!();
            };
            army.units.insert(0, unit.id);
            assigned[unit_index] = true;
        }
        Some(())
    }

    fn reassess_first_turn_missions(
        &self,
        missions: &mut [MissionState],
        city_scores: &ProvinceTable<i32>,
        pressure: &MajorNationTable<Option<AiDevelopmentPressureState>>,
    ) -> Option<()> {
        for (index, mission) in missions.iter_mut().enumerate() {
            let nation = MajorNationId::from_nation(mission.nation)?;
            if usize::from(nation.get()) != index / FIRST_TURN_MISSIONS_PER_AI {
                return None;
            }
            let development = pressure[nation]?;
            match &mut mission.data {
                MissionData::DefendProvince { province, army } => {
                    mission.state = if self.nations.majors[nation]
                        .common
                        .home_tile
                        .is_some_and(|home| self.world[home].province == Some(*province))
                    {
                        0
                    } else {
                        2
                    };
                    mission.importance_bits = self
                        .first_turn_defend_importance(nation, *province, city_scores)
                        .to_bits();
                    army.required_equipage_bits = self
                        .first_turn_defend_needs(nation, *province, development)?
                        .map(f32::to_bits);
                }
                MissionData::ControlSeaZone(navy) => {
                    let target = navy.target_zone?;
                    navy.resolved_port_zone?;
                    mission.state = 2;
                    mission.importance_bits = self
                        .first_turn_navy_importance(nation, target, city_scores)?
                        .to_bits();
                    navy.required_equipage_bits =
                        navy_needs(NAVY_CONTROL_PROFILE, 100.0).map(f32::to_bits);
                }
                MissionData::Escort(navy) => {
                    let primary_zone = self.first_turn_primary_sea_zone(nation.nation())?;
                    mission.state = 2;
                    let score = self.first_turn_navy_score(nation, primary_zone, city_scores)?;
                    let economy = &self.nations.majors[nation].economy;
                    let transport = economy.capacities.transport.max(1);
                    mission.importance_bits =
                        ((f64::from(score) / 5_000.0 * f64::from(economy.capacities.trade_offer)
                            / f64::from(transport)) as f32)
                            .to_bits();
                    navy.required_equipage_bits =
                        navy_needs(NAVY_ESCORT_PROFILE, 1.0).map(f32::to_bits);
                }
                MissionData::ScatteredShips(navy) => {
                    mission.state = 3;
                    mission.importance_bits = 0.001_f32.to_bits();
                    navy.required_equipage_bits = navy_needs(
                        NAVY_CONTROL_PROFILE,
                        development.active_mission_pressure_average() + 1.0,
                    )
                    .map(f32::to_bits);
                }
                _ => return None,
            }
        }
        Some(())
    }

    fn first_turn_defend_importance(
        &self,
        nation: MajorNationId,
        province: ProvinceId,
        city_scores: &ProvinceTable<i32>,
    ) -> f32 {
        let state = &self.provinces[province];
        let mut importance = city_scores[province] as f32;
        if !state.adjacency().is_empty() {
            let owned = state
                .adjacency()
                .iter()
                .filter(|&&adjacent| self.provinces[adjacent].owner() == Some(nation.nation()))
                .count();
            importance = ((owned as f64 / state.adjacency().len() as f64 - f64::from(-1.0_f32))
                * f64::from(importance)) as f32;
        }
        (f64::from(importance) / f64::from(5_000.0_f32)) as f32
    }

    fn first_turn_defend_needs(
        &self,
        nation: MajorNationId,
        province: ProvinceId,
        pressure: AiDevelopmentPressureState,
    ) -> Option<[f32; 5]> {
        let average = pressure.average_unit_divergence_per_owned_region();
        if !self.first_turn_province_is_compatible(nation, province) {
            let attributes = first_turn_unit_attributes(MilitaryUnitKind::Minutemen)?;
            let total: i16 = attributes[..5].iter().sum();
            return Some(std::array::from_fn(|index| {
                f32::from(attributes[index]) * average / f32::from(total)
            }));
        }

        let scale = pressure.expansion_pressure_per_compatible_region() + average;
        let profile = if self.provinces[province].fort_level() < 1 {
            UNIT_PROFILE_BASELINE
        } else {
            UNIT_PROFILE_FORTIFIED
        };
        Some(profile.map(|value| (f64::from(value) * f64::from(scale) * 0.01_f64) as f32))
    }

    fn first_turn_navy_importance(
        &self,
        nation: MajorNationId,
        zone: OceanZoneId,
        city_scores: &ProvinceTable<i32>,
    ) -> Option<f32> {
        Some(self.first_turn_navy_score(nation, zone, city_scores)? / 5_000.0)
    }

    fn first_turn_navy_score(
        &self,
        nation: MajorNationId,
        zone: OceanZoneId,
        city_scores: &ProvinceTable<i32>,
    ) -> Option<f32> {
        let geometry = self.world.geometry();
        let owner_tag = WATER_OWNER_TAG_BASE.checked_add(zone.get().try_into().ok()?)?;
        let mut seen = ProvinceTable::<bool>::default();
        for tile_index in 0..TileId::COUNT {
            let tile = TileId::new(tile_index);
            if self.world[tile].terrain != TerrainKind::Water
                || self.world[tile].owner_nation.map(TileOwnerTag::get) != Some(owner_tag)
            {
                continue;
            }
            for neighbor in geometry.neighbors(tile).into_iter().flatten() {
                if let Some(province) = self.world[neighbor].province {
                    seen[province] = true;
                }
            }
        }
        let mut sum = 0_u32;
        let mut count = 0_u32;
        for slot in 0..ProvinceId::COUNT {
            let province = ProvinceId::new(slot);
            if seen[province] {
                sum = sum.checked_add(city_scores[province].try_into().ok()?)?;
                count += 1;
            }
        }
        if count == 0 {
            return None;
        }
        let mut score = (sum / count) as f32;
        for port in &self.port_zone_owners {
            if self.first_turn_primary_sea_zone(port.former_owner)? != zone {
                continue;
            }
            let multiplier = if port.former_owner == nation.nation() {
                1.5_f64
            } else {
                1.25_f64
            };
            score = (f64::from(score) * multiplier) as f32;
        }
        Some(score)
    }

    fn first_turn_primary_sea_zone(&self, nation: NationId) -> Option<OceanZoneId> {
        let home = self.nations.common(nation)?.home_tile?;
        let geometry = self.world.geometry();
        for offset in 0..6_u16 {
            let direction = HexDirection::ALL[usize::from((home.get() + offset) % 6)];
            let Some(candidate) = geometry.neighbor(home, direction) else {
                continue;
            };
            if self.world[candidate].terrain != TerrainKind::Water {
                continue;
            }
            let qualifies = geometry
                .neighbors(candidate)
                .into_iter()
                .flatten()
                .all(|neighbor| match self.world[neighbor].owner_nation {
                    Some(owner) if owner.get() >= NationId::COUNT => true,
                    Some(owner) => owner.nation() == Some(nation),
                    None => false,
                });
            if qualifies {
                return ocean_zone_from_water_owner(self.world[candidate].owner_nation?);
            }
        }

        // The Easy fixture's sole fallback port has only one adjacent sea context;
        // retail's terrain-flow fallback therefore resolves that same context.
        let mut fallback = None;
        for neighbor in geometry.neighbors(home).into_iter().flatten() {
            if self.world[neighbor].terrain != TerrainKind::Water {
                continue;
            }
            let zone = ocean_zone_from_water_owner(self.world[neighbor].owner_nation?)?;
            if fallback.is_some_and(|existing| existing != zone) {
                return None;
            }
            fallback = Some(zone);
        }
        fallback
    }

    fn assign_first_turn_units(
        &self,
        missions: &mut [MissionState],
        assigned: &mut [bool],
    ) -> Option<()> {
        loop {
            let best_mission = best_first_turn_army_mission(missions, self)?;
            let Some(mission_index) = best_mission else {
                return Some(());
            };
            let weights = mission_lack_fractions(&missions[mission_index], self)?;
            let mut best_unit = None;
            let mut best_score = 0.0_f32;
            for (unit_index, unit) in self.military_units.iter().enumerate() {
                if assigned[unit_index] || unit.nation != missions[mission_index].nation {
                    continue;
                }
                let score = first_turn_unit_fitness(&missions[mission_index], unit, weights)?;
                // VC5 compares the fresh x87 result with the prior score spilled to f32.
                if best_unit.is_none() || f64::from(best_score) < score {
                    best_unit = Some(unit_index);
                    best_score = score as f32;
                }
            }
            let Some(unit_index) = best_unit else {
                return Some(());
            };
            let MissionData::DefendProvince { army, .. } = &mut missions[mission_index].data else {
                return None;
            };
            army.units.insert(0, self.military_units[unit_index].id);
            assigned[unit_index] = true;
        }
    }

    fn first_turn_development_action_plan(
        &self,
        missions: &[MissionState],
    ) -> Option<MajorNationTable<Vec<PendingDevelopmentAction>>> {
        const ENABLED_INDUSTRIES: [bool; 14] = [
            true, true, true, true, true, false, false, false, false, false, false, false, false,
            false,
        ];
        const ACTIVE_UNITS: [bool; 30] = [
            true, true, true, true, true, true, true, true, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, true,
            false, false, true, false, false,
        ];
        if self.technology.industry_enabled_by_slot != ENABLED_INDUSTRIES {
            return None;
        }

        let mut plan = MajorNationTable::from_fn(|_| Vec::new());
        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            let interior = &self.nations.majors[nation].economy.interior_civilian;
            if self.technology.military_unit_ability_active_by_nation[nation]
                .values()
                .copied()
                .ne(ACTIVE_UNITS)
                || interior.average_development_order_allocation != 0
                || !interior.pending_development_actions.is_empty()
            {
                return None;
            }
            if usize::from(slot) == FIRST_TURN_AI_COUNT {
                continue;
            }

            let mut pools = [0_i32; 9];
            for mission in missions
                .iter()
                .filter(|mission| mission.nation == nation.nation() && !mission.held)
            {
                match &mission.data {
                    MissionData::DefendProvince { army, .. } => {
                        let vector = mission_unit_vector(mission, self)?;
                        for index in 0..5 {
                            let required = f32::from_bits(army.required_equipage_bits[index]);
                            let value = if required <= vector[index] {
                                required - vector[index]
                            } else {
                                required - vector[index] + pools[index] as f32
                            };
                            pools[index] = value as i32;
                        }
                    }
                    MissionData::ControlSeaZone(navy)
                    | MissionData::Escort(navy)
                    | MissionData::ScatteredShips(navy) => {
                        if !navy.ships.is_empty() {
                            return None;
                        }
                        for index in 0..4 {
                            pools[index + 5] = (pools[index + 5] as f32
                                + f32::from_bits(navy.required_equipage_bits[index]))
                                as i32;
                        }
                    }
                    _ => return None,
                }
            }

            let mut industry_count = 0;
            let mut city_count = 0;
            for _ in 0..99 {
                let Some(action) = self.first_turn_select_development_action(nation, &mut pools)?
                else {
                    break;
                };
                let apply = match action {
                    PendingDevelopmentAction::Industry { .. } => {
                        let apply = industry_count < 1;
                        industry_count += 1;
                        apply
                    }
                    PendingDevelopmentAction::LandUnit { .. } => {
                        let apply = city_count < 2;
                        city_count += 1;
                        apply
                    }
                };
                if industry_count > 1 && city_count > 2 {
                    break;
                }
                if apply {
                    plan[nation].push(action);
                }
                subtract_first_turn_development_action(&mut pools, action)?;
            }
        }
        Some(plan)
    }

    fn first_turn_select_development_action(
        &self,
        nation: MajorNationId,
        pools: &mut [i32; 9],
    ) -> Option<Option<PendingDevelopmentAction>> {
        if pools.iter().all(|&value| value <= 0) {
            return Some(None);
        }

        let abilities = &self.technology.military_unit_ability_active_by_nation[nation];
        let mut best = None;
        let mut best_score = 0.0_f32;
        for index in 0..30_u8 {
            let unit_type = MilitaryUnitKind::from_index(index)?;
            if !abilities[unit_type]
                || matches!(
                    unit_type,
                    MilitaryUnitKind::Minutemen
                        | MilitaryUnitKind::GeneralEra1
                        | MilitaryUnitKind::GeneralEra2
                        | MilitaryUnitKind::GeneralEra3
                )
            {
                continue;
            }
            let attributes = first_turn_unit_attributes(unit_type)?;
            let weighted = (0..5)
                .filter(|&pool| pools[pool] > 0)
                .map(|pool| i32::from(attributes[pool]) * pools[pool])
                .sum::<i32>() as f32;
            let score = weighted / self.first_turn_city_action_cost(nation, unit_type)?;
            if score > best_score {
                best_score = score;
                best = Some(PendingDevelopmentAction::LandUnit { unit_type });
            }
        }

        for class in 0..4_i8 {
            let slot = (1..14_u8).rev().find_map(|index| {
                let production = CityFacilitySlot::from_index(index)?;
                (self.technology.industry_enabled_by_slot[usize::from(index)]
                    && first_turn_industry_class(production) == Some(class))
                .then_some(production)
            });
            let Some(slot) = slot else {
                continue;
            };
            let costs = first_turn_industry_normalized_costs(slot)?;
            let weighted = (0..4)
                .filter(|&pool| pools[pool + 5] > 0)
                .map(|pool| costs[pool] * pools[pool + 5])
                .sum::<i32>() as f32;
            let score = weighted / self.first_turn_industry_action_cost(slot)? as f32;
            if score > best_score {
                best_score = score;
                best = Some(PendingDevelopmentAction::Industry { slot });
            }
        }

        if let Some(action) = best {
            subtract_first_turn_development_action(pools, action)?;
        }
        Some(best)
    }

    fn first_turn_city_action_cost(
        &self,
        nation: MajorNationId,
        unit_type: MilitaryUnitKind,
    ) -> Option<f32> {
        let price = |commodity| self.market.rows[commodity].price;
        let base_bias = price(TradeCommodity::Clothing)
            + price(TradeCommodity::Furniture)
            + price(TradeCommodity::Food);
        let paper_bias = base_bias + price(TradeCommodity::Paper) + 100;
        let full_bias = paper_bias + 2 * price(TradeCommodity::Paper) + 1_000;
        let horses_available =
            self.nations.majors[nation].economy.need_current_by_type[ResourceKind::Horses];
        let (arms, horses, base, bias): (i32, i16, i32, i32) = match unit_type {
            MilitaryUnitKind::Skirmishers => (1, 0, 200, base_bias),
            MilitaryUnitKind::Regulars => (1, 0, 500, base_bias),
            MilitaryUnitKind::Grenadiers => (1, 0, 1_000, paper_bias),
            MilitaryUnitKind::Hussars => (1, 1, 100, base_bias),
            MilitaryUnitKind::Cuirassiers => (1, 1, 500, paper_bias),
            MilitaryUnitKind::LightArtillery => (2, 1, 1_000, paper_bias),
            MilitaryUnitKind::Artillery => (2, 0, 1_000, paper_bias),
            MilitaryUnitKind::Sappers => (2, 0, 5_000, full_bias),
            _ => return None,
        };
        let horse_cost = if horses > 0 && horses_available < horses {
            i32::from(horses) * price(TradeCommodity::Horses)
        } else {
            0
        };
        Some((arms * price(TradeCommodity::Arms) + horse_cost + base + bias) as f32)
    }

    fn first_turn_industry_action_cost(&self, slot: CityFacilitySlot) -> Option<i32> {
        let price = |commodity| self.market.rows[commodity].price;
        let weights = match slot {
            CityFacilitySlot::Metalworks => [0, 2, 5, 0, 2, 0],
            CityFacilitySlot::LumberMill => [0, 3, 8, 0, 5, 0],
            _ => return None,
        };
        Some(
            price(TradeCommodity::Steel) * weights[0]
                + price(TradeCommodity::Fabric) * weights[1]
                + price(TradeCommodity::Lumber) * weights[2]
                + price(TradeCommodity::Fuel) * weights[3]
                + price(TradeCommodity::Arms) * weights[4]
                + price(TradeCommodity::Coal) * weights[5],
        )
    }
}

fn primary_target(order: &MilitaryOrder) -> Option<ProvinceId> {
    match order {
        MilitaryOrder::Idle { .. } => None,
        MilitaryOrder::Retail { target, .. } => *target,
    }
}

fn first_turn_unit_attributes(unit: MilitaryUnitKind) -> Option<[i16; 6]> {
    match unit {
        MilitaryUnitKind::Minutemen => Some([25, 13, 1, 1, 10, 0]),
        MilitaryUnitKind::Skirmishers => Some([33, 16, 1, 1, 35, 30]),
        MilitaryUnitKind::Regulars => Some([50, 20, 1, 1, 10, 0]),
        MilitaryUnitKind::Grenadiers => Some([62, 30, 1, 1, 10, 0]),
        MilitaryUnitKind::Hussars => Some([23, 26, 1, 1, 70, 20]),
        MilitaryUnitKind::Cuirassiers => Some([26, 60, 1, 1, 60, 0]),
        MilitaryUnitKind::LightArtillery => Some([6, 96, 46, 66, 5, 0]),
        MilitaryUnitKind::Artillery => Some([20, 13, 92, 93, 5, 0]),
        MilitaryUnitKind::Sappers => Some([8, 6, 238, 1, 10, 0]),
        _ => None,
    }
}

fn first_turn_industry_class(slot: CityFacilitySlot) -> Option<i8> {
    match slot {
        CityFacilitySlot::Metalworks | CityFacilitySlot::PowerPlant => Some(1),
        CityFacilitySlot::LumberMill | CityFacilitySlot::TradeSchool => Some(0),
        CityFacilitySlot::Shipyard | CityFacilitySlot::Warehouse => Some(2),
        CityFacilitySlot::Armory | CityFacilitySlot::FoodProcessing => Some(3),
        _ => None,
    }
}

fn first_turn_industry_normalized_costs(slot: CityFacilitySlot) -> Option<[i32; 4]> {
    match slot {
        CityFacilitySlot::Metalworks => Some([51, 56, 100, 50]),
        CityFacilitySlot::LumberMill => Some([148, 143, 75, 125]),
        _ => None,
    }
}

fn subtract_first_turn_development_action(
    pools: &mut [i32; 9],
    action: PendingDevelopmentAction,
) -> Option<()> {
    match action {
        PendingDevelopmentAction::Industry { slot } => {
            let costs = first_turn_industry_normalized_costs(slot)?;
            for index in 0..4 {
                pools[index + 5] -= costs[index];
            }
        }
        PendingDevelopmentAction::LandUnit { unit_type } => {
            let attributes = first_turn_unit_attributes(unit_type)?;
            for index in 0..5 {
                pools[index] -= i32::from(attributes[index]);
            }
        }
    }
    Some(())
}

fn first_turn_unit_contribution(
    unit: &MilitaryUnitState,
    scale: f32,
    weight: f32,
) -> Option<[f32; 5]> {
    let attributes = first_turn_unit_attributes(unit.unit_type)?;
    let dampen = 1.0 - f32::from(attributes[5]) * weight * -0.0001;
    let scaled =
        f32::from(unit.strength) * 0.002 * (1.0 - f32::from(unit.experience / 100) * -0.1) * scale;
    Some([
        f32::from(unit.strength) * 0.002 * f32::from(attributes[0]) * scaled * dampen,
        f32::from(attributes[1]) * scaled * dampen,
        f32::from(attributes[2]) * scaled,
        f32::from(attributes[3]) * scaled,
        f32::from(attributes[4]) * scaled * dampen,
    ])
}

fn normalize_unit_vector(vector: [f32; 5], profile: [i16; 5]) -> f32 {
    let sum = vector.into_iter().sum::<f32>();
    if sum == 0.0 {
        return 0.0;
    }
    let mut difference = 0.0_f32;
    for index in 0..5 {
        let component = (f64::from(vector[index] / sum) - f64::from(profile[index]) * 0.01) as f32;
        difference += component.abs();
    }
    sum * (1.0 - difference * 0.5)
}

fn navy_needs(profile: [i16; 4], total: f32) -> [f32; 4] {
    profile.map(|value| (f64::from(f32::from(value) * total) * 0.01) as f32)
}

fn ocean_zone_from_water_owner(owner: TileOwnerTag) -> Option<OceanZoneId> {
    let zone = owner.get().checked_sub(WATER_OWNER_TAG_BASE)?;
    Some(OceanZoneId::new(u16::from(zone)))
}

fn quick_sort_missions(missions: &mut [MissionState], rng: &mut RetailCrtRng) {
    if missions.len() > 1 {
        quick_sort_mission_range(missions, 0, missions.len() - 1, rng);
    }
}

fn quick_sort_mission_range(
    missions: &mut [MissionState],
    lo: usize,
    hi: usize,
    rng: &mut RetailCrtRng,
) {
    if lo >= hi {
        return;
    }
    let pivot_ordinal = lo + rng.next_rand() as usize % (hi - lo);
    missions.swap(lo, pivot_ordinal);
    let pivot = missions[lo].clone();
    let mut below = lo as isize - 1;
    let mut above = hi + 1;
    loop {
        loop {
            above -= 1;
            if compare_mission_efficiency(&pivot, &missions[above]) >= 0 {
                break;
            }
        }
        loop {
            below += 1;
            if compare_mission_efficiency(&pivot, &missions[below as usize]) <= 0 {
                break;
            }
        }
        if above as isize <= below {
            break;
        }
        missions.swap(below as usize, above);
    }
    quick_sort_mission_range(missions, lo, above, rng);
    quick_sort_mission_range(missions, above + 1, hi, rng);
}

fn compare_mission_efficiency(left: &MissionState, right: &MissionState) -> i16 {
    if (right.state as i8) < left.state as i8 {
        return 1;
    }
    if (left.state as i8) < right.state as i8 {
        return -1;
    }
    let left_ratio = f32::from_bits(left.importance_bits) / mission_industrial_cost(left);
    let right_ratio = f32::from_bits(right.importance_bits) / mission_industrial_cost(right);
    if left_ratio < right_ratio {
        1
    } else if right_ratio < left_ratio {
        -1
    } else {
        0
    }
}

fn mission_industrial_cost(mission: &MissionState) -> f32 {
    mission_required_equipage(mission).into_iter().sum()
}

fn mission_required_equipage(mission: &MissionState) -> Vec<f32> {
    match &mission.data {
        MissionData::DefendProvince { army, .. } => army
            .required_equipage_bits
            .into_iter()
            .map(f32::from_bits)
            .collect(),
        MissionData::ControlSeaZone(navy)
        | MissionData::Escort(navy)
        | MissionData::ScatteredShips(navy) => navy
            .required_equipage_bits
            .into_iter()
            .map(f32::from_bits)
            .collect(),
        _ => Vec::new(),
    }
}

fn mission_unit_vector(mission: &MissionState, state: &GameState) -> Option<[f32; 5]> {
    let MissionData::DefendProvince { province, army } = &mission.data else {
        return None;
    };
    let mut vector = [0.0_f32; 5];
    for id in &army.units {
        let unit = state.military_units.iter().find(|unit| unit.id == *id)?;
        let weight = MISSION_DISTANCE_WEIGHTS[usize::from(unit.stationed_province? != *province)];
        let contribution = first_turn_unit_contribution(unit, weight, 33.0)?;
        for index in 0..5 {
            vector[index] += contribution[index];
        }
    }
    Some(vector)
}

fn mission_weighted_satisfaction(mission: &MissionState, state: &GameState) -> Option<f32> {
    let vector = mission_unit_vector(mission, state)?;
    let required = mission_required_equipage(mission);
    let mut numerator = 0.0_f64;
    let mut denominator = 0.0_f64;
    for index in 0..5 {
        let target = f64::from(required[index]);
        let mut value = f64::from(vector[index]);
        if target < value {
            value = (value - target) * f64::from(0.25_f32) + target;
        }
        denominator += target;
        numerator += (value * target).sqrt();
    }
    Some((numerator / denominator) as f32)
}

fn mission_remaining_priority(mission: &MissionState, state: &GameState) -> Option<f32> {
    let difference = 1.0 - mission_weighted_satisfaction(mission, state)?;
    let importance = f32::from_bits(mission.importance_bits);
    Some(if difference >= 0.0 {
        difference * importance
    } else {
        difference / importance
    })
}

fn best_first_turn_army_mission(
    missions: &[MissionState],
    state: &GameState,
) -> Option<Option<usize>> {
    let mut best = None;
    for (index, candidate) in missions.iter().enumerate() {
        if !matches!(candidate.data, MissionData::DefendProvince { .. }) || candidate.held {
            continue;
        }
        let candidate_score = mission_remaining_priority(candidate, state)?;
        let Some(best_index) = best else {
            best = Some(index);
            continue;
        };
        let best_mission = &missions[best_index];
        let best_score = mission_remaining_priority(best_mission, state)?;
        if candidate_score > 0.0 && (best_mission.state as i8) > candidate.state as i8 {
            best = Some(index);
            continue;
        }
        if best_score > 0.0 && (best_mission.state as i8) < candidate.state as i8 {
            continue;
        }
        if best_score < candidate_score {
            best = Some(index);
        }
    }
    Some(best)
}

fn mission_lack_fractions(mission: &MissionState, state: &GameState) -> Option<[f32; 5]> {
    let vector = mission_unit_vector(mission, state)?;
    let required = mission_required_equipage(mission);
    let mut lack = [0_i32; 5];
    let mut total = 0_i32;
    for index in 0..5 {
        lack[index] = (required[index] - vector[index]) as i32;
        if lack[index] < 0 {
            lack[index] = 0;
        }
        total += lack[index];
    }
    if total == 0 {
        total = 1;
    }
    Some(lack.map(|value| value as f32 / total as f32))
}

fn first_turn_unit_fitness(
    mission: &MissionState,
    unit: &MilitaryUnitState,
    reference: [f32; 5],
) -> Option<f64> {
    let MissionData::DefendProvince { province, .. } = mission.data else {
        return None;
    };
    let distance = usize::from(unit.stationed_province? != province);
    let attributes = first_turn_unit_attributes(unit.unit_type)?;
    let strength_scale = f64::from(unit.strength) * f64::from(0.002_f32);
    let quality_scale = 1.0 - f64::from(unit.experience / 100) * f64::from(-0.1_f32);
    let scale = strength_scale * quality_scale;
    let dampen = 1.0 - f64::from(attributes[5]) * 33.0 * f64::from(-0.0001_f32);
    let vector = [
        (strength_scale * f64::from(attributes[0]) * scale * dampen) as f32,
        (f64::from(attributes[1]) * scale * dampen) as f32,
        (f64::from(attributes[2]) * scale) as f32,
        (f64::from(attributes[3]) * scale) as f32,
        (f64::from(attributes[4]) * scale * dampen) as f32,
    ];
    let total = vector.into_iter().map(f64::from).sum::<f64>();
    if total == 0.0 {
        return Some(-1_000.0);
    }
    let mut squared_difference = 0.0_f64;
    for index in 0..5 {
        let difference = f64::from(vector[index]) / total - f64::from(reference[index]);
        squared_difference += difference * difference;
    }
    Some(-(squared_difference + f64::from([0.0_f32, 0.01_f32][distance])))
}
