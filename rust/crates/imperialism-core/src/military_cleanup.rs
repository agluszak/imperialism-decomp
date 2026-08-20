//! Military cleanup phase (`TSimMgr` turn-state 0x15).

use crate::military::{
    ActionClassScores, PROVINCE_UNIT_ORDER_WEIGHT, TACTICAL_COMPOSITION, accumulate_unit_priority,
};
use crate::navy_orders::{
    NAVY_DESCRIPTORS, NavyPriorityComponent, NavyPriorityTable, navy_category_baselines,
    navy_state, ship_priority_contribution, ship_stock_cap,
};
use crate::*;

const ATTACK_RESOURCE_SCALE: DifficultyTable<FortLevelTable<f32>> = DifficultyTable::from_array([
    FortLevelTable::from_array([1.9, 2.3, 2.5, 2.7]),
    FortLevelTable::from_array([1.9, 2.3, 2.5, 2.7]),
    FortLevelTable::from_array([2.0, 2.3, 2.5, 2.7]),
    FortLevelTable::from_array([2.1, 2.3, 2.5, 2.7]),
    FortLevelTable::from_array([2.3, 2.5, 2.7, 2.9]),
]);
const NAVY_QUEUE_PROFILE: NavyPriorityTable<i16> = NavyPriorityTable::from_array([40, 40, 20, 0]);
const UNIT_PRIORITY_WEIGHT: f32 = 0.33;
const PRESSURE_UNSET: f32 = -1.0;
const PRESSURE_RATIO_CAP: f32 = 1.0;
const PRESSURE_MIDPOINT: f32 = 0.5;
const PRESSURE_PEER_SCALE: f32 = 1.1;
const MISSION_ORDER_DISTANCE_DECAY: [f32; 6] = [1.0, 0.8, 0.64, 0.512, 0.4096, 0.32768];
const INDUSTRY_CLASS_BY_SHIP_TYPE: ShipTypeTable<i8> =
    ShipTypeTable::from_array([-1, -1, -1, 1, 0, -1, -1, 2, 3, 0, -1, 1, 3, 2]);

#[derive(Clone, Copy)]
struct AiCityActionCostProfile {
    primary: Option<(TradeCommodity, i16)>,
    secondary: Option<(TradeCommodity, i16)>,
    base: i16,
    context: i16,
}

#[derive(Clone, Copy)]
enum AiDevelopmentSelection {
    LandUnit(MilitaryUnitKind),
    Industry(ShipType),
}

const fn city_action_cost(
    primary: Option<(TradeCommodity, i16)>,
    secondary: Option<(TradeCommodity, i16)>,
    base: i16,
    context: i16,
) -> AiCityActionCostProfile {
    AiCityActionCostProfile {
        primary,
        secondary,
        base,
        context,
    }
}

const AI_CITY_ACTION_COSTS: [AiCityActionCostProfile; 30] = [
    city_action_cost(None, None, 0, 1),
    city_action_cost(Some((TradeCommodity::Arms, 1)), None, 200, 1),
    city_action_cost(Some((TradeCommodity::Arms, 1)), None, 500, 1),
    city_action_cost(Some((TradeCommodity::Arms, 1)), None, 1000, 2),
    city_action_cost(
        Some((TradeCommodity::Arms, 1)),
        Some((TradeCommodity::Horses, 1)),
        100,
        1,
    ),
    city_action_cost(
        Some((TradeCommodity::Arms, 1)),
        Some((TradeCommodity::Horses, 1)),
        500,
        2,
    ),
    city_action_cost(
        Some((TradeCommodity::Arms, 2)),
        Some((TradeCommodity::Horses, 1)),
        1000,
        2,
    ),
    city_action_cost(Some((TradeCommodity::Arms, 2)), None, 1000, 2),
    city_action_cost(None, None, 0, 1),
    city_action_cost(Some((TradeCommodity::Arms, 2)), None, 3000, 1),
    city_action_cost(Some((TradeCommodity::Arms, 2)), None, 3000, 1),
    city_action_cost(Some((TradeCommodity::Arms, 2)), None, 4000, 2),
    city_action_cost(
        Some((TradeCommodity::Arms, 2)),
        Some((TradeCommodity::Horses, 1)),
        2000,
        1,
    ),
    city_action_cost(
        Some((TradeCommodity::Arms, 2)),
        Some((TradeCommodity::Horses, 1)),
        3500,
        2,
    ),
    city_action_cost(
        Some((TradeCommodity::Arms, 4)),
        Some((TradeCommodity::Horses, 1)),
        5000,
        2,
    ),
    city_action_cost(Some((TradeCommodity::Arms, 4)), None, 5000, 2),
    city_action_cost(None, None, 0, 1),
    city_action_cost(Some((TradeCommodity::Arms, 4)), None, 5000, 2),
    city_action_cost(Some((TradeCommodity::Arms, 4)), None, 5000, 2),
    city_action_cost(Some((TradeCommodity::Arms, 4)), None, 7000, 2),
    city_action_cost(
        Some((TradeCommodity::Arms, 4)),
        Some((TradeCommodity::Fuel, 4)),
        5000,
        2,
    ),
    city_action_cost(
        Some((TradeCommodity::Arms, 10)),
        Some((TradeCommodity::Fuel, 4)),
        9000,
        2,
    ),
    city_action_cost(
        Some((TradeCommodity::Arms, 6)),
        Some((TradeCommodity::Fuel, 4)),
        5000,
        2,
    ),
    city_action_cost(Some((TradeCommodity::Arms, 8)), None, 9000, 2),
    city_action_cost(Some((TradeCommodity::Arms, 2)), None, 5000, 4),
    city_action_cost(Some((TradeCommodity::Arms, 2)), None, 7000, 4),
    city_action_cost(Some((TradeCommodity::Arms, 3)), None, 9000, 4),
    city_action_cost(None, None, 0, 4),
    city_action_cost(None, None, 0, 4),
    city_action_cost(None, None, 0, 4),
];

/// AutoGreatPower B64/B68/B6c scores and queue/unit divergence used by
/// mission reassess. Not saved.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct NationOrderPriorityMetrics {
    pub(crate) queue_divergence: [f32; 7],
    pub(crate) mobile_score: [f32; 7],
    pub(crate) mobile_divergence: [f32; 7],
    pub(crate) combined_divergence: [f32; 7],
    pub(crate) weighted_military: [f32; 7],
    pub(crate) expansion_pressure: [f32; 7],
    pub(crate) unit_divergence: [f32; 7],
    pub(crate) mission_pressure: [f32; 7],
}

impl GameState {
    /// Retail military-cleanup for a non-client host. Order-priority metrics run
    /// before mission reassess so defend needs read B64/B68.
    pub fn do_military_cleanup(&mut self) {
        self.clear_all_transient_navy_orders();
        self.recompute_tile_strategic_score_heatmap();
        let metrics = self.recompute_nation_order_priority_metrics();
        for nation in MajorNationId::all() {
            if !self.nation_is_eligible_for_optional_phase(nation.nation()) {
                continue;
            }
            if self.is_auto(nation) {
                self.adopt_unassigned_militia_into_defend_missions(nation.nation());
                self.reassess_missions_with_metrics(nation.nation(), Some(&metrics));
                self.prune_invalid_missions(nation.nation());
                self.update_mission_eligibility_for_ai_assignment(nation.nation());
                // SmokeEmIfYouGotEm releases mobile constituents before the retail
                // list is rebuilt. Keep its prior grouping only to reproduce the
                // linked-list order of otherwise interchangeable units.
                let previous_army_assignments = self.army_assignment_groups(nation.nation());
                self.release_reassignable_mission_constituents(nation.nation());
                self.assign_unassigned_ships_to_navy_missions(nation.nation());
                self.assign_unassigned_units_to_army_missions(
                    nation.nation(),
                    &metrics,
                    &previous_army_assignments,
                );
                self.plan_ai_military_development(nation);
            }
        }
        for nation in MajorNationId::all() {
            if self.nation_is_eligible_for_optional_phase(nation.nation()) {
                self.commit_purchased_items(nation);
            }
        }
        if self.turn.economic_turn % 40 == 0
            && Decade::for_economic_turn(self.turn.economic_turn)
                .is_some_and(|decade| self.turn.quarter_gate_by_decade[decade])
        {
            self.rebuild_council_ballot(false);
        }
    }

    /// `RecomputeNationOrderPriorityMetrics` plus AutoGreatPower
    /// `RecomputeAiExpansionAndMissionPressureScores`.
    pub(crate) fn recompute_nation_order_priority_metrics(&self) -> NationOrderPriorityMetrics {
        let mut metrics = NationOrderPriorityMetrics::default();
        let baselines = navy_category_baselines(&self.technology.industry_enabled_by_slot);
        for nation in MajorNationId::all() {
            if !self.nation_is_eligible_for_optional_phase(nation.nation()) {
                continue;
            }
            let slot = usize::from(nation.get());
            let mut category = NavyPriorityTable::default();
            for ship in self.ships.values() {
                if ship.nation != nation.nation() {
                    continue;
                }
                category[NavyPriorityComponent::Resolve] +=
                    ship_priority_contribution(ship, NavyPriorityComponent::Resolve, &baselines)
                        as f32;
                category[NavyPriorityComponent::Strength] +=
                    ship_priority_contribution(ship, NavyPriorityComponent::Strength, &baselines)
                        as f32;
                category[NavyPriorityComponent::Descriptor] +=
                    ship_priority_contribution(ship, NavyPriorityComponent::Descriptor, &baselines)
                        as f32;
                category[NavyPriorityComponent::Industry] +=
                    ship_priority_contribution(ship, NavyPriorityComponent::Industry, &baselines)
                        as f32;
            }
            metrics.queue_divergence[slot] = queue_divergence(category);

            let mut unit_vector = ActionClassScores::default();
            for unit in self.military_units.values() {
                if unit.nation != nation.nation() || unit.unit_type.is_militia_category() {
                    continue;
                }
                accumulate_unit_priority(unit, &mut unit_vector, 1.0, UNIT_PRIORITY_WEIGHT);
            }
            metrics.mobile_score[slot] = unit_vector.similarity(TACTICAL_COMPOSITION.fort_siege);
            metrics.mobile_divergence[slot] = unit_vector.similarity(TACTICAL_COMPOSITION.baseline);
            for unit in self.military_units.values() {
                if unit.nation != nation.nation() || !unit.unit_type.is_militia_category() {
                    continue;
                }
                accumulate_unit_priority(unit, &mut unit_vector, 1.0, UNIT_PRIORITY_WEIGHT);
            }
            metrics.combined_divergence[slot] =
                unit_vector.similarity(TACTICAL_COMPOSITION.baseline);
            let military_power = self.army_unit_power(nation.nation());
            let navy_arms = self.navy_arms(nation.nation());
            let mut power_ratio = 1.0_f32;
            if (military_power as f32) < navy_arms as f32 && navy_arms != 0 {
                power_ratio = military_power as f32 / navy_arms as f32;
            }
            metrics.weighted_military[slot] = metrics.mobile_score[slot] * power_ratio;
        }
        for nation in MajorNationId::all() {
            if !self.nation_is_eligible_for_optional_phase(nation.nation()) || !self.is_auto(nation)
            {
                continue;
            }
            self.write_ai_pressure_scores(nation, &mut metrics);
        }
        metrics
    }

    fn write_ai_pressure_scores(
        &self,
        nation: MajorNationId,
        metrics: &mut NationOrderPriorityMetrics,
    ) {
        let slot = usize::from(nation.get());
        let mut total_regions = 0;
        let mut compatible_regions = 0;
        self.count_pressure_regions(nation.nation(), &mut total_regions, &mut compatible_regions);
        for minor in MinorNationId::all() {
            if self
                .nations
                .common(minor.nation())
                .is_some_and(|common| common.status().is_colony_of(nation.nation()))
            {
                self.count_pressure_regions(
                    minor.nation(),
                    &mut total_regions,
                    &mut compatible_regions,
                );
            }
        }
        let active_missions = self
            .missions
            .values()
            .filter(|mission| {
                mission.nation == nation.nation()
                    && matches!(mission.data, MissionData::ScatteredShips(_))
            })
            .count();
        let own_unit_divergence =
            metrics.combined_divergence[slot] - metrics.mobile_divergence[slot];
        // Retail divides even when the nation owns no regions.
        let unit_divergence = own_unit_divergence / total_regions as f32;
        metrics.unit_divergence[slot] = unit_divergence;

        let mut maximum_adjusted_military = 0.0_f32;
        let mut maximum_adjusted_mission = 0.0_f32;
        let mut maximum_raw_military = 0.0_f32;
        let mut minimum_peer_combined = PRESSURE_UNSET;
        for peer in MajorNationId::all() {
            if peer == nation {
                continue;
            }
            let peer_slot = usize::from(peer.get());
            let peer_combined = metrics.combined_divergence[peer_slot];
            if peer_combined < minimum_peer_combined || minimum_peer_combined == PRESSURE_UNSET {
                minimum_peer_combined = peer_combined;
            }
            let military_score =
                if self.do_nation_territories_share_region_class(nation.nation(), peer.nation()) {
                    metrics.mobile_score[peer_slot]
                } else {
                    metrics.weighted_military[peer_slot]
                };
            if military_score > maximum_raw_military {
                maximum_raw_military = military_score;
            }
            let mission_score = metrics.queue_divergence[peer_slot];
            if self.diplomacy.standings[nation.nation()][peer.nation()] >= 100 {
                maximum_adjusted_military = military_score;
            }
            if military_score > maximum_adjusted_military {
                maximum_adjusted_military = military_score;
            }
            if mission_score > maximum_adjusted_mission {
                maximum_adjusted_mission = mission_score;
            }
        }
        let mut military_ratio =
            maximum_raw_military / (metrics.mobile_divergence[slot] + unit_divergence);
        if military_ratio > 1.0 {
            military_ratio = PRESSURE_RATIO_CAP;
        }
        let peer_scaled = (military_ratio - PRESSURE_UNSET)
            * PRESSURE_MIDPOINT
            * PRESSURE_PEER_SCALE
            * minimum_peer_combined;
        if peer_scaled > maximum_adjusted_military {
            maximum_adjusted_military = peer_scaled;
        }
        let mut expansion = maximum_adjusted_military - own_unit_divergence;
        if expansion < 0.0 {
            expansion = 0.0;
        }
        if compatible_regions != 0 {
            expansion /= compatible_regions as f32;
        }
        metrics.expansion_pressure[slot] = expansion;
        metrics.mission_pressure[slot] = if active_missions == 0 {
            maximum_adjusted_mission
        } else {
            maximum_adjusted_mission / active_missions as f32
        };
    }

    fn count_pressure_regions(&self, nation: NationId, total: &mut i32, compatible: &mut i32) {
        let Some(common) = self.nations.common(nation) else {
            return;
        };
        for &province in common.owned_regions() {
            *total += 1;
            if self.province_is_mission_compatible(province) {
                *compatible += 1;
            }
        }
    }

    fn reassess_missions_with_metrics(
        &mut self,
        nation: NationId,
        metrics: Option<&NationOrderPriorityMetrics>,
    ) {
        let missions: Vec<_> = self
            .missions
            .iter()
            .filter_map(|(&id, mission)| (mission.nation == nation).then_some(id))
            .collect();
        for mission in missions {
            self.reassess_mission(mission, metrics);
        }
    }

    /// ControlSeaZone reassess only. Opening ControlSea needs do not read
    /// AutoGreatPower pressure scores.
    #[cfg(feature = "oracle")]
    pub(crate) fn reassess_control_sea_missions(&mut self) {
        for nation in MajorNationId::all() {
            if !self.nation_is_eligible_for_optional_phase(nation.nation()) {
                continue;
            }
            if !self.is_auto(nation) {
                continue;
            }
            let missions: Vec<_> = self
                .missions
                .iter()
                .filter_map(|(&id, mission)| {
                    (mission.nation == nation.nation()
                        && matches!(
                            mission.data,
                            MissionData::ControlSeaZone(_)
                                | MissionData::Escort(_)
                                | MissionData::ScatteredShips(_)
                        ))
                    .then_some(id)
                })
                .collect();
            for mission in missions {
                self.reassess_navy_mission(mission);
            }
        }
    }

    fn reassess_mission(
        &mut self,
        mission: MissionId,
        metrics: Option<&NationOrderPriorityMetrics>,
    ) {
        match &self.missions[&mission].data {
            MissionData::DefendProvince { province, .. } => {
                let province = *province;
                self.reassess_defend_mission(mission, province, metrics);
            }
            MissionData::AttackProvince(attack) => {
                let attack = attack.clone();
                self.missions[&mission].state = 2;
                self.reassess_attack_mission_fields(mission, &attack);
            }
            MissionData::ControlSeaZone(_)
            | MissionData::Escort(_)
            | MissionData::ScatteredShips(_)
            | MissionData::BlockadePort { .. }
            | MissionData::Beachhead(_)
            | MissionData::Invade { .. } => {
                self.reassess_navy_mission(mission);
            }
        }
    }

    fn reassess_defend_mission(
        &mut self,
        mission: MissionId,
        province: ProvinceId,
        metrics: Option<&NationOrderPriorityMetrics>,
    ) {
        let nation = self.missions[&mission].nation;
        self.missions[&mission].state = if self.capitol_province(nation) == Some(province) {
            0
        } else {
            2
        };
        self.missions[&mission].importance_bits =
            self.province_mission_importance_bits(province, nation);
        let required = self.defend_required_equipage(nation, province, metrics);
        if let MissionData::DefendProvince { army, .. } = &mut self.missions[&mission].data {
            army.required_equipage_bits = required;
        }
    }

    pub(crate) fn reassess_attack_mission_fields(
        &mut self,
        mission: MissionId,
        attack: &AttackMissionState,
    ) {
        let nation = self.missions[&mission].nation;
        self.missions[&mission].importance_bits =
            self.province_mission_importance_bits(attack.target_province, nation);
        let required = self.attack_required_equipage(attack.target_province);
        match &mut self.missions[&mission].data {
            MissionData::AttackProvince(state) | MissionData::Invade { attack: state, .. } => {
                state.army.required_equipage_bits = required;
            }
            _ => {}
        }
    }

    fn defend_required_equipage(
        &self,
        nation: NationId,
        province: ProvinceId,
        metrics: Option<&NationOrderPriorityMetrics>,
    ) -> [u32; 5] {
        let compatible = self.province_is_mission_compatible(province);
        let pressure = defend_pressure_scale(nation, compatible, metrics);
        if !compatible {
            let kind = self.latest_militia_kind(nation);
            let costs = kind.class_costs();
            let sum: i32 = costs.iter().map(|&cost| i32::from(cost)).sum();
            if sum == 0 {
                return [0; 5];
            }
            // VC5 evaluates the multiply/divide in x87 precision, then stores float.
            return costs.map(|cost| {
                ((f64::from(cost) * f64::from(pressure) / f64::from(sum)) as f32).to_bits()
            });
        }
        let mut scale = pressure;
        if NationId::all().any(|other| self.at_war(nation, other)) {
            let cross = self.cross_nation_support_score(province) * 0.8;
            if scale < cross {
                scale = cross;
            }
        }
        let profile = if self.map.provinces[province].fort_level() == FortLevel::None {
            TACTICAL_COMPOSITION.baseline
        } else {
            TACTICAL_COMPOSITION.fort_garrison
        };
        profile
            .components()
            .map(|weight| (f64::from(weight) * f64::from(scale) * 0.01) as f32)
            .map(f32::to_bits)
    }

    fn attack_required_equipage(&self, target: ProvinceId) -> [u32; 5] {
        let mut scores = ActionClassScores::default();
        for unit in self.units_stationed_in(target) {
            accumulate_unit_priority(unit, &mut scores, 1.0, PROVINCE_UNIT_ORDER_WEIGHT);
        }
        let fort_level = self.map.provinces[target].fort_level();
        let fort = fort_level != FortLevel::None;
        let mut similarity = scores.similarity(if fort {
            TACTICAL_COMPOSITION.fort_garrison
        } else {
            TACTICAL_COMPOSITION.baseline
        });
        if similarity == 0.0 {
            similarity = 1.0;
        }
        let scale = ATTACK_RESOURCE_SCALE[self.turn.difficulty][fort_level] * similarity;
        let profile = if fort {
            TACTICAL_COMPOSITION.open_field
        } else {
            TACTICAL_COMPOSITION.fort_siege
        };
        profile
            .components()
            .map(|weight| (f32::from(weight) * scale * 0.01).to_bits())
    }

    fn province_is_mission_compatible(&self, province: ProvinceId) -> bool {
        let owner = self.map.provinces[province].owner();
        if owner.is_some_and(|owner| self.capitol_province(owner) == Some(province)) {
            return true;
        }
        if self.map.provinces[province]
            .adjacency()
            .iter()
            .any(|&neighbor| {
                let neighbor_owner = self.map.provinces[neighbor].owner();
                neighbor_owner.is_none_or(|nation| MajorNationId::from_nation(nation).is_some())
                    && neighbor_owner != owner
            })
        {
            return true;
        }
        let exclude = owner
            .and_then(MajorNationId::from_nation)
            .map(|major| (1u16 << major.get()) ^ 0x7f)
            .unwrap_or(0x7f);
        self.ocean.zones.iter().enumerate().any(|(ordinal, kind)| {
            let zone = OceanZoneId::new(ordinal as u16);
            self.zone_nation_key_mask(zone) & exclude != 0
                && kind.zone().secondary_neighbors.contains(&province)
        })
    }

    fn latest_militia_kind(&self, nation: NationId) -> MilitaryUnitKind {
        let Some(major) = MajorNationId::from_nation(nation) else {
            return MilitaryUnitKind::Minutemen;
        };
        let active = &self.technology.military_unit_ability_active_by_nation[major];
        if active[MilitaryUnitKind::Conscripts] {
            MilitaryUnitKind::Conscripts
        } else if active[MilitaryUnitKind::Militia] {
            MilitaryUnitKind::Militia
        } else {
            MilitaryUnitKind::Minutemen
        }
    }

    /// `TAutoGreatPower::RefreshTrackedEntriesAndReplanAiDevelopment` militia
    /// adoption.
    fn adopt_unassigned_militia_into_defend_missions(&mut self, nation: NationId) {
        let mut adoptions = Vec::new();
        for (&unit_id, unit) in &self.military_units {
            if unit.nation() != nation || !unit.unit_type().is_militia_category() {
                continue;
            }
            let Some(province) = unit.stationed_province() else {
                continue;
            };
            if self.mission_contains_unit(unit_id) {
                continue;
            }
            let Some(mission_id) = self.missions.iter().find_map(|(&id, mission)| {
                (mission.nation == nation
                    && matches!(
                        &mission.data,
                        MissionData::DefendProvince {
                            province: hold,
                            ..
                        } if *hold == province
                    ))
                .then_some(id)
            }) else {
                continue;
            };
            adoptions.push((mission_id, unit_id));
        }
        for (mission_id, id) in adoptions {
            if let MissionData::DefendProvince { army, .. } = &mut self.missions[&mission_id].data {
                army.units.insert(id);
            }
        }
    }

    fn prune_invalid_missions(&mut self, nation: NationId) {
        let mut remove = Vec::new();
        for (&id, mission) in &self.missions {
            if mission.nation != nation {
                continue;
            }
            let valid = match &mission.data {
                MissionData::DefendProvince { province, .. } => {
                    self.normalized_province_owner(*province) == Some(nation)
                }
                MissionData::ControlSeaZone(navy) | MissionData::Beachhead(navy) => {
                    navy.resolved_port_zone.is_some()
                        && navy.target_zone.is_some_and(|zone| {
                            self.ocean.zones[usize::from(zone.get())]
                                .zone()
                                .secondary_neighbors
                                .iter()
                                .any(|&province| {
                                    self.map.provinces[province].owner().is_some_and(|owner| {
                                        owner == nation
                                            || self.status_of(owner).is_colony_of(nation)
                                    })
                                })
                        })
                }
                MissionData::BlockadePort { navy, .. } => navy.resolved_port_zone.is_some(),
                MissionData::AttackProvince(_)
                | MissionData::Invade { .. }
                | MissionData::Escort(_)
                | MissionData::ScatteredShips(_) => true,
            };
            if !valid {
                remove.push(id);
            }
        }
        for id in remove {
            self.missions.shift_remove(&id);
        }
    }

    fn update_mission_eligibility_for_ai_assignment(&mut self, nation: NationId) {
        let mut sorted_ids: Vec<_> = self
            .missions
            .iter()
            .filter_map(|(&id, mission)| (mission.nation == nation).then_some(id))
            .collect();
        retail_sort_missions(&mut sorted_ids, &self.missions, &mut self.rng);
        self.missions.sort_by(|left_id, left, right_id, right| {
            left.nation.cmp(&right.nation).then_with(|| {
                if left.nation != nation {
                    std::cmp::Ordering::Equal
                } else {
                    sorted_ids
                        .iter()
                        .position(|id| id == left_id)
                        .cmp(&sorted_ids.iter().position(|id| id == right_id))
                }
            })
        });

        let mut next_by_class = [None; 4];
        for (&id, mission) in &self.missions {
            if mission.nation == nation && !mission.held && mission.marker != 0 {
                next_by_class[usize::from(mission.marker)] = Some(id);
            }
        }

        let ids: Vec<_> = self
            .missions
            .iter()
            .filter_map(|(&id, mission)| (mission.nation == nation).then_some(id))
            .collect();
        let mut available_class_mask = 3_u8;
        for id in ids {
            let marker = self.missions[&id].marker;
            if next_by_class[usize::from(marker)] == Some(id) {
                next_by_class[usize::from(marker)] = None;
            }

            let mission = &self.missions[&id];
            let mut eligible =
                marker == 0 || marker & available_class_mask == marker || mission.state == 0;
            if eligible && marker & 1 != 0 && army_state(&mission.data).is_none() {
                eligible = false;
            }
            if eligible && marker != 0 {
                if let Some(next_id) = next_by_class[usize::from(marker)] {
                    if mission_efficiency(mission)
                        < mission_efficiency(&self.missions[&next_id]) * 1.1
                    {
                        eligible = false;
                    } else {
                        available_class_mask &= !marker;
                    }
                } else {
                    available_class_mask &= !marker;
                }
            }
            self.missions[&id].held = !eligible;
        }
    }

    fn army_assignment_groups(&self, nation: NationId) -> Vec<Vec<MilitaryUnitId>> {
        self.missions
            .values()
            .filter(|mission| mission.nation == nation)
            .filter_map(|mission| army_state(&mission.data))
            .map(|army| army.units.iter().copied().collect())
            .collect()
    }

    fn release_reassignable_mission_constituents(&mut self, nation: NationId) {
        let military_units = &self.military_units;
        for mission in self
            .missions
            .values_mut()
            .filter(|mission| mission.nation == nation)
        {
            match &mut mission.data {
                MissionData::DefendProvince { army, .. }
                | MissionData::AttackProvince(AttackMissionState { army, .. }) => {
                    army.units
                        .retain(|id| military_units[id].unit_type().is_militia_category());
                }
                MissionData::Invade { attack, beachhead } => {
                    attack
                        .army
                        .units
                        .retain(|id| military_units[id].unit_type().is_militia_category());
                    if let Some(navy) = beachhead {
                        navy.ships.clear();
                    }
                }
                MissionData::ControlSeaZone(navy)
                | MissionData::Escort(navy)
                | MissionData::ScatteredShips(navy)
                | MissionData::Beachhead(navy)
                | MissionData::BlockadePort { navy, .. } => navy.ships.clear(),
            }
        }
    }

    fn assign_unassigned_units_to_army_missions(
        &mut self,
        nation: NationId,
        metrics: &NationOrderPriorityMetrics,
        previous_assignments: &[Vec<MilitaryUnitId>],
    ) {
        loop {
            let mut best_mission = None;
            let mut eligible_runner_up = None;
            for (&id, candidate) in &self.missions {
                if candidate.nation != nation
                    || candidate.held
                    || army_state(&candidate.data).is_none()
                {
                    continue;
                }
                let candidate_score = army_remaining_priority(self, candidate);
                if eligible_runner_up.is_none()
                    && candidate_score > 0.0
                    && candidate.marker & 1 != 0
                {
                    eligible_runner_up = Some(id);
                }
                let Some(best_id) = best_mission else {
                    best_mission = Some(id);
                    continue;
                };
                let best = &self.missions[&best_id];
                let best_score = army_remaining_priority(self, best);
                if candidate_score > 0.0 && best.state > candidate.state {
                    best_mission = Some(id);
                    continue;
                }
                if best_score > 0.0 && best.state < candidate.state {
                    continue;
                }
                if best_score < candidate_score {
                    best_mission = Some(id);
                }
            }
            let Some(mut mission_id) = best_mission else {
                return;
            };
            if let Some(runner_up_id) = eligible_runner_up {
                let best = &self.missions[&mission_id];
                let runner_up = &self.missions[&runner_up_id];
                if runner_up.state <= best.state
                    && best.marker & 1 == 0
                    && mission_efficiency(best) < mission_efficiency(runner_up)
                {
                    mission_id = runner_up_id;
                }
            }
            let reference = army_lack_profile(self, &self.missions[&mission_id]);
            let target = army_target(&self.missions[&mission_id].data);
            let mut best_unit = None;
            let mut best_score = 0.0_f32;
            for (&id, unit) in &self.military_units {
                if unit.nation() != nation || self.mission_contains_unit(id) {
                    continue;
                }
                let score = army_unit_fitness(unit, target, reference);
                let equivalent_to_best = best_unit.is_some_and(|best_id| {
                    let best = &self.military_units[&best_id];
                    best.unit_type() == unit.unit_type()
                        && best.strength() == unit.strength()
                        && best.experience() == unit.experience()
                });
                let shared_previous_mission = best_unit.is_some_and(|best_id| {
                    previous_assignments
                        .iter()
                        .any(|group| group.contains(&best_id) && group.contains(&id))
                });
                if best_unit.is_none()
                    || best_score < score
                    // Equal interchangeable constituents follow the retail linked-list
                    // rebuild order; unrelated rounded score ties keep the first unit.
                    || (best_score == score
                        && equivalent_to_best
                        && (unit.stationed_province() != target || shared_previous_mission))
                {
                    best_unit = Some(id);
                    best_score = score;
                }
            }
            let Some(unit_id) = best_unit else {
                return;
            };
            let Some(army) = army_state_mut(&mut self.missions[&mission_id].data) else {
                return;
            };
            army.units.insert(unit_id);
            self.reassess_mission(mission_id, Some(metrics));
        }
    }

    fn mission_contains_unit(&self, id: MilitaryUnitId) -> bool {
        self.missions.values().any(|mission| match &mission.data {
            MissionData::DefendProvince { army, .. }
            | MissionData::AttackProvince(AttackMissionState { army, .. })
            | MissionData::Invade {
                attack: AttackMissionState { army, .. },
                ..
            } => army.units.contains(&id),
            _ => false,
        })
    }

    pub(crate) fn plan_ai_military_development(&mut self, nation: MajorNationId) {
        let mut pools = [0_i32; 9];
        for mission in self
            .missions
            .values()
            .filter(|mission| mission.nation == nation.nation() && !mission.held)
        {
            accumulate_development_lack(self, mission, &mut pools);
        }

        let average = self.nations.majors[&nation]
            .economy
            .interior_civilian
            .average_development_order_allocation;
        let city_limit = average + 2;
        let industry_limit = average / 2 + 1;
        let mut city_count = 0;
        let mut industry_count = 0;
        for _ in 0..99 {
            let mut selected = None;
            let mut best_score = 0.0_f32;
            for index in 0..MilitaryUnitKind::LENGTH {
                let kind = MilitaryUnitKind::from_index(index as u8)
                    .expect("military unit index is in range");
                if !self.technology.military_unit_ability_active_by_nation[nation][kind]
                    || kind.is_militia_category()
                    || kind.tactical_category() == ArmyUnitCategory::Generals
                {
                    continue;
                }
                let weighted = kind
                    .class_costs()
                    .into_iter()
                    .zip(pools)
                    .filter(|(_, pool)| *pool > 0)
                    .fold(0_i32, |weighted, (cost, pool)| {
                        weighted.wrapping_add(i32::from(cost).wrapping_mul(pool))
                    });
                let score = weighted as f32 / self.ai_city_action_cost(nation, kind, false);
                if score > best_score {
                    best_score = score;
                    selected = Some(AiDevelopmentSelection::LandUnit(kind));
                }
            }

            for original_index in 0..MilitaryUnitKind::LENGTH {
                let original = MilitaryUnitKind::from_index(original_index as u8)
                    .expect("military unit index is in range");
                if original.is_militia_category()
                    || original.tactical_category() == ArmyUnitCategory::Generals
                {
                    continue;
                }
                let Some(upgrade) = self.upgrade_type(nation, original) else {
                    continue;
                };
                let Some(quality) = self
                    .military_units
                    .values()
                    .filter(|unit| unit.nation() == nation.nation() && unit.unit_type() == original)
                    .map(MilitaryUnitState::experience)
                    .max()
                else {
                    continue;
                };
                let weighted = upgrade
                    .class_costs()
                    .into_iter()
                    .zip(original.class_costs())
                    .zip(pools)
                    .filter(|(_, pool)| *pool > 0)
                    .fold(0_i32, |weighted, ((upgrade, original), pool)| {
                        weighted.wrapping_add(i32::from(upgrade - original).wrapping_mul(pool))
                    });
                let multiplier = (i32::from(quality / 100) + 10) / 10;
                let score = weighted.wrapping_mul(multiplier) as f32
                    / self.ai_city_action_cost(nation, upgrade, true);
                if score > best_score {
                    best_score = score;
                    selected = Some(AiDevelopmentSelection::LandUnit(upgrade));
                }
            }

            for class in 0..4 {
                let Some(ship_type) = self.enabled_industry_type_for_class(class) else {
                    continue;
                };
                let weighted = NavyPriorityComponent::ALL
                    .into_iter()
                    .zip(pools[5..].iter().copied())
                    .filter(|(_, pool)| *pool > 0)
                    .fold(0.0_f32, |weighted, (component, pool)| {
                        weighted
                            + (normalized_industry_action_cost(
                                &self.technology.industry_enabled_by_slot,
                                component,
                                ship_type,
                            )
                            .wrapping_mul(pool)) as f32
                    });
                let score = weighted / self.ai_industry_action_cost(ship_type);
                if score > best_score {
                    best_score = score;
                    selected = Some(AiDevelopmentSelection::Industry(ship_type));
                }
            }

            let Some(selection) = selected else {
                return;
            };
            subtract_development_costs(
                &mut pools,
                selection,
                &self.technology.industry_enabled_by_slot,
            );
            let apply = match selection {
                AiDevelopmentSelection::LandUnit(_) => {
                    let apply = city_count < city_limit;
                    city_count += 1;
                    apply
                }
                AiDevelopmentSelection::Industry(_) => {
                    let apply = industry_count < industry_limit;
                    industry_count += 1;
                    apply
                }
            };
            if city_count > city_limit && industry_count > industry_limit {
                return;
            }
            if apply {
                let action = match selection {
                    AiDevelopmentSelection::LandUnit(unit_type) => {
                        PendingDevelopmentAction::LandUnit { unit_type }
                    }
                    AiDevelopmentSelection::Industry(ship_type) => {
                        let slot =
                            IndustryCapabilitySlot::ALL[usize::from(ship_type.retail())].facility();
                        PendingDevelopmentAction::Industry { slot }
                    }
                };
                self.nations.majors[&nation]
                    .economy
                    .interior_civilian
                    .pending_development_actions
                    .push(action);
            }
            subtract_development_costs(
                &mut pools,
                selection,
                &self.technology.industry_enabled_by_slot,
            );
        }
    }

    fn enabled_industry_type_for_class(&self, class: i8) -> Option<ShipType> {
        (1..ShipType::LENGTH).rev().find_map(|index| {
            let ship_type =
                ShipType::from_index(index as u8).expect("industry ship type index is in range");
            (INDUSTRY_CLASS_BY_SHIP_TYPE[ship_type] == class
                && self.technology.industry_enabled_by_slot[IndustryCapabilitySlot::ALL[index]])
                .then_some(ship_type)
        })
    }

    fn ai_industry_action_cost(&self, ship_type: ShipType) -> f32 {
        ship_order_costs(ship_type)
            .iter()
            .into_iter()
            .fold(0_i32, |cost, (resource, quantity)| {
                let commodity = TradeCommodity::from_retail(i16::from(resource.retail()))
                    .expect("ship material has a market row");
                cost.wrapping_add(
                    self.market.rows[commodity]
                        .price
                        .wrapping_mul(i32::from(quantity)),
                )
            }) as f32
    }

    fn ai_city_action_cost(
        &self,
        nation: MajorNationId,
        kind: MilitaryUnitKind,
        skip_context: bool,
    ) -> f32 {
        let profile = AI_CITY_ACTION_COSTS[usize::from(kind.retail())];
        let horses =
            self.nations.majors[&nation].economy.need_current_by_type[ResourceKind::Horses];
        let mut cost = i32::from(profile.base);
        for (commodity, multiplier) in [profile.primary, profile.secondary].into_iter().flatten() {
            if commodity != TradeCommodity::Horses || horses < multiplier {
                cost += self.market.rows[commodity].price * i32::from(multiplier);
            }
        }
        if !skip_context {
            let base = self.market.rows[TradeCommodity::Clothing].price
                + self.market.rows[TradeCommodity::Furniture].price
                + self.market.rows[TradeCommodity::Food].price;
            let middle = self.market.rows[TradeCommodity::Paper].price + 100;
            let tail = self.market.rows[TradeCommodity::Paper].price * 2 + 1000;
            cost += match profile.context {
                1 => base,
                2 => base + middle,
                _ => base + middle + tail,
            };
        }
        cost as f32
    }
}

fn accumulate_development_lack(state: &GameState, mission: &MissionState, pools: &mut [i32; 9]) {
    if let Some(army) = army_state(&mission.data) {
        let actual = army_vector(state, mission).components();
        let required = army.required_equipage_bits.map(f32::from_bits);
        for index in 0..5 {
            let value = if required[index] <= actual[index] {
                required[index] - actual[index]
            } else {
                required[index] - actual[index] + pools[index] as f32
            };
            pools[index] = value as i32;
        }
    }

    let Some(navy) = navy_state(&mission.data) else {
        return;
    };
    let active_target = match navy.state {
        NavyMissionSelection::AssembleAtPort => navy.resolved_port_zone,
        NavyMissionSelection::EvadeAtTarget | NavyMissionSelection::ExecuteAtTarget => {
            navy.target_zone
        }
    };
    let distances = active_target.map(|target| state.zone_hop_distances_from(target));
    let baselines = navy_category_baselines(&state.technology.industry_enabled_by_slot);
    let mut actual: NavyPriorityTable<f32> = NavyPriorityTable::default();
    for &ship_id in navy.ships.keys() {
        let Some(ship) = state.ship(ship_id) else {
            continue;
        };
        let max_strength = ship_stock_cap(ship.ship_type);
        if max_strength == 0 {
            continue;
        }
        let distance = distances.as_ref().map_or(0, |distances| {
            distances
                .get(usize::from(ship.location.get()))
                .copied()
                .unwrap_or(5)
                .min(5)
        });
        let scale = MISSION_ORDER_DISTANCE_DECAY[distance as usize]
            * f32::from(ship.strength / max_strength);
        for component in NavyPriorityComponent::ALL {
            actual[component] +=
                ship_priority_contribution(ship, component, &baselines) as f32 * scale;
        }
    }
    let required = NavyPriorityTable::from_array(navy.required_equipage_bits.map(f32::from_bits));
    for (index, component) in NavyPriorityComponent::ALL.into_iter().enumerate() {
        pools[5 + index] =
            (required[component] - actual[component] + pools[5 + index] as f32) as i32;
    }
}

fn subtract_unit_costs(pools: &mut [i32; 9], kind: MilitaryUnitKind) {
    for (pool, cost) in pools.iter_mut().zip(kind.class_costs()) {
        *pool = pool.wrapping_sub(i32::from(cost));
    }
}

fn subtract_development_costs(
    pools: &mut [i32; 9],
    selection: AiDevelopmentSelection,
    enabled: &IndustryCapabilityTable<bool>,
) {
    match selection {
        AiDevelopmentSelection::LandUnit(kind) => subtract_unit_costs(pools, kind),
        AiDevelopmentSelection::Industry(ship_type) => {
            for (index, component) in NavyPriorityComponent::ALL.into_iter().enumerate() {
                pools[5 + index] = pools[5 + index].wrapping_sub(normalized_industry_action_cost(
                    enabled, component, ship_type,
                ));
            }
        }
    }
}

fn normalized_industry_action_cost(
    enabled: &IndustryCapabilityTable<bool>,
    component: NavyPriorityComponent,
    ship_type: ShipType,
) -> i32 {
    let baseline = navy_category_baselines(enabled)[component];
    let descriptor = NAVY_DESCRIPTORS[ship_type];
    match component {
        NavyPriorityComponent::Resolve => {
            descriptor.resolve_weight
                * descriptor.calculate_weight
                * descriptor.calculate_weight
                * 100
                / baseline
        }
        NavyPriorityComponent::Strength => {
            ((descriptor.calculate_weight * descriptor.stock_cap * 100
                / descriptor.task_force_weight)
                * 100)
                / baseline
        }
        NavyPriorityComponent::Descriptor => descriptor.navy_priority_weight * 100 / baseline,
        NavyPriorityComponent::Industry => {
            i32::from(ship_order_costs(ship_type).arms) * 100 / baseline
        }
    }
}

fn retail_sort_missions(
    ids: &mut [MissionId],
    missions: &indexmap::IndexMap<MissionId, MissionState>,
    rng: &mut RngState,
) {
    fn compare(left: &MissionState, right: &MissionState) -> i16 {
        if right.state < left.state {
            return 1;
        }
        if left.state < right.state {
            return -1;
        }
        let left_ratio = mission_efficiency(left);
        let right_ratio = mission_efficiency(right);
        if left_ratio < right_ratio {
            1
        } else if right_ratio < left_ratio {
            -1
        } else {
            0
        }
    }

    fn partition(
        ids: &mut [MissionId],
        missions: &indexmap::IndexMap<MissionId, MissionState>,
        lo: i32,
        hi: i32,
        rng: &mut RngState,
    ) -> i32 {
        let pivot_ordinal = rng.next_crt_rand() % (hi - lo).abs() + lo;
        ids.swap((lo - 1) as usize, (pivot_ordinal - 1) as usize);
        let pivot = ids[(lo - 1) as usize];
        let mut below = lo - 1;
        let mut above = hi + 1;
        loop {
            loop {
                above -= 1;
                if compare(&missions[&pivot], &missions[&ids[(above - 1) as usize]]) > -1 {
                    break;
                }
            }
            loop {
                below += 1;
                if compare(&missions[&pivot], &missions[&ids[(below - 1) as usize]]) < 1 {
                    break;
                }
            }
            if above <= below {
                return above;
            }
            ids.swap((below - 1) as usize, (above - 1) as usize);
        }
    }

    fn quick_sort(
        ids: &mut [MissionId],
        missions: &indexmap::IndexMap<MissionId, MissionState>,
        lo: i32,
        hi: i32,
        rng: &mut RngState,
    ) {
        if lo < hi {
            let pivot = partition(ids, missions, lo, hi, rng);
            quick_sort(ids, missions, lo, pivot, rng);
            quick_sort(ids, missions, pivot + 1, hi, rng);
        }
    }

    if !ids.is_empty() {
        quick_sort(ids, missions, 1, ids.len() as i32, rng);
    }
}

fn mission_efficiency(mission: &MissionState) -> f32 {
    let cost = match &mission.data {
        MissionData::AttackProvince(attack) => attack
            .army
            .required_equipage_bits
            .iter()
            .map(|&bits| f32::from_bits(bits))
            .sum(),
        MissionData::Invade { attack, beachhead } => {
            let army: f32 = attack
                .army
                .required_equipage_bits
                .iter()
                .map(|&bits| f32::from_bits(bits))
                .sum();
            army + beachhead.as_ref().map_or(0.0, |navy| {
                navy.required_equipage_bits
                    .iter()
                    .map(|&bits| f32::from_bits(bits))
                    .sum()
            })
        }
        MissionData::DefendProvince { army, .. } => army
            .required_equipage_bits
            .iter()
            .map(|&bits| f32::from_bits(bits))
            .sum(),
        MissionData::ControlSeaZone(navy)
        | MissionData::Escort(navy)
        | MissionData::ScatteredShips(navy)
        | MissionData::Beachhead(navy)
        | MissionData::BlockadePort { navy, .. } => navy
            .required_equipage_bits
            .iter()
            .map(|&bits| f32::from_bits(bits))
            .sum(),
    };
    f32::from_bits(mission.importance_bits) / cost
}

fn army_state(data: &MissionData) -> Option<&ArmyMissionState> {
    match data {
        MissionData::AttackProvince(attack) | MissionData::Invade { attack, .. } => {
            Some(&attack.army)
        }
        MissionData::DefendProvince { army, .. } => Some(army),
        MissionData::ControlSeaZone(_)
        | MissionData::Escort(_)
        | MissionData::ScatteredShips(_)
        | MissionData::BlockadePort { .. }
        | MissionData::Beachhead(_) => None,
    }
}

fn army_state_mut(data: &mut MissionData) -> Option<&mut ArmyMissionState> {
    match data {
        MissionData::AttackProvince(attack) | MissionData::Invade { attack, .. } => {
            Some(&mut attack.army)
        }
        MissionData::DefendProvince { army, .. } => Some(army),
        MissionData::ControlSeaZone(_)
        | MissionData::Escort(_)
        | MissionData::ScatteredShips(_)
        | MissionData::BlockadePort { .. }
        | MissionData::Beachhead(_) => None,
    }
}

fn army_target(data: &MissionData) -> Option<ProvinceId> {
    match data {
        MissionData::AttackProvince(attack) | MissionData::Invade { attack, .. } => {
            attack.present_province
        }
        MissionData::DefendProvince { province, .. } => Some(*province),
        _ => None,
    }
}

fn army_vector(state: &GameState, mission: &MissionState) -> ActionClassScores {
    let mut scores = ActionClassScores::default();
    let Some(army) = army_state(&mission.data) else {
        return scores;
    };
    let target = army_target(&mission.data);
    for id in army.units.iter().rev() {
        let unit = &state.military_units[id];
        let scale = if unit.stationed_province() == target {
            1.0
        } else {
            0.8
        };
        accumulate_unit_priority(unit, &mut scores, scale, PROVINCE_UNIT_ORDER_WEIGHT);
    }
    scores
}

fn army_satisfaction(state: &GameState, mission: &MissionState) -> f32 {
    let Some(army) = army_state(&mission.data) else {
        return 0.0;
    };
    let actual = army_vector(state, mission).components();
    let required = army.required_equipage_bits.map(f32::from_bits);
    let mut numerator = 0.0_f64;
    let mut denominator = 0.0_f64;
    for index in 0..5 {
        let target = required[index];
        let mut value = actual[index];
        if target < value {
            value = (value - target) * 0.25 + target;
        }
        denominator += f64::from(target);
        numerator += (f64::from(value) * f64::from(target)).sqrt();
    }
    (numerator / denominator) as f32
}

fn army_remaining_priority(state: &GameState, mission: &MissionState) -> f32 {
    let remaining = 1.0 - army_satisfaction(state, mission);
    let importance = f32::from_bits(mission.importance_bits);
    if remaining >= 0.0 {
        remaining * importance
    } else {
        remaining / importance
    }
}

fn army_lack_profile(state: &GameState, mission: &MissionState) -> [f32; 5] {
    let army = army_state(&mission.data).expect("army mission has army state");
    let actual = army_vector(state, mission).components();
    let required = army.required_equipage_bits.map(f32::from_bits);
    let mut lack = [0.0; 5];
    let mut total = 0.0;
    for index in 0..5 {
        lack[index] = (required[index] - actual[index]).max(0.0).trunc();
        total += lack[index];
    }
    if total == 0.0 {
        total = 1.0;
    }
    lack.map(|value| value / total)
}

fn army_unit_fitness(
    unit: &MilitaryUnitState,
    target: Option<ProvinceId>,
    reference: [f32; 5],
) -> f32 {
    let mut scores = ActionClassScores::default();
    accumulate_unit_priority(unit, &mut scores, 1.0, PROVINCE_UNIT_ORDER_WEIGHT);
    let vector = scores.components();
    let total: f32 = vector.iter().sum();
    if total == 0.0 {
        return -1000.0;
    }
    let squared: f32 = vector
        .iter()
        .zip(reference)
        .map(|(&value, target)| {
            let difference = value / total - target;
            difference * difference
        })
        .sum();
    let distance_penalty: f32 = if unit.stationed_province() == target {
        0.0
    } else {
        0.01
    };
    -(squared + distance_penalty)
}

fn queue_divergence(category: NavyPriorityTable<f32>) -> f32 {
    let sum: f32 = category.values().sum();
    if sum == 0.0 {
        return 0.0;
    }
    let accum = NavyPriorityComponent::ALL
        .into_iter()
        .map(|component| {
            (category[component] / sum - f32::from(NAVY_QUEUE_PROFILE[component]) * 0.01).abs()
        })
        .sum::<f32>();
    sum * (1.0 - accum * 0.5)
}

fn defend_pressure_scale(
    nation: NationId,
    compatible: bool,
    metrics: Option<&NationOrderPriorityMetrics>,
) -> f32 {
    let Some(metrics) = metrics else {
        return 1.0;
    };
    let Some(major) = MajorNationId::from_nation(nation) else {
        return 1.0;
    };
    let slot = usize::from(major.get());
    let mut b68 = metrics.unit_divergence[slot];
    if b68 <= 0.0 {
        b68 = 1.0;
    }
    if compatible {
        metrics.expansion_pressure[slot] + b68
    } else {
        b68
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    fn ship(_id: usize, selection: ShipSelection) -> ShipState {
        ShipState {
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(0),
            aggression: NavalAggression::Cautious,
            nation: NationId::new(0),
            name: String::new(),
            strength: 100,
            experience: 0,
            selection,
        }
    }

    fn seed_owned_province(state: &mut GameState, province: ProvinceId, owner: NationId) {
        state.map.provinces[province] = ProvinceState::new(
            Some(owner),
            Some(owner),
            ProvinceDevelopmentStage::None,
            Vec::new(),
            Vec::new(),
            None,
            FortLevel::None,
            None,
            0,
            None,
            None,
            Vec::new(),
            ResourceTable::default(),
            MajorNationTable::default(),
            0,
            false,
            0,
            String::new(),
        );
    }

    fn defend_mission(nation: NationId, province: ProvinceId) -> MissionState {
        MissionState {
            nation,
            data: MissionData::DefendProvince {
                province,
                army: ArmyMissionState {
                    required_equipage_bits: [0; 5],
                    units: Default::default(),
                },
            },
            path_nation: None,
            state: 2,
            importance_bits: 0,
            held: false,
            marker: 0,
        }
    }

    #[test]
    fn cleanup_resets_transient_selection_rebuilds_the_heatmap_and_commits_purchases() {
        let mut state = game_state();
        state.ships.extend([
            (ShipId::new(0), ship(0, ShipSelection::Transient)),
            (ShipId::new(1), ship(1, ShipSelection::Reserved)),
        ]);
        state.map[TileId::new(1)].province = Some(ProvinceId::new(0));
        state.map[TileId::new(1)].edge_resources = [Some(ResourceKind::Cotton), None];
        state.map.provinces[ProvinceId::new(0)].linked_tiles = vec![TileId::new(1)];

        let eligible = MajorNationId::new(0);
        let ineligible = MajorNationId::new(1);
        state.nations.majors[&eligible]
            .economy
            .purchased_items_by_resource[ResourceKind::Food] = 5;
        state.nations.majors[&eligible].city.stockpile[ResourceKind::Food] = 1;
        state.nations.majors[&ineligible]
            .economy
            .purchased_items_by_resource[ResourceKind::Food] = 7;
        state.nations.majors[&ineligible].city.stockpile[ResourceKind::Food] = 2;
        state.set_country_status(
            ineligible.nation(),
            CountryStatus::ProtectorateOf(NationId::new(0)),
        );

        let mut expected = state.clone();
        expected.recompute_tile_strategic_score_heatmap();
        for province in ProvinceId::all() {
            state.map.provinces[province].set_city_score(1);
        }
        state.map.city_score_total = 1;

        state.do_military_cleanup();

        assert_eq!(
            state.ships[&ShipId::new(0)].selection,
            ShipSelection::Available
        );
        assert_eq!(
            state.ships[&ShipId::new(1)].selection,
            ShipSelection::Reserved
        );
        assert_eq!(
            state.map.city_score_total, expected.map.city_score_total,
            "cleanup must rebuild the heatmap, not keep a corrupted total"
        );
        assert_ne!(state.map.city_score_total, 1);
        for province in ProvinceId::all() {
            assert_eq!(
                state.map.provinces[province].city_score(),
                expected.map.provinces[province].city_score()
            );
        }
        assert_eq!(
            state.nations.majors[&eligible].city.stockpile[ResourceKind::Food],
            6
        );
        assert_eq!(
            state.nations.majors[&eligible]
                .economy
                .purchased_items_by_resource[ResourceKind::Food],
            0
        );
        assert_eq!(
            state.nations.majors[&ineligible].city.stockpile[ResourceKind::Food],
            2,
            "protectorates skip purchase commit"
        );
        assert_eq!(
            state.nations.majors[&ineligible]
                .economy
                .purchased_items_by_resource[ResourceKind::Food],
            7
        );
    }

    #[test]
    fn cleanup_adopts_unassigned_militia_into_the_defend_mission() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.nations.majors[&nation].auto = Some(AutoGreatPowerState::default());
        let province = ProvinceId::new(3);
        seed_owned_province(&mut state, province, nation.nation());
        let id = state.unit_ids.next_military();
        state.military_units.insert(
            id,
            MilitaryUnitState::new(
                nation.nation(),
                MilitaryUnitKind::Minutemen,
                Some(province),
                MilitaryOrder::idle([Some(province); 3], [Some(province); 3]),
                nation.nation(),
                0,
                true,
                String::new(),
                500,
                MilitaryEra::First,
                0,
                0,
            ),
        );
        let mission = state.object_ids.mission();
        state
            .missions
            .insert(mission, defend_mission(nation.nation(), province));

        state.do_military_cleanup();

        let MissionData::DefendProvince { army, .. } = &state.missions[&mission].data else {
            panic!("expected a defend-province mission");
        };
        assert_eq!(army.units.iter().copied().collect::<Vec<_>>(), vec![id]);
    }

    #[test]
    fn cleanup_prunes_a_defend_mission_whose_province_changed_owner() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.nations.majors[&nation].auto = Some(AutoGreatPowerState::default());
        let province = ProvinceId::new(3);
        seed_owned_province(&mut state, province, NationId::new(1));
        let mission = state.object_ids.mission();
        state
            .missions
            .insert(mission, defend_mission(nation.nation(), province));

        state.do_military_cleanup();

        assert!(state.missions.is_empty());
    }

    #[test]
    fn cleanup_removes_sail_and_empty_task_forces_and_keeps_patrol() {
        let mut state = game_state();
        state
            .ships
            .insert(ShipId::new(0), ship(0, ShipSelection::Available));
        state
            .ships
            .insert(ShipId::new(1), ship(1, ShipSelection::Available));
        state.task_forces.insert(
            TaskForceId::new(0),
            TaskForceState {
                aggression: NavalAggression::Cautious,
                order: TaskForceOrder::Patrol,
                target: TaskForceTarget::Zone(OceanZoneId::new(0)),
                location: OceanZoneId::new(0),
                nation: NationId::new(0),
                defeated: false,
                ingot_tile: -1,
                flagship: Some(ShipId::new(0)),
                ships: [(ShipId::new(0), true)].into_iter().collect(),
            },
        );
        state.task_forces.insert(
            TaskForceId::new(1),
            TaskForceState {
                aggression: NavalAggression::Cautious,
                order: TaskForceOrder::Sail,
                target: TaskForceTarget::Zone(OceanZoneId::new(1)),
                location: OceanZoneId::new(0),
                nation: NationId::new(0),
                defeated: false,
                ingot_tile: -1,
                flagship: Some(ShipId::new(1)),
                ships: [(ShipId::new(1), true)].into_iter().collect(),
            },
        );

        state.do_military_cleanup();

        assert_eq!(state.task_forces.len(), 1);
        assert_eq!(
            state.task_forces[&TaskForceId::new(0)].order,
            TaskForceOrder::Patrol
        );
        assert_eq!(
            state.task_force_of_ship(ShipId::new(0)),
            Some(TaskForceId::new(0))
        );
        assert_eq!(state.task_force_of_ship(ShipId::new(1)), None);
    }

    fn attack_mission(nation: NationId, target: ProvinceId) -> MissionState {
        MissionState {
            nation,
            data: MissionData::AttackProvince(AttackMissionState {
                army: ArmyMissionState {
                    required_equipage_bits: [0; 5],
                    units: Default::default(),
                },
                present_province: Some(ProvinceId::new(0)),
                target_province: target,
                amassing_province: None,
            }),
            path_nation: Some(NationId::new(1)),
            state: 2,
            importance_bits: 0,
            held: false,
            marker: 1,
        }
    }

    #[test]
    fn reassess_writes_defend_needs_from_the_baseline_profile() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.nations.majors[&nation].auto = Some(AutoGreatPowerState::default());
        let province = ProvinceId::new(3);
        seed_owned_province(&mut state, province, nation.nation());
        state.map.provinces[province].set_city_score(2500);
        state.map[TileId::new(1)].province = Some(province);
        let mission = state.object_ids.mission();
        state
            .missions
            .insert(mission, defend_mission(nation.nation(), province));

        state.reassess_missions_with_metrics(nation.nation(), None);

        assert_eq!(
            state.missions[&mission].state, 0,
            "capitol province uses state 0"
        );
        assert_eq!(
            state.missions[&mission].importance_bits,
            (2500.0_f32 / 5000.0).to_bits()
        );
        let MissionData::DefendProvince { army, .. } = &state.missions[&mission].data else {
            panic!("expected a defend-province mission");
        };
        assert_eq!(
            army.required_equipage_bits,
            [40.0_f32, 27.0, 0.0, 17.0, 16.0]
                .map(|weight| ((f64::from(weight) * 0.01) as f32).to_bits())
        );
    }

    #[test]
    fn reassess_writes_attack_needs_from_the_unfortified_output_profile() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.nations.majors[&nation].auto = Some(AutoGreatPowerState::default());
        let target = ProvinceId::new(4);
        seed_owned_province(&mut state, target, NationId::new(1));
        state.map.provinces[target].set_city_score(1000);
        let mission = state.object_ids.mission();
        state
            .missions
            .insert(mission, attack_mission(nation.nation(), target));

        state.reassess_missions_with_metrics(nation.nation(), None);

        let MissionData::AttackProvince(attack) = &state.missions[&mission].data else {
            panic!("expected an attack-province mission");
        };
        let scale = 1.9_f32;
        assert_eq!(
            attack.army.required_equipage_bits,
            [27.0, 36.0, 0.0, 17.0, 20.0].map(|weight| (weight * scale * 0.01).to_bits())
        );
        assert_eq!(
            state.missions[&mission].importance_bits,
            (1000.0_f32 / 5000.0).to_bits()
        );
    }

    #[test]
    fn reassess_fills_control_sea_needs_when_the_zone_has_no_hostiles() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.nations.majors[&nation].auto = Some(AutoGreatPowerState::default());
        let tile = TileId::new(1);
        state.map[tile].former_owner_nation = Some(TileOwnerTag::from_nation(nation.nation()));
        state.ocean.zones = vec![
            ZoneKind::Zone(Zone {
                display_name: String::new(),
                status_code: None,
                target_tile: None,
                seed_owner: None,
                active_tile: None,
                primary_neighbors: vec![OceanZoneId::new(1)],
                secondary_neighbors: Vec::new(),
            }),
            ZoneKind::PortZone(PortZone {
                zone: Zone {
                    display_name: String::new(),
                    status_code: None,
                    target_tile: None,
                    seed_owner: None,
                    active_tile: None,
                    primary_neighbors: vec![OceanZoneId::new(0)],
                    secondary_neighbors: Vec::new(),
                },
                port_tile: tile,
            }),
        ];
        let mission = state.object_ids.mission();
        state.missions.insert(
            mission,
            MissionState {
                nation: nation.nation(),
                data: MissionData::ControlSeaZone(NavyMissionState {
                    target_zone: Some(OceanZoneId::new(0)),
                    resolved_port_zone: None,
                    selected_ship: None,
                    state: NavyMissionSelection::AssembleAtPort,
                    required_equipage_bits: [0; 4],
                    task_force: None,
                    ships: Default::default(),
                }),
                path_nation: None,
                state: 2,
                importance_bits: 0,
                held: false,
                marker: 0,
            },
        );

        state.reassess_missions_with_metrics(nation.nation(), None);

        let MissionData::ControlSeaZone(navy) = &state.missions[&mission].data else {
            panic!("expected a control-sea mission");
        };
        assert_eq!(
            navy.required_equipage_bits,
            [40.0_f32, 40.0, 20.0, 0.0].map(|weight| weight.to_bits())
        );
        assert_eq!(navy.state, NavyMissionSelection::AssembleAtPort);
        assert_eq!(state.missions[&mission].state, 2);
    }
}
