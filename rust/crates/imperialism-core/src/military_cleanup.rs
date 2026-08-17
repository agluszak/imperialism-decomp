//! Military cleanup phase (`TSimMgr` turn-state 0x15).

use crate::military::{
    ActionClassScores, PROVINCE_UNIT_ORDER_WEIGHT, TACTICAL_COMPOSITION, accumulate_unit_priority,
};
use crate::navy_orders::{navy_category_baselines, ship_priority_contribution};
use crate::*;

const ATTACK_RESOURCE_SCALE: [[f32; 4]; 5] = [
    [1.9, 2.3, 2.5, 2.7],
    [1.9, 2.3, 2.5, 2.7],
    [2.0, 2.3, 2.5, 2.7],
    [2.1, 2.3, 2.5, 2.7],
    [2.3, 2.5, 2.7, 2.9],
];
const NAVY_QUEUE_PROFILE: [i16; 4] = [40, 40, 20, 0];
const UNIT_PRIORITY_WEIGHT: f32 = 0.33;
const PRESSURE_UNSET: f32 = -1.0;
const PRESSURE_RATIO_CAP: f32 = 1.0;
const PRESSURE_MIDPOINT: f32 = 0.5;
const PRESSURE_PEER_SCALE: f32 = 1.1;

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
    /// before mission reassess so defend needs read B64/B68. AI development
    /// replanning (`PlanAiDevelopmentActionsFromResourcePools`) is not ported.
    pub fn do_military_cleanup(&mut self) {
        self.clear_all_transient_navy_orders();
        self.apply_military_cleanup_supported_subset();
        let metrics = self.recompute_nation_order_priority_metrics();
        for nation in MajorNationId::all() {
            if !self.nation_is_eligible_for_optional_phase(nation.nation()) {
                continue;
            }
            if self.is_auto(nation) {
                self.reassess_missions_with_metrics(nation.nation(), Some(&metrics));
                self.prune_invalid_defend_missions(nation.nation());
            }
        }
        let decade = self.turn.economic_turn / 40;
        if self.turn.economic_turn % 40 == 0
            && decade >= 0
            && self
                .turn
                .quarter_gate_by_decade
                .get(decade as usize)
                .is_some_and(|&gate| gate != 0)
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
            let mut category = [0.0_f32; 4];
            for ship in self.ships.values() {
                if ship.nation != nation.nation() {
                    continue;
                }
                category[0] += ship_priority_contribution(ship, 0, &baselines) as f32;
                category[1] += ship_priority_contribution(ship, 1, &baselines) as f32;
                category[2] += ship_priority_contribution(ship, 2, &baselines) as f32;
                category[3] += ship_priority_contribution(ship, 3, &baselines) as f32;
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
                        && matches!(mission.data, MissionData::ControlSeaZone(_)))
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
            return costs.map(|cost| (f32::from(cost) * pressure / sum as f32).to_bits());
        }
        let mut scale = pressure;
        if NationId::all().any(|other| self.at_war(nation, other)) {
            let cross = self.cross_nation_support_score(province) * 0.8;
            if scale < cross {
                scale = cross;
            }
        }
        let profile = if self.map.provinces[province].fort_level() < 1 {
            TACTICAL_COMPOSITION.baseline
        } else {
            TACTICAL_COMPOSITION.fort_garrison
        };
        profile
            .components()
            .map(|weight| (f32::from(weight) * scale * 0.01).to_bits())
    }

    fn attack_required_equipage(&self, target: ProvinceId) -> [u32; 5] {
        let mut scores = ActionClassScores::default();
        for unit in self.units_stationed_in(target) {
            accumulate_unit_priority(unit, &mut scores, 1.0, PROVINCE_UNIT_ORDER_WEIGHT);
        }
        let fort = self.map.provinces[target].fort_level() > 0;
        let mut similarity = scores.similarity(if fort {
            TACTICAL_COMPOSITION.fort_garrison
        } else {
            TACTICAL_COMPOSITION.baseline
        });
        if similarity == 0.0 {
            similarity = 1.0;
        }
        let difficulty = self.turn.difficulty as usize;
        let fort_column = (self.map.provinces[target].fort_level().max(0) as usize).min(3);
        let scale = ATTACK_RESOURCE_SCALE[difficulty][fort_column] * similarity;
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

    /// Selection-bit clear, heatmap, militia adoption, ship assignment, and
    /// `AddPurchasedItems`. Does not prune missions or remove navy stragglers.
    pub(crate) fn apply_military_cleanup_supported_subset(&mut self) {
        for ship in self.ships.values_mut() {
            if ship.selection == 1 {
                ship.selection = 0;
            }
        }
        self.recompute_tile_strategic_score_heatmap();
        for nation in MajorNationId::all() {
            if !self.nation_is_eligible_for_optional_phase(nation.nation()) {
                continue;
            }
            if self.is_auto(nation) {
                self.adopt_unassigned_militia_into_defend_missions(nation.nation());
                self.assign_unassigned_ships_to_navy_missions(nation.nation());
            }
            self.commit_purchased_items(nation);
        }
    }

    /// `TAutoGreatPower::RefreshTrackedEntriesAndReplanAiDevelopment` militia
    /// adoption. AI development replanning is not ported.
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

    /// `TDefendProvinceMission::GetReplacementSlot48`: drop defend missions whose
    /// province is no longer owned by the mission nation.
    fn prune_invalid_defend_missions(&mut self, nation: NationId) {
        let mut remove = Vec::new();
        for (&id, mission) in &self.missions {
            if mission.nation != nation {
                continue;
            }
            if let MissionData::DefendProvince { province, .. } = &mission.data
                && self.normalized_province_owner(*province) != Some(nation)
            {
                remove.push(id);
            }
        }
        for id in remove {
            self.missions.shift_remove(&id);
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
}

fn queue_divergence(category: [f32; 4]) -> f32 {
    let sum = category[0] + category[1] + category[2] + category[3];
    if sum == 0.0 {
        return 0.0;
    }
    let accum = (0..4)
        .map(|index| (category[index] / sum - f32::from(NAVY_QUEUE_PROFILE[index]) * 0.01).abs())
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

    fn ship(_id: usize, selection: i32) -> ShipState {
        ShipState {
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(0),
            aggression: 0,
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
            0,
            Vec::new(),
            Vec::new(),
            None,
            0,
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
        state
            .ships
            .extend([(ShipId::new(0), ship(0, 1)), (ShipId::new(1), ship(1, 2))]);
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

        assert_eq!(state.ships[&ShipId::new(0)].selection, 0);
        assert_eq!(state.ships[&ShipId::new(1)].selection, 2);
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
                0,
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
        state.ships.insert(ShipId::new(0), ship(0, 0));
        state.ships.insert(ShipId::new(1), ship(1, 0));
        state.task_forces.insert(
            TaskForceId::new(0),
            TaskForceState {
                aggression: 0,
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
                aggression: 0,
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
            [40.0_f32, 27.0, 0.0, 17.0, 16.0].map(|weight| (weight * 0.01).to_bits())
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
                    state: 0,
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

        state.do_military_cleanup();

        let MissionData::ControlSeaZone(navy) = &state.missions[&mission].data else {
            panic!("expected a control-sea mission");
        };
        assert_eq!(
            navy.required_equipage_bits,
            [40.0_f32, 40.0, 20.0, 0.0].map(|weight| weight.to_bits())
        );
        assert_eq!(navy.state, 0);
        assert_eq!(state.missions[&mission].state, 2);
    }
}
