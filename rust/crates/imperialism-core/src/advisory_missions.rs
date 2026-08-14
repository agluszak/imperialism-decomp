//! AutoGreatPower case-16 advisory mission selection (`TAutoGreatPower::
//! SelectAndQueueAdvisoryMapMissionsCase16` and `CreateMission`).

use crate::*;

const ADVISORY_RESOURCE_ORDERS: [ResourceKind; 4] = [
    ResourceKind::Timber,
    ResourceKind::Coal,
    ResourceKind::Iron,
    ResourceKind::Oil,
];

const ADVISORY_MISSION_TIER_THRESHOLDS: [[f32; 6]; 5] = [
    [1.5, 1.5, 2.5, 0.0, 2.25, 2.0],
    [1.75, 1.75, 2.5, 0.0, 2.25, 2.25],
    [2.0, 2.0, 2.0, 0.0, 1.5, 1.5],
    [2.0, 2.0, 3.0, 0.0, 2.0, 2.0],
    [1.5, 1.5, 2.5, 0.0, 1.75, 1.75],
];

const WEIGHTED_NEIGHBOR_UNIT_SCORE: [i32; 32] = [
    70, 137, 135, 164, 165, 211, 193, 300, 95, 243, 230, 265, 230, 275, 323, 549, 170, 450, 471,
    495, 493, 1010, 715, 913, 193, 260, 360, 200, 200, 200, 0, 1000,
];

const MISSION_SCORE_NORMALIZATION: f32 = 5000.0;
const PORT_ZONE_FRIENDLY_MULTIPLIER: f64 = 1.5;
const PORT_ZONE_FOREIGN_MULTIPLIER: f64 = 1.25;

const NAVY_RESOLVE_WEIGHT: [i32; 14] =
    [0, 0, 0, 300, 600, 0, 0, 300, 500, 1000, 0, 600, 2000, 1800];
const NAVY_CALCULATE_WEIGHT: [i32; 14] = [0, 0, 0, 5, 6, 0, 0, 7, 8, 10, 0, 9, 13, 13];
const NAVY_TASK_FORCE_WEIGHT: [i32; 14] = [0, 100, 95, 90, 80, 95, 100, 80, 45, 40, 75, 50, 30, 45];
const NAVY_PRIORITY_WEIGHT: [i32; 14] = [0, 0, 0, 4, 3, 0, 0, 7, 5, 6, 0, 8, 7, 9];

#[derive(Clone, Copy)]
enum AdvisoryMissionKind {
    AttackProvince = 0,
    AmassProvince = 1,
    InvadeProvince = 2,
    DefendProvince = 3,
    BlockadePort = 4,
}

impl GameState {
    /// Retail `TAutoGreatPower::SelectAndQueueAdvisoryMapMissionsCase16`.
    pub fn select_and_queue_advisory_map_missions_case16(&mut self, nation: MajorNationId) {
        if self.nations.major(nation).common.home_tile.is_none() {
            return;
        }

        self.populate_case16_advisory_map_node_candidate_state(nation);

        let mut best_score = 0.0_f32;
        let mut best_region = None;
        let mut best_link_region = None;
        let mut best_tier = None;
        let mut best_port_zone = None;
        let mut best_direct_score = 0.0_f32;
        let mut second_best_direct_score = 0.0_f32;
        let mut second_best_direct_region = None;
        let mut direct_region = None;

        for index in 0..ProvinceId::COUNT {
            let province = ProvinceId::new(index);
            if self.province_target(nation, province) != AiTargetState::Candidate {
                continue;
            }
            let mut link_region = None;
            let (score, tier) = if self.has_direct_or_fallback_linked_node(province, nation) {
                let score = self.advisory_map_node_composite_score(nation, province, 0, None);
                best_direct_score = score;
                direct_region = Some(province);
                (score, Some(0_i32))
            } else if let Some(link) = self.second_degree_link_with_minor_fallback(province, nation)
            {
                link_region = Some(link);
                (
                    self.advisory_map_node_composite_score(nation, province, 1, Some(link)),
                    Some(1),
                )
            } else if self
                .context_containing_province_newest_first(province)
                .is_some()
            {
                (
                    self.advisory_map_node_composite_score(nation, province, 2, None),
                    Some(2),
                )
            } else {
                self.set_province_target(nation, province, AiTargetState::Unmarked);
                (0.0, None)
            };
            if score > best_score {
                best_score = score;
                best_region = Some(province);
                best_link_region = link_region;
                best_tier = tier;
            }
            if best_direct_score > second_best_direct_score
                && let Some(direct) = direct_region
            {
                second_best_direct_region = Some(direct);
                second_best_direct_score = best_direct_score;
            }
        }

        for ordinal in (0..self.ocean.zones.len()).rev() {
            if self.zone_target(nation, ordinal) != AiTargetState::Candidate {
                continue;
            }
            let zone = OceanZoneId::new(ordinal as u16);
            let zone_score = self.map_action_context_composite_score(nation, zone);
            if zone_score > best_score {
                best_port_zone = Some(zone);
                best_score = zone_score;
                best_tier = Some(
                    if matches!(self.ocean.zones[ordinal], ZoneKind::PortZone(_)) {
                        4
                    } else {
                        2
                    },
                );
            }
        }

        let mut queue_secondary_defend = false;
        if let Some(tier) = best_tier {
            let skill = self.nations.majors[nation]
                .economy
                .defense_minister_skill_index;
            let threshold = ADVISORY_MISSION_TIER_THRESHOLDS[skill as usize][tier as usize];
            let accept = threshold < best_score;
            if !accept
                && self.nation_has_war_relation(nation.nation())
                && !self.has_active_mission(nation)
            {
                queue_secondary_defend = true;
            }
            if accept {
                if let Some(port) = best_port_zone {
                    self.create_advisory_mission(
                        nation,
                        advisory_kind(tier),
                        None,
                        Some(port),
                        None,
                    );
                } else if let Some(region) = best_region {
                    if tier == 2 {
                        if let Some(context) = self.context_containing_province_newest_first(region)
                        {
                            self.create_advisory_mission(
                                nation,
                                AdvisoryMissionKind::InvadeProvince,
                                None,
                                Some(context),
                                Some(region),
                            );
                        } else {
                            self.set_province_target(nation, region, AiTargetState::Unmarked);
                        }
                    } else if let Some(link) = best_link_region {
                        self.create_advisory_mission(
                            nation,
                            advisory_kind(tier),
                            Some(link),
                            None,
                            Some(region),
                        );
                    } else {
                        self.create_advisory_mission(
                            nation,
                            advisory_kind(tier),
                            Some(region),
                            None,
                            None,
                        );
                    }
                }
            }
            if queue_secondary_defend && let Some(direct) = second_best_direct_region {
                self.create_advisory_mission(
                    nation,
                    AdvisoryMissionKind::AttackProvince,
                    Some(direct),
                    None,
                    None,
                );
            }
        }

        let any_eligible_at_war = (0..MajorNationId::COUNT).any(|index| {
            let other = MajorNationId::new(index);
            other != nation
                && self.diplomacy.relationships[other.nation()][nation.nation()]
                    == DiplomaticRelationship::War
                && self.nation_is_eligible_for_optional_phase(other.nation())
        });
        if !any_eligible_at_war {
            return;
        }
        for ordinal in (0..self.ocean.zones.len()).rev() {
            if self.zone_target(nation, ordinal) == AiTargetState::MissionQueued {
                continue;
            }
            let zone = &self.ocean.zones[ordinal];
            if !zone
                .zone()
                .secondary_neighbors
                .iter()
                .any(|&province| self.map.provinces[province].owner() == Some(nation.nation()))
            {
                continue;
            }
            let mask = self.zone_nation_mask(OceanZoneId::new(ordinal as u16));
            for index in 0..MajorNationId::COUNT {
                let other = MajorNationId::new(index);
                if other == nation {
                    continue;
                }
                if self.diplomacy.relationships[nation.nation()][other.nation()]
                    != DiplomaticRelationship::War
                {
                    continue;
                }
                if mask & (1 << index) == 0 {
                    continue;
                }
                self.set_zone_target(nation, ordinal, AiTargetState::Candidate);
                self.create_advisory_mission(
                    nation,
                    AdvisoryMissionKind::DefendProvince,
                    None,
                    Some(OceanZoneId::new(ordinal as u16)),
                    None,
                );
            }
        }
    }

    fn populate_case16_advisory_map_node_candidate_state(&mut self, nation: MajorNationId) {
        for index in 0..ProvinceId::COUNT {
            let province = ProvinceId::new(index);
            if self.province_target(nation, province) == AiTargetState::Candidate {
                self.set_province_target(nation, province, AiTargetState::Unmarked);
            }
        }

        for slot in 0..MajorNationId::COUNT {
            let candidate = MajorNationId::new(slot);
            if self.nations.majors[nation].economy.candidate_nation_flags[candidate.nation()] == 0 {
                continue;
            }
            let owned = self
                .nations
                .major(candidate)
                .common
                .owned_regions()
                .to_vec();
            for province in owned {
                self.mark_province_candidate_if_unmarked(nation, province);
            }
            if self.nation_is_eligible_for_optional_phase(candidate.nation()) {
                for minor_slot in MinorNationId::FIRST..MinorNationId::FIRST + 9 {
                    let minor = NationId::new(minor_slot);
                    if !self
                        .nations
                        .country_status(minor)
                        .is_some_and(|status| status.is_colony_of(candidate.nation()))
                    {
                        continue;
                    }
                    let owned = self
                        .nations
                        .common(minor)
                        .map(|common| common.owned_regions().to_vec())
                        .unwrap_or_default();
                    for province in owned {
                        self.mark_province_candidate_if_unmarked(nation, province);
                    }
                }
            }
        }

        for minor_slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = NationId::new(minor_slot);
            if self.nations.majors[nation].economy.candidate_nation_flags[minor] == 0 {
                continue;
            }
            let owned = self
                .nations
                .common(minor)
                .map(|common| common.owned_regions().to_vec())
                .unwrap_or_default();
            for province in owned {
                self.mark_province_candidate_if_unmarked(nation, province);
            }
        }

        if self.nation_has_war_relation(nation.nation()) {
            for resource in ADVISORY_RESOURCE_ORDERS {
                self.nations.majors[nation]
                    .economy
                    .interior_civilian
                    .historical_need_by_resource[resource] = 0;
            }
            return;
        }

        for resource in ADVISORY_RESOURCE_ORDERS {
            let need = self.nations.majors[nation]
                .economy
                .interior_civilian
                .historical_need_by_resource[resource];
            if need < 5 {
                continue;
            }
            let mut candidates = Vec::new();
            for index in 0..ProvinceId::COUNT {
                let province = ProvinceId::new(index);
                let Some(owner) = self.map.provinces[province].owner() else {
                    continue;
                };
                if self.diplomacy.relationships[nation.nation()][owner]
                    == DiplomaticRelationship::Alliance
                {
                    continue;
                }
                if let CountryStatus::ColonyOf(master) = self.status_of(owner)
                    && self.diplomacy.relationships[nation.nation()][master]
                        == DiplomaticRelationship::Alliance
                {
                    continue;
                }
                if self.province_target(nation, province) != AiTargetState::Unmarked {
                    continue;
                }
                if (1 << (resource as u8))
                    & self.map.provinces[province].resource_presence_mask as u8
                    == 0
                {
                    continue;
                }
                let mut score = self.diplomacy.standings[nation.nation()][owner];
                let link_bonus = if self.has_direct_or_fallback_linked_node(province, nation) {
                    0
                } else if self
                    .second_degree_link_with_minor_fallback(province, nation)
                    .is_some()
                {
                    0x14
                } else if self
                    .context_containing_province_newest_first(province)
                    .is_some()
                {
                    0x28
                } else {
                    continue;
                };
                score = score.wrapping_add(link_bonus);
                if MajorNationId::from_nation(owner)
                    .is_some_and(|owner| self.nation_is_eligible_for_optional_phase(owner.nation()))
                {
                    score = score.wrapping_add(0x14);
                }
                insert_scored_province(&mut self.rng, &mut candidates, province, score);
            }
            if let Some(&(top, _)) = candidates.first() {
                self.mark_province_candidate_if_unmarked(nation, top);
            }
            if let Some(&(second, _)) = candidates.get(1) {
                self.mark_province_candidate_if_unmarked(nation, second);
            }
        }
    }

    fn create_advisory_mission(
        &mut self,
        nation: MajorNationId,
        kind: AdvisoryMissionKind,
        map_node: Option<ProvinceId>,
        zone: Option<OceanZoneId>,
        related: Option<ProvinceId>,
    ) {
        if let Some(province) = map_node
            && self.province_target(nation, province) != AiTargetState::Candidate
        {
            return;
        }
        if zone.is_some()
            && related.is_none()
            && let Some(zone) = zone
            && self.zone_target(nation, usize::from(zone.get())) != AiTargetState::Candidate
        {
            return;
        }

        let mut kind = kind;
        if zone.is_some()
            && map_node.is_none()
            && related.is_none()
            && !matches!(kind, AdvisoryMissionKind::BlockadePort)
        {
            kind = AdvisoryMissionKind::DefendProvince;
        }

        let mission = self.build_advisory_mission(nation, kind, map_node, zone, related);
        self.push_mission(mission);

        if let Some(province) = map_node {
            self.set_province_target(nation, province, AiTargetState::MissionQueued);
        }
        if related.is_none()
            && let Some(zone) = zone
        {
            self.set_zone_target(
                nation,
                usize::from(zone.get()),
                AiTargetState::MissionQueued,
            );
        }
        if let Some(province) = related {
            self.set_province_target(nation, province, AiTargetState::MissionQueued);
        }
    }

    fn build_advisory_mission(
        &self,
        nation: MajorNationId,
        kind: AdvisoryMissionKind,
        map_node: Option<ProvinceId>,
        zone: Option<OceanZoneId>,
        related: Option<ProvinceId>,
    ) -> MissionState {
        match kind {
            AdvisoryMissionKind::AttackProvince if zone.is_none() => {
                let target = map_node.expect("attack mission has a province");
                attack_mission(nation, target, None, self.map.provinces[target].owner(), 1)
            }
            AdvisoryMissionKind::AttackProvince => control_sea_zone_mission(
                nation,
                zone.expect("sea-zone attack uses a zone"),
                self.control_sea_zone_importance(
                    nation,
                    zone.expect("sea-zone attack uses a zone"),
                ),
            ),
            AdvisoryMissionKind::AmassProvince => {
                let target = map_node.expect("amass mission has a province");
                attack_mission(
                    nation,
                    target,
                    related,
                    self.map.provinces[target].owner(),
                    1,
                )
            }
            AdvisoryMissionKind::InvadeProvince if related.is_some() => {
                let target = related.expect("invade mission has a target province");
                let beachhead_zone = zone.expect("invade mission has a beachhead zone");
                MissionState {
                    nation: nation.nation(),
                    data: MissionData::Invade {
                        attack: AttackMissionState {
                            army: empty_army(),
                            present_province: None,
                            target_province: target,
                            amassing_province: None,
                        },
                        beachhead: Some(empty_navy(Some(beachhead_zone), None)),
                    },
                    path_nation: self.map.provinces[target].owner(),
                    state: 2,
                    importance_bits: 0,
                    held: false,
                    marker: 3,
                }
            }
            AdvisoryMissionKind::InvadeProvince => control_sea_zone_mission(
                nation,
                zone.expect("invade without a province uses a zone"),
                self.control_sea_zone_importance(
                    nation,
                    zone.expect("invade without a province uses a zone"),
                ),
            ),
            AdvisoryMissionKind::DefendProvince if zone.is_none() => {
                let province = map_node.expect("defend mission has a province");
                MissionState {
                    nation: nation.nation(),
                    data: MissionData::DefendProvince {
                        province,
                        army: empty_army(),
                    },
                    path_nation: None,
                    state: 2,
                    importance_bits: 0,
                    held: false,
                    marker: 0,
                }
            }
            AdvisoryMissionKind::DefendProvince => {
                let zone = zone.expect("defend-at-zone mission has a zone");
                if self.first_port_zone_for_nation(nation.nation()) == Some(zone) {
                    MissionState {
                        nation: nation.nation(),
                        data: MissionData::Escort(empty_navy(Some(zone), Some(zone))),
                        path_nation: None,
                        state: 2,
                        importance_bits: 0,
                        held: false,
                        marker: 0,
                    }
                } else {
                    control_sea_zone_mission(
                        nation,
                        zone,
                        self.control_sea_zone_importance(nation, zone),
                    )
                }
            }
            AdvisoryMissionKind::BlockadePort => {
                let port = zone.expect("blockade mission has a port zone");
                let target = self.ocean.zones[usize::from(port.get())]
                    .zone()
                    .primary_neighbors
                    .first()
                    .copied()
                    .expect("blockade port has a cached sea-zone neighbor");
                MissionState {
                    nation: nation.nation(),
                    data: MissionData::BlockadePort {
                        navy: empty_navy(Some(target), None),
                        port_zone: port,
                    },
                    path_nation: None,
                    state: 2,
                    importance_bits: self.control_sea_zone_importance(nation, target),
                    held: false,
                    marker: 0,
                }
            }
        }
    }

    fn control_sea_zone_importance(&self, nation: MajorNationId, target: OceanZoneId) -> u32 {
        let mut score = self.zone_value_average(target) as f64;
        for ordinal in (0..self.ocean.zones.len()).rev() {
            let ZoneKind::PortZone(port) = &self.ocean.zones[ordinal] else {
                continue;
            };
            if port.zone.primary_neighbors.first().copied() != Some(target) {
                continue;
            }
            let owner = self.map[port.port_tile]
                .owner_nation
                .and_then(TileOwnerTag::nation);
            score *= if owner == Some(nation.nation()) {
                PORT_ZONE_FRIENDLY_MULTIPLIER
            } else {
                PORT_ZONE_FOREIGN_MULTIPLIER
            };
        }
        (score as f32 / MISSION_SCORE_NORMALIZATION).to_bits()
    }

    fn advisory_map_node_composite_score(
        &self,
        nation: MajorNationId,
        province: ProvinceId,
        mode: i32,
        link: Option<ProvinceId>,
    ) -> f32 {
        let owner = self.map.provinces[province]
            .owner()
            .expect("scored province has an owner");
        let owner_is_gp = MajorNationId::from_nation(owner).is_some();
        if owner_is_gp {
            if mode == 0 {
                let f1 = self.advisory_score_factor(nation, 1, Some(province), None, owner);
                let f3 = self.advisory_score_factor(nation, 3, Some(province), None, owner);
                let f5 = self.advisory_score_factor(nation, 5, Some(province), None, owner);
                let score = self.advisory_score_factor(nation, 6, Some(province), None, owner)
                    * f5
                    * f3
                    * f1
                    * f1;
                return score * score;
            }
            if mode == 1 {
                let link = link.expect("mode-1 score has a link province");
                let link_owner = self.map.provinces[link]
                    .owner()
                    .expect("link province has an owner");
                if link_owner != owner {
                    return 0.0;
                }
                let f1 = self.advisory_score_factor(nation, 1, Some(province), None, owner);
                let f3 = self.advisory_score_factor(nation, 3, Some(province), None, owner);
                let f5 = self.advisory_score_factor(nation, 5, Some(province), None, owner);
                let f6 = self.advisory_score_factor(nation, 6, Some(province), None, owner);
                let score = self.advisory_score_factor(nation, 3, Some(link), None, link_owner)
                    * f6
                    * f5
                    * f3
                    * f1;
                return score * score;
            }
            let zone = self.context_containing_province_newest_first(province);
            let f1 = self.advisory_score_factor(nation, 1, Some(province), None, owner);
            let f2 = self.advisory_score_factor(nation, 2, Some(province), None, owner);
            let f3 = self.advisory_score_factor(nation, 3, Some(province), None, owner);
            let f4 = self.advisory_score_factor(nation, 4, Some(province), zone, owner);
            let f5 = self.advisory_score_factor(nation, 5, Some(province), None, owner);
            let f6 = self.advisory_score_factor(nation, 6, Some(province), None, owner);
            return self.advisory_score_factor(nation, 7, Some(province), zone, owner)
                * f6
                * f4
                * f5
                * f2
                * f3
                * f1;
        }
        if mode == 0 {
            let f3 = self.advisory_score_factor(nation, 3, Some(province), None, owner);
            let f5 = self.advisory_score_factor(nation, 5, Some(province), None, owner);
            return self.advisory_score_factor(nation, 6, Some(province), None, owner) * f5 * f3;
        }
        if mode == 1 {
            let link = link.expect("mode-1 score has a link province");
            let link_owner = self.map.provinces[link]
                .owner()
                .expect("link province has an owner");
            if link_owner != owner {
                return 0.0;
            }
            let f1 = self.advisory_score_factor(nation, 1, Some(province), None, owner);
            let f3 = self.advisory_score_factor(nation, 3, Some(province), None, owner);
            let f5 = self.advisory_score_factor(nation, 5, Some(province), None, owner);
            let f6 = self.advisory_score_factor(nation, 6, Some(province), None, owner);
            return self.advisory_score_factor(nation, 3, Some(link), None, link_owner)
                * f6
                * f5
                * f3
                * f1;
        }
        let zone = self.context_containing_province_newest_first(province);
        let f1 = self.advisory_score_factor(nation, 1, Some(province), None, owner);
        let f3 = self.advisory_score_factor(nation, 3, Some(province), None, owner);
        let f5 = self.advisory_score_factor(nation, 5, Some(province), None, owner);
        let f6 = self.advisory_score_factor(nation, 6, Some(province), None, owner);
        self.advisory_score_factor(nation, 7, Some(province), zone, owner) * f6 * f5 * f3 * f1
    }

    fn map_action_context_composite_score(&self, nation: MajorNationId, zone: OceanZoneId) -> f32 {
        let flags = &self.nations.majors[nation].economy.candidate_nation_flags;
        let mut active = 0;
        let mut selected = 0_u8;
        for slot in 0..0x17_u8 {
            if flags[NationId::new(slot)] != 0 {
                active += 1;
            }
        }
        let mut composite = 0.0_f32;
        if active == 1 {
            while selected < 0x17 && flags[NationId::new(selected)] == 0 {
                selected += 1;
            }
        } else {
            let mut max_priority = 0;
            for index in 0..MajorNationId::COUNT {
                let candidate = MajorNationId::new(index);
                if flags[candidate.nation()] == 0 {
                    continue;
                }
                let priority = self.sum_navy_priority_in_zone(candidate, zone);
                if priority > max_priority {
                    max_priority = priority;
                    selected = index;
                }
            }
            if max_priority == 0 {
                composite = 1.0;
            }
        }
        if composite == 0.0 {
            let selected_nation = NationId::new(selected);
            let f2 = self.advisory_score_factor(nation, 2, None, Some(zone), selected_nation);
            let f4 = self.advisory_score_factor(nation, 4, None, Some(zone), selected_nation);
            let f5 = self.advisory_score_factor(nation, 5, None, Some(zone), selected_nation);
            let f7 = self.advisory_score_factor(nation, 7, None, Some(zone), selected_nation);
            composite = f5 * f7 * f2 * f4;
        }
        composite
    }

    fn advisory_score_factor(
        &self,
        nation: MajorNationId,
        metric: i32,
        province: Option<ProvinceId>,
        zone: Option<OceanZoneId>,
        selected: NationId,
    ) -> f32 {
        match metric {
            1 => {
                let mut sum = 0.0_f32;
                let mut selected_power = 0.0_f32;
                for index in 0..MajorNationId::COUNT {
                    let gp = MajorNationId::new(index);
                    if !self.nation_is_eligible_for_optional_phase(gp.nation()) {
                        continue;
                    }
                    let power = self.military_power(gp);
                    sum += power;
                    if gp.nation() == selected {
                        selected_power = power;
                    }
                }
                if selected_power == 0.0 {
                    selected_power = 1.0;
                }
                let denominator = self.great_power_count() as f32 * selected_power - -6.0;
                (sum - -6.0) / denominator
            }
            2 => {
                let mut sum = 0.0_f32;
                let mut selected_force = 0.0_f32;
                for index in 0..MajorNationId::COUNT {
                    let gp = MajorNationId::new(index);
                    if !self.nation_is_eligible_for_optional_phase(gp.nation()) {
                        continue;
                    }
                    let force = self.naval_force(gp);
                    sum += force;
                    if gp.nation() == selected {
                        selected_force = force;
                    }
                }
                if selected_force == 0.0 {
                    selected_force = 1.0;
                }
                let denominator = self.great_power_count() as f32 * selected_force - -6.0;
                (sum - -6.0) / denominator
            }
            3 => {
                let Some(province) = province else {
                    return 0.0;
                };
                let owned = self
                    .nations
                    .common(selected)
                    .map(NationCommonState::owned_region_count)
                    .unwrap_or(0) as f32;
                let node = self.weighted_neighbor_link_score(province) as f32 * owned;
                let linked_sum = self
                    .nations
                    .common(selected)
                    .map(|common| {
                        common
                            .owned_regions()
                            .iter()
                            .map(|&owned| self.weighted_neighbor_link_score(owned))
                            .sum::<i32>()
                    })
                    .unwrap_or(0) as f32;
                (linked_sum - -100.0) / (node - -100.0)
            }
            4 => {
                let Some(selected) = MajorNationId::from_nation(selected) else {
                    return 0.0;
                };
                let Some(zone) = zone else {
                    return 0.0;
                };
                let node = self.sum_navy_priority_in_zone(selected, zone) as f32
                    * self.count_zones_with_nation_bit(selected) as f32;
                (self.sum_navy_priority(selected) as f32 - -6.0) / (node - -6.0)
            }
            5 => 100.0 / self.diplomacy.standings[nation.nation()][selected] as f32,
            6 => {
                let province = province.expect("city-score factor has a province");
                let total = self.map.city_score_total as f32;
                let mut result = self.map.provinces[province].city_score() as f32 / total;
                if self.map.provinces[province].former_owner() == Some(nation.nation()) {
                    let owner = self.map.provinces[province].owner();
                    if owner != Some(nation.nation())
                        && owner.is_some_and(|owner| {
                            self.diplomacy.relationships[nation.nation()][owner]
                                == DiplomaticRelationship::War
                        })
                    {
                        result *= 1.5;
                    }
                }
                result
            }
            7 => {
                let zone = zone.expect("zone-average factor has a zone");
                let global = self.global_zone_value_average();
                if global == 0 {
                    0.0
                } else {
                    self.zone_value_average(zone) as f32 / global as f32
                }
            }
            _ => 0.0,
        }
    }

    fn has_direct_or_fallback_linked_node(
        &self,
        province: ProvinceId,
        nation: MajorNationId,
    ) -> bool {
        let record = &self.map.provinces[province];
        if record
            .adjacency()
            .iter()
            .any(|&adjacent| self.map.provinces[adjacent].owner() == Some(nation.nation()))
        {
            return true;
        }
        (7..NationId::COUNT).any(|slot| {
            let minor = NationId::new(slot);
            self.nations
                .country_status(minor)
                .is_some_and(|status| status.is_colony_of(nation.nation()))
                && record
                    .adjacency()
                    .iter()
                    .any(|&adjacent| self.map.provinces[adjacent].owner() == Some(minor))
        })
    }

    fn second_degree_link_with_minor_fallback(
        &self,
        province: ProvinceId,
        nation: MajorNationId,
    ) -> Option<ProvinceId> {
        self.second_degree_links_matching(province, nation.nation())
    }

    fn second_degree_links_matching(
        &self,
        province: ProvinceId,
        nation: NationId,
    ) -> Option<ProvinceId> {
        if self.map.provinces[province].adjacency().is_empty() {
            return None;
        }
        self.map.provinces[province]
            .adjacency()
            .iter()
            .copied()
            .find(|&adjacent| {
                !self.map.provinces[adjacent].adjacency().is_empty()
                    && self.map.provinces[province].owner() == Some(nation)
            })
    }

    fn context_containing_province_newest_first(
        &self,
        province: ProvinceId,
    ) -> Option<OceanZoneId> {
        self.ocean
            .zones
            .iter()
            .enumerate()
            .rev()
            .find_map(|(ordinal, zone)| {
                zone.zone()
                    .secondary_neighbors
                    .contains(&province)
                    .then(|| OceanZoneId::new(ordinal as u16))
            })
    }

    fn zone_value_average(&self, zone: OceanZoneId) -> i32 {
        match &self.ocean.zones[usize::from(zone.get())] {
            ZoneKind::PortZone(port) => {
                let Some(owner) = self.map[port.port_tile]
                    .owner_nation
                    .and_then(TileOwnerTag::nation)
                else {
                    return 0;
                };
                if !self.event_eligible(owner) {
                    return 0;
                }
                self.capitol_city_score(owner)
            }
            ZoneKind::Zone(zone) if !zone.secondary_neighbors.is_empty() => {
                let sum: i32 = zone
                    .secondary_neighbors
                    .iter()
                    .map(|&province| self.map.provinces[province].city_score())
                    .sum();
                sum / zone.secondary_neighbors.len() as i32
            }
            ZoneKind::Zone(_) => 0,
        }
    }

    fn global_zone_value_average(&self) -> i32 {
        if self.ocean.zones.is_empty() {
            return 0;
        }
        let sum: i32 = (0..self.ocean.zones.len())
            .rev()
            .map(|ordinal| self.zone_value_average(OceanZoneId::new(ordinal as u16)))
            .sum();
        sum / self.ocean.zones.len() as i32
    }

    fn capitol_city_score(&self, nation: NationId) -> i32 {
        let Some(home) = self.nations.home_tile(nation) else {
            return 0;
        };
        let Some(province) = self.map[home].province else {
            return 0;
        };
        self.map.provinces[province].city_score()
    }

    fn weighted_neighbor_link_score(&self, province: ProvinceId) -> i32 {
        self.military_units
            .iter()
            .filter(|unit| unit.stationed_province() == Some(province))
            .map(|unit| WEIGHTED_NEIGHBOR_UNIT_SCORE[unit.unit_type() as usize])
            .sum()
    }

    fn sum_navy_priority_in_zone(&self, nation: MajorNationId, zone: OceanZoneId) -> i32 {
        self.ships
            .iter()
            .filter(|ship| ship.nation == nation.nation() && ship.location == zone)
            .map(ship_studliness)
            .sum()
    }

    fn sum_navy_priority(&self, nation: MajorNationId) -> i32 {
        self.ships
            .iter()
            .filter(|ship| ship.nation == nation.nation())
            .map(ship_studliness)
            .sum()
    }

    fn count_zones_with_nation_bit(&self, nation: MajorNationId) -> i32 {
        let bit = 1_u16 << nation.get();
        (0..self.ocean.zones.len())
            .rev()
            .filter(|&ordinal| self.zone_nation_mask(OceanZoneId::new(ordinal as u16)) & bit != 0)
            .count() as i32
    }

    fn zone_nation_mask(&self, zone: OceanZoneId) -> u16 {
        let mut mask = 0_u16;
        for ship in &self.ships {
            if ship.location == zone {
                mask |= 1 << ship.nation.get();
            }
        }
        mask
    }

    fn great_power_count(&self) -> i32 {
        (0..MajorNationId::COUNT)
            .map(MajorNationId::new)
            .filter(|&nation| self.nations.major(nation).common.home_tile.is_some())
            .count() as i32
    }

    fn nation_has_war_relation(&self, nation: NationId) -> bool {
        NationId::all()
            .any(|other| self.diplomacy.relationships[nation][other] == DiplomaticRelationship::War)
    }

    fn has_active_mission(&self, nation: MajorNationId) -> bool {
        self.missions
            .iter()
            .any(|mission| mission.nation == nation.nation() && mission.marker & 1 != 0)
    }

    fn province_target(&self, nation: MajorNationId, province: ProvinceId) -> AiTargetState {
        self.nations.majors[nation]
            .economy
            .ai_province_targets
            .as_ref()
            .map(|targets| targets[province])
            .unwrap_or(AiTargetState::Unmarked)
    }

    fn set_province_target(
        &mut self,
        nation: MajorNationId,
        province: ProvinceId,
        value: AiTargetState,
    ) {
        let value = if value == AiTargetState::Candidate
            && !self.province_mission_node_available(province, nation)
        {
            AiTargetState::Unmarked
        } else {
            value
        };
        self.nations.majors[nation]
            .economy
            .ai_province_targets
            .as_mut()
            .expect("automatic great power requires province target state")[province] = value;
    }

    fn mark_province_candidate_if_unmarked(&mut self, nation: MajorNationId, province: ProvinceId) {
        if self.province_target(nation, province) == AiTargetState::Unmarked {
            self.set_province_target(nation, province, AiTargetState::Candidate);
        }
    }

    fn zone_target(&self, nation: MajorNationId, ordinal: usize) -> AiTargetState {
        self.nations.majors[nation]
            .economy
            .ai_zone_targets
            .as_ref()
            .and_then(|targets| targets.get(ordinal).copied())
            .unwrap_or(AiTargetState::Unmarked)
    }

    fn set_zone_target(&mut self, nation: MajorNationId, ordinal: usize, value: AiTargetState) {
        let targets = self.nations.majors[nation]
            .economy
            .ai_zone_targets
            .as_mut()
            .expect("automatic great power requires zone target state");
        if ordinal < targets.len() {
            targets[ordinal] = value;
        }
    }

    fn push_mission(&mut self, mission: MissionState) {
        let nation = mission.nation;
        let insert_at = self
            .missions
            .iter()
            .rposition(|existing| existing.nation == nation)
            .map_or_else(
                || {
                    self.missions
                        .iter()
                        .position(|existing| existing.nation.get() > nation.get())
                        .unwrap_or(self.missions.len())
                },
                |position| position + 1,
            );
        self.missions.insert(insert_at, mission);
    }
}

fn advisory_kind(tier: i32) -> AdvisoryMissionKind {
    match tier {
        0 => AdvisoryMissionKind::AttackProvince,
        1 => AdvisoryMissionKind::AmassProvince,
        2 => AdvisoryMissionKind::InvadeProvince,
        3 => AdvisoryMissionKind::DefendProvince,
        4 => AdvisoryMissionKind::BlockadePort,
        _ => AdvisoryMissionKind::AttackProvince,
    }
}

fn empty_army() -> ArmyMissionState {
    ArmyMissionState {
        required_equipage_bits: [0; 5],
        units: Vec::new(),
    }
}

fn empty_navy(
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

fn attack_mission(
    nation: MajorNationId,
    target: ProvinceId,
    amassing: Option<ProvinceId>,
    path_nation: Option<NationId>,
    marker: u8,
) -> MissionState {
    MissionState {
        nation: nation.nation(),
        data: MissionData::AttackProvince(AttackMissionState {
            army: empty_army(),
            present_province: None,
            target_province: target,
            amassing_province: amassing,
        }),
        path_nation,
        state: 2,
        importance_bits: 0,
        held: false,
        marker,
    }
}

fn control_sea_zone_mission(
    nation: MajorNationId,
    zone: OceanZoneId,
    importance_bits: u32,
) -> MissionState {
    MissionState {
        nation: nation.nation(),
        data: MissionData::ControlSeaZone(empty_navy(Some(zone), None)),
        path_nation: None,
        state: 2,
        importance_bits,
        held: false,
        marker: 0,
    }
}

fn ship_studliness(ship: &ShipState) -> i32 {
    let index = ship.ship_type as usize;
    let quantity_term = i32::from(ship.experience) / 100;
    let navy_term = (quantity_term + NAVY_PRIORITY_WEIGHT[index] * 10 + 5) / 10;
    let resolve_term = (quantity_term + NAVY_RESOLVE_WEIGHT[index] * 10 + 5) / 10;
    ((navy_term + NAVY_CALCULATE_WEIGHT[index]) * 100 + resolve_term + i32::from(ship.strength))
        / NAVY_TASK_FORCE_WEIGHT[index]
}

fn insert_scored_province(
    rng: &mut RngState,
    items: &mut Vec<(ProvinceId, i16)>,
    province: ProvinceId,
    score: i16,
) {
    let mut ordinal = 0;
    while ordinal < items.len() {
        let existing = items[ordinal].1;
        let cmp = if existing < score {
            1
        } else if score < existing {
            -1
        } else if rng.next_crt_rand() % 2 != 0 {
            1
        } else {
            -1
        };
        if cmp != 1 {
            items.insert(ordinal, (province, score));
            return;
        }
        ordinal += 1;
    }
    items.push((province, score));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    fn auto_nation(state: &mut GameState) -> MajorNationId {
        let nation = MajorNationId::new(1);
        state.nations.majors[nation].kind = MajorNationKind::AutoGreatPower;
        state.nations.majors[nation].economy.ai_province_targets = Some(ProvinceTable::default());
        state.nations.majors[nation].economy.ai_zone_targets = Some(Vec::new());
        nation
    }

    fn seed_province(state: &mut GameState, province: u16, owner: u8, adjacency: &[u16]) {
        state.map.provinces[ProvinceId::new(province)] = ProvinceState::new(
            Some(NationId::new(owner)),
            Some(NationId::new(owner)),
            0,
            adjacency.iter().copied().map(ProvinceId::new).collect(),
            vec![TileId::new(0); adjacency.len()],
            Some(0),
            0,
            None,
            0,
            None,
            None,
            Vec::new(),
            ResourceTable::default(),
            MajorNationTable::default(),
            200,
            false,
            0,
            String::new(),
        );
    }

    #[test]
    fn create_mission_queues_an_attack_and_marks_the_province() {
        let mut state = game_state();
        let nation = auto_nation(&mut state);
        seed_province(&mut state, 0, 1, &[1]);
        seed_province(&mut state, 1, 1, &[0]);
        state
            .nations
            .append_owned_region_during_construction(nation.nation(), ProvinceId::new(0));
        state
            .nations
            .append_owned_region_during_construction(nation.nation(), ProvinceId::new(1));
        state.set_province_target(nation, ProvinceId::new(1), AiTargetState::Candidate);

        state.create_advisory_mission(
            nation,
            AdvisoryMissionKind::AttackProvince,
            Some(ProvinceId::new(1)),
            None,
            None,
        );

        assert_eq!(
            state.province_target(nation, ProvinceId::new(1)),
            AiTargetState::MissionQueued
        );
        assert_eq!(state.missions.len(), 1);
        assert!(matches!(
            &state.missions[0].data,
            MissionData::AttackProvince(attack) if attack.target_province == ProvinceId::new(1)
        ));
        assert_eq!(state.missions[0].marker, 1);
        assert_eq!(state.missions[0].path_nation, Some(nation.nation()));
    }

    #[test]
    fn create_mission_skips_a_province_that_is_not_a_candidate() {
        let mut state = game_state();
        let nation = auto_nation(&mut state);
        seed_province(&mut state, 0, 1, &[1]);
        seed_province(&mut state, 1, 1, &[0]);
        state.create_advisory_mission(
            nation,
            AdvisoryMissionKind::AttackProvince,
            Some(ProvinceId::new(1)),
            None,
            None,
        );
        assert!(state.missions.is_empty());
        assert_eq!(
            state.province_target(nation, ProvinceId::new(1)),
            AiTargetState::Unmarked
        );
    }

    #[test]
    fn populate_marks_owned_regions_of_candidate_nations() {
        let mut state = game_state();
        let nation = auto_nation(&mut state);
        seed_province(&mut state, 0, 1, &[1]);
        seed_province(&mut state, 1, 1, &[0]);
        state
            .nations
            .append_owned_region_during_construction(nation.nation(), ProvinceId::new(0));
        state
            .nations
            .append_owned_region_during_construction(nation.nation(), ProvinceId::new(1));
        state.nations.majors[nation].economy.candidate_nation_flags[nation.nation()] = 1;
        state.set_province_target(nation, ProvinceId::new(0), AiTargetState::Candidate);

        state.populate_case16_advisory_map_node_candidate_state(nation);

        assert_eq!(
            state.province_target(nation, ProvinceId::new(0)),
            AiTargetState::Candidate
        );
        assert_eq!(
            state.province_target(nation, ProvinceId::new(1)),
            AiTargetState::Candidate
        );
    }

    #[test]
    fn populate_at_war_clears_advisory_historical_need() {
        let mut state = game_state();
        let nation = auto_nation(&mut state);
        state.diplomacy.relationships[nation.nation()][NationId::new(0)] =
            DiplomaticRelationship::War;
        state.nations.majors[nation]
            .economy
            .interior_civilian
            .historical_need_by_resource[ResourceKind::Timber] = 9;

        state.populate_case16_advisory_map_node_candidate_state(nation);

        assert_eq!(
            state.nations.majors[nation]
                .economy
                .interior_civilian
                .historical_need_by_resource[ResourceKind::Timber],
            0
        );
    }
}
