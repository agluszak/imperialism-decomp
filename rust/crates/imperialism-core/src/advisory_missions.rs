//! AutoGreatPower `SelectAndQueueAdvisoryMapMissionsCase16` and its scorer.

use crate::*;

const ADVISORY_RESOURCE_KINDS: [ResourceKind; 4] = [
    ResourceKind::Timber,
    ResourceKind::Coal,
    ResourceKind::Iron,
    ResourceKind::Oil,
];

const TIER_THRESHOLDS: [[f32; 6]; 5] = [
    [1.5, 1.5, 2.5, 0.0, 2.25, 2.0],
    [1.75, 1.75, 2.5, 0.0, 2.25, 2.25],
    [2.0, 2.0, 2.0, 0.0, 1.5, 1.5],
    [2.0, 2.0, 3.0, 0.0, 2.0, 2.0],
    [1.5, 1.5, 2.5, 0.0, 1.75, 1.75],
];

const NEIGHBOR_UNIT_WEIGHT: [i32; 32] = [
    70, 137, 135, 164, 165, 211, 193, 300, 95, 243, 230, 265, 230, 275, 323, 549, 170, 450, 471,
    495, 493, 1010, 715, 913, 193, 260, 360, 200, 200, 200, 0, 1000,
];

const MISSION_SCORE_DIVISOR: f32 = 5000.0;
const PORT_FRIENDLY_MULTIPLIER: f32 = 1.5;
const PORT_FOREIGN_MULTIPLIER: f32 = 1.25;

#[derive(Clone, Copy)]
enum AdvisoryMissionKind {
    Attack = 0,
    Amass = 1,
    Invade = 2,
    Defend = 3,
    Blockade = 4,
}

#[derive(Clone, Copy)]
struct AdvisoryCandidate {
    score: f32,
    route: AdvisoryRoute,
}

#[derive(Clone, Copy)]
enum AdvisoryRoute {
    Direct(ProvinceId),
    Via {
        target: ProvinceId,
        link: ProvinceId,
    },
    Sea {
        zone: OceanZoneId,
        target: Option<ProvinceId>,
    },
}

impl AdvisoryRoute {
    fn tier(self, zones: &[ZoneKind]) -> i32 {
        match self {
            Self::Direct(_) => 0,
            Self::Via { .. } => 1,
            Self::Sea {
                target: Some(_), ..
            } => 2,
            Self::Sea { zone, target: None } => {
                if matches!(zones[usize::from(zone.get())], ZoneKind::PortZone(_)) {
                    4
                } else {
                    2
                }
            }
        }
    }
}

impl GameState {
    #[cfg(feature = "oracle")]
    pub(crate) fn select_and_queue_advisory_map_missions(&mut self) {
        for nation in MajorNationId::all() {
            if !self.nation_is_eligible_for_optional_phase(nation.nation()) {
                continue;
            }
            if self.is_auto(nation) {
                self.select_and_queue_advisory_map_missions_for(nation);
            }
        }
    }

    pub(crate) fn select_and_queue_advisory_map_missions_for(&mut self, nation: MajorNationId) {
        if self.nations.majors[nation].auto.is_none() {
            return;
        }

        self.populate_case16_advisory_candidates(nation);

        let mut best: Option<AdvisoryCandidate> = None;
        let mut best_direct: Option<(f32, ProvinceId)> = None;

        for province in ProvinceId::all() {
            if self.province_target(nation, province) != Some(AiTargetState::Candidate) {
                continue;
            }
            let candidate = if self.has_direct_or_colony_link(province, nation.nation()) {
                let score = self.advisory_direct_score(nation, province);
                if best_direct.is_none_or(|(best_score, _)| score > best_score) {
                    best_direct = Some((score, province));
                }
                Some(AdvisoryCandidate {
                    score,
                    route: AdvisoryRoute::Direct(province),
                })
            } else if let Some(link) = self.first_second_degree_link(province, nation.nation()) {
                Some(AdvisoryCandidate {
                    score: self.advisory_via_score(nation, province, link),
                    route: AdvisoryRoute::Via {
                        target: province,
                        link,
                    },
                })
            } else if let Some(zone) = self.newest_context_containing_province(province) {
                Some(AdvisoryCandidate {
                    score: self.advisory_overseas_score(nation, province),
                    route: AdvisoryRoute::Sea {
                        zone,
                        target: Some(province),
                    },
                })
            } else {
                self.set_province_target(nation, province, AiTargetState::Unmarked);
                None
            };
            if let Some(candidate) = candidate
                && candidate.score > best.map_or(0.0, |best| best.score)
            {
                best = Some(candidate);
            }
        }

        for ordinal in (0..self.ocean.zones.len()).rev() {
            if self.zone_target(nation, ordinal) != Some(AiTargetState::Candidate) {
                continue;
            }
            let zone = OceanZoneId::new(ordinal as u16);
            let score = self.map_action_context_score(nation, zone);
            if score > best.map_or(0.0, |best| best.score) {
                best = Some(AdvisoryCandidate {
                    score,
                    route: AdvisoryRoute::Sea { zone, target: None },
                });
            }
        }

        let mut queue_secondary = false;
        if let Some(best) = best {
            let tier = best.route.tier(&self.ocean.zones);
            let skill = self.nations.majors[nation]
                .economy
                .defense_minister_skill_index;
            let skill = usize::try_from(skill).expect("defense minister skill is a table row");
            let accept = TIER_THRESHOLDS[skill][tier as usize] < best.score;
            if !accept && self.nation_has_war_relation(nation.nation()) {
                let has_attack_mission = self
                    .missions
                    .values()
                    .any(|mission| mission.nation == nation.nation() && mission.marker & 1 != 0);
                if !has_attack_mission {
                    queue_secondary = true;
                }
            }
            if accept {
                match best.route {
                    AdvisoryRoute::Sea { zone, target: None } => {
                        self.create_advisory_mission(
                            nation,
                            kind_from_tier(tier),
                            None,
                            Some(zone),
                            None,
                        );
                    }
                    AdvisoryRoute::Sea {
                        zone,
                        target: Some(region),
                    } => {
                        self.create_advisory_mission(
                            nation,
                            AdvisoryMissionKind::Invade,
                            None,
                            Some(zone),
                            Some(region),
                        );
                    }
                    AdvisoryRoute::Via { target, link } => {
                        self.create_advisory_mission(
                            nation,
                            kind_from_tier(tier),
                            Some(link),
                            None,
                            Some(target),
                        );
                    }
                    AdvisoryRoute::Direct(region) => {
                        self.create_advisory_mission(
                            nation,
                            kind_from_tier(tier),
                            Some(region),
                            None,
                            None,
                        );
                    }
                }
            }
            if queue_secondary && let Some((_, region)) = best_direct {
                self.create_advisory_mission(
                    nation,
                    AdvisoryMissionKind::Attack,
                    Some(region),
                    None,
                    None,
                );
            }
        }

        let any_eligible_at_war = MajorNationId::all().any(|other| {
            self.at_war(other.nation(), nation.nation()) && self.event_eligible(other.nation())
        });
        if !any_eligible_at_war {
            return;
        }
        for ordinal in (0..self.ocean.zones.len()).rev() {
            if self.zone_target(nation, ordinal) == Some(AiTargetState::MissionQueued) {
                continue;
            }
            let zone = OceanZoneId::new(ordinal as u16);
            if !self.zone_has_secondary_neighbor_owner(zone, nation.nation()) {
                continue;
            }
            let mask = self.zone_nation_key_mask(zone);
            for other in MajorNationId::all() {
                if other == nation {
                    continue;
                }
                if !self.at_war(nation.nation(), other.nation()) {
                    continue;
                }
                if mask & (1 << other.get()) == 0 {
                    continue;
                }
                self.set_zone_target(nation, ordinal, AiTargetState::Candidate);
                self.create_advisory_mission(
                    nation,
                    AdvisoryMissionKind::Defend,
                    None,
                    Some(zone),
                    None,
                );
            }
        }
    }

    fn populate_case16_advisory_candidates(&mut self, nation: MajorNationId) {
        for province in ProvinceId::all() {
            if self.province_target(nation, province) == Some(AiTargetState::Candidate) {
                self.set_province_target(nation, province, AiTargetState::Unmarked);
            }
        }

        let flagged_majors: Vec<MajorNationId> = MajorNationId::all()
            .filter(|&slot| {
                self.nations.common(slot.nation()).is_some()
                    && self.nations.majors[nation].economy.candidate_nation_flags[slot.nation()]
                        != 0
            })
            .collect();
        for slot in flagged_majors {
            let owned = self.owned_regions_of(slot.nation()).to_vec();
            for region in owned {
                self.mark_province_candidate(nation, region);
            }
            if self.event_eligible(slot.nation()) {
                let colony_regions: Vec<ProvinceId> = MinorNationId::all()
                    .filter(|&minor| self.status_of(minor.nation()).is_colony_of(slot.nation()))
                    .flat_map(|minor| self.owned_regions_of(minor.nation()).iter().copied())
                    .collect();
                for region in colony_regions {
                    self.mark_province_candidate(nation, region);
                }
            }
        }

        let flagged_minors: Vec<NationId> = MinorNationId::all()
            .map(MinorNationId::nation)
            .filter(|&minor| self.nations.majors[nation].economy.candidate_nation_flags[minor] != 0)
            .collect();
        for minor in flagged_minors {
            let owned = self.owned_regions_of(minor).to_vec();
            for region in owned {
                self.mark_province_candidate(nation, region);
            }
        }

        if self.nation_has_war_relation(nation.nation()) {
            let interior = &mut self.nations.majors[nation].economy.interior_civilian;
            for resource in ADVISORY_RESOURCE_KINDS {
                interior.historical_need_by_resource[resource] = 0;
            }
            return;
        }

        for resource in ADVISORY_RESOURCE_KINDS {
            let need = self.nations.majors[nation]
                .economy
                .interior_civilian
                .historical_need_by_resource[resource];
            if need < 5 {
                continue;
            }
            let mut candidates = Vec::new();
            for rec in ProvinceId::all() {
                let Some(owner) = self.map.provinces[rec].owner() else {
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
                if self.province_target(nation, rec) != Some(AiTargetState::Unmarked) {
                    continue;
                }
                if i32::from(self.map.provinces[rec].resource_presence_mask)
                    & (1 << resource as i32)
                    == 0
                {
                    continue;
                }
                let mut score = self.diplomacy.standings[nation.nation()][owner];
                let link_bonus = if self.has_direct_or_colony_link(rec, nation.nation()) {
                    0
                } else if self
                    .first_second_degree_link(rec, nation.nation())
                    .is_some()
                {
                    0x14
                } else if self.newest_context_containing_province(rec).is_some() {
                    0x28
                } else {
                    continue;
                };
                score = score.wrapping_add(link_bonus);
                if MajorNationId::from_nation(owner).is_some() && self.event_eligible(owner) {
                    score = score.wrapping_add(0x14);
                }
                candidates.push((score, rec));
            }
            let mut ranked = Vec::new();
            for candidate in candidates {
                insert_scored(&mut ranked, candidate, &mut self.rng);
            }
            for &(_, region) in ranked.iter().take(2) {
                self.mark_province_candidate(nation, region);
            }
        }
    }

    fn mark_province_candidate(&mut self, nation: MajorNationId, province: ProvinceId) {
        if self.province_target(nation, province) != Some(AiTargetState::Unmarked) {
            return;
        }
        let mark = if self.node_link_unavailable(province, nation.nation()) {
            AiTargetState::Unmarked
        } else {
            AiTargetState::Candidate
        };
        self.set_province_target(nation, province, mark);
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
            && self.province_target(nation, province) != Some(AiTargetState::Candidate)
        {
            return;
        }
        if zone.is_some()
            && related.is_none()
            && let Some(ordinal) = zone.map(|zone| usize::from(zone.get()))
            && self.zone_target(nation, ordinal) != Some(AiTargetState::Candidate)
        {
            return;
        }

        let mut kind = kind;
        if zone.is_some()
            && map_node.is_none()
            && related.is_none()
            && !matches!(kind, AdvisoryMissionKind::Blockade)
        {
            kind = AdvisoryMissionKind::Defend;
        }

        let Some(data) = self.factory_mission_data(nation, kind, map_node, zone, related) else {
            return;
        };
        let path_nation = match &data {
            MissionData::AttackProvince(attack) | MissionData::Invade { attack, .. } => {
                self.map.provinces[attack.target_province].owner()
            }
            _ => None,
        };
        let marker = match &data {
            MissionData::AttackProvince(_) => 1,
            MissionData::Invade { .. } => 3,
            _ => 0,
        };
        let importance_bits = match &data {
            MissionData::ControlSeaZone(_) | MissionData::BlockadePort { .. } => {
                let scored_zone = match &data {
                    MissionData::BlockadePort { navy, .. } => navy.target_zone,
                    _ => zone,
                };
                scored_zone
                    .map(|scored| self.control_sea_zone_importance_bits(nation, scored))
                    .unwrap_or(0)
            }
            _ => 0,
        };
        let id = self.object_ids.mission();
        self.missions.insert(
            id,
            MissionState {
                nation: nation.nation(),
                data,
                path_nation,
                state: 2,
                importance_bits,
                held: false,
                marker,
            },
        );
        if let Some(province) = map_node {
            self.set_province_target(nation, province, AiTargetState::MissionQueued);
        }
        if let Some(zone) = zone
            && related.is_none()
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

    fn factory_mission_data(
        &self,
        nation: MajorNationId,
        kind: AdvisoryMissionKind,
        map_node: Option<ProvinceId>,
        zone: Option<OceanZoneId>,
        related: Option<ProvinceId>,
    ) -> Option<MissionData> {
        match kind {
            AdvisoryMissionKind::Attack => Some(if zone.is_none() {
                MissionData::AttackProvince(attack_mission(map_node?, None))
            } else {
                MissionData::ControlSeaZone(empty_navy_mission(zone, None))
            }),
            AdvisoryMissionKind::Amass => Some(MissionData::AttackProvince(attack_mission(
                map_node?, related,
            ))),
            AdvisoryMissionKind::Invade => {
                if let Some(target) = related {
                    Some(MissionData::Invade {
                        attack: attack_mission(target, None),
                        beachhead: Some(empty_navy_mission(zone, None)),
                    })
                } else {
                    Some(MissionData::ControlSeaZone(empty_navy_mission(zone, None)))
                }
            }
            AdvisoryMissionKind::Defend => {
                if zone.is_none() {
                    Some(MissionData::DefendProvince {
                        province: map_node?,
                        army: empty_army(),
                    })
                } else if zone == self.first_port_zone_for_nation(nation.nation()) {
                    Some(MissionData::Escort(empty_navy_mission(zone, zone)))
                } else {
                    Some(MissionData::ControlSeaZone(empty_navy_mission(zone, None)))
                }
            }
            AdvisoryMissionKind::Blockade => {
                let port = zone?;
                let target = self.ocean.zones[usize::from(port.get())]
                    .zone()
                    .primary_neighbors
                    .first()
                    .copied();
                Some(MissionData::BlockadePort {
                    navy: empty_navy_mission(target, None),
                    port_zone: port,
                })
            }
        }
    }

    fn advisory_direct_score(&self, nation: MajorNationId, province: ProvinceId) -> f32 {
        let Some(owner) = self.map.provinces[province].owner() else {
            return 0.0;
        };
        if MajorNationId::from_nation(owner).is_some() {
            let f1 = self.army_power_factor(owner);
            let f3 = self.province_strength_factor(province, owner);
            let f5 = self.standing_factor(nation, owner);
            let f6 = self.province_score_factor(nation, province);
            let score = f6 * f5 * f3 * f1 * f1;
            return score * score;
        }
        let f3 = self.province_strength_factor(province, owner);
        let f5 = self.standing_factor(nation, owner);
        let f6 = self.province_score_factor(nation, province);
        f6 * f5 * f3
    }

    fn advisory_via_score(
        &self,
        nation: MajorNationId,
        province: ProvinceId,
        link: ProvinceId,
    ) -> f32 {
        let Some(owner) = self.map.provinces[province].owner() else {
            return 0.0;
        };
        if self.map.provinces[link].owner() != Some(owner) {
            return 0.0;
        }
        let f1 = self.army_power_factor(owner);
        let f3 = self.province_strength_factor(province, owner);
        let f5 = self.standing_factor(nation, owner);
        let f6 = self.province_score_factor(nation, province);
        let f3_link = self.province_strength_factor(link, owner);
        if MajorNationId::from_nation(owner).is_some() {
            let score = f3_link * f6 * f5 * f3 * f1;
            score * score
        } else {
            f3_link * f6 * f5 * f3 * f1
        }
    }

    fn advisory_overseas_score(&self, nation: MajorNationId, province: ProvinceId) -> f32 {
        let Some(owner) = self.map.provinces[province].owner() else {
            return 0.0;
        };
        let zone = self.newest_context_containing_province(province);
        let f1 = self.army_power_factor(owner);
        let f3 = self.province_strength_factor(province, owner);
        let f5 = self.standing_factor(nation, owner);
        let f6 = self.province_score_factor(nation, province);
        let f7 = zone.map_or(0.0, |zone| self.zone_value_factor(zone));
        if MajorNationId::from_nation(owner).is_some() {
            let f2 = self.navy_power_factor(owner);
            let f4 = zone.map_or(0.0, |zone| self.navy_zone_factor(zone, owner));
            f7 * f6 * f4 * f5 * f2 * f3 * f1
        } else {
            f7 * f6 * f5 * f3 * f1
        }
    }

    fn army_power_factor(&self, selected: NationId) -> f32 {
        self.force_ratio_factor(selected, Self::military_power)
    }

    fn navy_power_factor(&self, selected: NationId) -> f32 {
        self.force_ratio_factor(selected, Self::naval_force)
    }

    fn force_ratio_factor(
        &self,
        selected: NationId,
        power: fn(&Self, MajorNationId) -> f32,
    ) -> f32 {
        let mut sum = 0.0_f32;
        let mut result = 0.0_f32;
        for slot in MajorNationId::all() {
            if !self.event_eligible(slot.nation()) {
                continue;
            }
            let power = power(self, slot);
            sum += power;
            if slot.nation() == selected {
                result = power;
            }
        }
        if result == 0.0 {
            result = 1.0;
        }
        let gps = self.num_great_powers() as f32;
        (sum - -6.0) / (gps * result - -6.0)
    }

    fn province_strength_factor(&self, province: ProvinceId, selected: NationId) -> f32 {
        let owned = self.owned_regions_of(selected).len() as f32;
        let node = self.weighted_neighbor_score(province) as f32 * owned;
        (self.sum_weighted_neighbor_scores(selected) as f32 - -100.0) / (node - -100.0)
    }

    fn navy_zone_factor(&self, zone: OceanZoneId, selected: NationId) -> f32 {
        let Some(major) = MajorNationId::from_nation(selected) else {
            return 0.0;
        };
        let in_zone = self.navy_priority_in_zone(major, zone) as f32
            * self.zone_count_with_nation_bit(major) as f32;
        (self.navy_priority_total(major) as f32 - -6.0) / (in_zone - -6.0)
    }

    fn standing_factor(&self, nation: MajorNationId, selected: NationId) -> f32 {
        100.0 / f32::from(self.diplomacy.standings[nation.nation()][selected])
    }

    fn province_score_factor(&self, nation: MajorNationId, province: ProvinceId) -> f32 {
        let total = self.map.city_score_total;
        let mut result = self.map.provinces[province].city_score() as f32 / total as f32;
        if self.map.provinces[province].former_owner() == Some(nation.nation())
            && let Some(owner) = self.map.provinces[province].owner()
            && owner != nation.nation()
            && self.at_war(nation.nation(), owner)
        {
            result *= 1.5;
        }
        result
    }

    fn zone_value_factor(&self, zone: OceanZoneId) -> f32 {
        let global = self.global_zone_value_average();
        if global == 0 {
            return 0.0;
        }
        self.zone_value_average(zone) as f32 / global as f32
    }

    fn map_action_context_score(&mut self, nation: MajorNationId, zone: OceanZoneId) -> f32 {
        let active: Vec<NationId> = NationId::all()
            .filter(|&slot| self.nations.majors[nation].economy.candidate_nation_flags[slot] != 0)
            .collect();
        let mut selected = NationId::new(0);
        let mut composite = 0.0_f32;
        match active.len() {
            0 => {
                let mut independents = Vec::new();
                for slot in MajorNationId::all().map(MajorNationId::nation) {
                    if slot == nation.nation()
                        || self.nations.common(slot).is_none()
                        || self.status_of(slot) != CountryStatus::Independent
                    {
                        continue;
                    }
                    insert_scored(
                        &mut independents,
                        (self.diplomacy.standings[nation.nation()][slot], slot),
                        &mut self.rng,
                    );
                }
                if let Some((_, slot)) = independents.first() {
                    selected = *slot;
                }
            }
            1 => selected = active[0],
            _ => {
                let mut best_priority = 0;
                for slot in MajorNationId::all() {
                    if self.nations.majors[nation].economy.candidate_nation_flags[slot.nation()]
                        == 0
                    {
                        continue;
                    }
                    let priority = self.navy_priority_in_zone(slot, zone);
                    if priority > best_priority {
                        best_priority = priority;
                        selected = slot.nation();
                    }
                }
                if best_priority == 0 {
                    composite = 1.0;
                }
            }
        }
        #[allow(clippy::float_cmp)]
        if composite == 0.0 {
            let f2 = self.navy_power_factor(selected);
            let f4 = self.navy_zone_factor(zone, selected);
            let f5 = self.standing_factor(nation, selected);
            let f7 = self.zone_value_factor(zone);
            composite = f5 * f7 * f2 * f4;
        }
        composite
    }

    fn num_great_powers(&self) -> i32 {
        MajorNationId::all()
            .filter(|&nation| self.status_of(nation.nation()) == CountryStatus::Independent)
            .count() as i32
    }

    fn weighted_neighbor_score(&self, province: ProvinceId) -> i32 {
        self.military_units
            .values()
            .filter(|unit| unit.stationed_province() == Some(province))
            .map(|unit| NEIGHBOR_UNIT_WEIGHT[unit.unit_type as usize])
            .sum()
    }

    fn sum_weighted_neighbor_scores(&self, owner: NationId) -> i32 {
        self.owned_regions_of(owner)
            .iter()
            .map(|&province| self.weighted_neighbor_score(province))
            .sum()
    }

    fn navy_priority_in_zone(&self, nation: MajorNationId, zone: OceanZoneId) -> i32 {
        self.ships
            .values()
            .filter(|ship| ship.nation == nation.nation() && ship.location == zone)
            .map(ship_studliness)
            .sum()
    }

    fn navy_priority_total(&self, nation: MajorNationId) -> i32 {
        self.ships
            .values()
            .filter(|ship| ship.nation == nation.nation())
            .map(ship_studliness)
            .sum()
    }

    fn zone_count_with_nation_bit(&self, nation: MajorNationId) -> i32 {
        let bit = 1u16 << nation.get();
        self.ocean
            .zones
            .iter()
            .enumerate()
            .filter(|(ordinal, _)| {
                self.zone_nation_key_mask(OceanZoneId::new(*ordinal as u16)) & bit != 0
            })
            .count() as i32
    }

    pub(crate) fn zone_nation_key_mask(&self, zone: OceanZoneId) -> u16 {
        let mut mask = 0u16;
        for ship in self.ships.values() {
            if ship.location == zone {
                mask |= 1 << ship.nation.get();
            }
        }
        mask
    }

    pub(crate) fn zone_value_average(&self, zone: OceanZoneId) -> i32 {
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
                self.nations
                    .home_tile(owner)
                    .and_then(|home| self.map[home].province)
                    .map(|province| self.map.provinces[province].city_score())
                    .unwrap_or(0)
            }
            ZoneKind::Zone(zone) => {
                if zone.secondary_neighbors.is_empty() {
                    return 0;
                }
                let sum: i32 = zone
                    .secondary_neighbors
                    .iter()
                    .map(|&province| self.map.provinces[province].city_score())
                    .sum();
                sum / zone.secondary_neighbors.len() as i32
            }
        }
    }

    fn global_zone_value_average(&self) -> i32 {
        if self.ocean.zones.is_empty() {
            return 0;
        }
        let sum: i32 = (0..self.ocean.zones.len())
            .map(|ordinal| self.zone_value_average(OceanZoneId::new(ordinal as u16)))
            .sum();
        sum / self.ocean.zones.len() as i32
    }

    pub(crate) fn control_sea_zone_importance_bits(
        &self,
        nation: MajorNationId,
        target: OceanZoneId,
    ) -> u32 {
        (self.sea_zone_importance(nation.nation(), target)).to_bits()
    }

    pub(crate) fn sea_zone_importance(&self, nation: NationId, target: OceanZoneId) -> f32 {
        let mut score = self.zone_value_average(target) as f32;
        for (_ordinal, kind) in self.ocean.zones.iter().enumerate().rev() {
            let ZoneKind::PortZone(port) = kind else {
                continue;
            };
            if port.zone.primary_neighbors.first().copied() != Some(target) {
                continue;
            }
            let owner = self.map[port.port_tile]
                .owner_nation
                .and_then(TileOwnerTag::nation);
            score *= if owner == Some(nation) {
                PORT_FRIENDLY_MULTIPLIER
            } else {
                PORT_FOREIGN_MULTIPLIER
            };
        }
        score / MISSION_SCORE_DIVISOR
    }

    fn has_direct_or_colony_link(&self, province: ProvinceId, nation: NationId) -> bool {
        let adjacency = self.map.provinces[province].adjacency();
        if adjacency
            .iter()
            .any(|&neighbor| self.map.provinces[neighbor].owner() == Some(nation))
        {
            return true;
        }
        if MajorNationId::from_nation(nation).is_none() {
            return false;
        }
        adjacency.iter().any(|&neighbor| {
            self.map.provinces[neighbor]
                .owner()
                .is_some_and(|owner| self.status_of(owner).is_colony_of(nation))
        })
    }

    fn first_second_degree_link(
        &self,
        province: ProvinceId,
        nation: NationId,
    ) -> Option<ProvinceId> {
        let mut found = collect_second_degree_links(&self.map, province, nation);
        if found.is_empty() && MajorNationId::from_nation(nation).is_none() {
            for minor in MinorNationId::all() {
                if !self.status_of(minor.nation()).is_colony_of(nation) {
                    continue;
                }
                found = collect_second_degree_links(&self.map, province, minor.nation());
                if !found.is_empty() {
                    break;
                }
            }
        }
        found.first().copied()
    }

    fn node_link_unavailable(&self, province: ProvinceId, nation: NationId) -> bool {
        if self.map.provinces[province]
            .adjacency()
            .iter()
            .any(|&neighbor| self.map.provinces[neighbor].owner() == Some(nation))
        {
            return false;
        }
        if !collect_second_degree_links(&self.map, province, nation).is_empty() {
            return false;
        }
        self.newest_context_containing_province(province).is_none()
    }

    fn newest_context_containing_province(&self, province: ProvinceId) -> Option<OceanZoneId> {
        self.ocean
            .zones
            .iter()
            .enumerate()
            .rev()
            .find_map(|(ordinal, zone)| {
                zone.zone()
                    .secondary_neighbors
                    .contains(&province)
                    .then_some(OceanZoneId::new(ordinal as u16))
            })
    }

    fn zone_has_secondary_neighbor_owner(&self, zone: OceanZoneId, nation: NationId) -> bool {
        self.ocean.zones[usize::from(zone.get())]
            .zone()
            .secondary_neighbors
            .iter()
            .any(|&province| self.map.provinces[province].owner() == Some(nation))
    }

    fn nation_has_war_relation(&self, nation: NationId) -> bool {
        NationId::all().any(|other| self.at_war(nation, other))
    }

    fn owned_regions_of(&self, nation: NationId) -> &[ProvinceId] {
        self.nations
            .common(nation)
            .map(|common| common.owned_regions())
            .unwrap_or(&[])
    }

    fn province_target(
        &self,
        nation: MajorNationId,
        province: ProvinceId,
    ) -> Option<AiTargetState> {
        self.nations.majors[nation]
            .auto
            .as_ref()
            .map(|auto| auto.province_targets[province])
    }

    fn set_province_target(
        &mut self,
        nation: MajorNationId,
        province: ProvinceId,
        flag: AiTargetState,
    ) {
        if let Some(auto) = self.nations.majors[nation].auto.as_mut() {
            auto.province_targets[province] = flag;
        }
    }

    fn zone_target(&self, nation: MajorNationId, ordinal: usize) -> Option<AiTargetState> {
        self.nations.majors[nation]
            .auto
            .as_ref()
            .and_then(|auto| auto.zone_targets.get(ordinal).copied())
    }

    fn set_zone_target(&mut self, nation: MajorNationId, ordinal: usize, flag: AiTargetState) {
        if let Some(auto) = self.nations.majors[nation].auto.as_mut()
            && let Some(slot) = auto.zone_targets.get_mut(ordinal)
        {
            *slot = flag;
        }
    }
}

fn kind_from_tier(tier: i32) -> AdvisoryMissionKind {
    match tier {
        1 => AdvisoryMissionKind::Amass,
        2 => AdvisoryMissionKind::Invade,
        3 => AdvisoryMissionKind::Defend,
        4 => AdvisoryMissionKind::Blockade,
        _ => AdvisoryMissionKind::Attack,
    }
}

fn insert_scored<T>(list: &mut Vec<(i16, T)>, candidate: (i16, T), rng: &mut RngState) {
    for index in 0..list.len() {
        let ordering = match candidate.0.cmp(&list[index].0) {
            std::cmp::Ordering::Greater => std::cmp::Ordering::Greater,
            std::cmp::Ordering::Less => std::cmp::Ordering::Less,
            std::cmp::Ordering::Equal => {
                if rng.next_crt_rand() % 2 != 0 {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Less
                }
            }
        };
        if ordering != std::cmp::Ordering::Greater {
            list.insert(index, candidate);
            return;
        }
    }
    list.push(candidate);
}

fn collect_second_degree_links(
    map: &MapMgr,
    province: ProvinceId,
    nation: NationId,
) -> Vec<ProvinceId> {
    let mut found = Vec::new();
    if map.provinces[province].adjacency().is_empty() {
        return found;
    }
    for &adjacent in map.provinces[province].adjacency() {
        if map.provinces[adjacent].adjacency().is_empty() {
            continue;
        }
        for _ in map.provinces[adjacent].adjacency() {
            if map.provinces[province].owner() == Some(nation) {
                found.push(adjacent);
                break;
            }
        }
    }
    found
}

fn ship_studliness(ship: &ShipState) -> i32 {
    let desc = crate::navy_orders::NAVY_DESCRIPTORS[ship.ship_type];
    let task_force = desc.task_force_weight;
    if task_force == 0 {
        return 0;
    }
    let quantity_term = i32::from(ship.experience) / 100;
    let navy_term = (quantity_term + desc.navy_priority_weight * 10 + 5) / 10;
    let resolve_term = (quantity_term + desc.resolve_weight * 10 + 5) / 10;
    ((navy_term + desc.calculate_weight) * 100 + resolve_term + i32::from(ship.strength))
        / task_force
}

fn empty_army() -> ArmyMissionState {
    ArmyMissionState {
        required_equipage_bits: [0; 5],
        units: Default::default(),
    }
}

fn attack_mission(target: ProvinceId, amassing: Option<ProvinceId>) -> AttackMissionState {
    AttackMissionState {
        army: empty_army(),
        present_province: None,
        target_province: target,
        amassing_province: amassing,
    }
}

fn empty_navy_mission(
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
        ships: Default::default(),
    }
}
