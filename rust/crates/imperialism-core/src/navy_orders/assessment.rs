use super::*;

impl GameState {
    pub(crate) fn reassess_navy_mission(&mut self, mission: MissionId) {
        match &self.missions[&mission].data {
            MissionData::ScatteredShips(_) => self.reassess_scattered_ships(mission),
            MissionData::ControlSeaZone(_)
            | MissionData::Beachhead(_)
            | MissionData::BlockadePort { .. }
            | MissionData::Escort(_) => self.reassess_navy_order_mission(mission),
            MissionData::Invade { .. } => self.reassess_invade_mission(mission),
            MissionData::AttackProvince(_) | MissionData::DefendProvince { .. } => {}
        }
    }

    fn reassess_scattered_ships(&mut self, mission: MissionId) {
        self.missions[&mission].state = 3;
        self.missions[&mission].importance_bits = 0.001_f32.to_bits();
        let required = navy_required_from_profile(NAVY_CONTROL_PROFILE, 1.0);
        if let Some(navy) = navy_state_mut(&mut self.missions[&mission].data) {
            navy.required_equipage_bits = required;
        }
    }

    fn reassess_invade_mission(&mut self, mission: MissionId) {
        if navy_state(&self.missions[&mission].data).is_some() {
            self.write_control_sea_needs(mission);
            self.advance_navy_selection_state(mission);
        }
        self.missions[&mission].state = 2;
        if let MissionData::Invade { attack, .. } = &self.missions[&mission].data {
            let attack = attack.clone();
            self.reassess_attack_mission_fields(mission, &attack);
        }
        if navy_state(&self.missions[&mission].data).is_some() {
            self.write_control_sea_needs(mission);
        }
    }

    fn reassess_navy_order_mission(&mut self, mission: MissionId) {
        let nation = self.missions[&mission].nation;
        match &self.missions[&mission].data {
            MissionData::BlockadePort { .. } => {
                self.missions[&mission].state = 3;
            }
            MissionData::Escort(_) => {
                self.missions[&mission].state = 2;
            }
            _ => {
                self.missions[&mission].state = self.control_sea_lifecycle_state(mission);
            }
        }
        match &self.missions[&mission].data {
            MissionData::Escort(_) => {
                self.missions[&mission].importance_bits = self.escort_importance_bits(nation);
            }
            MissionData::ControlSeaZone(navy)
            | MissionData::Beachhead(navy)
            | MissionData::BlockadePort { navy, .. } => {
                if let Some(target) = navy.target_zone
                    && let Some(major) = MajorNationId::from_nation(nation)
                {
                    self.missions[&mission].importance_bits =
                        self.control_sea_zone_importance_bits(major, target);
                }
            }
            _ => {}
        }
        match &self.missions[&mission].data {
            MissionData::Escort(_) => self.write_escort_needs(mission),
            _ => self.write_control_sea_needs(mission),
        }
        self.advance_navy_selection_state(mission);
    }

    fn control_sea_lifecycle_state(&self, mission: MissionId) -> u8 {
        let nation = self.missions[&mission].nation;
        let Some(navy) = navy_state(&self.missions[&mission].data) else {
            return 2;
        };
        let Some(target) = navy.target_zone else {
            return 2;
        };
        let Some(home) = self.first_port_zone_for_nation(nation) else {
            return 2;
        };
        if self.zone(home).primary_neighbors.first().copied() != Some(target) {
            return 2;
        }
        if self.hostile_navy_similarity(nation, target) > 0.0 {
            1
        } else {
            2
        }
    }

    fn escort_importance_bits(&self, nation: NationId) -> u32 {
        let Some(major) = MajorNationId::from_nation(nation) else {
            return 0;
        };
        let mut need_cap = self.nations.majors[&major].economy.capacities.transport;
        if need_cap == 0 {
            need_cap = 1;
        }
        let Some(home) = self.first_port_zone_for_nation(nation) else {
            return 0;
        };
        let Some(&cached) = self.zone(home).primary_neighbors.first() else {
            return 0;
        };
        let merchant = self.nations.majors[&major].economy.capacities.trade_offer;
        (self.sea_zone_importance(nation, cached) * f32::from(merchant) / f32::from(need_cap))
            .to_bits()
    }

    fn write_control_sea_needs(&mut self, mission: MissionId) {
        let nation = self.missions[&mission].nation;
        let Some(navy) = navy_state(&self.missions[&mission].data) else {
            return;
        };
        let Some(target) = navy.target_zone else {
            return;
        };
        let mut total = self.hostile_navy_similarity(nation, target) * 1.1;
        if total == 0.0 {
            total = 100.0;
        }
        if let Some(navy) = navy_state_mut(&mut self.missions[&mission].data) {
            navy.required_equipage_bits = navy_required_from_profile(NAVY_CONTROL_PROFILE, total);
        }
    }

    fn write_escort_needs(&mut self, mission: MissionId) {
        let nation = self.missions[&mission].nation;
        let year_threshold = (self.turn.economic_turn / 4) as f32 + 110.0;
        let mut total = 1.0_f32;
        for minor in MinorNationId::all() {
            if !self.escort_minor_eligible(minor.nation(), nation, year_threshold) {
                continue;
            }
            let Some(home) = self.first_port_zone_for_nation(minor.nation()) else {
                continue;
            };
            let Some(&target) = self.zone(home).primary_neighbors.first() else {
                continue;
            };
            total += self.navy_profile_similarity(
                self.hostile_navy_vector(nation, target),
                NAVY_ESCORT_PROFILE,
            );
        }
        if let Some(navy) = navy_state_mut(&mut self.missions[&mission].data) {
            navy.required_equipage_bits = navy_required_from_profile(NAVY_ESCORT_PROFILE, total);
        }
    }

    fn escort_minor_eligible(
        &self,
        minor: NationId,
        mission_nation: NationId,
        year_threshold: f32,
    ) -> bool {
        if self.nations.common(minor).is_none() {
            return false;
        }
        match self.status_of(minor) {
            CountryStatus::ProtectorateOf(master) => master == mission_nation,
            CountryStatus::Independent | CountryStatus::ColonyOf(_) => {
                f32::from(self.diplomacy.standings[minor][mission_nation]) > year_threshold
            }
        }
    }

    fn advance_navy_selection_state(&mut self, mission: MissionId) {
        let Some(navy) = navy_state(&self.missions[&mission].data) else {
            return;
        };
        if navy.ships.is_empty() {
            if let Some(navy) = navy_state_mut(&mut self.missions[&mission].data) {
                navy.state = 0;
            }
            return;
        }
        let nation = self.missions[&mission].nation;
        let target = navy.target_zone;
        let port = navy.resolved_port_zone;
        let required = navy.required_equipage_bits.map(f32::from_bits);
        let ships: Vec<ShipId> = navy.ships.keys().copied().collect();
        let mode = navy.state;
        let next = match mode {
            0 => {
                let near = self.assigned_navy_readiness(&ships, required, target, 1, port);
                if near >= 1.0 {
                    let at_target = self.assigned_navy_readiness(&ships, required, target, 0, port);
                    if at_target >= 1.0 { 2 } else { 1 }
                } else {
                    0
                }
            }
            1 => 2,
            2 => {
                let near = self.assigned_navy_readiness(&ships, required, target, 1, port);
                if near < 0.8 {
                    if let Some(target) = target {
                        let refreshed = self.safest_nearby_zone(target, nation);
                        if let Some(navy) = navy_state_mut(&mut self.missions[&mission].data) {
                            navy.resolved_port_zone = refreshed;
                        }
                    }
                    0
                } else {
                    2
                }
            }
            _ => mode,
        };
        if let Some(navy) = navy_state_mut(&mut self.missions[&mission].data) {
            navy.state = next;
        }
    }

    fn assigned_navy_readiness(
        &self,
        ships: &[ShipId],
        required: [f32; 4],
        near: Option<OceanZoneId>,
        distance_threshold: i16,
        far: Option<OceanZoneId>,
    ) -> f32 {
        let vector = self.assigned_navy_category_vector(ships, near, distance_threshold, far);
        let mut numerator = 0.0;
        let mut denominator = 0.0;
        for index in 0..4 {
            numerator += (required[index] * vector[index]).sqrt();
            denominator += required[index];
        }
        if denominator == 0.0 {
            0.0
        } else {
            numerator / denominator
        }
    }

    fn assigned_navy_category_vector(
        &self,
        ships: &[ShipId],
        near: Option<OceanZoneId>,
        distance_threshold: i16,
        far: Option<OceanZoneId>,
    ) -> [f32; 4] {
        let far = far.filter(|&zone| Some(zone) != near);
        let near_distances = near.map(|zone| self.zone_hop_distances_from(zone));
        let far_distances = far.map(|zone| self.zone_hop_distances_from(zone));
        let mut vector = [0.0_f32; 4];
        for &id in ships {
            let Some(ship) = self.ship(id) else {
                continue;
            };
            let near_ok = match &near_distances {
                None => true,
                Some(distances) => hop_distance(distances, ship.location) <= distance_threshold,
            };
            let far_ok = far_distances.as_ref().is_some_and(|distances| {
                hop_distance(distances, ship.location) <= distance_threshold
            });
            if near_ok || far_ok {
                accumulate_ship_categories(
                    ship,
                    &mut vector,
                    &self.technology.industry_enabled_by_slot,
                );
            }
        }
        vector
    }

    fn hostile_navy_similarity(&self, nation: NationId, zone: OceanZoneId) -> f32 {
        self.navy_profile_similarity(self.hostile_navy_vector(nation, zone), NAVY_CONTROL_PROFILE)
    }

    fn hostile_navy_vector(&self, nation: NationId, zone: OceanZoneId) -> [f32; 4] {
        let mut vector = [0.0_f32; 4];
        for ship in self.ships.values() {
            if ship.location != zone || !self.at_war(nation, ship.nation) {
                continue;
            }
            accumulate_ship_categories(
                ship,
                &mut vector,
                &self.technology.industry_enabled_by_slot,
            );
        }
        vector
    }

    fn navy_profile_similarity(&self, vector: [f32; 4], profile: [i16; 4]) -> f32 {
        let sum: f32 = vector.iter().sum();
        if sum == 0.0 {
            return 0.0;
        }
        let mut divergence = 0.0;
        for (component, &target) in vector.iter().zip(&profile) {
            divergence += (*component / sum - f32::from(target) * 0.01).abs();
        }
        sum * (1.0 - divergence * 0.5)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::zone;
    use super::*;
    use crate::test_support::game_state;
    #[test]
    fn reassess_advances_navy_state_when_assigned_ships_are_on_the_target() {
        let mut state = game_state();
        let nation = NationId::new(0);
        state.nations.majors[&MajorNationId::new(0)].auto = Some(AutoGreatPowerState::default());
        state.ocean.zones = vec![ZoneKind::Zone(zone(Vec::new()))];
        state.ships.insert(
            ShipId::new(0),
            ShipState {
                ship_type: ShipType::Frigate,
                location: OceanZoneId::new(0),
                aggression: 0,
                nation,
                name: String::new(),
                strength: 900,
                experience: 0,
                selection: 0,
            },
        );
        let mission = state.object_ids.mission();
        state.missions.insert(
            mission,
            MissionState {
                nation,
                data: MissionData::ControlSeaZone(NavyMissionState {
                    target_zone: Some(OceanZoneId::new(0)),
                    resolved_port_zone: None,
                    selected_ship: None,
                    state: 0,
                    required_equipage_bits: [0; 4],
                    task_force: None,
                    ships: [(ShipId::new(0), false)].into_iter().collect(),
                }),
                path_nation: None,
                state: 2,
                importance_bits: 0,
                held: false,
                marker: 0,
            },
        );

        state.reassess_navy_mission(mission);

        let MissionData::ControlSeaZone(navy) = &state.missions[&mission].data else {
            panic!("expected a control-sea mission");
        };
        assert_eq!(navy.state, 2);
    }

    #[test]
    fn damaged_hostile_frigate_scales_control_sea_needs_by_float_strength_ratio() {
        let mut state = game_state();
        let nation = NationId::new(0);
        let hostile = NationId::new(1);
        state.nations.majors[&MajorNationId::new(0)].auto = Some(AutoGreatPowerState::default());
        state.diplomacy.relationships[nation][hostile] = DiplomaticRelationship::War;
        state.ocean.zones = vec![ZoneKind::Zone(zone(Vec::new()))];
        state.ships.insert(
            ShipId::new(0),
            ShipState {
                ship_type: ShipType::Frigate,
                location: OceanZoneId::new(0),
                aggression: 0,
                nation: hostile,
                name: String::new(),
                strength: 899,
                experience: 0,
                selection: 0,
            },
        );
        let mission = state.object_ids.mission();
        state.missions.insert(
            mission,
            MissionState {
                nation,
                data: MissionData::ControlSeaZone(NavyMissionState {
                    target_zone: Some(OceanZoneId::new(0)),
                    resolved_port_zone: None,
                    selected_ship: None,
                    task_force: None,
                    state: 0,
                    required_equipage_bits: [0; 4],
                    ships: Default::default(),
                }),
                path_nation: None,
                state: 2,
                importance_bits: 0,
                held: false,
                marker: 0,
            },
        );

        state.reassess_navy_mission(mission);

        let MissionData::ControlSeaZone(navy) = &state.missions[&mission].data else {
            panic!("expected a control-sea mission");
        };
        let empty_zone = [40.0_f32, 40.0, 20.0, 0.0].map(|weight| weight.to_bits());
        assert_ne!(
            navy.required_equipage_bits, empty_zone,
            "integer strength/max_strength would treat 899/900 as 0.0 and keep the empty-zone needs"
        );
    }
}
