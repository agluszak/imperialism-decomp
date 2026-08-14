//! AutoGreatPower army movement (`TAutoGreatPower::MoveArmy` /
//! `TDefenseMinister::DoArmyMovement` / land `GiveOrders`).

use crate::*;

const UNIT_ORDER_REDEPLOY: i32 = 1;
const ATTACK_READINESS_THRESHOLD: f32 = 1.0;
const MISSION_SCORE_NORMALIZATION: f32 = 5000.0;

impl GameState {
    /// Retail `TAutoGreatPower::MoveArmy` / `TDefenseMinister::DoArmyMovement`.
    /// Navy mission `GiveOrders` is omitted.
    pub fn do_army_movement(&mut self, nation: MajorNationId) {
        let indices: Vec<usize> = self
            .missions
            .iter()
            .enumerate()
            .filter(|(_, mission)| mission.nation == nation.nation())
            .map(|(index, _)| index)
            .collect();
        for index in indices {
            self.give_mission_orders(index);
        }
    }

    fn give_mission_orders(&mut self, mission_index: usize) {
        match &self.missions[mission_index].data {
            MissionData::DefendProvince { .. } => self.give_defend_orders(mission_index),
            MissionData::AttackProvince(_) => self.give_attack_orders(mission_index),
            MissionData::Invade { attack, .. } => {
                let target = attack.target_province;
                let nation = self.missions[mission_index].nation;
                let explored = MajorNationId::from_nation(nation)
                    .is_some_and(|major| self.map.provinces[target].explored_by_majors()[major]);
                if explored {
                    self.give_attack_orders(mission_index);
                }
            }
            MissionData::ControlSeaZone(_)
            | MissionData::Escort(_)
            | MissionData::ScatteredShips(_)
            | MissionData::BlockadePort { .. }
            | MissionData::Beachhead(_) => {}
        }
    }

    fn give_defend_orders(&mut self, mission_index: usize) {
        let MissionData::DefendProvince { province, army } = &self.missions[mission_index].data
        else {
            return;
        };
        let province = *province;
        let units = army.units.clone();
        self.propagate_redeploy_if_different(&units, Some(province));
    }

    fn give_attack_orders(&mut self, mission_index: usize) {
        let nation = self.missions[mission_index].nation;
        let Some(attack) = attack_state(&self.missions[mission_index].data) else {
            return;
        };
        let target = attack.target_province;
        let units = attack.army.units.clone();
        let required = attack.army.required_equipage_bits;
        let mut present = attack.present_province;
        if present.is_none() {
            present = self.try_resolve_attack_present(nation, target);
            if let Some(attack) = attack_state_mut(&mut self.missions[mission_index].data) {
                attack.present_province = present;
            }
        }

        let projected = project_mission_equipage(&self.military_units, &units, present, 0);
        let required_f = required.map(f32::from_bits);
        let mut weighted = 0.0_f32;
        let mut total = 0.0_f32;
        for index in 0..5 {
            weighted += (required_f[index] * projected[index]).sqrt();
            total += required_f[index];
        }
        if weighted / total > ATTACK_READINESS_THRESHOLD {
            let Some(owner) = self.map.provinces[target].owner() else {
                self.propagate_redeploy_if_different(&units, present);
                return;
            };
            if self.war_stamp_out_of_date(nation, owner) {
                self.redeploy_units_stationed_at(&units, present, Some(target));
            } else if self.diplomacy.relationships[nation][owner] != DiplomaticRelationship::War {
                self.stamp_declare_war_policy(nation, owner);
            }
        }
        self.propagate_redeploy_if_different(&units, present);
    }

    fn try_resolve_attack_present(
        &self,
        nation: NationId,
        target: ProvinceId,
    ) -> Option<ProvinceId> {
        let mut present = None;
        let mut best_score = 0.0_f32;
        for &candidate in self.map.provinces[target].adjacency() {
            if self.normalized_province_owner(candidate) != Some(nation) {
                continue;
            }
            if present.is_some() {
                let score = self.owned_adjacency_importance(nation, candidate);
                if score <= best_score {
                    continue;
                }
            }
            present = Some(candidate);
            best_score = self.owned_adjacency_importance(nation, candidate);
        }
        present
    }

    fn owned_adjacency_importance(&self, nation: NationId, province: ProvinceId) -> f32 {
        let record = &self.map.provinces[province];
        let mut score = record.city_score() as f32;
        let adjacent = record.adjacency();
        if !adjacent.is_empty() {
            let owned = adjacent
                .iter()
                .filter(|&&neighbor| self.normalized_province_owner(neighbor) == Some(nation))
                .count();
            score *= owned as f32 / adjacent.len() as f32 - -1.0;
        }
        score / MISSION_SCORE_NORMALIZATION
    }

    fn normalized_province_owner(&self, province: ProvinceId) -> Option<NationId> {
        let owner = self.map.provinces[province].owner()?;
        match self.nations.country_status(owner) {
            Some(CountryStatus::ColonyOf(master)) => Some(master),
            _ => Some(owner),
        }
    }

    fn war_stamp_out_of_date(&self, source: NationId, target: NationId) -> bool {
        if self.nations.common(source).is_none() || self.nations.common(target).is_none() {
            return false;
        }
        if self.diplomacy.relationships[source][target] != DiplomaticRelationship::War {
            return false;
        }
        self.diplomacy.relationship_turns[source][target] != Some(self.turn.economic_turn as i16)
    }

    fn stamp_declare_war_policy(&mut self, source: NationId, target: NationId) {
        let Some(major) = MajorNationId::from_nation(source) else {
            return;
        };
        if self.nations.majors[major]
            .economy
            .diplomacy_policy_by_nation[target]
            == Some(DiplomacyPolicy::DeclareWar)
        {
            return;
        }
        self.apply_player_diplomacy_policy(major, target, DiplomacyPolicy::DeclareWar);
        if let Some(CountryStatus::ColonyOf(master)) = self.nations.country_status(target)
            && self.diplomacy.relationships[source][master] != DiplomaticRelationship::War
        {
            self.apply_player_diplomacy_policy(major, master, DiplomacyPolicy::DeclareWar);
        }
    }

    fn propagate_redeploy_if_different(
        &mut self,
        units: &[MilitaryUnitId],
        dest: Option<ProvinceId>,
    ) {
        let dest_index = dest.map(|province| province.get() as i16).unwrap_or(-1);
        for &id in units {
            let Some(unit) = self.military_units.iter_mut().find(|unit| unit.id() == id) else {
                continue;
            };
            let stationed = unit
                .stationed_province()
                .map(|province| province.get() as i16)
                .unwrap_or(-1);
            if stationed != dest_index {
                set_military_order(unit, UNIT_ORDER_REDEPLOY, dest_index);
            }
        }
    }

    fn redeploy_units_stationed_at(
        &mut self,
        units: &[MilitaryUnitId],
        present: Option<ProvinceId>,
        dest: Option<ProvinceId>,
    ) {
        let present_index = present.map(|province| province.get() as i16).unwrap_or(-1);
        let dest_index = dest.map(|province| province.get() as i16).unwrap_or(-1);
        for &id in units {
            let Some(unit) = self.military_units.iter_mut().find(|unit| unit.id() == id) else {
                continue;
            };
            let stationed = unit
                .stationed_province()
                .map(|province| province.get() as i16)
                .unwrap_or(-1);
            if stationed == present_index {
                set_military_order(unit, UNIT_ORDER_REDEPLOY, dest_index);
            }
        }
    }
}

fn attack_state(data: &MissionData) -> Option<&AttackMissionState> {
    match data {
        MissionData::AttackProvince(attack) | MissionData::Invade { attack, .. } => Some(attack),
        _ => None,
    }
}

fn attack_state_mut(data: &mut MissionData) -> Option<&mut AttackMissionState> {
    match data {
        MissionData::AttackProvince(attack) | MissionData::Invade { attack, .. } => Some(attack),
        _ => None,
    }
}

fn set_military_order(unit: &mut MilitaryUnitState, code: i32, target: i16) {
    let targets = *unit.order().targets();
    let mirrors = *unit.order().target_mirrors();
    let target = ProvinceId::try_new(target as u16).filter(|_| target >= 0);
    unit.order = MilitaryOrder::retail(
        MilitaryOrderCode::from_retail(code),
        target,
        targets,
        mirrors,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    fn auto_nation(state: &mut GameState) -> MajorNationId {
        let nation = MajorNationId::new(1);
        state.nations.majors[nation].kind = MajorNationKind::AutoGreatPower;
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

    fn push_unit(state: &mut GameState, nation: u8, province: u16) -> MilitaryUnitId {
        let id = state.unit_ids.next_military();
        let province = ProvinceId::new(province);
        state.military_units.push(MilitaryUnitState::new(
            id,
            NationId::new(nation),
            MilitaryUnitKind::Regulars,
            Some(province),
            MilitaryOrder::idle([Some(province); 3], [Some(province); 3]),
            NationId::new(nation),
            0,
            true,
            String::new(),
            400,
            MilitaryUnitKind::Regulars.spawn_era(),
            0,
            0,
        ));
        id
    }

    #[test]
    fn defend_give_orders_redeploys_units_not_on_the_province() {
        let mut state = game_state();
        let nation = auto_nation(&mut state);
        seed_province(&mut state, 0, 1, &[1]);
        seed_province(&mut state, 1, 1, &[0]);
        let unit = push_unit(&mut state, 1, 1);
        state.missions.push(MissionState {
            nation: nation.nation(),
            data: MissionData::DefendProvince {
                province: ProvinceId::new(0),
                army: ArmyMissionState {
                    required_equipage_bits: [0; 5],
                    units: vec![unit],
                },
            },
            path_nation: None,
            state: 2,
            importance_bits: 0,
            held: false,
            marker: 0,
        });

        state.do_army_movement(nation);

        let order = state.military_units[0].order();
        assert_eq!(order.code(), UNIT_ORDER_REDEPLOY);
        assert_eq!(order.target(), Some(ProvinceId::new(0)));
        assert_eq!(
            state.military_units[0].stationed_province(),
            Some(ProvinceId::new(1))
        );
    }

    #[test]
    fn attack_give_orders_resolves_present_from_owned_adjacent() {
        let mut state = game_state();
        let nation = auto_nation(&mut state);
        seed_province(&mut state, 0, 1, &[1]);
        seed_province(&mut state, 1, 2, &[0]);
        state.missions.push(MissionState {
            nation: nation.nation(),
            data: MissionData::AttackProvince(AttackMissionState {
                army: ArmyMissionState {
                    required_equipage_bits: [0; 5],
                    units: Vec::new(),
                },
                present_province: None,
                target_province: ProvinceId::new(1),
                amassing_province: None,
            }),
            path_nation: Some(NationId::new(2)),
            state: 2,
            importance_bits: 0,
            held: false,
            marker: 1,
        });

        state.do_army_movement(nation);

        let MissionData::AttackProvince(attack) = &state.missions[0].data else {
            panic!("expected an attack mission");
        };
        assert_eq!(attack.present_province, Some(ProvinceId::new(0)));
    }

    #[test]
    fn attack_give_orders_gathers_units_to_present() {
        let mut state = game_state();
        let nation = auto_nation(&mut state);
        seed_province(&mut state, 0, 1, &[1]);
        seed_province(&mut state, 1, 2, &[0]);
        let unit = push_unit(&mut state, 1, 0);
        state.missions.push(MissionState {
            nation: nation.nation(),
            data: MissionData::AttackProvince(AttackMissionState {
                army: ArmyMissionState {
                    required_equipage_bits: [0; 5],
                    units: vec![unit],
                },
                present_province: Some(ProvinceId::new(1)),
                target_province: ProvinceId::new(1),
                amassing_province: None,
            }),
            path_nation: Some(NationId::new(2)),
            state: 2,
            importance_bits: 0,
            held: false,
            marker: 1,
        });

        state.do_army_movement(nation);

        let order = state.military_units[0].order();
        assert_eq!(order.code(), UNIT_ORDER_REDEPLOY);
        assert_eq!(order.target(), Some(ProvinceId::new(1)));
    }

    #[test]
    fn attack_give_orders_attacks_when_war_stamp_is_stale_and_ready() {
        let mut state = game_state();
        let nation = auto_nation(&mut state);
        seed_province(&mut state, 0, 1, &[1]);
        seed_province(&mut state, 1, 2, &[0]);
        let unit = push_unit(&mut state, 1, 0);
        state.turn.economic_turn = 6;
        state.diplomacy.relationships[nation.nation()][NationId::new(2)] =
            DiplomaticRelationship::War;
        state.diplomacy.relationship_turns[nation.nation()][NationId::new(2)] = Some(0);
        state.missions.push(MissionState {
            nation: nation.nation(),
            data: MissionData::AttackProvince(AttackMissionState {
                army: ArmyMissionState {
                    required_equipage_bits: [1.0_f32.to_bits(); 5],
                    units: vec![unit],
                },
                present_province: Some(ProvinceId::new(0)),
                target_province: ProvinceId::new(1),
                amassing_province: None,
            }),
            path_nation: Some(NationId::new(2)),
            state: 2,
            importance_bits: 0,
            held: false,
            marker: 1,
        });

        state.do_army_movement(nation);

        let order = state.military_units[0].order();
        assert_eq!(order.code(), UNIT_ORDER_REDEPLOY);
        assert_eq!(order.target(), Some(ProvinceId::new(1)));
    }
}
