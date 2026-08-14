//! Military cleanup phase (`TSimMgr` turn-state 0x15).

use crate::military::{
    ActionClassScores, PROVINCE_UNIT_ORDER_WEIGHT, TACTICAL_COMPOSITION, accumulate_unit_priority,
};
use crate::*;

const ATTACK_RESOURCE_SCALE: [[f32; 4]; 5] = [
    [1.9, 2.3, 2.5, 2.7],
    [1.9, 2.3, 2.5, 2.7],
    [2.0, 2.3, 2.5, 2.7],
    [2.1, 2.3, 2.5, 2.7],
    [2.3, 2.5, 2.7, 2.9],
];

impl GameState {
    /// Retail military-cleanup for a non-client host. AI development replanning,
    /// order-priority metric globals, and the 40-turn diplomacy standing rebuild
    /// are not ported. AutoGreatPower pressure scores B64/B68/B6c are treated as
    /// unset (retail fallback 1.0) until those metrics live in `GameState`.
    pub fn do_military_cleanup(&mut self) {
        self.clear_all_transient_navy_orders();
        self.apply_military_cleanup_supported_subset();
        for nation in MajorNationId::all() {
            if !self.nation_is_eligible_for_optional_phase(nation.nation()) {
                continue;
            }
            if self.is_auto(nation) {
                self.reassess_missions(nation.nation());
                self.prune_invalid_defend_missions(nation.nation());
            }
        }
    }

    /// `TAutoGreatPower::MReassess`. Attack, defend, control-sea, escort,
    /// scattered-ships, and invade missions update lifecycle state, importance,
    /// and required equipage. Blockade uses the control-sea needs body without
    /// the extra threat floor.
    pub fn reassess_missions(&mut self, nation: NationId) {
        for index in 0..self.missions.len() {
            if self.missions[index].nation != nation {
                continue;
            }
            self.reassess_mission(index);
        }
    }

    /// Native `reassess_control_sea_missions`: ControlSeaZone only. Opening
    /// ControlSea needs do not read AutoGreatPower pressure scores.
    pub fn reassess_control_sea_missions(&mut self) {
        for nation in MajorNationId::all() {
            if !self.nation_is_eligible_for_optional_phase(nation.nation()) {
                continue;
            }
            if !self.is_auto(nation) {
                continue;
            }
            for index in 0..self.missions.len() {
                if self.missions[index].nation != nation.nation() {
                    continue;
                }
                if matches!(self.missions[index].data, MissionData::ControlSeaZone(_)) {
                    self.reassess_navy_mission(index);
                }
            }
        }
    }

    fn reassess_mission(&mut self, index: usize) {
        match &self.missions[index].data {
            MissionData::DefendProvince { province, .. } => {
                let province = *province;
                self.reassess_defend_mission(index, province);
            }
            MissionData::AttackProvince(attack) => {
                let attack = attack.clone();
                self.missions[index].state = 2;
                self.reassess_attack_mission_fields(index, &attack);
            }
            MissionData::ControlSeaZone(_)
            | MissionData::Escort(_)
            | MissionData::ScatteredShips(_)
            | MissionData::BlockadePort { .. }
            | MissionData::Beachhead(_)
            | MissionData::Invade { .. } => {
                self.reassess_navy_mission(index);
            }
        }
    }

    fn reassess_defend_mission(&mut self, index: usize, province: ProvinceId) {
        let nation = self.missions[index].nation;
        self.missions[index].state = if self.capitol_province(nation) == Some(province) {
            0
        } else {
            2
        };
        self.missions[index].importance_bits =
            self.province_mission_importance_bits(province, nation);
        let required = self.defend_required_equipage(nation, province);
        if let MissionData::DefendProvince { army, .. } = &mut self.missions[index].data {
            army.required_equipage_bits = required;
        }
    }

    pub(crate) fn reassess_attack_mission_fields(
        &mut self,
        index: usize,
        attack: &AttackMissionState,
    ) {
        let nation = self.missions[index].nation;
        self.missions[index].importance_bits =
            self.province_mission_importance_bits(attack.target_province, nation);
        let required = self.attack_required_equipage(attack.target_province);
        match &mut self.missions[index].data {
            MissionData::AttackProvince(state) | MissionData::Invade { attack: state, .. } => {
                state.army.required_equipage_bits = required;
            }
            _ => {}
        }
    }

    fn defend_required_equipage(&self, nation: NationId, province: ProvinceId) -> [u32; 5] {
        let pressure = 1.0_f32;
        if !self.province_is_mission_compatible(province) {
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
    /// `AddPurchasedItems`. This is the native `military_cleanup_supported_subset`
    /// operation; it does not prune missions or remove navy stragglers.
    pub fn apply_military_cleanup_supported_subset(&mut self) {
        for ship in &mut self.ships {
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
        for unit in &self.military_units {
            if unit.nation() != nation || !unit.unit_type().is_militia_category() {
                continue;
            }
            let Some(province) = unit.stationed_province() else {
                continue;
            };
            if self.mission_contains_unit(unit.id()) {
                continue;
            }
            let Some(index) = self.missions.iter().position(|mission| {
                mission.nation == nation
                    && matches!(
                        &mission.data,
                        MissionData::DefendProvince {
                            province: hold,
                            ..
                        } if *hold == province
                    )
            }) else {
                continue;
            };
            adoptions.push((index, unit.id()));
        }
        for (index, id) in adoptions {
            if let MissionData::DefendProvince { army, .. } = &mut self.missions[index].data {
                army.units.insert(0, id);
            }
        }
    }

    /// `TDefendProvinceMission::GetReplacementSlot48`: drop defend missions whose
    /// province is no longer owned by the mission nation.
    fn prune_invalid_defend_missions(&mut self, nation: NationId) {
        let mut remove = Vec::new();
        for (index, mission) in self.missions.iter().enumerate() {
            if mission.nation != nation {
                continue;
            }
            if let MissionData::DefendProvince { province, .. } = &mission.data
                && self.normalized_province_owner(*province) != Some(nation)
            {
                remove.push(index);
            }
        }
        for index in remove.into_iter().rev() {
            self.missions.remove(index);
        }
    }

    fn mission_contains_unit(&self, id: MilitaryUnitId) -> bool {
        self.missions.iter().any(|mission| match &mission.data {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    fn ship(selection: i32) -> ShipState {
        ShipState {
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(0),
            task_force: None,
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
                    units: Vec::new(),
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
        state.ships.extend([ship(1), ship(2)]);
        state.map[TileId::new(1)].province = Some(ProvinceId::new(0));
        state.map[TileId::new(1)].edge_resources = [Some(ResourceKind::Cotton), None];
        state.map.provinces[ProvinceId::new(0)].linked_tiles = vec![TileId::new(1)];

        let eligible = MajorNationId::new(0);
        let ineligible = MajorNationId::new(1);
        state.nations.majors[eligible]
            .economy
            .purchased_items_by_resource[ResourceKind::Food] = 5;
        state.nations.majors[eligible].city.stockpile[ResourceKind::Food] = 1;
        state.nations.majors[ineligible]
            .economy
            .purchased_items_by_resource[ResourceKind::Food] = 7;
        state.nations.majors[ineligible].city.stockpile[ResourceKind::Food] = 2;
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

        assert_eq!(state.ships[0].selection, 0);
        assert_eq!(state.ships[1].selection, 2);
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
            state.nations.majors[eligible].city.stockpile[ResourceKind::Food],
            6
        );
        assert_eq!(
            state.nations.majors[eligible]
                .economy
                .purchased_items_by_resource[ResourceKind::Food],
            0
        );
        assert_eq!(
            state.nations.majors[ineligible].city.stockpile[ResourceKind::Food],
            2,
            "protectorates skip purchase commit"
        );
        assert_eq!(
            state.nations.majors[ineligible]
                .economy
                .purchased_items_by_resource[ResourceKind::Food],
            7
        );
    }

    #[test]
    fn cleanup_adopts_unassigned_militia_into_the_defend_mission() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.nations.majors[nation].auto = Some(AutoGreatPowerState::default());
        let province = ProvinceId::new(3);
        seed_owned_province(&mut state, province, nation.nation());
        let id = state.unit_ids.next_military();
        state.military_units.push(MilitaryUnitState::new(
            id,
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
        ));
        state
            .missions
            .push(defend_mission(nation.nation(), province));

        state.do_military_cleanup();

        let MissionData::DefendProvince { army, .. } = &state.missions[0].data else {
            panic!("expected a defend-province mission");
        };
        assert_eq!(army.units, vec![id]);
    }

    #[test]
    fn cleanup_prunes_a_defend_mission_whose_province_changed_owner() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.nations.majors[nation].auto = Some(AutoGreatPowerState::default());
        let province = ProvinceId::new(3);
        seed_owned_province(&mut state, province, NationId::new(1));
        state
            .missions
            .push(defend_mission(nation.nation(), province));

        state.do_military_cleanup();

        assert!(state.missions.is_empty());
    }

    #[test]
    fn cleanup_removes_sail_and_empty_task_forces_and_keeps_patrol() {
        let mut state = game_state();
        state.ships.push(ship(0));
        state.ships.push(ship(0));
        state.task_forces.push(TaskForceState {
            aggression: 0,
            order: 3,
            target: TaskForceTarget::Zone(OceanZoneId::new(0)),
            location: OceanZoneId::new(0),
            nation: NationId::new(0),
            ship_counts: [0; 4],
            defeated: false,
            ingot_tile: -1,
            flagship: Some(ShipId::new(0)),
            ships: vec![SelectedShip {
                ship: ShipId::new(0),
                selected: true,
            }],
        });
        state.task_forces.push(TaskForceState {
            aggression: 0,
            order: 1,
            target: TaskForceTarget::Zone(OceanZoneId::new(1)),
            location: OceanZoneId::new(0),
            nation: NationId::new(0),
            ship_counts: [0; 4],
            defeated: false,
            ingot_tile: -1,
            flagship: Some(ShipId::new(1)),
            ships: vec![SelectedShip {
                ship: ShipId::new(1),
                selected: true,
            }],
        });
        state.ships[0].task_force = Some(TaskForceId::new(0));
        state.ships[1].task_force = Some(TaskForceId::new(1));

        state.do_military_cleanup();

        assert_eq!(state.task_forces.len(), 1);
        assert_eq!(state.task_forces[0].order, 3);
        assert_eq!(state.ships[0].task_force, Some(TaskForceId::new(0)));
        assert_eq!(state.ships[1].task_force, None);
    }

    fn attack_mission(nation: NationId, target: ProvinceId) -> MissionState {
        MissionState {
            nation,
            data: MissionData::AttackProvince(AttackMissionState {
                army: ArmyMissionState {
                    required_equipage_bits: [0; 5],
                    units: Vec::new(),
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
        state.nations.majors[nation].auto = Some(AutoGreatPowerState::default());
        let province = ProvinceId::new(3);
        seed_owned_province(&mut state, province, nation.nation());
        state.map.provinces[province].set_city_score(2500);
        state.map[TileId::new(1)].province = Some(province);
        state
            .missions
            .push(defend_mission(nation.nation(), province));

        state.reassess_missions(nation.nation());

        assert_eq!(state.missions[0].state, 0, "capitol province uses state 0");
        assert_eq!(
            state.missions[0].importance_bits,
            (2500.0_f32 / 5000.0).to_bits()
        );
        let MissionData::DefendProvince { army, .. } = &state.missions[0].data else {
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
        state.nations.majors[nation].auto = Some(AutoGreatPowerState::default());
        let target = ProvinceId::new(4);
        seed_owned_province(&mut state, target, NationId::new(1));
        state.map.provinces[target].set_city_score(1000);
        state.missions.push(attack_mission(nation.nation(), target));

        state.reassess_missions(nation.nation());

        let MissionData::AttackProvince(attack) = &state.missions[0].data else {
            panic!("expected an attack-province mission");
        };
        let scale = 1.9_f32;
        assert_eq!(
            attack.army.required_equipage_bits,
            [27.0, 36.0, 0.0, 17.0, 20.0].map(|weight| (weight * scale * 0.01).to_bits())
        );
        assert_eq!(
            state.missions[0].importance_bits,
            (1000.0_f32 / 5000.0).to_bits()
        );
    }

    #[test]
    fn reassess_fills_control_sea_needs_when_the_zone_has_no_hostiles() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.nations.majors[nation].auto = Some(AutoGreatPowerState::default());
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
        state.missions.push(MissionState {
            nation: nation.nation(),
            data: MissionData::ControlSeaZone(NavyMissionState {
                target_zone: Some(OceanZoneId::new(0)),
                resolved_port_zone: None,
                selected_ship: None,
                task_force: None,
                state: 0,
                required_equipage_bits: [0; 4],
                ships: Vec::new(),
            }),
            path_nation: None,
            state: 2,
            importance_bits: 0,
            held: false,
            marker: 0,
        });

        state.do_military_cleanup();

        let MissionData::ControlSeaZone(navy) = &state.missions[0].data else {
            panic!("expected a control-sea mission");
        };
        assert_eq!(
            navy.required_equipage_bits,
            [40.0_f32, 40.0, 20.0, 0.0].map(|weight| weight.to_bits())
        );
        assert_eq!(navy.state, 0);
        assert_eq!(state.missions[0].state, 2);
    }
}
