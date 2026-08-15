//! Military maintenance and order-preparation (`TSimMgr::DoMilitary`).

use crate::city::UNIVERSITY_REQUIREMENT_LEVEL_BY_ID;
use crate::combat_moves::set_unit_order;
use crate::military::{ActionClassScores, PROVINCE_UNIT_ORDER_WEIGHT, accumulate_unit_priority};
use crate::*;

const ATTACK_MISSION_READINESS_THRESHOLD: f32 = 1.0;

const HEATMAP_PACKED_DEVELOPMENT_OVERFLOW: [u8; 44] = [
    0, 0, 0, 1, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 10, 0, 4, 0, 7, 0, 6,
    0, 8, 0, 0, 0, 9, 0, 5, 0, 1, 0, 2, 0,
];

const HEATMAP_NEIGHBOR_DIFFUSION: f32 = 0.2;

impl GameState {
    /// Retail `TSimMgr::DoMilitary`. Auto great powers run advisory mission
    /// selection and `GiveOrders` for land and navy missions, then navy order
    /// execution for sail/repair/marines plus the CarryOutOrders straggler
    /// tail. Navy battle pairing, `MakeSureAllShipsHaveOrders`, and
    /// `CleanUpStacks` (map-context records) are not ported.
    pub fn do_military(&mut self) {
        self.apply_military_orders();
        self.prepare_to_carry_out_navy_orders();
        self.carry_out_navy_orders();
    }

    /// Heatmap, militia, pay, advisory selection, and mission `GiveOrders`.
    /// Does not execute navy `CarryOutOrders`.
    pub(crate) fn apply_military_orders(&mut self) {
        self.recompute_tile_strategic_score_heatmap();
        for nation in NationId::all() {
            if !self.nation_is_eligible_for_optional_phase(nation) {
                continue;
            }
            self.grow_militia(nation);
        }
        for nation in MajorNationId::all() {
            if !self.nation_is_eligible_for_optional_phase(nation.nation()) {
                continue;
            }
            self.pay_for_military(nation);
            if self.nations.major(nation).auto.is_none() {
                self.nations.majors[nation].economy.army_movement_budget =
                    i32::from(self.nations.majors[nation].economy.capacities.transport) / 5;
            } else {
                self.select_and_queue_advisory_map_missions_for(nation);
                self.give_auto_great_power_army_orders(nation.nation());
            }
        }
    }

    /// Retail `TAutoGreatPower::MoveArmy` / mission `GiveOrders`.
    pub(crate) fn do_army_movement(&mut self, nation: MajorNationId) {
        self.give_auto_great_power_army_orders(nation.nation());
    }

    fn give_auto_great_power_army_orders(&mut self, nation: NationId) {
        let mission_count = self.missions.len();
        for mission_index in 0..mission_count {
            if self.missions[mission_index].nation != nation {
                continue;
            }
            match &self.missions[mission_index].data {
                MissionData::DefendProvince { province, army } => {
                    let province = *province;
                    let units = army.units.clone();
                    self.redeploy_units_not_stationed_in(&units, province);
                }
                MissionData::AttackProvince(attack) => {
                    let attack = attack.clone();
                    self.give_attack_province_orders(nation, &attack);
                }
                MissionData::Invade { .. } => {
                    self.give_navy_mission_orders(mission_index);
                    let attack = match &self.missions[mission_index].data {
                        MissionData::Invade { attack, .. } => attack.clone(),
                        _ => continue,
                    };
                    let Some(major) = MajorNationId::from_nation(nation) else {
                        continue;
                    };
                    if self.map.provinces[attack.target_province].explored_by_majors()[major] {
                        self.give_attack_province_orders(nation, &attack);
                    }
                }
                MissionData::ControlSeaZone(_)
                | MissionData::Escort(_)
                | MissionData::ScatteredShips(_)
                | MissionData::BlockadePort { .. }
                | MissionData::Beachhead(_) => {
                    self.give_navy_mission_orders(mission_index);
                }
            }
        }
    }

    fn give_attack_province_orders(&mut self, nation: NationId, attack: &AttackMissionState) {
        let Some(present) = attack.present_province else {
            return;
        };

        let mut projected = ActionClassScores::default();
        for id in &attack.army.units {
            let Some(unit) = self.military_units.iter().find(|unit| unit.id() == *id) else {
                continue;
            };
            if unit.stationed_province() == Some(present) {
                accumulate_unit_priority(unit, &mut projected, 1.0, PROVINCE_UNIT_ORDER_WEIGHT);
            }
        }
        let required = attack.army.required_equipage_bits.map(f32::from_bits);
        let projected = projected.components();
        let mut weighted = 0.0;
        let mut total = 0.0;
        for index in 0..5 {
            weighted += (required[index] * projected[index]).sqrt();
            total += required[index];
        }
        if weighted / total > ATTACK_MISSION_READINESS_THRESHOLD
            && let Some(owner) = self.map.provinces[attack.target_province].owner()
        {
            if self.war_stamp_stale(nation, owner) {
                self.redeploy_units_stationed_in(
                    &attack.army.units,
                    present,
                    attack.target_province,
                );
            } else if !self.at_war(nation, owner)
                && let Some(major) = MajorNationId::from_nation(nation)
                && self.nations.majors[major]
                    .economy
                    .diplomacy_policy_by_nation[owner]
                    != Some(DiplomacyPolicy::DeclareWar)
            {
                self.post_policy(major, owner, DiplomacyPolicy::DeclareWar);
            }
        }

        self.redeploy_units_not_stationed_in(&attack.army.units, present);
    }

    fn redeploy_units_not_stationed_in(&mut self, units: &[MilitaryUnitId], province: ProvinceId) {
        for id in units {
            let Some(unit) = self.military_units.iter_mut().find(|unit| unit.id() == *id) else {
                continue;
            };
            if unit.stationed_province() != Some(province) {
                set_unit_order(unit, MilitaryOrderCode::Redeploy, Some(province));
            }
        }
    }

    fn redeploy_units_stationed_in(
        &mut self,
        units: &[MilitaryUnitId],
        present: ProvinceId,
        target: ProvinceId,
    ) {
        for id in units {
            let Some(unit) = self.military_units.iter_mut().find(|unit| unit.id() == *id) else {
                continue;
            };
            if unit.stationed_province() == Some(present) {
                set_unit_order(unit, MilitaryOrderCode::Redeploy, Some(target));
            }
        }
    }

    pub(crate) fn nation_is_eligible_for_optional_phase(&self, nation: NationId) -> bool {
        let Some(common) = self.nations.common(nation) else {
            return false;
        };
        if MajorNationId::from_nation(nation).is_none() {
            return true;
        }
        !matches!(common.status(), CountryStatus::ProtectorateOf(_))
    }

    pub(crate) fn recompute_tile_strategic_score_heatmap(&mut self) {
        let mut resource_weights = ResourceTable::<i32>::default();
        for resource in 0_i16..=16 {
            let commodity = TradeCommodity::from_retail(resource)
                .expect("manufactured heatmap weights use trade commodities");
            resource_weights[commodity.resource()] = self.market.rows[commodity].base_price;
        }
        resource_weights[ResourceKind::Gems] = 500;
        resource_weights[ResourceKind::Gold] = 200;
        let oil_drilling = self.technology.oil_drilling_available();

        let mut region_scores = ProvinceTable::from_fn(|_| 200);
        for province in ProvinceId::all() {
            for &tile in &self.map.provinces[province].linked_tiles {
                for resource in self.map[tile].edge_resources.iter().flatten() {
                    if *resource == ResourceKind::Oil && !oil_drilling {
                        continue;
                    }
                    region_scores[province] += i32::from(heatmap_requirement_level(
                        *resource as usize,
                        self.map[tile].development.packed_byte(),
                    )) * resource_weights[*resource];
                }
            }
        }

        for province in ProvinceId::all() {
            region_scores[province] +=
                i32::from(self.map.provinces[province].development_stage() + 3) * 1000;
        }

        for nation in NationId::all() {
            let Some(home) = self.nations.home_tile(nation) else {
                continue;
            };
            let Some(capitol) = self.map[home].province else {
                continue;
            };
            region_scores[capitol] += if MajorNationId::from_nation(nation).is_some() {
                10_000
            } else {
                8_000
            };
        }

        for province in ProvinceId::all() {
            let mut city_score = region_scores[province];
            for &adjacent in self.map.provinces[province].adjacency().iter().rev() {
                city_score = (region_scores[adjacent] as f32 * HEATMAP_NEIGHBOR_DIFFUSION
                    + city_score as f32) as i32;
            }
            self.map.provinces[province].set_city_score(city_score);
        }

        let total: i32 = self
            .map
            .provinces
            .as_array()
            .iter()
            .map(ProvinceState::city_score)
            .sum();
        self.map.city_score_total = total / PROVINCE_COUNT as i32;
    }

    fn grow_militia(&mut self, nation: NationId) {
        if !is_recruit_quarter_tick_gate(self.turn.economic_turn) {
            return;
        }
        let threshold = if MajorNationId::from_nation(nation).is_some() {
            4
        } else {
            3
        };
        let owned = self
            .nations
            .common(nation)
            .expect("eligible militia nation is present")
            .owned_regions()
            .to_vec();
        for province in owned {
            let garrison = self
                .military_units
                .iter()
                .filter(|unit| {
                    unit.stationed_province == Some(province)
                        && tactical_category(unit.unit_type) == 0
                })
                .count();
            if garrison < threshold {
                self.add_militia(nation, province);
            }
        }
    }

    pub(crate) fn insert_land_unit(
        &mut self,
        nation: NationId,
        unit_type: MilitaryUnitKind,
        province: Option<ProvinceId>,
        order_code: MilitaryOrderCode,
    ) {
        let id = self.unit_ids.next_military();
        let order = if order_code == MilitaryOrderCode::Idle {
            MilitaryOrder::idle([province; 3], [province; 3])
        } else {
            MilitaryOrder::retail(order_code, None, [province; 3], [province; 3])
        };
        let unit = MilitaryUnitState::new(
            id,
            nation,
            unit_type,
            province,
            order,
            nation,
            0,
            true,
            String::new(),
            500,
            unit_type.spawn_era(),
            0,
            0,
        );
        let insert_at = self
            .military_units
            .partition_point(|existing| existing.nation <= nation);
        self.military_units.insert(insert_at, unit);
    }

    fn add_militia(&mut self, nation: NationId, province: ProvinceId) {
        let unit_type = self.militia_kind(nation);
        self.insert_land_unit(nation, unit_type, Some(province), MilitaryOrderCode::Sleep);
    }

    pub(crate) fn militia_kind(&self, nation: NationId) -> MilitaryUnitKind {
        let Some(major) = MajorNationId::from_nation(nation) else {
            return MilitaryUnitKind::Minutemen;
        };
        let abilities = &self.technology.military_unit_ability_active_by_nation[major];
        if abilities[MilitaryUnitKind::Conscripts] {
            MilitaryUnitKind::Conscripts
        } else if abilities[MilitaryUnitKind::Militia] {
            MilitaryUnitKind::Militia
        } else {
            MilitaryUnitKind::Minutemen
        }
    }
}

pub(crate) fn is_recruit_quarter_tick_gate(tick: i32) -> bool {
    let quarter_index = (tick + ((tick >> 31) & 3)) >> 2;
    if quarter_index & 1 == 0 {
        return false;
    }
    let sign = tick >> 31;
    let mut mod4 = tick;
    mod4 ^= sign;
    mod4 -= sign;
    mod4 &= 3;
    mod4 ^= sign;
    mod4 -= sign;
    mod4 == 2
}

pub(crate) fn tactical_category(kind: MilitaryUnitKind) -> i16 {
    const CATEGORY: MilitaryUnitTable<i16> = MilitaryUnitTable::from_array([
        0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 9, 9, 9,
    ]);
    CATEGORY[kind]
}

pub(crate) fn combat_class(kind: MilitaryUnitKind) -> i16 {
    const CLASS: MilitaryUnitTable<i16> = MilitaryUnitTable::from_array([
        1, 2, 1, 1, 3, 2, 2, 1, 1, 2, 1, 1, 3, 2, 2, 1, 1, 2, 1, 1, 3, 3, 2, 1, 1, 2, 3, 2, 2, 2,
    ]);
    CLASS[kind]
}

fn heatmap_requirement_level(resource_type: usize, packed_development: i8) -> u8 {
    let flat_index = resource_type as i32 * 4 + i32::from(packed_development);
    const TABLE_BYTES: i32 = 96;
    if (0..TABLE_BYTES).contains(&flat_index) {
        UNIVERSITY_REQUIREMENT_LEVEL_BY_ID[flat_index as usize / 4][flat_index as usize % 4]
    } else if flat_index >= TABLE_BYTES {
        let overflow = (flat_index - TABLE_BYTES) as usize;
        HEATMAP_PACKED_DEVELOPMENT_OVERFLOW[overflow]
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    #[test]
    fn heatmap_on_an_empty_map_is_the_undeveloped_mean() {
        let mut state = game_state();
        state.recompute_tile_strategic_score_heatmap();
        for province in state.map.provinces.as_array() {
            assert_eq!(province.city_score(), 3200);
        }
        assert_eq!(state.map.city_score_total, 3200);
    }

    #[test]
    fn militia_quarter_gate_matches_retail_odd_quarter_mod_four() {
        assert!(!is_recruit_quarter_tick_gate(0));
        assert!(!is_recruit_quarter_tick_gate(2));
        assert!(is_recruit_quarter_tick_gate(6));
        assert!(!is_recruit_quarter_tick_gate(10));
        assert!(is_recruit_quarter_tick_gate(14));
    }

    #[test]
    fn grow_militia_on_the_quarter_gate_inserts_sleeping_minutemen() {
        let mut state = game_state();
        state.turn.economic_turn = 6;
        let nation = NationId::new(0);
        let province = ProvinceId::new(3);
        state
            .nations
            .append_owned_region_during_construction(nation, province);
        state.do_military();
        assert_eq!(state.military_units.len(), 1);
        assert_eq!(state.military_units[0].nation, nation);
        assert_eq!(
            state.military_units[0].unit_type,
            MilitaryUnitKind::Minutemen
        );
        assert_eq!(state.military_units[0].stationed_province, Some(province));
        assert_eq!(
            state.military_units[0].order.code(),
            MilitaryOrderCode::Sleep
        );
        assert_eq!(state.military_units[0].strength, 500);
        assert_eq!(
            state.nations.majors[MajorNationId::new(0)]
                .economy
                .army_movement_budget,
            0
        );
    }

    #[test]
    fn auto_great_power_defend_orders_redeploy_units_off_the_held_province() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.nations.majors[nation].auto = Some(AutoGreatPowerState::default());
        let hold = ProvinceId::new(0);
        let away = ProvinceId::new(1);
        let id = state.unit_ids.next_military();
        state.military_units.push(MilitaryUnitState::new(
            id,
            nation.nation(),
            MilitaryUnitKind::Minutemen,
            Some(away),
            MilitaryOrder::idle([Some(away); 3], [Some(away); 3]),
            nation.nation(),
            0,
            true,
            String::new(),
            500,
            0,
            0,
            0,
        ));
        state.missions.push(MissionState {
            nation: nation.nation(),
            data: MissionData::DefendProvince {
                province: hold,
                army: ArmyMissionState {
                    required_equipage_bits: [0; 5],
                    units: vec![id],
                },
            },
            path_nation: None,
            state: 2,
            importance_bits: 0,
            held: false,
            marker: 0,
        });

        state.do_military();

        assert_eq!(
            state.military_units[0].order().code(),
            MilitaryOrderCode::Redeploy
        );
        assert_eq!(state.military_units[0].order().target(), Some(hold));
    }

    fn set_owned_province(state: &mut GameState, province: u16, owner: u8, adjacent: &[u16]) {
        let owner = NationId::new(owner);
        let id = ProvinceId::new(province);
        state.map.provinces[id] = ProvinceState::new(
            Some(owner),
            Some(owner),
            0,
            adjacent.iter().copied().map(ProvinceId::new).collect(),
            vec![TileId::new(0); adjacent.len()],
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
        state
            .nations
            .append_owned_region_during_construction(owner, id);
    }

    fn add_armor(state: &mut GameState, nation: NationId, province: ProvinceId) {
        let id = state.unit_ids.next_military();
        state.military_units.push(MilitaryUnitState::new(
            id,
            nation,
            MilitaryUnitKind::Armor,
            Some(province),
            MilitaryOrder::idle([Some(province); 3], [Some(province); 3]),
            nation,
            0,
            true,
            String::new(),
            500,
            0,
            0,
            0,
        ));
    }

    #[test]
    fn auto_great_power_queues_a_direct_attack_on_a_flagged_neighbor() {
        let mut state = game_state();
        let attacker = MajorNationId::new(0);
        let defender = MajorNationId::new(1);
        state.nations.majors[attacker].auto = Some(AutoGreatPowerState::default());
        set_owned_province(&mut state, 0, 0, &[1]);
        set_owned_province(&mut state, 1, 1, &[0]);
        state.nations.majors[attacker]
            .economy
            .candidate_nation_flags[defender.nation()] = 1;
        for _ in 0..20 {
            add_armor(&mut state, attacker.nation(), ProvinceId::new(0));
        }

        state.do_military();

        assert_eq!(state.missions.len(), 1);
        assert_eq!(state.missions[0].nation, attacker.nation());
        assert_eq!(state.missions[0].marker, 1);
        assert_eq!(state.missions[0].path_nation, Some(defender.nation()));
        assert_eq!(state.missions[0].state, 2);
        match &state.missions[0].data {
            MissionData::AttackProvince(attack) => {
                assert_eq!(attack.target_province, ProvinceId::new(1));
                assert_eq!(attack.present_province, None);
                assert_eq!(attack.amassing_province, None);
            }
            other => panic!("expected a direct attack mission, got {other:?}"),
        }
        assert_eq!(
            state.nations.majors[attacker]
                .auto
                .as_ref()
                .unwrap()
                .province_targets[ProvinceId::new(1)],
            AiTargetState::MissionQueued
        );
    }

    #[test]
    fn human_great_power_does_not_queue_advisory_missions() {
        let mut state = game_state();
        let attacker = MajorNationId::new(0);
        let defender = MajorNationId::new(1);
        state.nations.majors[attacker].auto = None;
        set_owned_province(&mut state, 0, 0, &[1]);
        set_owned_province(&mut state, 1, 1, &[0]);
        state.nations.majors[attacker]
            .economy
            .candidate_nation_flags[defender.nation()] = 1;
        for _ in 0..20 {
            add_armor(&mut state, attacker.nation(), ProvinceId::new(0));
        }

        state.do_military();

        assert!(state.missions.is_empty());
    }
}
