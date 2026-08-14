//! Military maintenance and order-preparation (`TSimMgr::DoMilitary`).

use crate::*;

const HEATMAP_PACKED_DEVELOPMENT_OVERFLOW: [u8; 44] = [
    0, 0, 0, 1, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 10, 0, 4, 0, 7, 0, 6,
    0, 8, 0, 0, 0, 9, 0, 5, 0, 1, 0, 2, 0,
];

const UNIVERSITY_REQUIREMENT_LEVEL: [[u8; 4]; 24] = [
    [1, 2, 3, 4],
    [1, 2, 3, 4],
    [1, 2, 3, 4],
    [0, 2, 4, 6],
    [0, 2, 4, 6],
    [1, 1, 1, 1],
    [0, 2, 4, 6],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [1, 2, 3, 4],
    [1, 2, 3, 4],
    [1, 2, 3, 4],
    [1, 2, 3, 4],
    [0, 1, 2, 3],
    [0, 1, 2, 3],
    [0, 0, 0, 0],
];

const HEATMAP_NEIGHBOR_DIFFUSION: f32 = 0.2;

impl GameState {
    /// Retail `TSimMgr::DoMilitary` without AutoGreatPower mission planning or navy
    /// `CarryOutOrders`. Those branches are not represented as complete `GameState`
    /// operations yet and must not mutate half the world.
    pub fn do_military(&mut self) {
        self.recompute_tile_strategic_score_heatmap();
        for slot in 0..NationId::COUNT {
            let nation = NationId::new(slot);
            if !self.nation_is_eligible_for_optional_phase(nation) {
                continue;
            }
            self.grow_militia(nation);
        }
        for index in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(index);
            if !self.nation_is_eligible_for_optional_phase(nation.nation()) {
                continue;
            }
            self.pay_for_military(nation);
            if self.nations.major(nation).kind == MajorNationKind::GreatPower {
                self.nations.majors[nation].economy.army_movement_budget =
                    i32::from(self.nations.majors[nation].economy.capacities.transport) / 5;
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
        let mut resource_weights = [0_i32; ResourceKind::LENGTH];
        for resource in 0_i16..=16 {
            let commodity = TradeCommodity::from_retail(resource)
                .expect("manufactured heatmap weights use trade commodities");
            resource_weights[resource as usize] = self.market.rows[commodity].base_price;
        }
        resource_weights[ResourceKind::Gems as usize] = 500;
        resource_weights[ResourceKind::Gold as usize] = 200;
        let oil_drilling = self.technology.oil_drilling_available();

        let mut region_scores = [0_i32; PROVINCE_COUNT];
        for (index, score) in region_scores.iter_mut().enumerate() {
            let province = ProvinceId::new(index as u16);
            *score = 200;
            for &tile in &self.map.provinces[province].linked_tiles {
                for resource in self.map[tile].edge_resources.iter().flatten() {
                    if *resource == ResourceKind::Oil && !oil_drilling {
                        continue;
                    }
                    *score += i32::from(heatmap_requirement_level(
                        *resource as usize,
                        self.map[tile].development.packed_byte(),
                    )) * resource_weights[*resource as usize];
                }
            }
        }

        for (index, score) in region_scores.iter_mut().enumerate() {
            let province = ProvinceId::new(index as u16);
            *score += i32::from(self.map.provinces[province].development_stage() + 3) * 1000;
        }

        for slot in 0..NationId::COUNT {
            let nation = NationId::new(slot);
            let Some(home) = self.nations.home_tile(nation) else {
                continue;
            };
            let Some(capitol) = self.map[home].province else {
                continue;
            };
            region_scores[usize::from(capitol.get())] += if slot < MajorNationId::COUNT {
                10_000
            } else {
                8_000
            };
        }

        for (index, region_score) in region_scores.iter().enumerate() {
            let province = ProvinceId::new(index as u16);
            let mut city_score = *region_score;
            for &adjacent in self.map.provinces[province].adjacency().iter().rev() {
                city_score = (region_scores[usize::from(adjacent.get())] as f32
                    * HEATMAP_NEIGHBOR_DIFFUSION
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
        order_code: i32,
    ) {
        let id = self.unit_ids.next_military();
        let order = if order_code == 0 {
            MilitaryOrder::idle([province; 3], [province; 3])
        } else {
            MilitaryOrder::retail(
                MilitaryOrderCode::from_retail(order_code),
                None,
                [province; 3],
                [province; 3],
            )
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
            .partition_point(|existing| existing.nation.get() <= nation.get());
        self.military_units.insert(insert_at, unit);
    }

    fn add_militia(&mut self, nation: NationId, province: ProvinceId) {
        let unit_type = self.militia_kind(nation);
        self.insert_land_unit(nation, unit_type, Some(province), 2);
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
    const CATEGORY: [i16; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 9, 9, 9,
        0, 0,
    ];
    CATEGORY[kind as usize]
}

pub(crate) fn combat_class(kind: MilitaryUnitKind) -> i16 {
    const CLASS: [i16; 32] = [
        1, 2, 1, 1, 3, 2, 2, 1, 1, 2, 1, 1, 3, 2, 2, 1, 1, 2, 1, 1, 3, 3, 2, 1, 1, 2, 3, 2, 2, 2,
        0, 0,
    ];
    CLASS[kind as usize]
}

fn heatmap_requirement_level(resource_type: usize, packed_development: i8) -> u8 {
    let flat_index = resource_type as i32 * 4 + i32::from(packed_development);
    const TABLE_BYTES: i32 = 96;
    if (0..TABLE_BYTES).contains(&flat_index) {
        UNIVERSITY_REQUIREMENT_LEVEL[flat_index as usize / 4][flat_index as usize % 4]
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
        assert_eq!(state.military_units[0].order.code(), 2);
        assert_eq!(state.military_units[0].strength, 500);
        assert_eq!(
            state.nations.majors[MajorNationId::new(0)]
                .economy
                .army_movement_budget,
            0
        );
    }
}
