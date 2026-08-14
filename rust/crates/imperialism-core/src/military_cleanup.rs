//! Military cleanup phase (`TSimMgr` turn-state 0x15).

use crate::*;

impl GameState {
    /// Retail military-cleanup for a non-client host. Navy straggler removal,
    /// mission reassess/prune, power-score globals, and AI development replanning
    /// are not ported. Ship assignment onto navy missions is.
    pub fn do_military_cleanup(&mut self) {
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
    /// adoption. Reassess, prune, and AI development replanning are not ported.
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
        state.nations.majors[nation].kind = MajorNationKind::AutoGreatPower;
        let province = ProvinceId::new(3);
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
        state.missions.push(MissionState {
            nation: nation.nation(),
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
        });

        state.do_military_cleanup();

        let MissionData::DefendProvince { army, .. } = &state.missions[0].data else {
            panic!("expected a defend-province mission");
        };
        assert_eq!(army.units, vec![id]);
    }
}
