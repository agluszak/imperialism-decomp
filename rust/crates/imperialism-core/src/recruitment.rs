use crate::{
    CivilianUnitId, CivilianUnitKind, CivilianUnitState, GameState, MajorNationId, MapGeometry,
    MilitaryUnitId, MilitaryUnitKind, MilitaryUnitState, MilitaryUnitTable, NationId,
    PendingActionKind, RecruitKind, TileId, TurnSummary, UnitProductionOrder, WorldState,
};

const MILITARY_POWER_BY_UNIT_TYPE: MilitaryUnitTable<i16> = MilitaryUnitTable::from_array([
    0, 1, 1, 1, 1, 1, 2, 2, 0, 2, 2, 2, 2, 2, 4, 4, 0, 4, 4, 4, 4, 10, 6, 8, 2, 2, 3, 0, 0, 0,
]);

impl WorldState {
    pub fn find_reachable_recruit_spawn_tile(
        &self,
        civilians: &[CivilianUnitState],
        start: TileId,
        allow_active_flag_2: bool,
    ) -> Option<TileId> {
        let owner = self.tiles.get(usize::from(start.get()))?.owner_nation;
        let geometry = MapGeometry::new(self.wraps_horizontally);
        let mut visited = vec![false; self.tiles.len()];
        let mut pending = vec![start];

        while let Some(tile_id) = pending.pop() {
            let index = usize::from(tile_id.get());
            let Some(tile) = self.tiles.get(index) else {
                continue;
            };
            if visited[index] {
                continue;
            }
            visited[index] = true;
            if tile.owner_nation != owner {
                continue;
            }

            let occupied = civilians.iter().any(|civilian| {
                civilian.tile == Some(tile_id)
                    && owner.is_some_and(|owner| civilian.nation.get() == owner.get())
            });
            if !occupied && (tile.active_flags & 2 == 0 || allow_active_flag_2) {
                return Some(tile_id);
            }

            for neighbor in geometry.neighbors(tile_id).iter().rev().flatten() {
                pending.push(*neighbor);
            }
        }
        None
    }
}

impl GameState {
    pub fn selected_military_power_score(&self, nation: NationId) -> i32 {
        self.military_units
            .iter()
            .filter(|unit| unit.nation == nation)
            .fold(0_i32, |power, unit| {
                power + i32::from(MILITARY_POWER_BY_UNIT_TYPE[unit.unit_type])
            })
    }

    pub fn produce_civilian_recruits(
        &mut self,
        nation: MajorNationId,
        order: &mut UnitProductionOrder,
    ) -> Result<(), RecruitmentError> {
        let pending_delta = order.quantity;
        if pending_delta == 0 {
            return Ok(());
        }
        let RecruitKind::Civilian(unit_kind) = order.profile.recruit_kind else {
            return Err(RecruitmentError::SpecialistOrder);
        };
        let city = self.major_nations[nation]
            .as_ref()
            .and_then(|major| major.city.as_ref())
            .ok_or(RecruitmentError::MissingCity(nation))?;
        let home_tile = city
            .home_town_tile
            .filter(|tile| usize::from(tile.get()) < self.world.tiles.len())
            .ok_or(RecruitmentError::InvalidHomeTile)?;

        let metric = &mut self.major_nations[nation]
            .as_mut()
            .expect("city presence was checked")
            .city
            .as_mut()
            .expect("city presence was checked")
            .civilian_recruit_count_by_kind[unit_kind];
        *metric += pending_delta;

        if pending_delta > 0 {
            let nation_id = nation.nation();
            for _ in 0..pending_delta {
                let Some(tile) = self.world.find_reachable_recruit_spawn_tile(
                    &self.civilian_units,
                    home_tile,
                    unit_kind == CivilianUnitKind::Engineer,
                ) else {
                    continue;
                };
                self.persistent_unit_id_counter += 1;
                let id = CivilianUnitId::new(self.persistent_unit_id_counter);
                let unit = CivilianUnitState {
                    id,
                    nation: nation_id,
                    unit_type: unit_kind,
                    tile: Some(tile),
                    raw_order_code: 0,
                    order_target: -1,
                    roster_id: 0,
                    registered: false,
                    remaining_turns: 0,
                };
                let insert_at = self
                    .civilian_units
                    .iter()
                    .position(|existing| existing.nation.get() > nation_id.get())
                    .unwrap_or(self.civilian_units.len());
                self.civilian_units.insert(insert_at, unit);
            }
        }

        order.quantity = 0;
        if unit_kind == CivilianUnitKind::Miner {
            let city = self.major_nations[nation]
                .as_mut()
                .expect("city presence was checked")
                .city
                .as_mut()
                .expect("city presence was checked");
            city.serialized_state += 1;
        }
        Ok(())
    }

    pub fn produce_specialist_recruits(
        &mut self,
        nation: MajorNationId,
        order: &mut UnitProductionOrder,
    ) -> Result<(), RecruitmentError> {
        let pending_delta = order.quantity;
        if pending_delta == 0 {
            return Ok(());
        }
        let RecruitKind::Military(unit_kind) = order.profile.recruit_kind else {
            return Err(RecruitmentError::CivilianOrder);
        };
        let major = self.major_nations[nation]
            .as_ref()
            .ok_or(RecruitmentError::MissingNation(nation))?;
        let city = major
            .city
            .as_ref()
            .ok_or(RecruitmentError::MissingCity(nation))?;
        let (home_province, experienced) = if pending_delta > 0 {
            let home_tile = city
                .home_town_tile
                .filter(|tile| usize::from(tile.get()) < self.world.tiles.len())
                .ok_or(RecruitmentError::InvalidHomeTile)?;
            let province = self.world.tiles[usize::from(home_tile.get())]
                .province
                .ok_or(RecruitmentError::MissingHomeProvince)?;
            let action_6 =
                major.state.pending_action_status[PendingActionKind::ConqueredCapitalArmoryUpgrade];
            (
                i16::try_from(province.get()).expect("province IDs fit military-unit state"),
                action_6 >= 0x33,
            )
        } else {
            (0, false)
        };

        if pending_delta > 0 {
            let nation_id = nation.nation();
            for _ in 0..pending_delta {
                self.persistent_unit_id_counter += 1;
                let id = MilitaryUnitId::new(self.persistent_unit_id_counter);
                let experience = if experienced { 100 } else { 0 };
                let unit = MilitaryUnitState {
                    id,
                    nation: nation_id,
                    unit_type: unit_kind,
                    stationed_province: home_province,
                    raw_order_code: 0,
                    order_target: -1,
                    roster_id: 0,
                    registered: true,
                    order_target_tiles: [home_province; 3],
                    order_target_mirrors: [home_province; 3],
                    name: String::new(),
                    strength: 500,
                    era: unit_kind.spawn_era(),
                    experience,
                    battle_flags: 0,
                };
                let insert_at = self
                    .military_units
                    .iter()
                    .position(|existing| existing.nation.get() > nation_id.get())
                    .unwrap_or(self.military_units.len());
                self.military_units.insert(insert_at, unit);

                let pending_status = self.major_nations[nation]
                    .as_ref()
                    .expect("nation presence was checked")
                    .state
                    .pending_action_status[PendingActionKind::ArmyGrowthReward];
                if pending_status != 0x32 {
                    let current_level = if pending_status == 0 {
                        0
                    } else {
                        i32::from(pending_status) - 0x33
                    };
                    let military_power = self.selected_military_power_score(nation_id);
                    if let Some(payload) =
                        pending_military_action_payload(military_power, current_level)
                    {
                        let major = &mut self.major_nations[nation]
                            .as_mut()
                            .expect("nation presence was checked")
                            .state;
                        major.pending_action_status[PendingActionKind::ArmyGrowthReward] = 0x32;
                        major.pending_action_payload_by_action
                            [PendingActionKind::ArmyGrowthReward] = payload;
                    }
                }
            }
        }

        insert_turn_summary(
            &mut self.rng,
            &mut self.pending.nations[nation].turn_summary,
            TurnSummary {
                turn_tick: self.turn.economic_turn,
                order_kind: 3,
                payload: i16::from(unit_kind.index()),
                flags: pending_delta,
            },
        );
        order.quantity = 0;
        if unit_kind == MilitaryUnitKind::Minutemen {
            let city = self.major_nations[nation]
                .as_mut()
                .expect("city presence was checked")
                .city
                .as_mut()
                .expect("city presence was checked");
            city.serialized_state += 1;
        }
        Ok(())
    }
}

fn insert_turn_summary(
    rng: &mut crate::RngState,
    queue: &mut Vec<TurnSummary>,
    record: TurnSummary,
) {
    let insert_at = queue.iter().position(|existing| {
        if existing.order_kind < record.order_kind {
            false
        } else if record.order_kind < existing.order_kind {
            true
        } else {
            rng.next_crt_rand() % 2 == 0
        }
    });
    queue.insert(insert_at.unwrap_or(queue.len()), record);
}

fn pending_military_action_payload(military_power: i32, current_level: i32) -> Option<i16> {
    if (15..40).contains(&military_power) && current_level == 0 {
        Some(1)
    } else if (40..70).contains(&military_power) && current_level < 2 {
        Some(2)
    } else if (70..120).contains(&military_power) && current_level < 3 {
        Some(3)
    } else if (120..170).contains(&military_power) && current_level < 4 {
        Some(4)
    } else if (220..270).contains(&military_power) && current_level < 5 {
        Some(5)
    } else if (270..320).contains(&military_power) && current_level < 6 {
        Some(6)
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecruitmentError {
    #[error("major nation {} has no city", .0.get())]
    MissingCity(MajorNationId),
    #[error("major nation {} has no nation state", .0.get())]
    MissingNation(MajorNationId),
    #[error("city has no valid recruit origin tile")]
    InvalidHomeTile,
    #[error("city's recruit origin has no province")]
    MissingHomeProvince,
    #[error("civilian recruitment uses the civilian path")]
    CivilianOrder,
    #[error("military recruitment uses the specialist path")]
    SpecialistOrder,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Difficulty, LaborPool, MajorNation, MilitaryUnitState, NationCommonState,
        ProductionConstraint, RecruitKind, ResourceCost, ResourceKind, RngState, SkillBand,
        TileState, TurnState, UnitCostProfile, test_support,
    };

    fn tile(owner_nation: Option<crate::TileOwnerTag>) -> TileState {
        TileState {
            terrain_kind: 5,
            owner_nation,
            former_owner_nation: owner_nation,
            province: None,
            development_classes: 0,
            edge_resources: [None; 2],
            rail_flags: 0,
            action_state: -1,
            active_flags: 0,
            region_marker: -1,
            river_sprite_code: 0,
        }
    }

    fn civilian(id: i32, nation: u8, tile: TileId) -> CivilianUnitState {
        CivilianUnitState {
            id: CivilianUnitId::new(id),
            nation: NationId::new(nation),
            unit_type: CivilianUnitKind::Miner,
            tile: Some(tile),
            raw_order_code: 0,
            order_target: -1,
            roster_id: 0,
            registered: false,
            remaining_turns: 0,
        }
    }

    fn world() -> WorldState {
        WorldState {
            wraps_horizontally: true,
            tiles: vec![tile(None); 108 * 60],
        }
    }

    fn game(home_town_tile: TileId) -> GameState {
        let mut game = test_support::game_state();
        game.turn = TurnState {
            scenario_map_index_plus_one: 0,
            economic_turn: 1,
            phase_code: 5,
            difficulty: Difficulty::Easy,
            active_nation: NationId::new(0),
            selected_nation: NationId::new(0),
        };
        game.persistent_unit_id_counter = 40;
        game.world = world();
        game.rng = RngState {
            crt_rand: 1,
            map_generation: 0,
            zone_status: 0,
        };
        game.major_nations = crate::MajorNationTable::default();
        let mut city = test_support::city();
        city.home_town_tile = Some(home_town_tile);
        city.population = crate::PopulationState {
            count: 7,
            count_float_bits: 7.0_f32.to_bits(),
            strength: 7,
            extra: 0,
            phase_value: 0,
            baseline_labor: LaborPool::new(7, 0, 0),
            production_labor: LaborPool::new(7, 0, 0),
            pending_labor_delta: LaborPool::default(),
            predicted_need_by_resource: crate::ResourceTable::default(),
        };
        game.major_nations[MajorNationId::new(0)] = Some(MajorNation {
            common: NationCommonState {
                treasury: 0,
                home_tile: Some(home_town_tile),
                trade_policy_by_nation: crate::NationTable::default(),
            },
            state: test_support::major_nation_state(),
            city: Some(city),
        });
        game
    }

    fn order(unit_kind: CivilianUnitKind, quantity: i16) -> UnitProductionOrder {
        UnitProductionOrder {
            profile: UnitCostProfile {
                recruit_kind: RecruitKind::Civilian(unit_kind),
                primary: ResourceCost {
                    resource: ResourceKind::Paper,
                    per_unit: 1,
                },
                secondary: None,
                cash_per_unit: 0,
                workforce: Some(SkillBand::Low),
            },
            quantity,
            tracking_by_resource: crate::ResourceTable::default(),
            reserved_workforce: 0,
            limiting_constraint: ProductionConstraint::Resources,
            accumulated_value: 0,
        }
    }

    fn specialist_order(unit_kind: MilitaryUnitKind, quantity: i16) -> UnitProductionOrder {
        UnitProductionOrder {
            profile: UnitCostProfile {
                recruit_kind: RecruitKind::Military(unit_kind),
                primary: ResourceCost {
                    resource: ResourceKind::Paper,
                    per_unit: 1,
                },
                secondary: None,
                cash_per_unit: 0,
                workforce: Some(SkillBand::Low),
            },
            quantity,
            tracking_by_resource: crate::ResourceTable::default(),
            reserved_workforce: 0,
            limiting_constraint: ProductionConstraint::Resources,
            accumulated_value: 0,
        }
    }

    fn military_unit(
        id: i32,
        nation: u8,
        unit_type: MilitaryUnitKind,
        province: i16,
    ) -> MilitaryUnitState {
        MilitaryUnitState {
            id: MilitaryUnitId::new(id),
            nation: NationId::new(nation),
            unit_type,
            stationed_province: province,
            raw_order_code: 0,
            order_target: -1,
            roster_id: 0,
            registered: true,
            order_target_tiles: [province; 3],
            order_target_mirrors: [province; 3],
            name: String::new(),
            strength: 500,
            era: unit_type.spawn_era(),
            experience: 0,
            battle_flags: 0,
        }
    }

    #[test]
    fn follows_retail_depth_first_neighbor_order() {
        let mut state = world();
        let geometry = MapGeometry::new(true);
        let start = geometry.tile(2, 10).unwrap();
        let first_neighbor = geometry
            .neighbor(start, crate::HexDirection::NorthEast)
            .unwrap();
        state.tiles[usize::from(start.get())].owner_nation = Some(crate::TileOwnerTag::new(0));
        state.tiles[usize::from(first_neighbor.get())].owner_nation =
            Some(crate::TileOwnerTag::new(0));

        assert_eq!(
            state.find_reachable_recruit_spawn_tile(&[civilian(1, 0, start)], start, false),
            Some(first_neighbor)
        );
    }

    #[test]
    fn active_flag_two_is_allowed_only_for_the_retail_unit_type() {
        let mut state = world();
        let start = TileId::new(200);
        state.tiles[usize::from(start.get())].owner_nation = Some(crate::TileOwnerTag::new(0));
        state.tiles[usize::from(start.get())].active_flags = 2;

        assert_eq!(
            state.find_reachable_recruit_spawn_tile(&[], start, false),
            None
        );
        assert_eq!(
            state.find_reachable_recruit_spawn_tile(&[], start, true),
            Some(start)
        );
    }

    #[test]
    fn occupancy_checks_the_tile_owner_not_an_unrelated_civilian() {
        let mut state = world();
        let start = TileId::new(200);
        state.tiles[usize::from(start.get())].owner_nation = Some(crate::TileOwnerTag::new(0));

        assert_eq!(
            state.find_reachable_recruit_spawn_tile(&[civilian(1, 1, start)], start, false),
            Some(start)
        );
    }

    #[test]
    fn repeated_recruitment_observes_each_newly_occupied_tile() {
        let geometry = MapGeometry::new(true);
        let start = geometry.tile(2, 10).unwrap();
        let first_neighbor = geometry
            .neighbor(start, crate::HexDirection::NorthEast)
            .unwrap();
        let mut state = game(start);
        state.world.tiles[usize::from(start.get())].owner_nation =
            Some(crate::TileOwnerTag::new(0));
        state.world.tiles[usize::from(first_neighbor.get())].owner_nation =
            Some(crate::TileOwnerTag::new(0));
        state.civilian_units.push(civilian(40, 0, start));
        let mut production = order(CivilianUnitKind::Forester, 2);

        state
            .produce_civilian_recruits(MajorNationId::new(0), &mut production)
            .unwrap();

        assert_eq!(state.civilian_units.len(), 2);
        assert_eq!(state.civilian_units[1].tile, Some(first_neighbor));
        assert_eq!(state.civilian_units[1].id, CivilianUnitId::new(41));
        assert_eq!(state.persistent_unit_id_counter, 41);
        assert_eq!(
            state.major_nations[MajorNationId::new(0)]
                .as_ref()
                .unwrap()
                .city
                .as_ref()
                .unwrap()
                .civilian_recruit_count_by_kind[CivilianUnitKind::Forester],
            2
        );
        assert_eq!(production.quantity, 0);
    }

    #[test]
    fn negative_quantity_skips_spawns_but_keeps_retail_tail_effects() {
        let start = TileId::new(200);
        let mut state = game(start);
        state.world.tiles[usize::from(start.get())].owner_nation =
            Some(crate::TileOwnerTag::new(0));
        let mut production = order(CivilianUnitKind::Miner, -2);

        state
            .produce_civilian_recruits(MajorNationId::new(0), &mut production)
            .unwrap();

        assert!(state.civilian_units.is_empty());
        assert_eq!(
            state.major_nations[MajorNationId::new(0)]
                .as_ref()
                .unwrap()
                .city
                .as_ref()
                .unwrap()
                .civilian_recruit_count_by_kind[CivilianUnitKind::Miner],
            -2
        );
        assert_eq!(
            state.major_nations[MajorNationId::new(0)]
                .as_ref()
                .unwrap()
                .city
                .as_ref()
                .unwrap()
                .serialized_state,
            1
        );
        assert_eq!(production.quantity, 0);
    }

    #[test]
    fn specialist_recruitment_builds_the_retail_military_unit_shape() {
        let home_tile = TileId::new(200);
        let mut state = game(home_tile);
        state.world.tiles[usize::from(home_tile.get())].province = Some(crate::ProvinceId::new(17));
        {
            let major = &mut state.major_nations[MajorNationId::new(0)]
                .as_mut()
                .unwrap()
                .state;
            major.pending_action_status[PendingActionKind::ArmyGrowthReward] = 0x32;
            major.pending_action_status[PendingActionKind::ConqueredCapitalArmoryUpgrade] = 0x33;
        }
        let mut production = specialist_order(MilitaryUnitKind::Sappers, 1);

        state
            .produce_specialist_recruits(MajorNationId::new(0), &mut production)
            .unwrap();

        assert_eq!(
            state.military_units,
            vec![MilitaryUnitState {
                id: MilitaryUnitId::new(41),
                nation: NationId::new(0),
                unit_type: MilitaryUnitKind::Sappers,
                stationed_province: 17,
                raw_order_code: 0,
                order_target: -1,
                roster_id: 0,
                registered: true,
                order_target_tiles: [17; 3],
                order_target_mirrors: [17; 3],
                name: String::new(),
                strength: 500,
                era: 3,
                experience: 100,
                battle_flags: 0,
            }]
        );
        assert_eq!(state.persistent_unit_id_counter, 41);
        assert_eq!(production.quantity, 0);
        assert_eq!(
            state.pending.nations[MajorNationId::new(0)].turn_summary,
            vec![TurnSummary {
                turn_tick: 1,
                order_kind: 3,
                payload: 24,
                flags: 1,
            }]
        );
    }

    #[test]
    fn specialist_recruitment_queues_only_the_first_reached_power_threshold() {
        let home_tile = TileId::new(200);
        let mut state = game(home_tile);
        state.world.tiles[usize::from(home_tile.get())].province = Some(crate::ProvinceId::new(17));
        state.military_units = (0..14)
            .map(|index| military_unit(41 + index, 0, MilitaryUnitKind::Skirmishers, 17))
            .collect();
        state.persistent_unit_id_counter = 54;
        let mut production = specialist_order(MilitaryUnitKind::Skirmishers, 2);

        state
            .produce_specialist_recruits(MajorNationId::new(0), &mut production)
            .unwrap();

        assert_eq!(state.selected_military_power_score(NationId::new(0)), 16);
        assert_eq!(state.military_units[14].id, MilitaryUnitId::new(55));
        assert_eq!(state.military_units[15].id, MilitaryUnitId::new(56));
        let major = &state.major_nations[MajorNationId::new(0)]
            .as_ref()
            .unwrap()
            .state;
        assert_eq!(
            major.pending_action_status[PendingActionKind::ArmyGrowthReward],
            0x32
        );
        assert_eq!(
            major.pending_action_payload_by_action[PendingActionKind::ArmyGrowthReward],
            1
        );
    }

    #[test]
    fn military_pending_action_thresholds_preserve_the_retail_gap() {
        for (power, expected) in [
            (14, None),
            (15, Some(1)),
            (39, Some(1)),
            (40, Some(2)),
            (69, Some(2)),
            (70, Some(3)),
            (119, Some(3)),
            (120, Some(4)),
            (169, Some(4)),
            (170, None),
            (219, None),
            (220, Some(5)),
            (269, Some(5)),
            (270, Some(6)),
            (319, Some(6)),
            (320, None),
        ] {
            assert_eq!(pending_military_action_payload(power, 0), expected);
        }
        assert_eq!(pending_military_action_payload(15, 1), None);
        assert_eq!(pending_military_action_payload(40, 2), None);
        assert_eq!(pending_military_action_payload(270, 6), None);
    }

    #[test]
    fn negative_specialist_quantity_runs_only_the_retail_tail() {
        let home_tile = TileId::new(200);
        let mut state = game(home_tile);
        let mut production = specialist_order(MilitaryUnitKind::Minutemen, -2);

        state
            .produce_specialist_recruits(MajorNationId::new(0), &mut production)
            .unwrap();

        assert!(state.military_units.is_empty());
        assert_eq!(
            state.major_nations[MajorNationId::new(0)]
                .as_ref()
                .unwrap()
                .city
                .as_ref()
                .unwrap()
                .serialized_state,
            1
        );
        assert_eq!(
            state.pending.nations[MajorNationId::new(0)].turn_summary,
            vec![TurnSummary {
                turn_tick: 1,
                order_kind: 3,
                payload: 0,
                flags: -2,
            }]
        );
        assert_eq!(production.quantity, 0);
    }
}
