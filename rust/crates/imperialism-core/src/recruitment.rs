use crate::{
    CivilianLocation, CivilianUnitKind, CivilianUnitState, CivilianWorkOrder, Difficulty,
    GameState, MajorNationId, MapMgr, MilitaryUnitKind, MilitaryUnitState, NationId,
    PendingActionKind, ShipType, TileFlags, TileId, TileOwnerTag, TurnSummary,
};
#[cfg(test)]
use crate::{CivilianUnitId, MilitaryUnitId};

impl MapMgr {
    pub fn find_reachable_recruit_spawn_tile(
        &mut self,
        civilians: &[CivilianUnitState],
        start: TileId,
        allow_active_flag_2: bool,
    ) -> Option<TileId> {
        let owner = self[start].owner_nation;
        let geometry = self.geometry();
        for index in 0..TileId::COUNT {
            self[TileId::new(index)].recruit_search_visited = 0;
        }
        let mut pending = vec![start];

        while let Some(tile_id) = pending.pop() {
            if self[tile_id].recruit_search_visited != 0 {
                continue;
            }
            self[tile_id].recruit_search_visited = 1;
            if self[tile_id].owner_nation != owner {
                continue;
            }

            let occupied = civilians.iter().any(|civilian| {
                civilian.location.tile() == Some(tile_id)
                    && Some(civilian.owner_nation) == owner.and_then(TileOwnerTag::nation)
            });
            if !occupied
                && (!self[tile_id]
                    .flags
                    .contains(TileFlags::RECRUITMENT_RESERVED)
                    || allow_active_flag_2)
            {
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
            .map(|unit| unit.unit_type.arms_required())
            .sum()
    }

    pub fn produce_civilian_recruits(
        &mut self,
        nation: MajorNationId,
        unit_kind: CivilianUnitKind,
        pending_delta: i16,
    ) {
        let nation_id = nation.nation();
        if pending_delta == 0 {
            return;
        }
        let home_tile = self
            .nations
            .major(nation)
            .common
            .home_tile
            .expect("civilian recruit production requires a home town tile");

        let metric = &mut self.nations.city_mut(nation).civilian_recruit_count_by_kind[unit_kind];
        *metric += pending_delta;

        if pending_delta > 0 {
            for _ in 0..pending_delta {
                let Some(tile) = self.map.find_reachable_recruit_spawn_tile(
                    &self.civilian_units,
                    home_tile,
                    unit_kind == CivilianUnitKind::Engineer,
                ) else {
                    continue;
                };
                self.insert_idle_civilian(nation_id, unit_kind, CivilianLocation::OnMap(tile));
            }
        }

        if unit_kind == CivilianUnitKind::Miner {
            let city = self.nations.city_mut(nation);
            city.serialized_state += 1;
        }
    }

    /// Opening-turn civilian grant from `TGreatPower::SetHomeCityTileAndDisplayName`.
    pub(crate) fn grant_opening_civilians(&mut self) {
        if self.turn.scenario_map.is_some() {
            return;
        }
        for index in 0..MajorNationId::COUNT {
            self.grant_opening_civilians_for_nation(MajorNationId::new(index));
        }
    }

    /// One nation's prospector/engineer pair, plus the Introductory human extras.
    pub fn grant_opening_civilians_for_nation(&mut self, nation: MajorNationId) {
        if self.nations.major(nation).common.home_tile.is_none() {
            return;
        }
        self.spawn_opening_civilian(nation, CivilianUnitKind::Prospector, false);
        self.spawn_opening_civilian(nation, CivilianUnitKind::Engineer, true);
        self.nations.city_mut(nation).ship_order_count_by_type[ShipType::Trader] += 2;
        if self.turn.difficulty == Difficulty::Introductory
            && self.nations.major(nation).economy.diplomacy_eligible
        {
            self.nations.city_mut(nation).ship_order_count_by_type[ShipType::Trader] += 6;
            self.spawn_opening_civilian(nation, CivilianUnitKind::Prospector, false);
            self.spawn_opening_civilian(nation, CivilianUnitKind::Miner, false);
            self.spawn_opening_civilian(nation, CivilianUnitKind::Farmer, false);
        }
    }

    fn spawn_opening_civilian(
        &mut self,
        nation: MajorNationId,
        kind: CivilianUnitKind,
        allow_reserved: bool,
    ) {
        let nation_id = nation.nation();
        let home = self
            .nations
            .major(nation)
            .common
            .home_tile
            .expect("opening civilians require a home town tile");
        let location = self
            .map
            .find_reachable_recruit_spawn_tile(&self.civilian_units, home, allow_reserved)
            .map(CivilianLocation::OnMap)
            .unwrap_or(CivilianLocation::OffMap);
        self.insert_idle_civilian(nation_id, kind, location);
    }

    fn insert_idle_civilian(
        &mut self,
        nation_id: NationId,
        kind: CivilianUnitKind,
        location: CivilianLocation,
    ) {
        let id = self.unit_ids.next_civilian();
        let unit = CivilianUnitState {
            id,
            nation: nation_id,
            unit_type: kind,
            location,
            order: CivilianWorkOrder::Idle,
            owner_nation: nation_id,
            roster_id: 0,
            registered: false,
            next_on_tile: None,
        };
        let insert_at = self
            .civilian_units
            .partition_point(|existing| existing.nation.get() <= nation_id.get());
        self.civilian_units.insert(insert_at, unit);
    }

    pub fn produce_military_recruits(
        &mut self,
        nation: MajorNationId,
        unit_kind: MilitaryUnitKind,
        pending_delta: i16,
    ) {
        let nation_id = nation.nation();
        if pending_delta == 0 {
            return;
        }
        let major_nation = &self.nations.majors[nation];
        let major = &major_nation.economy;
        let military_start = if pending_delta > 0 {
            let home_tile = major_nation
                .common
                .home_tile
                .expect("military recruit production requires a home town tile");
            let province = self.map[home_tile]
                .province
                .expect("military recruit production requires the home town's province");
            let action_6 =
                major.pending_actions[PendingActionKind::ConqueredCapitalArmoryUpgrade].status();
            Some((
                province,
                action_6.has_reached(crate::PendingActionStatus::Level3),
            ))
        } else {
            None
        };

        if let Some((home_province, experienced)) = military_start {
            for _ in 0..pending_delta {
                let id = self.unit_ids.next_military();
                let experience = if experienced { 100 } else { 0 };
                let unit = MilitaryUnitState {
                    id,
                    nation: nation_id,
                    unit_type: unit_kind,
                    stationed_province: Some(home_province),
                    order: crate::MilitaryOrder::idle(
                        [Some(home_province); 3],
                        [Some(home_province); 3],
                    ),
                    owner_nation: nation_id,
                    roster_id: 0,
                    registered: true,
                    name: String::new(),
                    strength: 500,
                    era: unit_kind.spawn_era(),
                    experience,
                    battle_flags: 0,
                };
                let insert_at = self
                    .military_units
                    .partition_point(|existing| existing.nation.get() <= nation_id.get());
                self.military_units.insert(insert_at, unit);

                let pending = self.nations.majors[nation].economy.pending_actions
                    [PendingActionKind::ArmyGrowthReward];
                if let Some(current_level) = pending.level() {
                    let military_power = self.selected_military_power_score(nation_id);
                    if let Some(payload) =
                        pending_military_action_payload(military_power, i32::from(current_level))
                    {
                        let major = &mut self.nations.majors[nation].economy;
                        major.pending_actions[PendingActionKind::ArmyGrowthReward].queue(payload);
                    }
                }
            }
        }

        insert_turn_summary(
            &mut self.rng,
            &mut self.pending.nations[nation].turn_summary,
            TurnSummary::MilitaryRecruit {
                turn_tick: self.turn.economic_turn,
                unit_type: unit_kind,
                count: pending_delta,
            },
        );
        if unit_kind == MilitaryUnitKind::Minutemen {
            let city = self.nations.city_mut(nation);
            city.serialized_state += 1;
        }
    }
}

pub(crate) fn insert_turn_summary(
    rng: &mut crate::RngState,
    queue: &mut Vec<TurnSummary>,
    record: TurnSummary,
) {
    let insert_at = queue.iter().position(|existing| {
        if existing.order_key() < record.order_key() {
            false
        } else if record.order_key() < existing.order_key() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CityState, LaborPool, MapGeometry, MapTopology, MilitaryUnitState, PopulationState,
        RetailCrtRng, RetailLcg, RngState, TileState,
    };

    fn tile(owner_nation: Option<crate::TileOwnerTag>) -> TileState {
        TileState {
            terrain: crate::TerrainKind::Water,
            rendering: Default::default(),
            owner_nation,
            former_owner_nation: owner_nation,
            secondary_owner_nation: None,
            owner_border_mask: 0,
            city_border_mask: 0,
            water_adjacency_mask: 0,
            province: None,
            gate: 0,
            recruit_search_visited: 0,
            per_tile_visited: 0,
            marker_slot_index: -1,
            tile_action_ordinal: -1,
            development: Default::default(),
            edge_resources: [None; 2],
            transport_links: Default::default(),
            pending_rail_links: Default::default(),
            action: None,
            flags: TileFlags::empty(),
            region: None,
        }
    }

    fn civilian(id: i32, nation: u8, tile: TileId) -> CivilianUnitState {
        CivilianUnitState {
            id: CivilianUnitId::new(id),
            nation: NationId::new(nation),
            unit_type: CivilianUnitKind::Miner,
            location: crate::CivilianLocation::OnMap(tile),
            order: CivilianWorkOrder::Idle,
            owner_nation: NationId::new(nation),
            roster_id: 0,
            registered: false,
            next_on_tile: None,
        }
    }

    fn world() -> MapMgr {
        MapMgr::new(MapTopology::Wrapping, vec![tile(None); 108 * 60])
    }

    fn city() -> CityState {
        CityState {
            population: PopulationState {
                count: 7,
                accumulator: crate::PopulationAccumulator::from_bits(7.0_f32.to_bits()),
                strength: 7,
                extra: 0,
                strike_phase: crate::StrikePhase::default(),
                baseline_labor: LaborPool::new(7, 0, 0),
                production_labor: LaborPool::new(7, 0, 0),
                pending_labor_delta: LaborPool::default(),
                predicted_need_by_resource: crate::ResourceTable::default(),
            },
            ..crate::test_support::city()
        }
    }

    fn game(home_town_tile: TileId) -> GameState {
        let mut nation = crate::test_support::major_nation();
        nation.common.treasury = 0;
        nation.common.home_tile = Some(home_town_tile);
        nation.city = city();
        nation.towns = vec![crate::TownState::for_frog_city(
            home_town_tile,
            MajorNationId::new(0).nation(),
        )];
        let mut state = crate::test_support::game_state();
        state.unit_ids = crate::UnitIdAllocator::from_retail(40);
        state.map = world();
        state.rng = RngState {
            crt_rand: RetailCrtRng::from_state(1),
            map_generation: RetailLcg::from_state(0),
            zone_status: RetailLcg::from_state(0),
        };
        state.nations.majors[MajorNationId::new(0)] = nation;
        state
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
            stationed_province: u16::try_from(province)
                .ok()
                .and_then(crate::ProvinceId::try_new),
            order: crate::MilitaryOrder::idle(
                [u16::try_from(province)
                    .ok()
                    .and_then(crate::ProvinceId::try_new); 3],
                [u16::try_from(province)
                    .ok()
                    .and_then(crate::ProvinceId::try_new); 3],
            ),
            owner_nation: NationId::new(nation),
            roster_id: 0,
            registered: true,
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
        let geometry = MapGeometry::new(MapTopology::Wrapping);
        let start = geometry.tile(2, 10).unwrap();
        let first_neighbor = geometry
            .neighbor(start, crate::HexDirection::NorthEast)
            .unwrap();
        state[start].owner_nation = Some(crate::TileOwnerTag::new(0));
        state[first_neighbor].owner_nation = Some(crate::TileOwnerTag::new(0));

        assert_eq!(
            state.find_reachable_recruit_spawn_tile(&[civilian(1, 0, start)], start, false),
            Some(first_neighbor)
        );
    }

    #[test]
    fn active_flag_two_is_allowed_only_for_the_retail_unit_type() {
        let mut state = world();
        let start = TileId::new(200);
        state[start].owner_nation = Some(crate::TileOwnerTag::new(0));
        state[start].flags = TileFlags::RECRUITMENT_RESERVED;

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
        state[start].owner_nation = Some(crate::TileOwnerTag::new(0));

        assert_eq!(
            state.find_reachable_recruit_spawn_tile(&[civilian(1, 1, start)], start, false),
            Some(start)
        );
    }

    #[test]
    fn repeated_recruitment_observes_each_newly_occupied_tile() {
        let geometry = MapGeometry::new(MapTopology::Wrapping);
        let start = geometry.tile(2, 10).unwrap();
        let first_neighbor = geometry
            .neighbor(start, crate::HexDirection::NorthEast)
            .unwrap();
        let mut state = game(start);
        state.map[start].owner_nation = Some(crate::TileOwnerTag::new(0));
        state.map[first_neighbor].owner_nation = Some(crate::TileOwnerTag::new(0));
        state.civilian_units.push(civilian(40, 0, start));
        state.produce_civilian_recruits(MajorNationId::new(0), CivilianUnitKind::Forester, 2);

        assert_eq!(state.civilian_units.len(), 2);
        assert_eq!(
            state.civilian_units[1].location.tile(),
            Some(first_neighbor)
        );
        assert_eq!(state.civilian_units[1].id, CivilianUnitId::new(41));
        assert_eq!(state.unit_ids.current(), 41);
        assert_eq!(
            state
                .nations
                .city(MajorNationId::new(0))
                .civilian_recruit_count_by_kind[CivilianUnitKind::Forester],
            2
        );
    }

    #[test]
    fn negative_quantity_skips_spawns_but_keeps_retail_tail_effects() {
        let start = TileId::new(200);
        let mut state = game(start);
        state.map[start].owner_nation = Some(crate::TileOwnerTag::new(0));
        state.produce_civilian_recruits(MajorNationId::new(0), CivilianUnitKind::Miner, -2);

        assert!(state.civilian_units.is_empty());
        assert_eq!(
            state
                .nations
                .city(MajorNationId::new(0))
                .civilian_recruit_count_by_kind[CivilianUnitKind::Miner],
            -2
        );
        assert_eq!(
            state.nations.city(MajorNationId::new(0)).serialized_state,
            1
        );
    }

    #[test]
    fn military_recruitment_queues_only_the_first_reached_power_threshold() {
        let home_tile = TileId::new(200);
        let mut state = game(home_tile);
        state.map[home_tile].province = Some(crate::ProvinceId::new(17));
        state.military_units = (0..14)
            .map(|index| military_unit(41 + index, 0, MilitaryUnitKind::Skirmishers, 17))
            .collect();
        state.unit_ids = crate::UnitIdAllocator::from_retail(54);
        state.produce_military_recruits(MajorNationId::new(0), MilitaryUnitKind::Skirmishers, 2);

        assert_eq!(state.selected_military_power_score(NationId::new(0)), 16);
        assert_eq!(state.military_units[14].id, MilitaryUnitId::new(55));
        assert_eq!(state.military_units[15].id, MilitaryUnitId::new(56));
        let major = &state.nations.major(MajorNationId::new(0)).economy;
        assert_eq!(
            major.pending_actions[PendingActionKind::ArmyGrowthReward].status(),
            crate::PendingActionStatus::Queued
        );
        assert_eq!(
            major.pending_actions[PendingActionKind::ArmyGrowthReward].payload(),
            Some(1)
        );
    }

    #[test]
    fn military_recruitment_uses_pending_status_not_payload_as_the_growth_level() {
        let home_tile = TileId::new(200);
        let mut state = game(home_tile);
        state.map[home_tile].province = Some(crate::ProvinceId::new(17));
        state.military_units = (0..14)
            .map(|index| military_unit(41 + index, 0, MilitaryUnitKind::Skirmishers, 17))
            .collect();
        state.unit_ids = crate::UnitIdAllocator::from_retail(54);
        state
            .nations
            .major_mut(MajorNationId::new(0))
            .economy
            .pending_actions[PendingActionKind::ArmyGrowthReward] =
            crate::PendingActionState::new(crate::PendingActionStatus::Level3, Some(6));
        state.produce_military_recruits(MajorNationId::new(0), MilitaryUnitKind::Skirmishers, 1);

        let pending = state
            .nations
            .major(MajorNationId::new(0))
            .economy
            .pending_actions[PendingActionKind::ArmyGrowthReward];
        assert_eq!(pending.status(), crate::PendingActionStatus::Queued);
        assert_eq!(pending.payload(), Some(1));
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
    fn negative_military_quantity_runs_only_the_retail_tail() {
        let home_tile = TileId::new(200);
        let mut state = game(home_tile);
        state.produce_military_recruits(MajorNationId::new(0), MilitaryUnitKind::Minutemen, -2);

        assert!(state.military_units.is_empty());
        assert_eq!(
            state.nations.city(MajorNationId::new(0)).serialized_state,
            1
        );
        assert_eq!(
            state.pending.nations[MajorNationId::new(0)].turn_summary,
            vec![TurnSummary::MilitaryRecruit {
                turn_tick: 1,
                unit_type: MilitaryUnitKind::Minutemen,
                count: -2,
            }]
        );
    }
}
