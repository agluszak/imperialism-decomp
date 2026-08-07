use crate::{
    CivilianUnitId, CivilianUnitState, GameEvent, GameState, MapGeometry, MilitaryUnitId,
    MilitaryUnitState, NationId, StepOutcome, TileId, UnitProductionOrder, WorldState,
};
use std::error::Error;
use std::fmt;

const MILITARY_POWER_BY_UNIT_TYPE: [i16; 30] = [
    0, 1, 1, 1, 1, 1, 2, 2, 0, 2, 2, 2, 2, 2, 4, 4, 0, 4, 4, 4, 4, 10, 6, 8, 2, 2, 3, 0, 0, 0,
];

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
                civilian.tile == Some(tile_id) && i64::from(civilian.owner_nation) == owner
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
    pub fn selected_military_power_score(&self, nation: NationId) -> Result<i32, RecruitmentError> {
        self.military_units
            .iter()
            .filter(|unit| unit.nation == nation)
            .try_fold(0_i32, |power, unit| {
                let unit_type = usize::try_from(unit.unit_type)
                    .map_err(|_| RecruitmentError::InvalidMilitaryUnitType(unit.unit_type))?;
                let contribution = MILITARY_POWER_BY_UNIT_TYPE
                    .get(unit_type)
                    .copied()
                    .ok_or(RecruitmentError::InvalidMilitaryUnitType(unit.unit_type))?;
                Ok(power.wrapping_add(i32::from(contribution)))
            })
    }

    pub fn produce_civilian_recruits(
        &mut self,
        nation: NationId,
        order: &mut UnitProductionOrder,
    ) -> Result<StepOutcome, RecruitmentError> {
        let pending_delta = order.quantity;
        if pending_delta == 0 {
            return Ok(StepOutcome::default());
        }
        if order.profile.specialist {
            return Err(RecruitmentError::SpecialistOrder);
        }

        let entry_index = usize::try_from(order.profile.entry_id)
            .map_err(|_| RecruitmentError::InvalidEntryId(order.profile.entry_id))?;
        let city_index = usize::from(nation.get());
        let city = self
            .cities
            .get(city_index)
            .and_then(Option::as_ref)
            .ok_or(RecruitmentError::MissingCity(nation))?;
        if entry_index >= city.metrics_4a.len() {
            return Err(RecruitmentError::InvalidEntryId(order.profile.entry_id));
        }
        let home_tile = u16::try_from(city.home_town_tile)
            .ok()
            .filter(|tile| usize::from(*tile) < self.world.tiles.len())
            .map(TileId::new)
            .ok_or(RecruitmentError::InvalidHomeTile(city.home_town_tile))?;

        let metric = &mut self.cities[city_index]
            .as_mut()
            .expect("city presence was checked")
            .metrics_4a[entry_index];
        *metric = metric.wrapping_add(pending_delta);

        let mut events = Vec::new();
        if pending_delta > 0 {
            for _ in 0..pending_delta {
                let Some(tile) = self.world.find_reachable_recruit_spawn_tile(
                    &self.civilian_units,
                    home_tile,
                    order.profile.entry_id == 4,
                ) else {
                    continue;
                };
                self.persistent_unit_id_counter = self.persistent_unit_id_counter.wrapping_add(1);
                let id = CivilianUnitId::new(self.persistent_unit_id_counter as u32);
                let roster_index = self
                    .civilian_units
                    .iter()
                    .filter(|unit| unit.nation == nation)
                    .count() as u32;
                let unit = CivilianUnitState {
                    id,
                    nation,
                    roster_index,
                    unit_type: order.profile.entry_id,
                    tile: Some(tile),
                    order: 0,
                    order_target: -1,
                    owner_nation: i16::from(nation.get()),
                    roster_id: 0,
                    registered: false,
                    remaining_turns: 0,
                };
                let insert_at = self
                    .civilian_units
                    .iter()
                    .position(|existing| existing.nation.get() > nation.get())
                    .unwrap_or(self.civilian_units.len());
                self.civilian_units.insert(insert_at, unit);
                events.push(GameEvent::CivilianUnitRecruited {
                    id,
                    nation,
                    unit_type: order.profile.entry_id,
                    tile,
                });
            }
        }

        events.push(GameEvent::RecruitmentAnnounced {
            nation,
            specialist: false,
            unit_type: order.profile.entry_id,
            requested: pending_delta,
        });
        order.quantity = 0;
        if order.profile.entry_id == 0 {
            let city = self.cities[city_index]
                .as_mut()
                .expect("city presence was checked");
            city.serialized_state = city.serialized_state.wrapping_add(1);
        }
        Ok(StepOutcome { events })
    }

    pub fn produce_specialist_recruits(
        &mut self,
        nation: NationId,
        order: &mut UnitProductionOrder,
    ) -> Result<StepOutcome, RecruitmentError> {
        let pending_delta = order.quantity;
        if pending_delta == 0 {
            return Ok(StepOutcome::default());
        }
        if !order.profile.specialist {
            return Err(RecruitmentError::CivilianOrder);
        }

        let unit_type = usize::try_from(order.profile.entry_id)
            .map_err(|_| RecruitmentError::InvalidMilitaryUnitType(order.profile.entry_id))?;
        if unit_type >= MILITARY_POWER_BY_UNIT_TYPE.len() {
            return Err(RecruitmentError::InvalidMilitaryUnitType(
                order.profile.entry_id,
            ));
        }
        let nation_index = usize::from(nation.get());
        let city = self
            .cities
            .get(nation_index)
            .and_then(Option::as_ref)
            .ok_or(RecruitmentError::MissingCity(nation))?;
        let major = self
            .nations
            .get(nation_index)
            .and_then(Option::as_ref)
            .ok_or(RecruitmentError::MissingNation(nation))?
            .major
            .as_ref()
            .ok_or(RecruitmentError::NotMajorNation(nation))?;
        let pending_nation_index = self
            .pending
            .nations
            .iter()
            .position(|pending| pending.nation == nation)
            .ok_or(RecruitmentError::MissingPendingNation(nation))?;

        let (home_province, experienced) = if pending_delta > 0 {
            let home_tile = u16::try_from(city.home_town_tile)
                .ok()
                .filter(|tile| usize::from(*tile) < self.world.tiles.len())
                .map(TileId::new)
                .ok_or(RecruitmentError::InvalidHomeTile(city.home_town_tile))?;
            let province = i16::try_from(
                self.world.tiles[usize::from(home_tile.get())].city_or_province_index,
            )
            .map_err(|_| {
                RecruitmentError::InvalidHomeProvince(
                    self.world.tiles[usize::from(home_tile.get())].city_or_province_index,
                )
            })?;
            let action_6 = *major
                .pending_action_status
                .get(6)
                .ok_or(RecruitmentError::MissingPendingAction(6))?;
            major
                .pending_action_status
                .get(1)
                .ok_or(RecruitmentError::MissingPendingAction(1))?;
            major
                .pending_action_payload_by_action
                .get(1)
                .ok_or(RecruitmentError::MissingPendingActionPayload(1))?;
            self.selected_military_power_score(nation)?;
            (province, action_6 >= 0x33)
        } else {
            (0, false)
        };

        let mut events = Vec::new();
        if pending_delta > 0 {
            for _ in 0..pending_delta {
                self.persistent_unit_id_counter = self.persistent_unit_id_counter.wrapping_add(1);
                let id = MilitaryUnitId::new(self.persistent_unit_id_counter as u32);
                let roster_index = self
                    .military_units
                    .iter()
                    .filter(|unit| unit.nation == nation)
                    .count() as u32;
                let experience = if experienced { 100 } else { 0 };
                let unit = MilitaryUnitState {
                    id,
                    nation,
                    roster_index,
                    unit_type: order.profile.entry_id,
                    stationed_province: home_province,
                    order: 0,
                    order_target: -1,
                    owner_nation: i16::from(nation.get()),
                    roster_id: 0,
                    registered: true,
                    order_target_tiles: [home_province; 3],
                    order_target_mirrors: [home_province; 3],
                    name: String::new(),
                    strength: 500,
                    era: order.profile.entry_id / 8,
                    experience,
                    battle_flags: 0,
                };
                let insert_at = self
                    .military_units
                    .iter()
                    .position(|existing| existing.nation.get() > nation.get())
                    .unwrap_or(self.military_units.len());
                self.military_units.insert(insert_at, unit);
                events.push(GameEvent::MilitaryUnitRecruited {
                    id,
                    nation,
                    unit_type: order.profile.entry_id,
                    province: home_province,
                    experience,
                });

                self.selected_military_power_score(nation)?;
                let pending_status = self.nations[nation_index]
                    .as_ref()
                    .expect("nation presence was checked")
                    .major
                    .as_ref()
                    .expect("major-nation presence was checked")
                    .pending_action_status[1];
                if pending_status != 0x32 {
                    let current_level = if pending_status == 0 {
                        0
                    } else {
                        i32::from(pending_status) - 0x33
                    };
                    let military_power = self.selected_military_power_score(nation)?;
                    if let Some(payload) =
                        pending_military_action_payload(military_power, current_level)
                    {
                        let major = self.nations[nation_index]
                            .as_mut()
                            .expect("nation presence was checked")
                            .major
                            .as_mut()
                            .expect("major-nation presence was checked");
                        major.pending_action_status[1] = 0x32;
                        major.pending_action_payload_by_action[1] = payload;
                        events.push(GameEvent::NationPendingActionQueued {
                            nation,
                            action: 1,
                            payload,
                        });
                    }
                }
            }
        }

        events.push(GameEvent::RecruitmentAnnounced {
            nation,
            specialist: true,
            unit_type: order.profile.entry_id,
            requested: pending_delta,
        });
        insert_turn_summary(
            &mut self.rng,
            &mut self.pending.nations[pending_nation_index].turn_summary,
            [
                self.turn.economic_turn,
                3,
                order.profile.entry_id,
                pending_delta,
            ],
        );
        order.quantity = 0;
        if order.profile.entry_id == 0 {
            let city = self.cities[nation_index]
                .as_mut()
                .expect("city presence was checked");
            city.serialized_state = city.serialized_state.wrapping_add(1);
        }
        Ok(StepOutcome { events })
    }
}

fn insert_turn_summary(rng: &mut crate::RngState, queue: &mut Vec<[i16; 4]>, record: [i16; 4]) {
    let insert_at = queue.iter().position(|existing| {
        if existing[1] < record[1] {
            false
        } else if record[1] < existing[1] {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecruitmentError {
    MissingCity(NationId),
    MissingNation(NationId),
    NotMajorNation(NationId),
    MissingPendingNation(NationId),
    InvalidEntryId(i16),
    InvalidMilitaryUnitType(i16),
    InvalidHomeTile(i16),
    InvalidHomeProvince(i64),
    MissingPendingAction(usize),
    MissingPendingActionPayload(usize),
    CivilianOrder,
    SpecialistOrder,
}

impl fmt::Display for RecruitmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCity(nation) => {
                write!(formatter, "nation {} has no city", nation.get())
            }
            Self::MissingNation(nation) => {
                write!(formatter, "nation {} has no nation state", nation.get())
            }
            Self::NotMajorNation(nation) => {
                write!(
                    formatter,
                    "nation {} has no major-nation state",
                    nation.get()
                )
            }
            Self::MissingPendingNation(nation) => {
                write!(
                    formatter,
                    "nation {} has no pending-work state",
                    nation.get()
                )
            }
            Self::InvalidEntryId(entry) => write!(formatter, "invalid civilian unit type {entry}"),
            Self::InvalidMilitaryUnitType(entry) => {
                write!(formatter, "invalid military unit type {entry}")
            }
            Self::InvalidHomeTile(tile) => write!(formatter, "invalid recruit origin tile {tile}"),
            Self::InvalidHomeProvince(province) => {
                write!(formatter, "invalid recruit home province {province}")
            }
            Self::MissingPendingAction(action) => {
                write!(formatter, "missing pending-action state {action}")
            }
            Self::MissingPendingActionPayload(action) => {
                write!(formatter, "missing pending-action payload {action}")
            }
            Self::CivilianOrder => {
                write!(formatter, "civilian recruitment uses the civilian path")
            }
            Self::SpecialistOrder => {
                write!(formatter, "military recruitment uses the specialist path")
            }
        }
    }
}

impl Error for RecruitmentError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CityState, LaborPool, MajorNationState, MilitaryUnitState, NationKind, NationState,
        PopulationState, ProductionConstraint, ResourceCost, ResourceKind, RngState, SkillBand,
        TileState, TurnState, UnitCostProfile,
    };

    fn tile(owner_nation: i64) -> TileState {
        TileState {
            terrain_kind: 5,
            owner_nation,
            former_owner_nation: owner_nation,
            city_or_province_index: -1,
            development_classes: 0,
            edge_resources: [-1; 2],
            rail_flags: 0,
            action_state: -1,
            active_flags: 0,
        }
    }

    fn civilian(id: u32, nation: u8, tile: TileId) -> CivilianUnitState {
        CivilianUnitState {
            id: CivilianUnitId::new(id),
            nation: NationId::new(nation),
            roster_index: 0,
            unit_type: 0,
            tile: Some(tile),
            order: 0,
            order_target: -1,
            owner_nation: i16::from(nation),
            roster_id: 0,
            registered: false,
            remaining_turns: 0,
        }
    }

    fn world() -> WorldState {
        WorldState {
            width: 108,
            height: 60,
            wraps_horizontally: true,
            tiles: vec![tile(-1); 108 * 60],
        }
    }

    fn city(nation: NationId, home_town_tile: i16) -> CityState {
        CityState {
            nation,
            power_plant_upgrade_queued: false,
            food_substitution_count: 0,
            starvation_population_loss: 0,
            serialized_state: 0,
            phase_counter: 0,
            metrics_0e: vec![0; 30],
            metrics_4a: vec![0; 9],
            order_count_by_type: vec![0; 14],
            rolling_item_production_score: 0,
            low_production: false,
            low_stock: false,
            reserved_by_type: vec![0; ResourceKind::COUNT],
            home_town_tile,
            power_available: 0,
            stock_by_type: vec![0; ResourceKind::COUNT],
            production_orders: vec![0; 16],
            production_accum: vec![0; 16],
            production_flags: vec![0; 16],
            production_current: vec![0; 16],
            production_progress: vec![0; 16],
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: vec![0; ResourceKind::COUNT],
            consumed_production_input_by_type: vec![0; ResourceKind::COUNT],
            population: PopulationState {
                count: 7,
                count_float_bits: 7.0_f32.to_bits(),
                strength: 7,
                extra: 0,
                phase_value: 0,
                baseline_labor: Some(LaborPool::new(7, 0, 0)),
                production_labor: Some(LaborPool::new(7, 0, 0)),
                pending_labor_delta: Some(LaborPool::default()),
                predicted_need_by_resource: vec![0; ResourceKind::COUNT],
            },
        }
    }

    fn game(home_town_tile: TileId) -> GameState {
        let nation = NationId::new(0);
        let mut cities = vec![None; 7];
        cities[0] = Some(city(nation, home_town_tile.get() as i16));
        let mut nations = vec![None; 23];
        nations[0] = Some(NationState {
            id: nation,
            kind: NationKind::Major,
            encoded_nation_slot: 0,
            owner_nation: 0,
            treasury: 0,
            home_tile: i32::from(home_town_tile.get()),
            need_level_by_nation: vec![0; 23],
            major: Some(MajorNationState {
                diplomacy_eligible: true,
                capacities: [0; 4],
                grant_total_cost: 0,
                unfilled_trade_offer_count: 0,
                diplomacy_policy_by_nation: vec![0; 23],
                diplomacy_grant_by_nation: vec![0; 23],
                need_current_by_type: vec![0; ResourceKind::COUNT],
                need_target_by_type: vec![0; ResourceKind::COUNT],
                relation_delta_current: vec![0; 23],
                purchased_items_by_resource: vec![0; ResourceKind::COUNT],
                item_potentials: vec![0; ResourceKind::COUNT],
                unfilled_trade_turns_by_resource: vec![0; ResourceKind::COUNT],
                transported_items_by_resource: vec![0; ResourceKind::COUNT],
                remembered_trade_offers_by_resource: vec![0; ResourceKind::COUNT],
                aid_allocation_matrix: vec![0; 23 * 23],
                budget_pool_base: 0,
                budget_pool_delta: 0,
                special_resource_trade_balance: 0,
                candidate_nation_flags: vec![0; 23],
                scenario_initialized: false,
                turn_finished: false,
                pending_action_status: vec![0; 13],
                pending_action_payload_by_action: vec![0; 13],
                diplomacy_budget_base: 0,
                escalation_counter: 0,
                pending_commitment_cost: 0,
                pressure_counter: 0,
                aid_allocation_total: 0,
                colony_boycott_flags: vec![0; 23],
                military_expenses: 0,
            }),
        });
        GameState {
            turn: TurnState {
                scenario_map_index_plus_one: 0,
                economic_turn: 1,
                phase_code: 5,
                difficulty: 1,
                active_nation: 0,
                selected_nation: 0,
            },
            persistent_unit_id_counter: 40,
            world: world(),
            rng: RngState {
                crt_rand: 1,
                map_generation: 0,
                zone_status: 0,
            },
            nations,
            cities,
            military_units: Vec::new(),
            civilian_units: Vec::new(),
            ships: Vec::new(),
            task_forces: Vec::new(),
            missions: Vec::new(),
            pending: crate::PendingWorkState {
                turn_flow_status_flags: 0,
                nations: (0..7)
                    .map(|nation| crate::NationPendingWork {
                        nation: NationId::new(nation),
                        turn_events: Vec::new(),
                        proposals: Vec::new(),
                        turn_summary: Vec::new(),
                        turn_start_events: Vec::new(),
                    })
                    .collect(),
                war_transitions: Vec::new(),
            },
        }
    }

    fn order(entry_id: i16, quantity: i16) -> UnitProductionOrder {
        UnitProductionOrder {
            profile: UnitCostProfile {
                entry_id,
                primary: ResourceCost {
                    resource: ResourceKind::Paper,
                    per_unit: 1,
                },
                secondary: None,
                cash_per_unit: 0,
                workforce: Some(SkillBand::Low),
                specialist: false,
            },
            quantity,
            tracking_by_resource: [0; ResourceKind::COUNT],
            reserved_workforce: 0,
            limiting_constraint: ProductionConstraint::Resources,
            accumulated_value: 0,
        }
    }

    fn specialist_order(entry_id: i16, quantity: i16) -> UnitProductionOrder {
        let mut order = order(entry_id, quantity);
        order.profile.specialist = true;
        order
    }

    fn military_unit(id: u32, nation: u8, unit_type: i16, province: i16) -> MilitaryUnitState {
        MilitaryUnitState {
            id: MilitaryUnitId::new(id),
            nation: NationId::new(nation),
            roster_index: 0,
            unit_type,
            stationed_province: province,
            order: 0,
            order_target: -1,
            owner_nation: i16::from(nation),
            roster_id: 0,
            registered: true,
            order_target_tiles: [province; 3],
            order_target_mirrors: [province; 3],
            name: String::new(),
            strength: 500,
            era: unit_type / 8,
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
        state.tiles[usize::from(start.get())].owner_nation = 0;
        state.tiles[usize::from(first_neighbor.get())].owner_nation = 0;

        assert_eq!(
            state.find_reachable_recruit_spawn_tile(&[civilian(1, 0, start)], start, false),
            Some(first_neighbor)
        );
    }

    #[test]
    fn active_flag_two_is_allowed_only_for_the_retail_unit_type() {
        let mut state = world();
        let start = TileId::new(200);
        state.tiles[usize::from(start.get())].owner_nation = 0;
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
        state.tiles[usize::from(start.get())].owner_nation = 0;

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
        state.world.tiles[usize::from(start.get())].owner_nation = 0;
        state.world.tiles[usize::from(first_neighbor.get())].owner_nation = 0;
        state.civilian_units.push(civilian(40, 0, start));
        let mut production = order(3, 2);

        let outcome = state
            .produce_civilian_recruits(NationId::new(0), &mut production)
            .unwrap();

        assert_eq!(state.civilian_units.len(), 2);
        assert_eq!(state.civilian_units[1].tile, Some(first_neighbor));
        assert_eq!(state.civilian_units[1].id, CivilianUnitId::new(41));
        assert_eq!(state.persistent_unit_id_counter, 41);
        assert_eq!(state.cities[0].as_ref().unwrap().metrics_4a[3], 2);
        assert_eq!(production.quantity, 0);
        assert_eq!(
            outcome.events,
            vec![
                GameEvent::CivilianUnitRecruited {
                    id: CivilianUnitId::new(41),
                    nation: NationId::new(0),
                    unit_type: 3,
                    tile: first_neighbor,
                },
                GameEvent::RecruitmentAnnounced {
                    nation: NationId::new(0),
                    specialist: false,
                    unit_type: 3,
                    requested: 2,
                },
            ]
        );
    }

    #[test]
    fn negative_quantity_skips_spawns_but_keeps_retail_tail_effects() {
        let start = TileId::new(200);
        let mut state = game(start);
        state.world.tiles[usize::from(start.get())].owner_nation = 0;
        let mut production = order(0, -2);

        let outcome = state
            .produce_civilian_recruits(NationId::new(0), &mut production)
            .unwrap();

        assert!(state.civilian_units.is_empty());
        assert_eq!(state.cities[0].as_ref().unwrap().metrics_4a[0], -2);
        assert_eq!(state.cities[0].as_ref().unwrap().serialized_state, 1);
        assert_eq!(production.quantity, 0);
        assert_eq!(
            outcome.events,
            vec![GameEvent::RecruitmentAnnounced {
                nation: NationId::new(0),
                specialist: false,
                unit_type: 0,
                requested: -2,
            }]
        );
    }

    #[test]
    fn specialist_recruitment_builds_the_retail_military_unit_shape() {
        let home_tile = TileId::new(200);
        let mut state = game(home_tile);
        state.world.tiles[usize::from(home_tile.get())].city_or_province_index = 17;
        state.nations[0]
            .as_mut()
            .unwrap()
            .major
            .as_mut()
            .unwrap()
            .pending_action_status[1] = 0x32;
        state.nations[0]
            .as_mut()
            .unwrap()
            .major
            .as_mut()
            .unwrap()
            .pending_action_status[6] = 0x33;
        let mut production = specialist_order(24, 1);

        let outcome = state
            .produce_specialist_recruits(NationId::new(0), &mut production)
            .unwrap();

        assert_eq!(
            state.military_units,
            vec![MilitaryUnitState {
                id: MilitaryUnitId::new(41),
                nation: NationId::new(0),
                roster_index: 0,
                unit_type: 24,
                stationed_province: 17,
                order: 0,
                order_target: -1,
                owner_nation: 0,
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
        assert_eq!(state.pending.nations[0].turn_summary, vec![[1, 3, 24, 1]]);
        assert_eq!(
            outcome.events,
            vec![
                GameEvent::MilitaryUnitRecruited {
                    id: MilitaryUnitId::new(41),
                    nation: NationId::new(0),
                    unit_type: 24,
                    province: 17,
                    experience: 100,
                },
                GameEvent::RecruitmentAnnounced {
                    nation: NationId::new(0),
                    specialist: true,
                    unit_type: 24,
                    requested: 1,
                },
            ]
        );
    }

    #[test]
    fn specialist_recruitment_queues_only_the_first_reached_power_threshold() {
        let home_tile = TileId::new(200);
        let mut state = game(home_tile);
        state.world.tiles[usize::from(home_tile.get())].city_or_province_index = 17;
        state.military_units = (0..14)
            .map(|index| military_unit(41 + index, 0, 1, 17))
            .collect();
        state.persistent_unit_id_counter = 54;
        let mut production = specialist_order(1, 2);

        let outcome = state
            .produce_specialist_recruits(NationId::new(0), &mut production)
            .unwrap();

        assert_eq!(
            state.selected_military_power_score(NationId::new(0)),
            Ok(16)
        );
        assert_eq!(state.military_units[14].id, MilitaryUnitId::new(55));
        assert_eq!(state.military_units[14].roster_index, 14);
        assert_eq!(state.military_units[15].id, MilitaryUnitId::new(56));
        assert_eq!(state.military_units[15].roster_index, 15);
        let major = state.nations[0].as_ref().unwrap().major.as_ref().unwrap();
        assert_eq!(major.pending_action_status[1], 0x32);
        assert_eq!(major.pending_action_payload_by_action[1], 1);
        assert_eq!(
            outcome
                .events
                .iter()
                .filter(|event| matches!(event, GameEvent::NationPendingActionQueued { .. }))
                .count(),
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
        let mut production = specialist_order(0, -2);

        let outcome = state
            .produce_specialist_recruits(NationId::new(0), &mut production)
            .unwrap();

        assert!(state.military_units.is_empty());
        assert_eq!(state.cities[0].as_ref().unwrap().serialized_state, 1);
        assert_eq!(state.pending.nations[0].turn_summary, vec![[1, 3, 0, -2]]);
        assert_eq!(production.quantity, 0);
        assert_eq!(
            outcome.events,
            vec![GameEvent::RecruitmentAnnounced {
                nation: NationId::new(0),
                specialist: true,
                unit_type: 0,
                requested: -2,
            }]
        );
    }
}
