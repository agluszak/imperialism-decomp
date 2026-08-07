use crate::{
    CivilianUnitId, CivilianUnitState, GameEvent, GameState, MapGeometry, NationId, StepOutcome,
    TileId, UnitProductionOrder, WorldState,
};
use std::error::Error;
use std::fmt;

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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecruitmentError {
    MissingCity(NationId),
    InvalidEntryId(i16),
    InvalidHomeTile(i16),
    SpecialistOrder,
}

impl fmt::Display for RecruitmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCity(nation) => {
                write!(formatter, "nation {} has no city", nation.get())
            }
            Self::InvalidEntryId(entry) => write!(formatter, "invalid civilian unit type {entry}"),
            Self::InvalidHomeTile(tile) => write!(formatter, "invalid recruit origin tile {tile}"),
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
        CityState, LaborPool, PopulationState, ProductionConstraint, ResourceCost, ResourceKind,
        RngState, SkillBand, TileState, TurnState, UnitCostProfile,
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
            nations: Vec::new(),
            cities,
            military_units: Vec::new(),
            civilian_units: Vec::new(),
            ships: Vec::new(),
            task_forces: Vec::new(),
            missions: Vec::new(),
            pending: crate::PendingWorkState {
                turn_flow_status_flags: 0,
                nations: Vec::new(),
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
}
