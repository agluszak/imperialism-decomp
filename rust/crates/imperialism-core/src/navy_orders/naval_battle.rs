#![allow(clippy::needless_range_loop)]

use super::*;
use serde::{Deserialize, Serialize};

const TILE_COUNT: usize = 0xb4;
const TILE_STRIDE: i32 = 6;
/// `DeployTacticalUnitToTile` / hit-distance row width. Original `0x005a55c0` uses
/// signed-divide-by-29 magic (`0x8d3dcb09`); `InitTacticalBattle` (`0x005a5540`)
/// still sets `tacticalTileStride40 = 6` for neighbor walks and auto-deploy origins.
const DEPLOY_ROW_WIDTH: i32 = 0x1d;
const MOVE_COSTS: [i16; 6] = [15, 10, 20, 40, 20, 10];
const UNIT_TYPE_BY_SHIP_TYPE: [i8; 14] = [-1, -1, -1, 0, 1, -1, -1, 2, 3, 4, -1, 5, 6, 7];
const ATTACK_POWER: [f32; 8] = [3.0, 3.5, 4.0, 4.0, 8.0, 8.0, 15.0, 15.0];
const DAMAGE_SCALE: [f32; 8] = [0.045, 0.04, 0.04, 0.022, 0.02, 0.025, 0.015, 0.022];
const DEFENDER_AUTO_DEPLOY_START: i32 = 0x29;
const ROUND_LIMIT: i32 = 0x23;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NavyTargeting {
    #[default]
    Hull,
    Crew,
    Sail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NavyBattleStage {
    Deploying,
    Live,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NavyActionRejection {
    NoLiveBattle,
    NoSelectedUnit,
    NotControlled,
    Unplaced,
    InvalidTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NavyMoveResult {
    pub from: i32,
    pub to: i32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NavyUnitView {
    pub ship: ShipId,
    pub side: BattleSide,
    pub tile: i32,
    pub strength: i32,
    pub secondary_strength: i32,
    pub action_points: i32,
    pub destroyed: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum NavyUnitState {
    Ready,
    Retreated,
    Destroyed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct NavyUnit {
    ship: ShipId,
    ship_type: ShipType,
    unit_type: usize,
    side: BattleSide,
    tile: i32,
    strength: i32,
    secondary_strength: i32,
    base_action_points: i32,
    action_points: i32,
    quality: i16,
    order_seed: i16,
    selected: bool,
    state: NavyUnitState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct NavySide {
    ready: bool,
    auto_play: bool,
    nation: NationId,
    cursor: i32,
    units: Vec<usize>,
    secondary: Vec<usize>,
    targeting: NavyTargeting,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NavyBattle {
    forces: [TaskForceId; 2],
    nations: [NationId; 2],
    units: Vec<NavyUnit>,
    occupants: Vec<Option<usize>>,
    move_costs: Vec<i16>,
    current_side: BattleSide,
    selected: Option<usize>,
    round: i32,
    outcome: Option<u8>,
    live: bool,
    pending_end: bool,
    records: Vec<usize>,
    sides: [NavySide; 2],
    battlefield_column_count: i32,
    tactical_initialized: bool,
    move_cost_rotation_start: usize,
    move_cost_by_direction: [i16; 6],
}

impl NavyBattle {
    fn new(state: &mut GameState, pending: &PendingNavalBattle) -> Self {
        let forces = [pending.attacker, pending.defender];
        let nations = forces.map(|force| {
            state
                .task_force(force)
                .expect("pending naval force exists")
                .nation
        });
        let mut units = Vec::new();
        let mut side_units = [Vec::new(), Vec::new()];
        for (side_index, force) in forces.into_iter().enumerate() {
            let ships: Vec<_> = state
                .task_force(force)
                .expect("pending naval force exists")
                .ships()
                .map(|(ship, _)| ship)
                .collect();
            for ship_id in ships {
                let ship = state.ship(ship_id).expect("task-force ship exists");
                let unit_type = UNIT_TYPE_BY_SHIP_TYPE[usize::from(ship.ship_type.retail())];
                if unit_type < 0 {
                    continue;
                }
                let descriptor = NAVY_DESCRIPTORS[ship.ship_type];
                let speed =
                    (i32::from(ship.experience / 100) + 5 + descriptor.navy_priority_weight * 10)
                        / 10;
                let strength = i32::from(ship.strength);
                let idx = units.len();
                side_units[side_index].push(idx);
                units.push(NavyUnit {
                    ship: ship_id,
                    ship_type: ship.ship_type,
                    unit_type: unit_type as usize,
                    side: side_from_index(side_index),
                    tile: -2,
                    strength,
                    secondary_strength: strength,
                    base_action_points: speed * 10,
                    action_points: speed * 10,
                    quality: 0,
                    order_seed: state.rng.next_crt_rand() as i16,
                    selected: side_index != 0,
                    state: NavyUnitState::Ready,
                });
            }
        }
        let battlefield_column_count = units
            .iter()
            .map(|unit| NAVY_DESCRIPTORS[unit.ship_type].calculate_weight)
            .max()
            .unwrap_or(0)
            + 11;
        let records: Vec<usize> = (0..units.len()).collect();
        let active = state.turn.active_nation;
        Self {
            forces,
            nations,
            units,
            occupants: vec![None; TILE_COUNT],
            move_costs: vec![-1; TILE_COUNT + 1],
            current_side: BattleSide::Defender,
            selected: None,
            round: 0,
            outcome: None,
            live: false,
            pending_end: false,
            records,
            sides: [
                NavySide {
                    ready: false,
                    auto_play: nations[0] != active,
                    nation: nations[0],
                    cursor: 0,
                    units: side_units[0].clone(),
                    secondary: Vec::new(),
                    targeting: NavyTargeting::Hull,
                },
                NavySide {
                    ready: false,
                    auto_play: nations[1] != active,
                    nation: nations[1],
                    cursor: 0,
                    units: side_units[1].clone(),
                    secondary: Vec::new(),
                    targeting: NavyTargeting::Hull,
                },
            ],
            battlefield_column_count,
            tactical_initialized: false,
            move_cost_rotation_start: 0,
            move_cost_by_direction: [0; 6],
        }
    }

    pub fn units(&self) -> impl Iterator<Item = NavyUnitView> + '_ {
        self.units.iter().map(|unit| unit.view())
    }

    pub fn current_side(&self) -> BattleSide {
        self.current_side
    }

    pub fn selected_ship(&self) -> Option<ShipId> {
        self.selected.map(|idx| self.units[idx].ship)
    }

    pub fn round(&self) -> i32 {
        self.round
    }

    pub fn stage(&self) -> NavyBattleStage {
        if self.live {
            NavyBattleStage::Live
        } else {
            NavyBattleStage::Deploying
        }
    }

    pub fn targeting(&self) -> NavyTargeting {
        self.sides[side_index(self.current_side)].targeting
    }

    pub const fn battlefield_column_count(&self) -> i32 {
        self.battlefield_column_count
    }

    pub const fn move_cost_rotation_start(&self) -> usize {
        self.move_cost_rotation_start
    }

    pub const fn move_costs_by_direction(&self) -> [i16; 6] {
        self.move_cost_by_direction
    }

    pub const fn outcome(&self) -> Option<u8> {
        self.outcome
    }

    pub const fn tile_stride() -> i32 {
        TILE_STRIDE
    }

    pub const fn tile_count() -> i32 {
        TILE_COUNT as i32
    }

    /// Tiles `DeployTacticalUnitToTile` would accept for `side` on the empty 180-cell grid.
    pub fn deployable_tiles(&self, side: BattleSide) -> Vec<i32> {
        (0..TILE_COUNT as i32)
            .filter(|&tile| self.can_deploy(side, tile))
            .collect()
    }

    /// Deployment band, or live move-cost tiles already computed for the selection.
    pub fn selected_reachable_tiles(&self) -> Vec<i32> {
        let Some(selected) = self.selected else {
            return Vec::new();
        };
        if !self.live {
            return self.deployable_tiles(self.current_side);
        }
        if self.units[selected].tile < 0 {
            return Vec::new();
        }
        (0..TILE_COUNT as i32)
            .filter(|&tile| self.cost(tile) > 0)
            .collect()
    }

    fn initialize_tactical_map(&mut self, state: &mut GameState) {
        if self.tactical_initialized {
            return;
        }
        let rotation = (state.rng.next_crt_rand() % 6) as usize;
        for (offset, cost) in MOVE_COSTS.into_iter().enumerate() {
            self.move_cost_by_direction[(rotation + offset) % 6] = cost;
        }
        self.move_cost_rotation_start = rotation;
        self.tactical_initialized = true;
    }

    fn start(&mut self, state: &mut GameState) {
        self.initialize_tactical_map(state);
        self.start_side(BattleSide::Defender);
    }

    fn start_side(&mut self, side: BattleSide) {
        self.current_side = side;
        self.selected = self.select_next_undeployed(side);
        if self.sides[side_index(side)].auto_play {
            self.auto_deploy();
        }
    }

    fn auto_deploy(&mut self) {
        let side = self.current_side;
        let mut tile = if side == BattleSide::Attacker {
            self.battlefield_column_count * TILE_STRIDE - 25
        } else {
            DEFENDER_AUTO_DEPLOY_START
        };
        let mut attempts = 0;
        while !self.sides[side_index(self.current_side)].ready && attempts < TILE_COUNT as i32 {
            if tile < 0 {
                break;
            }
            let _ = self.deploy_selected_to(tile);
            tile -= 1;
            attempts += 1;
        }
        if !self.sides[side_index(side)].ready {
            self.sides[side_index(side)].ready = true;
            self.handover_after_side_ready();
        }
    }

    fn deploy_click(&mut self, tile: i32) -> bool {
        let side = self.current_side;
        let list = &self.sides[side_index(side)].units;
        let mut ordinal = 0;
        while ordinal < list.len() {
            let idx = list[ordinal];
            ordinal += 1;
            if self.units[idx].tile == -2 {
                return self.place_and_advance(idx, tile);
            }
        }
        self.sides[side_index(side)].ready = true;
        false
    }

    fn deploy_selected_to(&mut self, tile: i32) -> bool {
        let Some(idx) = self.selected else {
            return false;
        };
        self.place_and_advance(idx, tile)
    }

    fn place_and_advance(&mut self, unit: usize, tile: i32) -> bool {
        if !self.can_deploy(self.units[unit].side, tile) {
            return false;
        }
        self.units[unit].tile = tile;
        self.occupants[tile as usize] = Some(unit);
        let side = self.current_side;
        self.selected = self.select_next_undeployed(side);
        if self.sides[side_index(side)].ready {
            self.handover_after_side_ready();
        }
        true
    }

    fn can_deploy(&self, side: BattleSide, tile: i32) -> bool {
        if !(0..TILE_COUNT as i32).contains(&tile) || self.occupants[tile as usize].is_some() {
            return false;
        }
        let row = tile / DEPLOY_ROW_WIDTH;
        deploy_rows(side, self.battlefield_column_count).contains(&row)
    }

    fn can_fire_on(&self, unit: usize, tile: i32) -> bool {
        if !self.units[unit].selected {
            return false;
        }
        let Some(target) = self.occupants.get(tile as usize).copied().flatten() else {
            return false;
        };
        if self.units[target].side == self.units[unit].side
            || self.units[target].state != NavyUnitState::Ready
        {
            return false;
        }
        let range = NAVY_DESCRIPTORS[self.units[unit].ship_type].calculate_weight;
        navy_hit_distance(self.units[unit].tile, tile) <= range
    }

    fn handover_after_side_ready(&mut self) {
        let incoming = self.current_side.opponent();
        self.current_side = incoming;
        self.selected = self.select_next_undeployed(incoming);
        if self.sides[side_index(incoming)].ready {
            self.finalize_turn_state();
            return;
        }
        if self.sides[side_index(incoming)].auto_play {
            self.auto_deploy();
        }
    }

    fn handover_deployment(&mut self) {
        self.handover_after_side_ready();
    }

    fn finalize_turn_state(&mut self) {
        self.retire_undeployed(BattleSide::Attacker);
        self.retire_undeployed(BattleSide::Defender);
        self.sort_records();
        self.selected = self.records.last().copied();
        self.live = true;
        self.pending_end = false;
    }

    fn retire_undeployed(&mut self, side: BattleSide) {
        let slot = side_index(side);
        let mut ordinal = self.sides[slot].units.len() as i32;
        while ordinal > 0 {
            let idx = self.sides[slot].units[(ordinal - 1) as usize];
            if self.units[idx].tile == -2 {
                self.sides[slot].units.remove((ordinal - 1) as usize);
                self.sides[slot].secondary.insert(0, idx);
            }
            ordinal -= 1;
        }
        for &retired in &self.sides[slot].secondary {
            if let Some(pos) = self.records.iter().position(|&idx| idx == retired) {
                self.records.remove(pos);
            }
        }
    }

    fn sort_records(&mut self) {
        let mut list = std::mem::take(&mut self.records);
        navy_retail_sort(&mut list, |a, b| {
            compare_turn_order(&self.units[a], &self.units[b])
        });
        self.records = list;
    }

    fn select_next_undeployed(&mut self, side: BattleSide) -> Option<usize> {
        let slot = side_index(side);
        let list_len = self.sides[slot].units.len();
        if list_len == 0 {
            self.sides[slot].ready = true;
            return None;
        }
        let start = self.sides[slot].cursor;
        let mut scanned = 0;
        loop {
            self.sides[slot].cursor += 1;
            if self.sides[slot].cursor > list_len as i32 {
                self.sides[slot].cursor = 1;
            }
            let idx = self.sides[slot].units[(self.sides[slot].cursor - 1) as usize];
            if self.units[idx].tile == -2 {
                return Some(idx);
            }
            scanned += 1;
            if self.sides[slot].cursor == start || scanned >= list_len {
                break;
            }
        }
        let idx = self.sides[slot].units[(self.sides[slot].cursor.max(1) - 1) as usize];
        if self.units[idx].tile != -2 {
            self.sides[slot].ready = true;
        }
        Some(idx)
    }

    fn selected_unit_for_action(
        &self,
        active_nation: NationId,
    ) -> Result<usize, NavyActionRejection> {
        let idx = self.selected.ok_or(NavyActionRejection::NoSelectedUnit)?;
        let slot = side_index(self.current_side);
        if self.units[idx].side != self.current_side
            || self.sides[slot].nation != active_nation
            || self.sides[slot].auto_play
        {
            return Err(NavyActionRejection::NotControlled);
        }
        Ok(idx)
    }

    fn selected_unit_is_controlled(&self, active_nation: NationId) -> bool {
        self.selected.is_some_and(|unit| {
            self.units[unit].side == self.current_side
                && self.sides[side_index(self.current_side)].nation == active_nation
                && !self.sides[side_index(self.current_side)].auto_play
                && self.units[unit].state == NavyUnitState::Ready
        })
    }

    fn pump_until_active_input(&mut self, state: &mut GameState) -> bool {
        let mut guard = 20_000;
        loop {
            assert!(
                guard > 0,
                "interactive naval pump did not reach an input boundary"
            );
            guard -= 1;
            if self.outcome.is_some() {
                self.commit_outcome(state);
                return true;
            }
            if self.pending_end {
                if self.selected_unit_is_controlled(state.turn.active_nation) {
                    return false;
                }
                if let Some(selected) = self.selected {
                    self.advance_auto_pulse(state, selected);
                }
                continue;
            }
            self.pending_end = true;
            self.advance_turn_step(state, true);
        }
    }

    fn finish_action(&mut self) {
        self.pending_end = false;
    }

    fn advance_turn_step(&mut self, state: &mut GameState, stop_for_active_nation: bool) {
        let Some(candidate) = self.select_next_record_unit() else {
            return;
        };
        self.set_current_selection(candidate);
        self.current_side = self.units[candidate].side;
        if stop_for_active_nation && self.selected_unit_is_controlled(state.turn.active_nation) {
            return;
        }
        self.advance_auto_pulse(state, candidate);
    }

    fn select_next_record_unit(&mut self) -> Option<usize> {
        let mut position = if let Some(selected) = self.selected {
            1 + self
                .records
                .iter()
                .position(|&idx| idx == selected)
                .unwrap_or(0) as i32
        } else {
            1
        };
        loop {
            let total = self.records.len() as i32;
            if total == 0 {
                self.evaluate_outcome();
                self.finish_action();
                return None;
            }
            if position == total {
                self.round += 1;
                if self.round >= ROUND_LIMIT {
                    self.evaluate_outcome();
                    self.finish_action();
                    return None;
                }
                position = 1;
            } else {
                position += 1;
            }
            let idx = self.records[(position - 1) as usize];
            if self.units[idx].state != NavyUnitState::Destroyed {
                return Some(idx);
            }
        }
    }

    fn set_current_selection(&mut self, unit: usize) {
        self.current_side = self.units[unit].side;
        self.units[unit].action_points = self.units[unit].base_action_points;
        self.units[unit].selected = true;
        self.selected = Some(unit);
        self.compute_reachable(unit);
    }

    fn advance_auto_pulse(&mut self, state: &mut GameState, unit: usize) {
        if self.units[unit].state != NavyUnitState::Ready || self.units[unit].tile < 0 {
            self.finish_action();
            return;
        }
        self.compute_reachable(unit);
        let Some(target) = self.closest_enemy(unit) else {
            self.finish_action();
            return;
        };
        let target_tile = self.units[target].tile;
        let mut destination = self.units[unit].tile;
        let mut best = navy_hit_distance(destination, target_tile);
        for tile in 0..TILE_COUNT as i32 {
            if self.cost(tile) != -1 {
                let approach = navy_hit_distance(tile, target_tile);
                if approach < best {
                    destination = tile;
                    best = approach;
                }
            }
        }
        if destination != self.units[unit].tile && self.selected == Some(unit) {
            while self.units[unit].tile != destination && self.selected == Some(unit) {
                self.move_and_maybe_finish(state, unit, destination);
                if self.selected != Some(unit) {
                    break;
                }
            }
        }
        let range = NAVY_DESCRIPTORS[self.units[unit].ship_type].calculate_weight;
        if best <= range && self.selected == Some(unit) {
            self.resolve_shot(state, unit, target_tile);
        }
        if self.selected == Some(unit) {
            self.finish_action();
        }
    }

    fn closest_enemy(&self, unit: usize) -> Option<usize> {
        let enemy = self.units[unit].side.opponent();
        let current = self.units[unit].tile;
        self.sides[side_index(enemy)]
            .units
            .iter()
            .copied()
            .filter(|&idx| {
                self.units[idx].tile >= 0 && self.units[idx].state == NavyUnitState::Ready
            })
            .min_by_key(|&idx| navy_hit_distance(current, self.units[idx].tile))
    }

    fn move_and_maybe_finish(&mut self, state: &mut GameState, unit: usize, target: i32) {
        self.move_toward(state, unit, target);
        if !self.units[unit].selected {
            let selected = self.selected.unwrap_or(unit);
            if !self.has_adjacent_reachable(selected) {
                self.finish_action();
                return;
            }
        }
        if self.units[unit].state == NavyUnitState::Ready && self.outcome.is_none() {
            return;
        }
        self.finish_action();
    }

    fn fire_and_maybe_finish(&mut self, state: &mut GameState, unit: usize, target: i32) {
        self.resolve_shot(state, unit, target);
        if self.outcome.is_none() {
            let selected = self.selected.unwrap_or(unit);
            if self.has_adjacent_reachable(selected) {
                return;
            }
        }
        self.finish_action();
    }

    fn has_adjacent_reachable(&self, unit: usize) -> bool {
        if self.units[unit].tile < 0 {
            return false;
        }
        for neighbor in navy_neighbors(self.units[unit].tile) {
            if neighbor != -1 {
                let cost = self.cost(neighbor);
                if cost != -1 && i32::from(cost) <= self.units[unit].action_points {
                    return true;
                }
            }
        }
        false
    }

    fn move_toward(&mut self, state: &mut GameState, unit: usize, target: i32) {
        let mut path = [0; 12];
        path[0] = target;
        let mut step_count = self.build_path(target, 0, self.units[unit].tile, &mut path, state);
        if step_count == -1 {
            return;
        }
        if step_count != 0 {
            let mut stopped = false;
            while step_count != 0 && !stopped {
                let from = path[step_count as usize];
                let to = path[(step_count - 1) as usize];
                self.move_between(unit, from, to);
                step_count -= 1;
                stopped = self.reaction_fire(state, path[step_count as usize]);
            }
        }
        self.units[unit].action_points -= i32::from(self.cost(path[step_count as usize]));
        let arrived = path[step_count as usize];
        let exit_column = (((arrived / 29) & 1) + 2 * (arrived % 29)) / 2;
        let side = self.units[unit].side;
        if (side == BattleSide::Defender && exit_column >= self.battlefield_column_count - 1)
            || (side == BattleSide::Attacker && exit_column == 0)
        {
            let unit_may_leave = self.units[unit].state != NavyUnitState::Ready;
            if unit_may_leave {
                self.units[unit].state = NavyUnitState::Retreated;
                if arrived >= 0 {
                    self.occupants[arrived as usize] = None;
                }
                self.units[unit].tile = -2;
                self.evaluate_outcome();
            }
        }
        self.compute_reachable(unit);
    }

    fn build_path(
        &mut self,
        walk: i32,
        depth: i32,
        goal: i32,
        out: &mut [i32; 12],
        state: &mut GameState,
    ) -> i32 {
        if depth < 0 || depth >= out.len() as i32 {
            return -1;
        }
        if walk == goal {
            out[depth as usize] = walk;
            return depth;
        }
        let walk_cost = self.cost(walk);
        let neighbors = navy_neighbors(walk);
        let mut candidates = [0; 6];
        let mut count = 0;
        for neighbor in neighbors {
            let neighbor_cost = self.cost(neighbor);
            if neighbor_cost != -1 && neighbor_cost < walk_cost {
                candidates[count] = neighbor;
                count += 1;
            }
        }
        if count == 0 {
            return -1;
        }
        if count > 1 {
            for outer in 0..count - 1 {
                for inner in 1..count {
                    let next_tile = candidates[inner];
                    let cur_tile = candidates[outer];
                    let mut swap = self.cost(next_tile) < self.cost(cur_tile);
                    if !swap && self.cost(next_tile) == self.cost(cur_tile) {
                        swap = (state.rng.next_crt_rand() & 1) != 0;
                    }
                    if swap {
                        candidates[outer] = next_tile;
                        candidates[inner] = cur_tile;
                    }
                }
            }
        }
        for candidate in candidates.iter().take(count) {
            let found = self.build_path(*candidate, depth + 1, goal, out, state);
            if found != -1 {
                out[depth as usize] = walk;
                return found;
            }
        }
        -1
    }

    fn move_between(&mut self, unit: usize, from: i32, to: i32) {
        self.occupants[from as usize] = None;
        self.units[unit].tile = to;
        self.occupants[to as usize] = Some(unit);
    }

    fn reaction_fire(&mut self, state: &mut GameState, tile: i32) -> bool {
        let Some(occupant) = self.occupants[tile as usize] else {
            return false;
        };
        let reacting = self.units[occupant].side.opponent();
        let reactors = self.sides[side_index(reacting)].units.clone();
        let mut fired = false;
        for reactor in reactors {
            if self.units[reactor].state == NavyUnitState::Ready
                && self.units[reactor].selected
                && self.units[reactor].tile >= 0
            {
                let range = NAVY_DESCRIPTORS[self.units[reactor].ship_type].calculate_weight;
                if navy_hit_distance(self.units[reactor].tile, tile) <= range {
                    self.resolve_shot(state, reactor, tile);
                    fired = true;
                }
            }
            if self.units[occupant].strength == 0 {
                break;
            }
        }
        fired
    }

    fn compute_reachable(&mut self, unit: usize) {
        self.move_costs.fill(-1);
        let start = self.units[unit].tile;
        if !(0..TILE_COUNT as i32).contains(&start) {
            return;
        }
        self.move_costs[start as usize] = 0;
        let action_points = self.units[unit].action_points;
        for band in (0..=action_points).step_by(10) {
            for tile in 0..TILE_COUNT as i32 {
                let cost = self.move_costs[tile as usize];
                if cost < band as i16 {
                    continue;
                }
                for (direction, neighbor) in navy_neighbors(tile).into_iter().enumerate() {
                    if neighbor < 0 || self.occupants[neighbor as usize].is_some() {
                        continue;
                    }
                    let step = if self.units[unit].unit_type < 2 {
                        self.move_cost_by_direction[direction]
                    } else {
                        10
                    };
                    let next = cost + step;
                    if next <= action_points as i16
                        && (self.move_costs[neighbor as usize] == -1
                            || next < self.move_costs[neighbor as usize])
                    {
                        self.move_costs[neighbor as usize] = next;
                    }
                }
            }
        }
    }

    fn cost(&self, tile: i32) -> i16 {
        if !(0..TILE_COUNT as i32).contains(&tile) {
            return self.move_costs[TILE_COUNT];
        }
        self.move_costs[tile as usize]
    }

    pub fn reachable_tiles(&mut self, ship: ShipId) -> &[i16] {
        self.move_costs.fill(-1);
        let Some(unit) = self.units.iter().position(|unit| unit.ship == ship) else {
            return &self.move_costs;
        };
        self.compute_reachable(unit);
        &self.move_costs
    }

    fn resolve_shot(&mut self, state: &mut GameState, attacker: usize, target_tile: i32) {
        let Some(target) = self.occupants[target_tile as usize] else {
            return;
        };
        if self.units[attacker].state != NavyUnitState::Ready
            || self.units[target].state != NavyUnitState::Ready
            || self.units[attacker].side == self.units[target].side
            || self.units[attacker].tile < 0
        {
            return;
        }
        let distance = navy_hit_distance(self.units[attacker].tile, target_tile);
        let range = NAVY_DESCRIPTORS[self.units[attacker].ship_type].calculate_weight;
        let ratio = distance as f64 / (range as f64 * 0.5);
        let threshold =
            (f64::from(self.units[attacker].quality) * 5.0 + 80.0 / (ratio.powi(3) + 1.0)) as f32;
        if ((state.rng.next_crt_rand() % 100) as f32) < threshold {
            let damage = DAMAGE_SCALE[self.units[target].unit_type]
                * self.units[attacker].strength as f32
                * ATTACK_POWER[self.units[attacker].unit_type];
            let targeting = self.sides[side_index(self.units[attacker].side)].targeting;
            self.apply_damage(state, target, damage, targeting);
        }
        self.units[attacker].selected = false;
        self.evaluate_outcome();
    }

    fn apply_damage(
        &mut self,
        state: &mut GameState,
        target: usize,
        damage: f32,
        targeting: NavyTargeting,
    ) {
        let (strength, secondary, action_points) = match targeting {
            NavyTargeting::Hull => ((damage * 0.25) as i32, damage as i32, 0),
            NavyTargeting::Crew => ((damage * 0.75) as i32, (damage * 0.25) as i32, 0),
            NavyTargeting::Sail => (
                0,
                (damage * 0.25) as i32,
                i32::from(((state.rng.next_crt_rand() % 10) as f32) < damage) * 10,
            ),
        };
        let unit = &mut self.units[target];
        unit.strength -= strength;
        unit.secondary_strength -= secondary;
        unit.base_action_points -= action_points;
        if unit.strength <= 0 || unit.secondary_strength <= 0 {
            unit.strength = 0;
            unit.secondary_strength = 0;
            unit.state = NavyUnitState::Destroyed;
            if unit.tile >= 0 {
                self.occupants[unit.tile as usize] = None;
                unit.tile = -1;
            }
        }
    }

    fn evaluate_outcome(&mut self) {
        let live = [BattleSide::Attacker, BattleSide::Defender].map(|side| {
            self.records.iter().any(|&idx| {
                self.units[idx].side == side && self.units[idx].state == NavyUnitState::Ready
            })
        });
        if live[0] && live[1] && self.round < ROUND_LIMIT {
            return;
        }
        self.outcome = Some(u8::from(!(live[0] && self.round < ROUND_LIMIT)));
    }

    fn commit_outcome(&mut self, state: &mut GameState) {
        for unit in &self.units {
            if let Some(ship) = state.ships.get_mut(&unit.ship) {
                ship.strength = unit.strength.clamp(0, i32::from(i16::MAX)) as i16;
            }
        }
        for force in self.forces {
            if let Some(force_state) = state.task_forces.get_mut(&force) {
                force_state.defeated = true;
            }
            state.prune_sunk_force_ships(force);
        }
    }

    fn set_targeting(&mut self, targeting: NavyTargeting) {
        self.sides[side_index(self.current_side)].targeting = targeting;
    }
}

impl NavyUnit {
    fn view(&self) -> NavyUnitView {
        NavyUnitView {
            ship: self.ship,
            side: self.side,
            tile: self.tile,
            strength: self.strength,
            secondary_strength: self.secondary_strength,
            action_points: self.action_points,
            destroyed: self.state == NavyUnitState::Destroyed,
        }
    }
}

impl GameState {
    pub fn navy_battle(&self) -> Option<&NavyBattle> {
        match &self.turn_flow {
            TurnFlow::NavalBattle(continuation) => {
                continuation.navy_battle.as_deref()
            }
            _ => None,
        }
    }

    pub fn ensure_navy_battle(&mut self) -> &NavyBattle {
        let stop = self.synchronize_navy_battle();
        assert!(
            stop.is_none(),
            "interactive navy battle ended before reaching local input"
        );
        self.navy_battle()
            .expect("interactive navy battle was just stored")
    }

    pub fn synchronize_navy_battle(&mut self) -> Option<crate::TurnStop> {
        if self
            .navy_battle()
            .is_some_and(|battle| battle.tactical_initialized)
        {
            return None;
        }
        let TurnFlow::NavalBattle(_) = &self.turn_flow else {
            return None;
        };
        let mut battle = if let Some(battle) = self.take_navy_battle() {
            battle
        } else {
            let pending = self
                .pending_naval_battle()
                .cloned()
                .expect("navy battle requires a pending encounter");
            NavyBattle::new(self, &pending)
        };
        battle.start(self);
        if battle.live && battle.pump_until_active_input(self) {
            return Some(self.resume_after_naval_battle());
        }
        self.store_navy_battle(battle);
        None
    }

    pub fn selected_navy_unit(&self) -> Option<NavyUnitView> {
        let battle = self.navy_battle()?;
        let idx = battle.selected?;
        Some(battle.units[idx].view())
    }

    pub fn deploy_navy_unit(&mut self, tile: i32) -> Result<bool, NavyActionRejection> {
        let active_nation = self.turn.active_nation;
        let mut battle = self
            .take_navy_battle()
            .ok_or(NavyActionRejection::NoLiveBattle)?;
        if let Err(error) = battle.selected_unit_for_action(active_nation) {
            self.store_navy_battle(battle);
            return Err(error);
        }
        if battle.live {
            self.store_navy_battle(battle);
            return Err(NavyActionRejection::InvalidTarget);
        }
        let deployed = battle.deploy_click(tile);
        if !battle.live {
            self.store_navy_battle(battle);
            return Ok(deployed);
        }
        let stop = self.finish_interactive_navy_action(battle);
        Ok(deployed || stop.is_some())
    }

    pub fn move_navy_unit(
        &mut self,
        tile: i32,
    ) -> Result<(NavyMoveResult, Option<crate::TurnStop>), NavyActionRejection> {
        let active_nation = self.turn.active_nation;
        let mut battle = self
            .take_navy_battle()
            .ok_or(NavyActionRejection::NoLiveBattle)?;
        let idx = match battle.selected_unit_for_action(active_nation) {
            Ok(idx) => idx,
            Err(error) => {
                self.store_navy_battle(battle);
                return Err(error);
            }
        };
        if !battle.live {
            self.store_navy_battle(battle);
            return Err(NavyActionRejection::InvalidTarget);
        }
        if battle.units[idx].tile < 0 {
            self.store_navy_battle(battle);
            return Err(NavyActionRejection::Unplaced);
        }
        if !(0..TILE_COUNT as i32).contains(&tile) {
            self.store_navy_battle(battle);
            return Err(NavyActionRejection::InvalidTarget);
        }
        battle.compute_reachable(idx);
        if battle.cost(tile) <= 0 || battle.occupants[tile as usize].is_some() {
            self.store_navy_battle(battle);
            return Err(NavyActionRejection::InvalidTarget);
        }
        let from = battle.units[idx].tile;
        battle.move_and_maybe_finish(self, idx, tile);
        let to = battle.units[idx].tile;
        let stop = self.finish_interactive_navy_action(battle);
        Ok((NavyMoveResult { from, to }, stop))
    }

    pub fn fire_navy_unit(
        &mut self,
        tile: i32,
    ) -> Result<Option<crate::TurnStop>, NavyActionRejection> {
        let active_nation = self.turn.active_nation;
        let mut battle = self
            .take_navy_battle()
            .ok_or(NavyActionRejection::NoLiveBattle)?;
        let idx = match battle.selected_unit_for_action(active_nation) {
            Ok(idx) => idx,
            Err(error) => {
                self.store_navy_battle(battle);
                return Err(error);
            }
        };
        if !battle.live {
            self.store_navy_battle(battle);
            return Err(NavyActionRejection::InvalidTarget);
        }
        if battle.units[idx].tile < 0 {
            self.store_navy_battle(battle);
            return Err(NavyActionRejection::Unplaced);
        }
        if !battle.can_fire_on(idx, tile) {
            self.store_navy_battle(battle);
            return Err(NavyActionRejection::InvalidTarget);
        }
        battle.fire_and_maybe_finish(self, idx, tile);
        Ok(self.finish_interactive_navy_action(battle))
    }

    pub fn finish_selected_navy_unit_action(
        &mut self,
    ) -> Result<Option<crate::TurnStop>, NavyActionRejection> {
        let active_nation = self.turn.active_nation;
        let mut battle = self
            .take_navy_battle()
            .ok_or(NavyActionRejection::NoLiveBattle)?;
        if let Err(error) = battle.selected_unit_for_action(active_nation) {
            self.store_navy_battle(battle);
            return Err(error);
        }
        if !battle.live {
            let side = battle.current_side;
            battle.selected = battle.select_next_undeployed(side);
            self.store_navy_battle(battle);
            return Ok(None);
        }
        battle.finish_action();
        Ok(self.finish_interactive_navy_action(battle))
    }

    pub fn retreat_from_navy_battle(
        &mut self,
    ) -> Result<Option<crate::TurnStop>, NavyActionRejection> {
        let active_nation = self.turn.active_nation;
        let mut battle = self
            .take_navy_battle()
            .ok_or(NavyActionRejection::NoLiveBattle)?;
        if let Err(error) = battle.selected_unit_for_action(active_nation) {
            self.store_navy_battle(battle);
            return Err(error);
        }
        if !battle.live {
            battle.handover_deployment();
            if !battle.live {
                self.store_navy_battle(battle);
                return Ok(None);
            }
            return Ok(self.finish_interactive_navy_action(battle));
        }
        let slot = side_index(battle.current_side);
        battle.sides[slot].auto_play = true;
        if let Some(selected) = battle.selected {
            battle.advance_auto_pulse(self, selected);
        }
        Ok(self.finish_interactive_navy_action(battle))
    }

    pub fn navy_unit_reachable_costs(&mut self) -> Vec<i16> {
        let Some(mut battle) = self.take_navy_battle() else {
            return Vec::new();
        };
        let costs = if let Some(selected) = battle.selected {
            battle.compute_reachable(selected);
            battle.move_costs.clone()
        } else {
            Vec::new()
        };
        self.store_navy_battle(battle);
        costs
    }

    pub fn set_navy_targeting(&mut self, targeting: NavyTargeting) {
        if let Some(mut battle) = self.take_navy_battle() {
            battle.set_targeting(targeting);
            self.store_navy_battle(battle);
        }
    }

    pub fn commit_finished_navy_battle(&mut self) -> Option<crate::TurnStop> {
        let mut battle = self.take_navy_battle()?;
        if battle.outcome.is_none() {
            self.store_navy_battle(battle);
            return None;
        }
        battle.commit_outcome(self);
        Some(self.resume_after_naval_battle())
    }

    pub fn selected_navy_unit_reachable_tiles(&self) -> Vec<i32> {
        match self.navy_battle() {
            Some(battle) => battle.selected_reachable_tiles(),
            None => Vec::new(),
        }
    }

    pub fn navy_action_at(
        &mut self,
        tile: i32,
    ) -> Result<Option<crate::TurnStop>, NavyActionRejection> {
        let active_nation = self.turn.active_nation;
        let mut battle = self
            .take_navy_battle()
            .ok_or(NavyActionRejection::NoLiveBattle)?;
        let idx = match battle.selected_unit_for_action(active_nation) {
            Ok(idx) => idx,
            Err(error) => {
                self.store_navy_battle(battle);
                return Err(error);
            }
        };
        if !battle.live {
            let _ = battle.deploy_click(tile);
            if !battle.live {
                self.store_navy_battle(battle);
                return Ok(None);
            }
            return Ok(self.finish_interactive_navy_action(battle));
        }
        if battle.units[idx].tile < 0 {
            self.store_navy_battle(battle);
            return Err(NavyActionRejection::Unplaced);
        }
        if battle.can_fire_on(idx, tile) {
            battle.fire_and_maybe_finish(self, idx, tile);
            return Ok(self.finish_interactive_navy_action(battle));
        }
        if !(0..TILE_COUNT as i32).contains(&tile) {
            self.store_navy_battle(battle);
            return Err(NavyActionRejection::InvalidTarget);
        }
        battle.compute_reachable(idx);
        if battle.cost(tile) <= 0 || battle.occupants[tile as usize].is_some() {
            self.store_navy_battle(battle);
            return Err(NavyActionRejection::InvalidTarget);
        }
        battle.move_and_maybe_finish(self, idx, tile);
        Ok(self.finish_interactive_navy_action(battle))
    }

    /// Headless Auto: auto-deploy the current side if needed, then pump both
    /// sides until the battle commits and navy orders resume.
    pub fn auto_resolve_navy_battle(&mut self) -> crate::TurnStop {
        let TurnFlow::NavalBattle(_) = &self.turn_flow else {
            panic!("navy-battle auto-resolve requires a navy-orders continuation");
        };
        let mut battle = match self.take_navy_battle() {
            Some(mut live) => {
                if !live.tactical_initialized {
                    for side in &mut live.sides {
                        side.auto_play = true;
                    }
                    live.start(self);
                    live
                } else {
                    if !live.live {
                        let slot = side_index(live.current_side);
                        live.sides[slot].auto_play = true;
                        live.auto_deploy();
                    }
                    for side in &mut live.sides {
                        side.auto_play = true;
                    }
                    live
                }
            }
            None => {
                let pending = self
                    .pending_naval_battle()
                    .cloned()
                    .expect("navy battle requires a pending encounter");
                let mut battle = NavyBattle::new(self, &pending);
                for side in &mut battle.sides {
                    side.auto_play = true;
                }
                battle.start(self);
                battle
            }
        };
        if battle.pump_until_active_input(self) {
            return self.resume_after_naval_battle();
        }
        self.store_navy_battle(battle);
        crate::TurnStop::NavalBattle
    }

    fn finish_interactive_navy_action(
        &mut self,
        mut battle: NavyBattle,
    ) -> Option<crate::TurnStop> {
        if battle.pump_until_active_input(self) {
            return Some(self.resume_after_naval_battle());
        }
        self.store_navy_battle(battle);
        None
    }

    fn take_navy_battle(&mut self) -> Option<NavyBattle> {
        match &mut self.turn_flow {
            TurnFlow::NavalBattle(continuation) => {
                continuation.navy_battle.take().map(|battle| *battle)
            }
            _ => None,
        }
    }

    fn store_navy_battle(&mut self, battle: NavyBattle) {
        let TurnFlow::NavalBattle(continuation) = &mut self.turn_flow
        else {
            panic!("navy battle storage requires a pending encounter")
        };
        continuation.navy_battle = Some(Box::new(battle));
    }

    #[cfg(feature = "oracle")]
    pub(crate) fn navy_tactical_init_snapshot(
        &mut self,
        our: TaskForceId,
        enemy: TaskForceId,
    ) -> crate::differential::NavyTacticalInitSnapshot {
        let mut battle = NavyBattle::new(
            self,
            &PendingNavalBattle {
                attacker: our,
                defender: enemy,
            },
        );
        battle.initialize_tactical_map(self);
        crate::differential::NavyTacticalInitSnapshot {
            column_count: battle.battlefield_column_count,
            current_side: side_index(battle.current_side) as i32,
            side0_nation: i32::from(battle.nations[0].get()),
            side1_nation: i32::from(battle.nations[1].get()),
            side0_selected: i32::from(
                battle
                    .units
                    .iter()
                    .any(|unit| unit.side == BattleSide::Attacker && unit.selected),
            ),
            side1_selected: i32::from(
                battle
                    .units
                    .iter()
                    .any(|unit| unit.side == BattleSide::Defender && unit.selected),
            ),
            side0_tiles: battle.deployable_tiles(BattleSide::Attacker),
            side1_tiles: battle.deployable_tiles(BattleSide::Defender),
        }
    }
}

fn side_index(side: BattleSide) -> usize {
    match side {
        BattleSide::Attacker => 0,
        BattleSide::Defender => 1,
    }
}

fn side_from_index(index: usize) -> BattleSide {
    if index == 0 {
        BattleSide::Attacker
    } else {
        BattleSide::Defender
    }
}

fn deploy_rows(side: BattleSide, column_count: i32) -> std::ops::RangeInclusive<i32> {
    // `TNavyBattle::DeployTacticalUnitToTile` (0x005a55c0) uses row = tile / 29.
    // Auto-deploy origins still use stride 6 (`column_count * 6 - 25` and tile 0x29).
    if side == BattleSide::Attacker {
        column_count - 6..=column_count - 5
    } else {
        5..=6
    }
}

fn navy_retail_sort(list: &mut [usize], cmp: impl Fn(usize, usize) -> i16) {
    list.sort_by(|&left, &right| {
        if left == right {
            return std::cmp::Ordering::Equal;
        }
        match cmp(left, right) {
            ..=-1 => std::cmp::Ordering::Less,
            0 => std::cmp::Ordering::Equal,
            1.. => std::cmp::Ordering::Greater,
        }
    });
}

fn compare_turn_order(a: &NavyUnit, b: &NavyUnit) -> i16 {
    if b.base_action_points < a.base_action_points {
        return -1;
    }
    if b.base_action_points > a.base_action_points {
        return 1;
    }
    if b.quality < a.quality {
        return -1;
    }
    if b.quality > a.quality {
        return 1;
    }
    match a.order_seed.cmp(&b.order_seed) {
        std::cmp::Ordering::Greater => -1,
        _ => 1,
    }
}

fn navy_neighbors(tile: i32) -> [i32; 6] {
    let row = tile / TILE_STRIDE;
    let column = tile % TILE_STRIDE;
    let mut out = if row & 1 != 0 {
        [
            tile - TILE_STRIDE + 1,
            tile + 1,
            tile + TILE_STRIDE + 1,
            tile + TILE_STRIDE,
            tile - 1,
            tile - TILE_STRIDE,
        ]
    } else {
        [
            tile - TILE_STRIDE,
            tile + 1,
            tile + TILE_STRIDE,
            tile + TILE_STRIDE - 1,
            tile - 1,
            tile - TILE_STRIDE - 1,
        ]
    };
    if column == TILE_STRIDE - 1 {
        out[1] = -1;
        if row & 1 != 0 {
            out[0] = -1;
            out[2] = -1;
        }
    } else if column == 0 {
        out[4] = -1;
        if row & 1 == 0 {
            out[3] = -1;
            out[5] = -1;
        }
    }
    if tile >= TILE_COUNT as i32 - TILE_STRIDE {
        out[2] = -1;
        out[3] = -1;
    } else if tile < TILE_STRIDE {
        out[0] = -1;
        out[5] = -1;
    }
    out
}

fn navy_hit_distance(a: i32, b: i32) -> i32 {
    let row_a = a / 0x1d;
    let x_a = (row_a & 1) + (a % 0x1d) * 2;
    let mut row_b = b / 0x1d;
    let mut x_b = (row_b & 1) + (b % 0x1d) * 2;
    if x_b < x_a {
        x_b = x_a * 2 - x_b;
    }
    if row_b < row_a {
        row_b = row_a * 2 - row_b;
    }
    let row_delta = row_b - row_a;
    let extra = x_b - row_delta - x_a;
    if extra > 0 {
        row_delta + extra / 2
    } else {
        row_delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    fn unit(ship: usize, side: BattleSide, tile: i32, unit_type: usize) -> NavyUnit {
        NavyUnit {
            ship: ShipId::new(ship),
            ship_type: ShipType::Frigate,
            unit_type,
            side,
            tile,
            strength: 100,
            secondary_strength: 100,
            base_action_points: 40,
            action_points: 40,
            quality: 0,
            order_seed: 0,
            selected: true,
            state: NavyUnitState::Ready,
        }
    }

    fn battle(units: Vec<NavyUnit>) -> NavyBattle {
        let mut occupants = vec![None; TILE_COUNT];
        let mut side_units = [Vec::new(), Vec::new()];
        for (index, unit) in units.iter().enumerate() {
            if unit.tile >= 0 {
                occupants[unit.tile as usize] = Some(index);
            }
            side_units[side_index(unit.side)].push(index);
        }
        let records: Vec<usize> = (0..units.len()).collect();
        NavyBattle {
            forces: [TaskForceId::new(1), TaskForceId::new(2)],
            nations: [NationId::new(0), NationId::new(1)],
            units,
            occupants,
            move_costs: vec![-1; TILE_COUNT + 1],
            current_side: BattleSide::Attacker,
            selected: Some(0),
            round: 0,
            outcome: None,
            live: true,
            pending_end: true,
            records,
            sides: [
                NavySide {
                    ready: true,
                    auto_play: false,
                    nation: NationId::new(0),
                    cursor: 1,
                    units: side_units[0].clone(),
                    secondary: Vec::new(),
                    targeting: NavyTargeting::Hull,
                },
                NavySide {
                    ready: true,
                    auto_play: false,
                    nation: NationId::new(1),
                    cursor: 1,
                    units: side_units[1].clone(),
                    secondary: Vec::new(),
                    targeting: NavyTargeting::Hull,
                },
            ],
            battlefield_column_count: 16,
            tactical_initialized: true,
            move_cost_rotation_start: 0,
            move_cost_by_direction: MOVE_COSTS,
        }
    }

    #[test]
    fn navy_neighbors_use_the_recovered_six_tile_stride() {
        assert_eq!(navy_neighbors(6), [1, 7, 13, 12, -1, 0]);
        assert_eq!(navy_neighbors(11), [-1, -1, -1, 17, 10, 5]);
    }

    #[test]
    fn navy_hit_distance_keeps_the_retail_fixed_29_wide_conversion() {
        assert_eq!(navy_hit_distance(29, 31), 2);
        assert_eq!(navy_hit_distance(31, 29), 2);
        assert_eq!(navy_hit_distance(0, 58), 2);
    }

    #[test]
    fn navy_deployment_uses_the_retail_29_wide_row_index() {
        let attacker = unit(1, BattleSide::Attacker, -2, 0);
        let defender = unit(2, BattleSide::Defender, -2, 0);
        let mut battle = battle(vec![attacker, defender]);
        battle.live = false;
        battle.occupants.fill(None);
        assert!(battle.can_deploy(BattleSide::Defender, 5 * DEPLOY_ROW_WIDTH));
        assert!(battle.can_deploy(BattleSide::Defender, 6 * DEPLOY_ROW_WIDTH));
        assert!(battle.place_and_advance(1, 5 * DEPLOY_ROW_WIDTH));
        assert!(!battle.can_deploy(BattleSide::Defender, 4 * DEPLOY_ROW_WIDTH + 28));
        assert!(!battle.can_deploy(BattleSide::Defender, DEFENDER_AUTO_DEPLOY_START));
        assert!(
            battle.deployable_tiles(BattleSide::Attacker).is_empty(),
            "frigate column_count 16 puts attacker rows 10-11 off the 180-cell grid"
        );
        assert_eq!(
            battle.deployable_tiles(BattleSide::Defender),
            (5 * DEPLOY_ROW_WIDTH..TILE_COUNT as i32)
                .filter(|&tile| battle.occupants[tile as usize].is_none())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn navy_reachability_rotates_costs_for_the_first_two_ship_classes() {
        let mut battle = battle(vec![unit(1, BattleSide::Attacker, 7, 0)]);
        battle.units[0].action_points = 15;
        let costs = battle.reachable_tiles(ShipId::new(1));
        let neighbors = navy_neighbors(7);
        for (direction, neighbor) in neighbors.into_iter().enumerate() {
            if neighbor >= 0 {
                let expected = (MOVE_COSTS[direction] <= 15).then_some(MOVE_COSTS[direction]);
                assert_eq!(
                    (costs[neighbor as usize] >= 0).then_some(costs[neighbor as usize]),
                    expected
                );
            }
        }
    }

    #[test]
    fn navy_hull_damage_uses_the_recovered_quarter_and_full_pools() {
        let mut state = game_state();
        let mut battle = battle(vec![
            unit(1, BattleSide::Attacker, 29, 0),
            unit(2, BattleSide::Defender, 31, 0),
        ]);
        battle.apply_damage(&mut state, 1, 40.0, NavyTargeting::Hull);
        assert_eq!(battle.units[1].strength, 90);
        assert_eq!(battle.units[1].secondary_strength, 60);
        assert_ne!(battle.units[1].state, NavyUnitState::Destroyed);
    }

    #[test]
    fn navy_move_consumes_action_points_from_the_reachable_cost() {
        let mut state = game_state();
        let mut battle = battle(vec![unit(1, BattleSide::Attacker, 7, 0)]);
        battle.units[0].action_points = 15;
        battle.compute_reachable(0);
        let neighbor = navy_neighbors(7)
            .into_iter()
            .find(|&tile| tile >= 0 && battle.cost(tile) > 0)
            .expect("reachable neighbor");
        let cost = battle.cost(neighbor);
        battle.move_toward(&mut state, 0, neighbor);
        assert_eq!(battle.units[0].tile, neighbor);
        assert_eq!(battle.units[0].action_points, 15 - i32::from(cost));
    }

    #[test]
    fn navy_shot_consumes_rng_and_applies_hull_split_on_a_guaranteed_hit() {
        let mut state = game_state();
        let mut battle = battle(vec![
            unit(1, BattleSide::Attacker, 7, 0),
            unit(2, BattleSide::Defender, 8, 0),
        ]);
        battle.units[0].quality = 20;
        let before = state.rng;
        battle.resolve_shot(&mut state, 0, 8);
        assert_ne!(state.rng, before, "naval firing consumes CRT rand");
        assert!(
            battle.units[1].strength < 100 || battle.units[1].secondary_strength < 100,
            "guaranteed hull hit must damage a combat pool"
        );
        assert!(!battle.units[0].selected);
    }

    #[test]
    fn navy_done_advances_the_round_cursor_to_the_next_record() {
        let mut battle = battle(vec![
            unit(1, BattleSide::Attacker, 7, 0),
            unit(2, BattleSide::Defender, 41, 0),
        ]);
        battle.selected = Some(0);
        battle.pending_end = true;
        battle.finish_action();
        let next = battle.select_next_record_unit().expect("next live ship");
        battle.set_current_selection(next);
        assert_eq!(battle.selected, Some(1));
        assert_eq!(battle.current_side, BattleSide::Defender);
        assert_eq!(
            battle.units[1].action_points,
            battle.units[1].base_action_points
        );
    }

    #[test]
    fn navy_outcome_ignores_undeployed_reserve_ships() {
        let mut battle = battle(vec![
            unit(1, BattleSide::Attacker, 7, 0),
            unit(2, BattleSide::Attacker, -2, 0),
            unit(3, BattleSide::Defender, 41, 0),
        ]);
        battle.retire_undeployed(BattleSide::Attacker);
        assert_eq!(battle.sides[0].secondary, vec![1]);
        assert!(!battle.records.contains(&1));
        battle.units[0].state = NavyUnitState::Destroyed;
        battle.evaluate_outcome();
        assert_eq!(
            battle.outcome,
            Some(1),
            "a Ready ship retired to reserve must not keep its side alive"
        );
    }

    fn attach_live_battle(state: &mut GameState, battle: NavyBattle) {
        state.turn.active_nation = NationId::new(0);
        state.turn_flow = TurnFlow::NavalBattle(
            crate::NavyOrdersContinuation::player_encounter(
                TaskForceId::new(1),
                TaskForceId::new(2),
            ),
        );
        state.store_navy_battle(battle);
    }

    #[test]
    fn navy_fire_rejects_a_second_shot_during_the_same_activation() {
        let mut state = game_state();
        let mut battle = battle(vec![
            unit(1, BattleSide::Attacker, 7, 0),
            unit(2, BattleSide::Defender, 8, 0),
        ]);
        battle.units[0].quality = 20;
        battle.compute_reachable(0);
        attach_live_battle(&mut state, battle);
        assert_eq!(state.fire_navy_unit(8), Ok(None));
        assert_eq!(
            state.fire_navy_unit(8),
            Err(NavyActionRejection::InvalidTarget)
        );
    }

    #[test]
    fn navy_fire_rejects_an_out_of_range_shot_without_advancing_rng() {
        let mut state = game_state();
        let battle = battle(vec![
            unit(1, BattleSide::Attacker, 0, 0),
            unit(2, BattleSide::Defender, 6 * DEPLOY_ROW_WIDTH, 0),
        ]);
        attach_live_battle(&mut state, battle);
        let before = state.rng;
        assert_eq!(
            state.fire_navy_unit(6 * DEPLOY_ROW_WIDTH),
            Err(NavyActionRejection::InvalidTarget)
        );
        assert_eq!(state.rng, before);
    }

    #[test]
    fn navy_move_rejects_an_out_of_grid_tile() {
        let mut state = game_state();
        attach_live_battle(
            &mut state,
            battle(vec![unit(1, BattleSide::Attacker, 7, 0)]),
        );
        assert_eq!(
            state.move_navy_unit(TILE_COUNT as i32),
            Err(NavyActionRejection::InvalidTarget)
        );
        assert_eq!(
            state.move_navy_unit(10_000),
            Err(NavyActionRejection::InvalidTarget)
        );
    }

    #[test]
    fn navy_round_limit_completes_the_battle() {
        let mut battle = battle(vec![
            unit(1, BattleSide::Attacker, 7, 0),
            unit(2, BattleSide::Defender, 41, 0),
        ]);
        battle.round = ROUND_LIMIT;
        battle.evaluate_outcome();
        assert_eq!(battle.outcome, Some(1));
    }

    fn encounter_force(
        state: &mut GameState,
        nation: NationId,
        location: OceanZoneId,
        order: TaskForceOrder,
    ) -> (ShipId, TaskForceId) {
        let ship = state.object_ids.ship();
        let force = state.object_ids.task_force();
        state.ships.insert(
            ship,
            ShipState {
                ship_type: ShipType::Frigate,
                location,
                aggression: NavalAggression::Balanced,
                nation,
                name: String::new(),
                strength: 900,
                experience: 0,
                selection: ShipSelection::Available,
            },
        );
        state.task_forces.insert(
            force,
            TaskForceState {
                aggression: NavalAggression::Balanced,
                order,
                target: TaskForceTarget::None,
                location,
                nation,
                defeated: false,
                ingot_tile: -1,
                flagship: Some(ship),
                ships: [(ship, true)].into_iter().collect(),
            },
        );
        (ship, force)
    }

    #[test]
    fn player_as_defender_deployment_reaches_a_live_selected_ship() {
        let mut state = game_state();
        let player = NationId::new(0);
        let hostile = NationId::new(1);
        state.turn.active_nation = player;
        state.diplomacy.relationships[player][hostile] = DiplomaticRelationship::War;
        state.diplomacy.relationships[hostile][player] = DiplomaticRelationship::War;
        encounter_force(
            &mut state,
            hostile,
            OceanZoneId::new(0),
            TaskForceOrder::Patrol,
        );
        encounter_force(
            &mut state,
            player,
            OceanZoneId::new(0),
            TaskForceOrder::Blockade,
        );
        let continuation = state.carry_out_navy_orders().expect("player encounter");
        state.turn_flow = TurnFlow::NavalBattle(continuation);
        state.ensure_navy_battle();
        assert_eq!(
            state.navy_battle().map(NavyBattle::stage),
            Some(NavyBattleStage::Deploying)
        );
        assert_eq!(
            state.navy_battle().map(NavyBattle::current_side),
            Some(BattleSide::Defender)
        );
        let deploy_tile = 5 * DEPLOY_ROW_WIDTH;
        assert!(
            state
                .selected_navy_unit_reachable_tiles()
                .contains(&deploy_tile)
        );
        assert_eq!(
            state.navy_action_at(deploy_tile).expect("deploy click"),
            None
        );
        let battle = state.navy_battle().expect("live battle remains");
        assert_eq!(battle.stage(), NavyBattleStage::Live);
        assert!(state.selected_navy_unit().is_some());
        state.set_navy_targeting(NavyTargeting::Crew);
        assert_eq!(
            state.navy_battle().map(NavyBattle::targeting),
            Some(NavyTargeting::Crew)
        );
    }
}
