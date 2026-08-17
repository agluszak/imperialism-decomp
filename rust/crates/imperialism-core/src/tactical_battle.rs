//! Headless retail `TArmyBattle` Auto: deploy, turn pump, ApplyChanges, post-battle.

#![allow(clippy::if_same_then_else)] // retail cursor-mode branches keep identical arms
#![allow(clippy::needless_range_loop)] // parallel C++ index walks
#![allow(clippy::neg_cmp_op_on_partial_ord)] // retail `!(a < b)` form

use crate::military::{ActionClassScores, ActionClassWeights, TACTICAL_COMPOSITION};
use crate::military_phase::tactical_category;
use crate::tactical_tables::*;
use crate::*;

const OUTCOME_IN_PROGRESS: i32 = 0;
const OUTCOME_SIDE0: i32 = 1;
const OUTCOME_SIDE1: i32 = 2;

#[derive(Clone, Copy)]
struct Tile {
    terrain: i32,
    occupant: Option<usize>,
    deploy_mark: i32,
    mine_run: i32,
    trench_mask: u8,
}

struct TacUnit {
    source: MilitaryUnitId,
    unit_type: usize,
    tile: i32,
    selected: bool,
    state: i32,
    action_points: i32,
    ai_state: i32,
    strength: i32,
    morale: i32,
    quality: i16,
    sap_target: i32,
    flag3c: bool,
    side: i32,
    field24: i16,
    projection: [f32; 5],
}

struct Side {
    is_our: bool,
    ready: bool,
    nation: NationId,
    cursor: i32,
    units: Vec<usize>,
    secondary: Vec<usize>,
    projection_sums: [f32; 5],
    max_range: i16,
    max_non_artillery_range: i16,
    field20: bool,
    field48: i32,
    field51: u8,
    field_f: bool,
    last_cursor_mode: i32,
    random_parity: u8,
    cached_bombard_tile: i32,
}

struct Battle {
    tiles: [Tile; TACTICAL_TILE_COUNT],
    move_costs: [i16; TACTICAL_TILE_COUNT + 1],
    threat: [i8; TACTICAL_TILE_COUNT],
    candidate_scores: [i32; TACTICAL_TILE_COUNT],
    distance_field: [i32; TACTICAL_TILE_COUNT],
    units: Vec<TacUnit>,
    sides: [Side; 2],
    records: Vec<usize>,
    current_side: i32,
    selected: Option<usize>,
    column_count: i32,
    outcome: i32,
    pending_end: bool,
    fort_level: i32,
    fort_strength: [i32; 8],
    battle_site: ProvinceId,
    round: i32,
}

impl GameState {
    /// Headless retail Auto: TArmyPlayer auto-deploy + Auto turn pump + ApplyChanges
    /// + ApplyPostBattleStackOutcomeAndGrowUnitMeters, then remaining combat-moves.
    pub fn auto_resolve_land_battle(&mut self, story_ids: &[i32]) -> TurnStop {
        let crate::turn_flow::TurnContinuation::LandBattle(_) = &self.continuation else {
            panic!("land-battle auto-resolve requires a combat-moves continuation");
        };
        let mut battle = Box::new(Battle::init(self));
        battle.start(self);
        let mut guard = 20_000;
        loop {
            assert!(guard > 0, "tactical auto did not terminate");
            guard -= 1;
            if battle.next_move(self) {
                break;
            }
        }
        self.resume_after_land_battle(story_ids)
    }
}

impl Battle {
    fn init(state: &mut GameState) -> Self {
        let battle = state
            .pending_land_battle()
            .cloned()
            .expect("auto-resolve requires a pending land battle");
        let mut fort_level = i32::from(state.map.provinces[battle.province].fort_level());
        if fort_level > 0 {
            fort_level += 1;
        }
        let composition = classify_city_gate_terrain(state, battle.province);
        let _ = composition;

        let empty_side = |is_our: bool, nation: NationId, parity: u8| Side {
            is_our,
            ready: false,
            nation,
            cursor: 0,
            units: Vec::new(),
            secondary: Vec::new(),
            projection_sums: [0.0; 5],
            max_range: 0,
            max_non_artillery_range: 0,
            field20: false,
            field48: 0,
            field51: 0,
            field_f: false,
            last_cursor_mode: -1,
            random_parity: parity,
            cached_bombard_tile: -1,
        };
        let our_parity = (state.rng.next_crt_rand() & 1) as u8;
        let enemy_parity = (state.rng.next_crt_rand() & 1) as u8;
        let mut this = Self {
            tiles: [Tile {
                terrain: 0,
                occupant: None,
                deploy_mark: 0,
                mine_run: -1,
                trench_mask: 0,
            }; TACTICAL_TILE_COUNT],
            move_costs: [-1; TACTICAL_TILE_COUNT + 1],
            threat: [0; TACTICAL_TILE_COUNT],
            candidate_scores: [0; TACTICAL_TILE_COUNT],
            distance_field: [0; TACTICAL_TILE_COUNT],
            units: Vec::new(),
            sides: [
                empty_side(true, battle.attacker_nation, our_parity),
                empty_side(false, battle.defender_nation, enemy_parity),
            ],
            records: Vec::new(),
            current_side: 1,
            selected: None,
            column_count: 0,
            outcome: OUTCOME_IN_PROGRESS,
            pending_end: false,
            fort_level,
            fort_strength: [0; 8],
            battle_site: battle.province,
            round: 0,
        };

        for &id in &battle.attacker_units {
            if !state.military_units.contains_key(&id) {
                continue;
            }
            this.push_unit(state, id, 0, false);
        }
        for &id in &battle.defender_units {
            if !state.military_units.contains_key(&id) {
                continue;
            }
            this.push_unit(state, id, 1, true);
        }

        for unit in &mut this.units {
            unit.field24 = state.rng.next_crt_rand() as i16;
        }
        this.records.extend(
            this.units
                .iter()
                .enumerate()
                .filter(|(_, unit)| unit.side == 0)
                .map(|(idx, _)| idx),
        );
        this.records.extend(
            this.units
                .iter()
                .enumerate()
                .filter(|(_, unit)| unit.side == 1)
                .map(|(idx, _)| idx),
        );

        this.selected = this.select_next_undeployed(1);
        let mut max_range = 0;
        for &idx in &this.records {
            let range = this.unit_range(idx);
            if range > max_range {
                max_range = range;
            }
        }
        this.column_count = max_range + 11;
        this.load_setup();
        this
    }

    fn push_unit(
        &mut self,
        state: &GameState,
        source: MilitaryUnitId,
        side: i32,
        enemy_selected: bool,
    ) {
        let unit = &state.military_units[&source];
        let unit_type = unit.unit_type as usize;
        let mut record = TacUnit {
            source,
            unit_type,
            tile: -2,
            selected: enemy_selected,
            state: 0,
            action_points: BASE_ACTION_POINTS[unit_type],
            ai_state: 0,
            strength: i32::from(unit.strength),
            morale: i32::from(unit.strength),
            quality: unit.experience / 100,
            sap_target: -1,
            flag3c: unit.order.code() == MilitaryOrderCode::Sleep
                && combat_category(unit.unit_type) == 0,
            side,
            field24: 0,
            projection: [0.0; 5],
        };
        record.action_points = record.base_action_points();
        let idx = self.units.len();
        self.units.push(record);
        self.sides[side as usize].units.push(idx);
    }

    fn load_setup(&mut self) {
        for tile in &mut self.tiles {
            *tile = Tile {
                terrain: 0,
                occupant: None,
                deploy_mark: 0,
                mine_run: -1,
                trench_mask: 0,
            };
        }
        if self.fort_level != 0 {
            let mut tile = self.column_count - 6;
            while tile < TACTICAL_TILE_COUNT as i32 {
                self.tiles[tile as usize].deploy_mark = self.fort_level;
                tile += TACTICAL_STRIDE;
            }
            let points = FORT_STRENGTH_BY_LEVEL[self.fort_level.clamp(0, 5) as usize];
            self.fort_strength = [points; 8];
        }
    }

    fn start(&mut self, state: &mut GameState) {
        self.start_side(state, 1);
        self.start_side(state, 0);
        self.finalize_turn_state(state);
    }

    fn start_side(&mut self, state: &mut GameState, side: i32) {
        self.current_side = side;
        self.selected = self.select_next_undeployed(side);
        self.select_and_apply_cursor_mode(state, side, 1);
        self.auto_deploy(state, side);
    }

    fn auto_deploy(&mut self, state: &mut GameState, side: i32) {
        self.current_side = side;
        let free = self.count_free_deploy_tiles();
        if self.sides[side as usize].units.len() as i32 > free {
            self.prune_to(state, side, free);
        }
        if self.sides[side as usize].is_our {
            self.deploy_attacker(state, side);
        } else {
            self.deploy_defender(state, side);
        }
        self.sides[side as usize].ready = true;
    }

    fn deploy_attacker(&mut self, state: &mut GameState, side: i32) {
        self.sort_side_units(state, side, compare_deploy_priority);
        let units = self.sides[side as usize].units.clone();
        for idx in units {
            let mut best_score = 0;
            let mut best_tile = -1;
            for tile in 0..TACTICAL_TILE_COUNT as i32 {
                if self.deploy_guard(tile) == 0 {
                    continue;
                }
                let row = tile / TACTICAL_STRIDE;
                let column = tile % TACTICAL_STRIDE;
                let ai_class = i32::from(AI_CLASS[self.units[idx].unit_type]);
                let mut score = ATTACKER_DEPLOY_ZONE_SCORES
                    [(2 * (3 * ai_class - column) - (row & 1) + 11) as usize];
                let mut edge = row;
                if edge > 7 {
                    edge = TACTICAL_ROWS - edge;
                }
                score += edge;
                if score > best_score {
                    best_score = score;
                    best_tile = tile;
                }
            }
            self.deploy_to_tile(idx, best_tile);
        }
    }

    fn deploy_defender(&mut self, state: &mut GameState, side: i32) {
        self.sort_side_units(state, side, compare_deploy_priority);
        let units = self.sides[side as usize].units.clone();
        for idx in units {
            let tile = match AI_CLASS[self.units[idx].unit_type] {
                0 => self.select_defender_melee_tile(),
                2 => self.select_defender_artillery_tile(),
                _ => self.select_defender_other_tile(),
            };
            self.deploy_to_tile(idx, tile);
        }
    }

    fn select_defender_artillery_tile(&mut self) -> i32 {
        let mut best_score = 0;
        let mut best_tile = -1;
        for tile in 0..TACTICAL_TILE_COUNT as i32 {
            if self.deploy_guard(tile) == 0 {
                continue;
            }
            let row = tile / TACTICAL_STRIDE;
            let column = tile % TACTICAL_STRIDE;
            let zone_cell = (row & 1) + 2 * (column - self.column_count) + 10;
            let mut score = if zone_cell == 0 {
                10
            } else {
                (7 - zone_cell) * 10
            };
            let mut row_distance = row;
            if row_distance > 7 {
                row_distance = TACTICAL_ROWS - row_distance;
            }
            score += row_distance;
            let mut adjacent_artillery = 0;
            let neighbors = self.neighbors(tile);
            for neighbor in neighbors {
                if neighbor == -1 {
                    continue;
                }
                if let Some(occupant) = self.tiles[neighbor as usize].occupant
                    && AI_CLASS[self.units[occupant].unit_type] == 2
                {
                    adjacent_artillery = 0x64;
                }
            }
            score += adjacent_artillery;
            self.candidate_scores[tile as usize] = score;
            if score > best_score {
                best_score = score;
                best_tile = tile;
            }
        }
        best_tile
    }

    fn select_defender_melee_tile(&self) -> i32 {
        let mut best_score = 0;
        let mut best_tile = -1;
        for tile in 0..TACTICAL_TILE_COUNT as i32 {
            if self.deploy_guard(tile) == 0 {
                continue;
            }
            let row = tile / TACTICAL_STRIDE;
            let column = tile % TACTICAL_STRIDE;
            let mut score = (2 * (self.column_count - column) - (row & 1) - 3) * 10;
            let mut row_distance = row;
            if row_distance > 7 {
                row_distance = TACTICAL_ROWS - row_distance;
            }
            score += row_distance;
            let neighbors = self.neighbors(tile);
            let mut adjacency = 0;
            for neighbor in neighbors {
                if neighbor == -1 {
                    continue;
                }
                if let Some(occupant) = self.tiles[neighbor as usize].occupant {
                    if AI_CLASS[self.units[occupant].unit_type] == 2 {
                        adjacency = 0x64;
                    } else if adjacency == 0 {
                        adjacency = 0xa;
                    }
                }
            }
            score += adjacency;
            if score > best_score {
                best_score = score;
                best_tile = tile;
            }
        }
        best_tile
    }

    fn select_defender_other_tile(&self) -> i32 {
        let mut best_score = 0;
        let mut best_tile = -1;
        for tile in 0..TACTICAL_TILE_COUNT as i32 {
            if self.deploy_guard(tile) == 0 {
                continue;
            }
            let mut row = tile / TACTICAL_STRIDE;
            let mut score = (self.column_count - 5) * 20;
            if row > 7 {
                row = TACTICAL_ROWS - row;
            }
            score += row;
            let neighbors = self.neighbors(tile);
            let mut occupied = 0;
            for neighbor in neighbors {
                if occupied != 0 {
                    break;
                }
                if neighbor != -1 && self.tiles[neighbor as usize].occupant.is_some() {
                    occupied = 0xa;
                }
            }
            score += occupied;
            if score > best_score {
                best_score = score;
                best_tile = tile;
            }
        }
        best_tile
    }

    fn deploy_to_tile(&mut self, unit: usize, tile: i32) {
        let column = tile % TACTICAL_STRIDE;
        if tile < TACTICAL_STRIDE {
            return;
        }
        if self.tiles[tile as usize].terrain == 4 {
            return;
        }
        if self.tiles[tile as usize].occupant.is_some() {
            return;
        }
        if self.current_side == 0 {
            if !(3..=5).contains(&column) {
                return;
            }
        } else if column > self.column_count - 3 || column < self.column_count - 5 {
            return;
        }
        self.place_deployed(unit, tile);
        let side = self.current_side;
        self.selected = self.select_next_undeployed(side);
        self.clear_move_costs();
    }

    fn place_deployed(&mut self, unit: usize, tile: i32) {
        self.units[unit].tile = tile;
        self.tiles[tile as usize].occupant = Some(unit);
        if self.units[unit].flag3c && self.fort_level == 0 {
            self.tiles[tile as usize].deploy_mark = 1;
        }
    }

    fn finalize_turn_state(&mut self, state: &mut GameState) {
        self.retire_undeployed(0);
        self.retire_undeployed(1);
        self.sort_records(state);
        self.selected = self.records.last().copied();
        self.pending_end = false;
    }

    fn retire_undeployed(&mut self, side: i32) {
        let mut ordinal = self.sides[side as usize].units.len() as i32;
        while ordinal > 0 {
            let idx = self.sides[side as usize].units[(ordinal - 1) as usize];
            if self.units[idx].tile == -2 {
                self.sides[side as usize]
                    .units
                    .remove((ordinal - 1) as usize);
                self.sides[side as usize].secondary.insert(0, idx);
            }
            ordinal -= 1;
        }
        for &retired in &self.sides[side as usize].secondary {
            if let Some(pos) = self.records.iter().position(|&idx| idx == retired) {
                self.records.remove(pos);
            }
        }
    }

    fn next_move(&mut self, state: &mut GameState) -> bool {
        if self.outcome != OUTCOME_IN_PROGRESS {
            let side0_won = self.outcome == OUTCOME_SIDE0;
            self.apply_changes(state);
            state.resolve_land_battle(side0_won);
            return true;
        }
        self.pending_end = true;
        self.advance_turn_step(state);
        false
    }

    fn finish_action(&mut self) {
        self.pending_end = false;
    }

    fn advance_turn_step(&mut self, state: &mut GameState) {
        let mut position = if let Some(selected) = self.selected {
            1 + self
                .records
                .iter()
                .position(|&idx| idx == selected)
                .unwrap_or(0) as i32
        } else {
            1
        };
        let candidate = loop {
            let total = self.records.len() as i32;
            if position == total {
                self.round += 1;
                if self.round >= 0x23 {
                    self.evaluate_outcome();
                    self.finish_action();
                    return;
                }
                position = 1;
            } else {
                position += 1;
            }
            let idx = self.records[(position - 1) as usize];
            if self.units[idx].state != 3 {
                break idx;
            }
        };
        self.set_current_selection(candidate);
        if self.units[candidate].state == 1 {
            self.process_morale_broken(state, candidate);
            return;
        }
        if tactical_category_of(self.units[candidate].unit_type) == 8
            && self.units[candidate].sap_target != -1
        {
            self.advance_mine_run(candidate);
            return;
        }
        self.current_side = self.units[candidate].side;
        self.advance_auto_pulse(state, self.current_side);
    }

    fn set_current_selection(&mut self, unit: usize) {
        self.current_side = self.units[unit].side;
        self.units[unit].action_points = self.units[unit].base_action_points();
        self.units[unit].selected = true;
        self.selected = Some(unit);
        self.compute_reachable(unit);
    }

    fn apply_changes(&mut self, state: &mut GameState) {
        for side in 0..2 {
            let lists = [
                self.sides[side].units.clone(),
                self.sides[side].secondary.clone(),
            ];
            for list in lists {
                for idx in list {
                    let source = self.units[idx].source;
                    let strength = self.units[idx].strength as i16;
                    state.military_units[&source].strength = strength;
                    if strength == 0 {
                        detach_unit(state, source);
                    }
                }
            }
        }
    }
}

fn detach_unit(state: &mut GameState, id: MilitaryUnitId) {
    state.military_units[&id].stationed_province = None;
    for mission in state.missions.values_mut() {
        match &mut mission.data {
            MissionData::DefendProvince { army, .. }
            | MissionData::AttackProvince(AttackMissionState { army, .. })
            | MissionData::Invade {
                attack: AttackMissionState { army, .. },
                ..
            } => {
                army.units.shift_remove(&id);
            }
            _ => {}
        }
    }
}

fn combat_category(kind: MilitaryUnitKind) -> i16 {
    AI_CLASS[kind as usize]
}

fn tactical_category_of(unit_type: usize) -> i16 {
    tactical_category(
        MilitaryUnitKind::from_index(unit_type as u8).unwrap_or(MilitaryUnitKind::Minutemen),
    )
}

fn classify_city_gate_terrain(state: &GameState, province: ProvinceId) -> i32 {
    let city = &state.map.provinces[province];
    if let Some(tile) = city.city_tile()
        && state.map[tile].flags.has_base_transport()
    {
        return 3;
    }
    let mut tally_a = 0;
    let mut tally_b = 0;
    let mut tally_c = 0;
    for &tile in &city.linked_tiles {
        let gate = i32::from(state.map[tile].gate);
        if !(1..=15).contains(&gate) {
            continue;
        }
        match GATE_FLAG_SCORE_BUCKET[(gate - 1) as usize] {
            0 => tally_b += 1,
            1 => tally_b += 2,
            2 => tally_a += 2,
            3 => tally_a += 4,
            4 => tally_c += 6,
            _ => {}
        }
    }
    if tally_c > tally_a && tally_c > tally_b {
        2
    } else if tally_a > tally_b {
        1
    } else {
        0
    }
}

fn composition_row(row: usize) -> ActionClassWeights {
    match row {
        1 => TACTICAL_COMPOSITION.fort_siege,
        2 => TACTICAL_COMPOSITION.open_field,
        3 => TACTICAL_COMPOSITION.fort_garrison,
        _ => TACTICAL_COMPOSITION.baseline,
    }
}

fn scores_from(vector: [f32; 5]) -> ActionClassScores {
    ActionClassScores {
        infantry: vector[0],
        cavalry: vector[1],
        artillery: vector[2],
        armor: vector[3],
        support: vector[4],
    }
}

fn compare_deploy_priority(a: &TacUnit, b: &TacUnit) -> i16 {
    const PRIORITY: [i16; 5] = [1, 0, 2, 0, 0];
    let priority_a = PRIORITY[AI_CLASS[a.unit_type] as usize];
    let priority_b = PRIORITY[AI_CLASS[b.unit_type] as usize];
    if priority_a < priority_b {
        1
    } else {
        -i16::from(priority_a != priority_b)
    }
}

fn compare_turn_order(a: &TacUnit, b: &TacUnit) -> i16 {
    let ap_a = a.base_action_points();
    let ap_b = b.base_action_points();
    if ap_b < ap_a {
        return -1;
    }
    if ap_b > ap_a {
        return 1;
    }
    if b.quality < a.quality {
        return -1;
    }
    if b.quality > a.quality {
        return 1;
    }
    i16::from(a.field24 <= b.field24) * 2 - 1
}

fn hex_distance(a: i32, b: i32) -> i32 {
    let row_a = a / TACTICAL_STRIDE;
    let mut col_a = (row_a & 1) + (a % TACTICAL_STRIDE) * 2;
    let mut row_b = b / TACTICAL_STRIDE;
    let mut col_b = (row_b & 1) + (b % TACTICAL_STRIDE) * 2;
    if col_b < col_a {
        col_b = col_a * 2 - col_b;
    }
    if row_b < row_a {
        row_b = row_a * 2 - row_b;
    }
    let row_delta = row_b - row_a;
    col_a = (col_b - row_delta) - col_a;
    if col_a > 0 {
        col_a / 2 + row_delta
    } else {
        row_delta
    }
}

impl TacUnit {
    fn base_action_points(&self) -> i32 {
        BASE_ACTION_POINTS[self.unit_type]
    }
}

impl Battle {
    fn unit_range(&self, idx: usize) -> i32 {
        let mut range = UNIT_RANGE[self.units[idx].unit_type];
        if self.units[idx].side == 1 && combat_category_of(self.units[idx].unit_type) == 2 {
            range += 1;
        }
        range
    }

    fn cost(&self, tile: i32) -> i16 {
        self.move_costs[(tile + 1) as usize]
    }

    fn set_cost(&mut self, tile: i32, value: i16) {
        self.move_costs[(tile + 1) as usize] = value;
    }

    fn clear_move_costs(&mut self) {
        self.move_costs = [-1; TACTICAL_TILE_COUNT + 1];
    }

    fn neighbors(&self, tile: i32) -> [i32; 6] {
        neighbor_list(tile)
    }

    fn deploy_guard(&self, tile: i32) -> u8 {
        let column = tile % TACTICAL_STRIDE;
        if tile < TACTICAL_STRIDE {
            return 0;
        }
        let record = &self.tiles[tile as usize];
        if record.terrain == 4 || record.occupant.is_some() {
            return 0;
        }
        if self.current_side == 0 {
            u8::from((3..=5).contains(&column))
        } else {
            u8::from(column <= self.column_count - 3 && column >= self.column_count - 5)
        }
    }

    fn count_free_deploy_tiles(&self) -> i32 {
        (0..TACTICAL_TILE_COUNT as i32)
            .filter(|&tile| self.deploy_guard(tile) != 0)
            .count() as i32
    }

    fn select_next_undeployed(&mut self, side: i32) -> Option<usize> {
        let list = &self.sides[side as usize].units;
        if list.is_empty() {
            self.sides[side as usize].ready = true;
            return None;
        }
        let start = self.sides[side as usize].cursor;
        let mut scanned = 0;
        loop {
            self.sides[side as usize].cursor += 1;
            if self.sides[side as usize].cursor > list.len() as i32 {
                self.sides[side as usize].cursor = 1;
            }
            let idx = list[(self.sides[side as usize].cursor - 1) as usize];
            if self.units[idx].tile == -2 {
                return Some(idx);
            }
            scanned += 1;
            if self.sides[side as usize].cursor == start || scanned >= list.len() {
                break;
            }
        }
        let idx = list[(self.sides[side as usize].cursor.max(1) - 1) as usize];
        if self.units[idx].tile != -2 {
            self.sides[side as usize].ready = true;
        }
        Some(idx)
    }

    fn sort_side_units(
        &mut self,
        state: &mut GameState,
        side: i32,
        cmp: fn(&TacUnit, &TacUnit) -> i16,
    ) {
        let mut list = std::mem::take(&mut self.sides[side as usize].units);
        retail_sort(&mut list, &mut state.rng, |a, b| {
            cmp(&self.units[a], &self.units[b])
        });
        self.sides[side as usize].units = list;
    }

    fn sort_records(&mut self, state: &mut GameState) {
        let mut list = std::mem::take(&mut self.records);
        retail_sort(&mut list, &mut state.rng, |a, b| {
            compare_turn_order(&self.units[a], &self.units[b])
        });
        self.records = list;
    }

    fn prune_to(&mut self, state: &GameState, side: i32, max_count: i32) {
        let profile_row = if self.sides[side as usize].is_our {
            usize::from(self.fort_level != 0) + 1
        } else {
            0
        };
        let mut secondary = Vec::new();
        for ordinal in (1..=self.sides[side as usize].units.len()).rev() {
            let idx = self.sides[side as usize].units[ordinal - 1];
            self.compute_projection(state, idx);
            secondary.push(idx);
        }
        secondary.reverse();
        self.sides[side as usize].units.clear();
        let mut remaining = max_count;
        if remaining != 0
            && let Some(pos) = secondary
                .iter()
                .position(|&idx| tactical_category_of(self.units[idx].unit_type) == 9)
        {
            let kept = secondary.remove(pos);
            self.sides[side as usize].units.push(kept);
            remaining -= 1;
        }
        let mut kept_sum = [0.0f32; 5];
        for _ in 0..remaining {
            let mut best_ordinal = 0;
            let mut best_score = 0.0f32;
            for candidate_ordinal in 1..secondary.len() {
                let candidate = secondary[candidate_ordinal - 1];
                for component in 0..5 {
                    kept_sum[component] += self.units[candidate].projection[component];
                }
                let score = scores_from(kept_sum).similarity(composition_row(profile_row));
                if score > best_score {
                    best_score = score;
                    best_ordinal = candidate_ordinal as i32;
                }
                for component in 0..5 {
                    kept_sum[component] -= self.units[candidate].projection[component];
                }
            }
            if best_ordinal == 0 || best_ordinal as usize > secondary.len() {
                continue;
            }
            let kept = secondary.remove((best_ordinal - 1) as usize);
            self.sides[side as usize].units.push(kept);
            for component in 0..5 {
                kept_sum[component] += self.units[kept].projection[component];
            }
        }
        self.sides[side as usize].secondary = secondary;
        for &pruned in &self.sides[side as usize].secondary {
            if let Some(pos) = self.records.iter().position(|&idx| idx == pruned) {
                self.records.remove(pos);
            }
        }
    }

    fn compute_projection(&mut self, state: &GameState, idx: usize) {
        let source = &state.military_units[&self.units[idx].source];
        let quality = source.experience / 100;
        let quality_factor = 1.0 - f64::from(quality) * -0.1;
        let strength_term = self.units[idx].strength as f32 * 0.002;
        let scale = strength_term * quality_factor as f32;
        let kind = source.unit_type;
        self.units[idx].projection = [
            f32::from(kind.tactical_attribute(0)) * scale * strength_term,
            f32::from(kind.tactical_attribute(1)) * scale,
            f32::from(kind.tactical_attribute(2)) * scale,
            f32::from(kind.tactical_attribute(3)) * scale,
            f32::from(kind.tactical_attribute(4)) * scale,
        ];
    }

    fn accumulate_metrics(&mut self, state: &GameState, side: i32) {
        self.sides[side as usize].max_non_artillery_range = 0;
        self.sides[side as usize].max_range = 0;
        self.sides[side as usize].projection_sums = [0.0; 5];
        self.sides[side as usize].field51 = 0;
        let units = self.sides[side as usize].units.clone();
        for idx in units {
            if self.units[idx].state != 0 {
                continue;
            }
            self.compute_projection(state, idx);
            for component in 0..5 {
                self.sides[side as usize].projection_sums[component] +=
                    self.units[idx].projection[component];
            }
            let range = self.unit_range(idx) as i16;
            if range > self.sides[side as usize].max_range {
                self.sides[side as usize].max_range = range;
            }
            if AI_CLASS[self.units[idx].unit_type] != 2
                && range > self.sides[side as usize].max_non_artillery_range
            {
                self.sides[side as usize].max_non_artillery_range = range;
            }
            if AI_CLASS[self.units[idx].unit_type] == 2
                || tactical_category_of(self.units[idx].unit_type) == 8
            {
                self.sides[side as usize].field51 = 1;
            }
        }
        let sums = self.sides[side as usize].projection_sums;
        let baseline = scores_from(sums).similarity(TACTICAL_COMPOSITION.baseline);
        let row = if self.fort_level != 0 { 1 } else { 2 };
        self.sides[side as usize].projection_sums[1] =
            scores_from(sums).similarity(composition_row(row));
        self.sides[side as usize].projection_sums[0] = baseline;
    }

    fn site_is_home_capital(&self, state: &GameState, side: i32) -> bool {
        let Some(home) = state.nations.home_tile(self.sides[side as usize].nation) else {
            return false;
        };
        state.map[home].province == Some(self.battle_site)
    }

    fn fort_breached(&self) -> bool {
        if self.fort_level == 0 {
            return true;
        }
        self.fort_strength.iter().any(|&pool| pool <= 0)
    }

    fn opponent_has_artillery(&self, side: i32) -> bool {
        let enemy = 1 - side;
        self.sides[enemy as usize].units.iter().any(|&idx| {
            self.units[idx].tile >= 0
                && AI_CLASS[self.units[idx].unit_type] == 2
                && self.units[idx].state == 0
        })
    }

    fn select_and_apply_cursor_mode(&mut self, state: &GameState, side: i32, _mode: i32) {
        let opponent = 1 - side;
        self.accumulate_metrics(state, side);
        self.accumulate_metrics(state, opponent);
        let opponent_metrics = self.sides[opponent as usize].projection_sums;
        let enemy_has_active = self.sides[opponent as usize]
            .units
            .iter()
            .any(|&idx| self.units[idx].state == 0);
        self.sides[side as usize].field48 = i32::from(!enemy_has_active);
        let mut cursor_mode;
        if !self.sides[side as usize].is_our {
            if !enemy_has_active {
                cursor_mode = 6;
            } else if self.sides[opponent as usize].field51 == 0 && !self.fort_breached() {
                cursor_mode = 7;
            } else if self.sides[side as usize].projection_sums[1] / opponent_metrics[1]
                > CURSOR_STRONG_RATIO
            {
                if self.fort_breached() {
                    cursor_mode = 2;
                } else if self.sides[side as usize].projection_sums[1] / opponent_metrics[1]
                    > CURSOR_OVERWHELM_RATIO
                {
                    cursor_mode = 2;
                } else {
                    cursor_mode = 0;
                }
            } else if self.sides[side as usize].projection_sums[0] / opponent_metrics[1]
                < CURSOR_WEAK_RATIO
                && !self.site_is_home_capital(state, side)
            {
                cursor_mode = 1;
            } else {
                cursor_mode = i32::from(
                    self.sides[side as usize].max_range < self.sides[opponent as usize].max_range,
                ) * 2;
            }
        } else {
            let strength_ratio = self.sides[side as usize].projection_sums[1] / opponent_metrics[0];
            let have_sapper = self.sides[side as usize].units.iter().any(|&idx| {
                tactical_category_of(self.units[idx].unit_type) == 8 && self.units[idx].state == 0
            });
            let have_artillery = self.sides[side as usize]
                .units
                .iter()
                .any(|&idx| AI_CLASS[self.units[idx].unit_type] == 2 && self.units[idx].state == 0);
            if !self.fort_breached() {
                if have_sapper {
                    cursor_mode = 3;
                } else if !have_artillery {
                    cursor_mode = 1;
                } else if self.sides[side as usize].projection_sums[3] / opponent_metrics[3]
                    < CURSOR_ARTILLERY_PARITY
                {
                    cursor_mode = 1;
                } else {
                    cursor_mode = 3;
                }
            } else if !enemy_has_active {
                cursor_mode = 6;
            } else if strength_ratio > CURSOR_STRONG_RATIO {
                cursor_mode = 4;
            } else if !(self.sides[side as usize].projection_sums[3] / opponent_metrics[3]
                < CURSOR_ARTILLERY_SUPERIORITY)
                && have_artillery
            {
                cursor_mode = 3;
            } else if !(strength_ratio < CURSOR_ASSAULT_RATIO) {
                cursor_mode = 4;
            } else if strength_ratio < CURSOR_RETREAT_RATIO
                && !self.site_is_home_capital(state, side)
            {
                cursor_mode = 1;
            } else {
                cursor_mode = 5;
            }
        }
        if self.sides[side as usize].field_f {
            cursor_mode = 1;
        }
        if cursor_mode == 1 {
            self.sides[side as usize].field48 = cursor_mode;
        }
        if cursor_mode == self.sides[side as usize].last_cursor_mode {
            return;
        }
        self.sides[side as usize].last_cursor_mode = cursor_mode;
        self.apply_stance(side, cursor_mode);
    }

    fn apply_stance(&mut self, side: i32, mode: i32) {
        match mode {
            0 => self.stance_hold(side),
            1 => self.stance_retreat(side),
            2 => self.stance_bombard(side),
            3 => self.stance_siege(side),
            4 => self.stance_assault(side),
            5 => self.stance_standoff(side),
            6 => self.stance_unopposed(side),
            7 => self.stance_garrison(side),
            _ => {}
        }
    }

    fn stance_retreat(&mut self, side: i32) {
        for &idx in &self.sides[side as usize].units.clone() {
            self.units[idx].ai_state = if tactical_category_of(self.units[idx].unit_type) != 0 {
                0xc
            } else {
                7
            };
        }
    }

    fn stance_garrison(&mut self, side: i32) {
        for &idx in &self.sides[side as usize].units.clone() {
            self.units[idx].ai_state = 0x13;
        }
    }

    fn stance_hold(&mut self, side: i32) {
        for &idx in &self.sides[side as usize].units.clone() {
            if self.units[idx].state != 0 {
                continue;
            }
            self.units[idx].ai_state = match AI_CLASS[self.units[idx].unit_type] {
                0 => 0,
                2 => 9,
                1 | 3 => 0xe,
                4 if self.units[idx].unit_type >= 0x1b => 0xb,
                4 => 0xc,
                _ => self.units[idx].ai_state,
            };
        }
    }

    fn stance_bombard(&mut self, side: i32) {
        for &idx in &self.sides[side as usize].units.clone() {
            if self.units[idx].state != 0 {
                continue;
            }
            self.units[idx].ai_state = match AI_CLASS[self.units[idx].unit_type] {
                0 => 7,
                2 => 8,
                1 | 3 => 5,
                4 if self.units[idx].unit_type >= 0x1b => 0xb,
                4 => 0xc,
                _ => self.units[idx].ai_state,
            };
        }
    }

    fn stance_siege(&mut self, side: i32) {
        let enemy_artillery = self.opponent_has_artillery(side);
        let opponent_range = self.sides[(1 - side) as usize].max_non_artillery_range;
        let wall_up = self.tiles[174].deploy_mark > 1;
        for &idx in &self.sides[side as usize].units.clone() {
            if tactical_category_of(self.units[idx].unit_type) == 8 {
                self.units[idx].ai_state = if wall_up { 0xd } else { 0xc };
                continue;
            }
            self.units[idx].ai_state =
                match AI_CLASS[self.units[idx].unit_type] {
                    0 if self.unit_range(idx) > i32::from(opponent_range) => 0x11,
                    0 if tactical_category_of(self.units[idx].unit_type) == 1 => {
                        if enemy_artillery { 0x10 } else { 0xa }
                    }
                    0 => 1,
                    1 | 3 => 0xe,
                    2 if tactical_category_of(self.units[idx].unit_type) == 6 => 0x11,
                    2 => 8,
                    4 => 0xb,
                    _ => self.units[idx].ai_state,
                };
        }
    }

    fn stance_assault(&mut self, side: i32) {
        self.stance_assault_or_standoff(side, 5);
    }

    fn stance_standoff(&mut self, side: i32) {
        self.stance_assault_or_standoff(side, 2);
    }

    fn stance_assault_or_standoff(&mut self, side: i32, flank: i32) {
        let enemy_artillery = self.opponent_has_artillery(side);
        let opponent_range = self.sides[(1 - side) as usize].max_non_artillery_range;
        for &idx in &self.sides[side as usize].units.clone() {
            self.units[idx].ai_state =
                match AI_CLASS[self.units[idx].unit_type] {
                    0 if self.unit_range(idx) > i32::from(opponent_range) => 0x11,
                    0 if tactical_category_of(self.units[idx].unit_type) == 1 => {
                        if enemy_artillery { 0x10 } else { 0xa }
                    }
                    0 => 7,
                    1 | 3 => flank,
                    2 if tactical_category_of(self.units[idx].unit_type) == 6 => 0x11,
                    2 => 8,
                    4 if tactical_category_of(self.units[idx].unit_type) == 8 => 0xc,
                    4 => 0xb,
                    _ => self.units[idx].ai_state,
                };
        }
    }

    fn stance_unopposed(&mut self, side: i32) {
        for &idx in &self.sides[side as usize].units.clone() {
            self.units[idx].ai_state = match AI_CLASS[self.units[idx].unit_type] {
                0 => 7,
                1 | 3 => 5,
                2 => 8,
                4 if tactical_category_of(self.units[idx].unit_type) == 8 => 0xc,
                4 => 0xb,
                _ => self.units[idx].ai_state,
            };
        }
    }

    fn advance_auto_pulse(&mut self, state: &mut GameState, side: i32) {
        if self.sides[side as usize].field20 {
            let selected = self.selected;
            for &idx in &self.sides[side as usize].units.clone() {
                if tactical_category_of(self.units[idx].unit_type) == 8
                    && self.units[idx].state == 0
                {
                    if selected
                        .is_none_or(|sel| tactical_category_of(self.units[sel].unit_type) != 8)
                    {
                        self.finish_action();
                        return;
                    }
                    self.sides[side as usize].field20 = false;
                    return;
                }
            }
            self.sides[side as usize].field20 = false;
            return;
        }
        self.run_auto_controller(state, side);
    }

    fn run_auto_controller(&mut self, state: &mut GameState, side: i32) {
        let Some(unit) = self.selected else {
            self.finish_action();
            return;
        };
        if AI_CLASS[self.units[unit].unit_type] != 2 || self.units[unit].side == 1 {
            self.select_and_apply_cursor_mode(state, side, 0);
        }
        let home = self.units[unit].tile;
        let category = tactical_category_of(self.units[unit].unit_type);
        let mut target = if category == 8 && self.units[unit].ai_state != 0xc {
            if self.fort_breached() {
                self.best_tile(state, unit, side, 12)
            } else if self.tiles[home as usize].trench_mask != 0 || self.threat[home as usize] != 0
            {
                home
            } else {
                self.best_tile(state, unit, side, 13)
            }
        } else if (self.units[unit].ai_state == 5
            || self.units[unit].ai_state == 2
            || category == 4)
            && self.round < 2
        {
            home
        } else if category == 6 && self.round < 2 {
            self.best_tile(state, unit, side, 18)
        } else {
            self.best_tile(state, unit, side, self.units[unit].ai_state)
        };
        if target == -1 {
            target = self.units[unit].tile;
        }
        if target != self.units[unit].tile {
            let mut guard = 200;
            while self.pending_end && self.units[unit].state == 0 && self.units[unit].tile != target
            {
                if guard == 0 {
                    break;
                }
                guard -= 1;
                self.move_and_maybe_finish(state, unit, target);
            }
        }
        if self.pending_end && self.units[unit].state == 0 {
            if self.units[unit].unit_type >= 0x1b {
                let neighbors = self.neighbors(self.units[unit].tile);
                let mut rally = None;
                for neighbor in neighbors {
                    if neighbor == -1 {
                        continue;
                    }
                    if let Some(occupant) = self.tiles[neighbor as usize].occupant
                        && self.units[occupant].side == self.units[unit].side
                        && self.units[occupant].morale < self.units[occupant].strength
                    {
                        rally = Some(occupant);
                        break;
                    }
                }
                if let Some(target_unit) = rally {
                    self.rally(state, unit, target_unit);
                }
            } else if tactical_category_of(self.units[unit].unit_type) == 8 {
                if self.units[unit].tile == home {
                    while self.units[unit].action_points
                        >= BASE_ACTION_POINTS[self.units[unit].unit_type] / 2
                    {
                        let wall = self.units[unit].tile + 1;
                        if wall < 0 || wall >= TACTICAL_TILE_COUNT as i32 {
                            break;
                        }
                        if self.tiles[wall as usize].deploy_mark > 1 {
                            self.mine(state, unit, wall);
                            return;
                        }
                        if self.tiles[wall as usize].occupant.is_none()
                            && self.tiles[wall as usize].trench_mask == 0
                        {
                            self.dig(state, unit, wall);
                        } else {
                            break;
                        }
                    }
                }
            } else if self.units[unit].selected {
                let fire_tile = self.best_target(state, unit, side, true);
                let fire_target = if fire_tile != -1 {
                    self.tiles[fire_tile as usize].occupant
                } else {
                    None
                };
                if let Some(target_unit) = fire_target {
                    let tile = self.units[target_unit].tile;
                    self.fire_and_maybe_finish(state, unit, tile);
                    if self.pending_end
                        && AI_CLASS[self.units[unit].unit_type] == 1
                        && self.units[unit].action_points != 0
                    {
                        let ai_state = self.units[unit].ai_state;
                        if ai_state == 2 || ai_state == 5 || ai_state == 0xe {
                            let advance = self.best_tile(state, unit, side, ai_state + 1);
                            if advance != self.units[unit].tile {
                                let mut guard = 200;
                                while self.selected == Some(unit)
                                    && self.units[unit].state == 0
                                    && self.units[unit].tile != advance
                                {
                                    if guard == 0 {
                                        break;
                                    }
                                    guard -= 1;
                                    self.move_and_maybe_finish(state, unit, advance);
                                }
                            }
                        }
                    }
                }
            }
        }
        if self.pending_end {
            self.finish_action();
        }
    }

    fn best_tile(&mut self, state: &mut GameState, unit: usize, side: i32, row: i32) -> i32 {
        let row = row.clamp(0, 19) as usize;
        self.select_best_tile(state, unit, side, HEURISTIC_WEIGHTS[row])
    }

    fn select_best_tile(
        &mut self,
        state: &mut GameState,
        unit: usize,
        side: i32,
        weights: [i32; 15],
    ) -> i32 {
        let mut best_tile = -1;
        let mut best_score = -99999;
        let mut distance_built = false;
        if weights[8] > 0 {
            self.build_distance_field(self.sides[side as usize].is_our);
            distance_built = true;
        }
        for tile in 0..TACTICAL_TILE_COUNT as i32 {
            let column = tile % TACTICAL_STRIDE;
            if self.cost(tile) == -1 {
                self.candidate_scores[tile as usize] = 0;
                continue;
            }
            if !distance_built && (column == 0 || column == self.column_count - 1) {
                self.candidate_scores[tile as usize] = 0;
                continue;
            }
            let mut score = 0;
            for heuristic in 0..15 {
                if weights[heuristic] != 0 {
                    score += self.score_heuristic(state, unit, side, tile, heuristic)
                        * weights[heuristic];
                }
            }
            let cheaper = best_tile != -1 && self.cost(tile) < self.cost(best_tile);
            if score > best_score || (score == best_score && (best_tile == -1 || cheaper)) {
                best_tile = tile;
                best_score = score;
            }
            self.candidate_scores[tile as usize] = score;
        }
        best_tile
    }

    fn score_heuristic(
        &mut self,
        state: &mut GameState,
        unit: usize,
        side: i32,
        tile: i32,
        heuristic: usize,
    ) -> i32 {
        match heuristic {
            0 => i32::from(self.units[unit].tile == tile) * 0x64,
            1 => self.score_fire_opportunity(state, unit, side, tile),
            2 => self.score_sapper_column(unit, tile),
            3 => self.score_adjacent_enemy(unit, side, tile),
            4 => self.score_exposure(unit, side, tile, false),
            5 => self.score_retreat_edge(side, tile),
            6 => {
                let terrain = self.tiles[tile as usize].terrain;
                i32::from(terrain == 1 || terrain == 2) * 0x64
            }
            7 => self.score_rally(unit, tile),
            8 => {
                let value = self.distance_field[tile as usize];
                if value != -1 { 0x64 - value } else { 0 }
            }
            9 => self.score_artillery_spacing(side, tile),
            10 => self.score_firing_lane(tile),
            11 => self.score_exposure(unit, side, tile, true),
            12 => self.score_standoff(state, unit, side, tile),
            13 => self.score_hunt_artillery(unit, tile),
            14 => i32::from(tile % TACTICAL_STRIDE > self.column_count - 5) * 0x64,
            _ => 0,
        }
    }

    fn score_fire_opportunity(
        &mut self,
        state: &mut GameState,
        unit: usize,
        side: i32,
        tile: i32,
    ) -> i32 {
        let _ = self.unit_range(unit);
        let mut score = 0;
        let mut scan = 0;
        while score == 0 && scan < TACTICAL_TILE_COUNT as i32 {
            if let Some(occupant) = self.tiles[scan as usize].occupant
                && self.units[occupant].side != self.units[unit].side
                && (self.units[occupant].state == 0 || self.sides[side as usize].field48 == 1)
            {
                let category = tactical_category_of(self.units[unit].unit_type);
                if self.reachable_for_action(
                    tile,
                    scan,
                    DIRECT_FIRE[category as usize] != 0.0,
                    self.unit_range(unit),
                ) {
                    score = 0x32;
                }
            }
            scan += 1;
        }
        let target = self.best_target(state, unit, side, false);
        if target != -1 && (AI_CLASS[self.units[unit].unit_type] != 2 || score == 0) {
            score += 0x32 - hex_distance(tile, target);
        }
        score
    }

    fn score_sapper_column(&self, unit: usize, tile: i32) -> i32 {
        if tile % TACTICAL_STRIDE != 6 {
            return 0;
        }
        let mut score = if self.tiles[tile as usize].deploy_mark != 0 {
            0x14
        } else {
            0
        } + 0x50;
        if tile + 1 < TACTICAL_TILE_COUNT as i32
            && let Some(right) = self.tiles[(tile + 1) as usize].occupant
            && self.units[right].side == self.units[unit].side
        {
            score -= 0x14;
        }
        if tile > 0
            && let Some(left) = self.tiles[(tile - 1) as usize].occupant
            && self.units[left].side == self.units[unit].side
        {
            score -= 0x14;
        }
        score
    }

    fn score_adjacent_enemy(&self, unit: usize, side: i32, tile: i32) -> i32 {
        for neighbor in self.neighbors(tile) {
            if neighbor == -1 {
                continue;
            }
            if let Some(occupant) = self.tiles[neighbor as usize].occupant
                && self.units[occupant].side != self.units[unit].side
                && (self.units[occupant].state == 0 || self.sides[side as usize].field48 == 1)
            {
                return 0x64;
            }
        }
        0
    }

    fn score_exposure(&self, _unit: usize, side: i32, tile: i32, artillery_only: bool) -> i32 {
        let enemy = 1 - side;
        let mut count = 0;
        for &idx in &self.sides[enemy as usize].units {
            if self.units[idx].tile < 0 {
                continue;
            }
            if artillery_only && AI_CLASS[self.units[idx].unit_type] != 2 {
                continue;
            }
            let category = tactical_category_of(self.units[idx].unit_type);
            if self.reachable_for_action(
                tile,
                self.units[idx].tile,
                DIRECT_FIRE[category as usize] != 0.0,
                self.unit_range(idx),
            ) {
                count += 1;
            }
        }
        count
    }

    fn score_retreat_edge(&self, side: i32, tile: i32) -> i32 {
        let row = tile / TACTICAL_STRIDE;
        if self.sides[side as usize].random_parity != 0 {
            if row <= 1 {
                0x64
            } else {
                (0xf - row) * 50 / 15
            }
        } else if row >= 0xd {
            0x64
        } else {
            row * 50 / 15
        }
    }

    fn score_rally(&self, unit: usize, tile: i32) -> i32 {
        for neighbor in self.neighbors(tile) {
            if neighbor == -1 {
                continue;
            }
            if let Some(occupant) = self.tiles[neighbor as usize].occupant
                && self.units[occupant].side == self.units[unit].side
                && self.units[occupant].morale < self.units[occupant].strength
            {
                return 0x64;
            }
        }
        0
    }

    fn score_artillery_spacing(&self, side: i32, tile: i32) -> i32 {
        let mut best = 0;
        for &idx in &self.sides[side as usize].units {
            if AI_CLASS[self.units[idx].unit_type] != 2 {
                continue;
            }
            let distance = hex_distance(tile, self.units[idx].tile);
            if distance <= 2 {
                return 0;
            }
            let score = 0x64 - distance * 100 / 10;
            if score > best {
                best = score;
            }
        }
        best
    }

    fn score_firing_lane(&self, tile: i32) -> i32 {
        let column = tile % TACTICAL_STRIDE;
        let wall = self.column_count - 6;
        if column < wall {
            for scan in column..wall {
                let scan_tile = tile - column + scan;
                if self.tiles[scan_tile as usize].terrain == 4 {
                    return 0;
                }
            }
        }
        if self.threat[tile as usize] != 0 || column > wall {
            return 0;
        }
        column
    }

    fn score_standoff(&mut self, state: &mut GameState, unit: usize, side: i32, tile: i32) -> i32 {
        let range = self.unit_range(unit);
        let mut score = 0;
        let target = self.best_target(state, unit, side, false);
        let category = tactical_category_of(self.units[unit].unit_type);
        for scan in 0..TACTICAL_TILE_COUNT as i32 {
            if let Some(occupant) = self.tiles[scan as usize].occupant
                && self.units[occupant].side != self.units[unit].side
                && self.units[occupant].state == 0
                && self.reachable_for_action(
                    tile,
                    scan,
                    DIRECT_FIRE[category as usize] != 0.0,
                    range,
                )
            {
                let candidate = hex_distance(tile, scan) + 0x32;
                if score == 0 || candidate < score {
                    score = candidate;
                }
            }
        }
        if score > 0 {
            if target != -1
                && self.reachable_for_action(
                    tile,
                    target,
                    DIRECT_FIRE[category as usize] != 0.0,
                    range,
                )
            {
                score += 5;
            }
            if score > 0 {
                return score;
            }
        }
        if target != -1 {
            0x32 - hex_distance(tile, target)
        } else {
            0
        }
    }

    fn score_hunt_artillery(&self, unit: usize, tile: i32) -> i32 {
        let range = self.unit_range(unit);
        let category = tactical_category_of(self.units[unit].unit_type);
        for scan in 0..TACTICAL_TILE_COUNT as i32 {
            if let Some(occupant) = self.tiles[scan as usize].occupant
                && self.units[occupant].side != self.units[unit].side
                && self.units[occupant].state == 0
                && AI_CLASS[self.units[occupant].unit_type] == 2
                && self.reachable_for_action(
                    tile,
                    scan,
                    DIRECT_FIRE[category as usize] != 0.0,
                    range,
                )
            {
                return 0x64;
            }
        }
        0
    }

    fn best_target(
        &mut self,
        state: &mut GameState,
        unit: usize,
        side: i32,
        require_reach: bool,
    ) -> i32 {
        let enemy = 1 - side;
        let neighbors = self.neighbors(self.units[unit].tile);
        let mut best_tile = -1;
        let mut best_score = 0;
        const VALUE: [i32; 10] = [
            0x1f4, 0x1f4, 0x1f4, 0x1f4, 0x258, 0x2bc, 0x320, 0x384, 0x64, 0x190,
        ];
        for &idx in &self.sides[enemy as usize].units.clone() {
            let broken_ok = self.sides[side as usize].field48 == 1 && self.units[idx].state == 1;
            if !broken_ok && self.units[idx].state != 0 {
                continue;
            }
            if require_reach {
                let category = tactical_category_of(self.units[unit].unit_type);
                if !self.reachable_for_action(
                    self.units[unit].tile,
                    self.units[idx].tile,
                    DIRECT_FIRE[category as usize] != 0.0,
                    self.unit_range(unit),
                ) {
                    continue;
                }
            }
            let category = tactical_category_of(self.units[idx].unit_type) as usize;
            let mut score = VALUE[category.min(9)];
            if self.sides[side as usize].field48 == 1 {
                score += 0x1f4 - self.units[idx].morale;
            } else {
                score += self.units[idx].strength;
            }
            let record_tile = self.units[idx].tile;
            let adjacent = neighbors.contains(&record_tile);
            if adjacent {
                if self.tiles[record_tile as usize].deploy_mark == 1 {
                    score += score;
                }
                if AI_CLASS[self.units[unit].unit_type] == 1 {
                    score += score;
                }
            }
            if best_tile == -1 || score > best_score {
                best_tile = record_tile;
                best_score = score;
            }
        }
        if best_tile == -1
            && self.units[unit].side == 0
            && DIRECT_FIRE[tactical_category_of(self.units[unit].unit_type) as usize] == 0.0
            && !self.fort_breached()
        {
            if self.sides[side as usize].cached_bombard_tile == -1 {
                loop {
                    let rolled = (state.rng.next_crt_rand() % 0xd) * 29 + self.column_count + 0x17;
                    self.sides[side as usize].cached_bombard_tile = rolled;
                    if self.fort_gun_slot(rolled) == 0 {
                        break;
                    }
                }
            }
            best_tile = self.sides[side as usize].cached_bombard_tile;
        }
        best_tile
    }

    fn fort_gun_slot(&self, tile: i32) -> u8 {
        let row = tile / TACTICAL_STRIDE;
        let doubled = (row & 1) + (tile % TACTICAL_STRIDE) * 2;
        u8::from((row == 5 || row == 7 || row == 9) && doubled / 2 == self.column_count - 6)
    }

    fn evaluate_outcome(&mut self) {
        let mut live = [false; 2];
        for &idx in &self.records {
            if self.units[idx].state == 0 || self.units[idx].state == 1 {
                live[self.units[idx].side as usize] = true;
                if live[0] && live[1] {
                    break;
                }
            }
        }
        if live[0] && live[1] && self.round < 0x23 {
            return;
        }
        self.outcome = if live[0] && self.round < 0x23 {
            OUTCOME_SIDE0
        } else {
            OUTCOME_SIDE1
        };
    }
}

fn combat_category_of(unit_type: usize) -> i16 {
    AI_CLASS[unit_type]
}

fn neighbor_list(tile: i32) -> [i32; 6] {
    let mut out = if (tile / TACTICAL_STRIDE) & 1 != 0 {
        [
            tile - TACTICAL_STRIDE + 1,
            tile + 1,
            tile + TACTICAL_STRIDE + 1,
            tile + TACTICAL_STRIDE,
            tile - 1,
            tile - TACTICAL_STRIDE,
        ]
    } else {
        [
            tile - TACTICAL_STRIDE,
            tile + 1,
            tile + TACTICAL_STRIDE,
            tile + TACTICAL_STRIDE - 1,
            tile - 1,
            tile - TACTICAL_STRIDE - 1,
        ]
    };
    if (tile + 1) % TACTICAL_STRIDE == 0 {
        out[1] = -1;
        if (tile / TACTICAL_STRIDE) & 1 != 0 {
            out[0] = -1;
            out[2] = -1;
        }
    } else if tile % TACTICAL_STRIDE == 0 {
        out[4] = -1;
        if (tile / TACTICAL_STRIDE) & 1 == 0 {
            out[3] = -1;
            out[5] = -1;
        }
    }
    if tile >= TACTICAL_TILE_COUNT as i32 - TACTICAL_STRIDE {
        out[2] = -1;
        out[3] = -1;
    } else if tile < TACTICAL_STRIDE {
        out[0] = -1;
        out[5] = -1;
    }
    out
}

fn retail_sort(
    list: &mut [usize],
    rng: &mut crate::rng::RngState,
    cmp: impl Fn(usize, usize) -> i16,
) {
    if !list.is_empty() {
        // TSortedList comparators return 0 for the same object; without that, Hoare
        // partition can return `hi` unchanged and QuickSort(lo, hi) never shrinks.
        retail_quicksort(list, 1, list.len() as i32, rng, &|a, b| {
            if a == b { 0 } else { cmp(a, b) }
        });
    }
}

fn retail_quicksort(
    list: &mut [usize],
    lo: i32,
    hi: i32,
    rng: &mut crate::rng::RngState,
    cmp: &impl Fn(usize, usize) -> i16,
) {
    if lo < hi {
        let pivot = retail_partition(list, lo, hi, rng, cmp);
        retail_quicksort(list, lo, pivot, rng, cmp);
        retail_quicksort(list, pivot + 1, hi, rng, cmp);
    }
}

fn retail_partition(
    list: &mut [usize],
    lo: i32,
    hi: i32,
    rng: &mut crate::rng::RngState,
    cmp: &impl Fn(usize, usize) -> i16,
) -> i32 {
    let mut pivot_ordinal = lo;
    if lo != hi {
        pivot_ordinal = rng.next_crt_rand() % (hi - lo).abs() + lo;
    }
    list.swap((lo - 1) as usize, (pivot_ordinal - 1) as usize);
    retail_partition_core(list, lo, hi, cmp)
}

fn retail_partition_core(
    list: &mut [usize],
    lo: i32,
    hi: i32,
    cmp: &impl Fn(usize, usize) -> i16,
) -> i32 {
    if lo >= hi {
        return hi;
    }
    let pivot = list[(lo - 1) as usize];
    let mut below = lo - 1;
    let mut above = hi + 1;
    loop {
        loop {
            above -= 1;
            if cmp(pivot, list[(above - 1) as usize]) > -1 {
                break;
            }
        }
        loop {
            below += 1;
            if cmp(pivot, list[(below - 1) as usize]) < 1 {
                break;
            }
        }
        if above <= below {
            return above;
        }
        list.swap((below - 1) as usize, (above - 1) as usize);
    }
}

impl Battle {
    fn compute_reachable(&mut self, unit: usize) {
        let category = tactical_category_of(self.units[unit].unit_type) as usize;
        let action_points = self.units[unit].action_points;
        self.clear_move_costs();
        let start = self.units[unit].tile;
        if start < 0 || start >= TACTICAL_TILE_COUNT as i32 {
            return;
        }
        let edge_column = if self.units[unit].side == 0 {
            self.column_count - 1
        } else {
            0
        };
        self.set_cost(start, 0);
        let mut cost_level = 0;
        while cost_level <= action_points {
            let mut column = 0;
            for tile in TACTICAL_STRIDE..TACTICAL_TILE_COUNT as i32 {
                if column < self.column_count
                    && column != edge_column
                    && self.cost(tile) >= cost_level as i16
                {
                    let neighbors = self.neighbors(tile);
                    for direction in 0..6 {
                        let neighbor = neighbors[direction];
                        let neighbor_index = neighbor as i16;
                        if neighbor_index == -1 {
                            continue;
                        }
                        let record = self.tiles[neighbor as usize];
                        if record.occupant.is_some() || neighbor < TACTICAL_STRIDE {
                            continue;
                        }
                        if record.deploy_mark > 1
                            && self.fort_strength[(neighbor / TACTICAL_STRIDE / 2) as usize] > 0
                        {
                            let wall_row = neighbor / TACTICAL_STRIDE;
                            let wall_column = neighbor % TACTICAL_STRIDE;
                            if wall_row != 5 && wall_row != 7 && wall_row != 9 {
                                continue;
                            }
                            if ((wall_row & 1) + wall_column * 2) / 2 != self.column_count - 6 {
                                continue;
                            }
                            if self.units[unit].side != 1 {
                                continue;
                            }
                        }
                        let new_cost =
                            MOVE_COST[category * 5 + record.terrain as usize] + self.cost(tile);
                        if i32::from(new_cost) > action_points {
                            continue;
                        }
                        let existing = self.cost(neighbor);
                        if existing != -1 && existing <= new_cost {
                            continue;
                        }
                        let mut blocked = false;
                        let prev_direction = if direction > 0 { direction - 1 } else { 5 };
                        let prev_neighbor = neighbors[prev_direction];
                        if prev_neighbor != -1
                            && let Some(prev) = self.tiles[prev_neighbor as usize].occupant
                            && self.units[prev].side != self.units[unit].side
                        {
                            blocked = true;
                        }
                        let next_direction = if direction >= 5 { 0 } else { 1 };
                        let next_neighbor = neighbors[next_direction];
                        if next_neighbor != -1
                            && let Some(next) = self.tiles[next_neighbor as usize].occupant
                            && self.units[next].side != self.units[unit].side
                        {
                            blocked = true;
                        }
                        if blocked || neighbor % TACTICAL_STRIDE == edge_column {
                            continue;
                        }
                        self.set_cost(neighbor, new_cost);
                    }
                }
                column += 1;
                if column == TACTICAL_STRIDE {
                    column = 0;
                }
            }
            cost_level += 10;
        }
        self.propagate_threat(unit);
    }

    fn propagate_threat(&mut self, unit: usize) {
        let side = self.units[unit].side;
        for tile in 0..TACTICAL_TILE_COUNT {
            if let Some(occupant) = self.tiles[tile].occupant
                && self.units[occupant].side != side
                && self.units[occupant].state == 0
            {
                self.threat[tile] = (self.unit_range(occupant) + 1) as i8;
            } else {
                self.threat[tile] = 0;
            }
        }
        for level in (1..=0x13).rev() {
            for tile in 0..TACTICAL_TILE_COUNT {
                if self.threat[tile] == level {
                    for neighbor in self.neighbors(tile as i32) {
                        if neighbor != -1 && self.threat[neighbor as usize] < level - 1 {
                            self.threat[neighbor as usize] = level - 1;
                        }
                    }
                }
            }
        }
    }

    fn build_distance_field(&mut self, our_side: bool) {
        self.distance_field = [-1; TACTICAL_TILE_COUNT];
        if our_side {
            let mut row_start = 0;
            while row_start < TACTICAL_TILE_COUNT as i32 {
                if self.tiles[row_start as usize].terrain != 4 {
                    self.distance_field[row_start as usize] = 0;
                }
                row_start += TACTICAL_STRIDE;
            }
        } else {
            let mut row_start = 0;
            while row_start < TACTICAL_TILE_COUNT as i32 {
                let edge = self.column_count + row_start - 1;
                if self.tiles[edge as usize].terrain != 4 {
                    self.distance_field[edge as usize] = 0;
                }
                row_start += TACTICAL_STRIDE;
            }
        }
        let mut distance = 0;
        loop {
            let mut expanded = false;
            for tile in 0..TACTICAL_TILE_COUNT {
                if self.distance_field[tile] != distance {
                    continue;
                }
                for neighbor in self.neighbors(tile as i32) {
                    if neighbor == -1 || self.distance_field[neighbor as usize] != -1 {
                        continue;
                    }
                    let record = self.tiles[neighbor as usize];
                    if record.occupant.is_some() {
                        continue;
                    }
                    if record.deploy_mark > 1 {
                        let wall_row = neighbor / TACTICAL_STRIDE;
                        if self.fort_strength[(wall_row / 2) as usize] > 0 {
                            let doubled = (wall_row & 1) + (neighbor % TACTICAL_STRIDE) * 2;
                            if wall_row != 5 && wall_row != 7 && wall_row != 9 {
                                continue;
                            }
                            if doubled / 2 != self.column_count - 6 {
                                continue;
                            }
                            if our_side {
                                continue;
                            }
                        }
                    }
                    if record.terrain != 4 {
                        expanded = true;
                        self.distance_field[neighbor as usize] = distance + 1;
                    }
                }
            }
            distance += 1;
            if !expanded {
                break;
            }
        }
    }

    fn reachable_for_action(
        &self,
        attacker_tile: i32,
        target_tile: i32,
        direct_fire: bool,
        range: i32,
    ) -> bool {
        if hex_distance(attacker_tile, target_tile) > range {
            return false;
        }
        let target = &self.tiles[target_tile as usize];
        if let Some(occupant) = target.occupant
            && tactical_category_of(self.units[occupant].unit_type) == 8
            && target.trench_mask != 0
        {
            let neighbors = self.neighbors(attacker_tile);
            if !neighbors.contains(&target_tile) {
                return false;
            }
        }
        if !direct_fire {
            return true;
        }
        let wall = self.wall_on_firing_line(target_tile, attacker_tile);
        if wall == 0 {
            return true;
        }
        if self.tiles[wall as usize].deploy_mark <= 1 {
            return true;
        }
        if self.fort_strength[(wall / TACTICAL_STRIDE / 2) as usize] <= 0 {
            return true;
        }
        let target_column = target_tile % TACTICAL_STRIDE;
        let attacker_column = attacker_tile % TACTICAL_STRIDE;
        target_column <= self.column_count - 5 || attacker_column == self.column_count - 5
    }

    fn wall_on_firing_line(&self, target: i32, attacker: i32) -> i32 {
        let wall_x = (2 * self.column_count - 12) as f32;
        let mut x1 = 2 * (target % TACTICAL_STRIDE) + ((target / TACTICAL_STRIDE) & 1);
        let mut y1 = 2 * (target / TACTICAL_STRIDE);
        let mut x2 = 2 * (attacker % TACTICAL_STRIDE) + ((attacker / TACTICAL_STRIDE) & 1);
        let mut y2 = 2 * (attacker / TACTICAL_STRIDE);
        if x2 == x1 {
            return 0;
        }
        if x2 > x1 {
            std::mem::swap(&mut x1, &mut x2);
            std::mem::swap(&mut y1, &mut y2);
        }
        let left_x = x2 as f32;
        if left_x > wall_x || (x1 as f32) < wall_x {
            return 0;
        }
        if y1 == y2 {
            return TACTICAL_STRIDE * y1 / 2 + self.column_count - 6;
        }
        self.column_count
            - ((y2 as f32 + (wall_x - left_x) * ((y1 - y2) as f32 / (x1 - x2) as f32)) * -0.5)
                as i32
                * TACTICAL_STRIDE
            - 6
    }

    fn consume_fort(&mut self, tile: i32, amount: i32) {
        let pool = (tile / TACTICAL_STRIDE / 2) as usize;
        let remaining = self.fort_strength[pool] - amount;
        self.fort_strength[pool] = remaining.max(0);
    }

    fn move_and_maybe_finish(&mut self, state: &mut GameState, unit: usize, target: i32) {
        self.move_toward(state, unit, target);
        if tactical_category_of(self.units[unit].unit_type) == 7 {
            self.units[unit].selected = false;
        }
        if self.units[unit].state == 0 && self.outcome == OUTCOME_IN_PROGRESS {
            if self.units[unit].selected && self.has_followup(unit) {
                return;
            }
            if self.has_adjacent_reachable(unit) {
                return;
            }
        }
        self.finish_action();
    }

    fn fire_and_maybe_finish(&mut self, state: &mut GameState, unit: usize, target: i32) {
        self.resolve_action(state, unit, target);
        let category = tactical_category_of(self.units[unit].unit_type);
        if (category == 4 || category == 5)
            && self.has_adjacent_reachable(self.selected.unwrap_or(unit))
        {
            if self.outcome != OUTCOME_IN_PROGRESS {
                self.finish_action();
            }
            return;
        }
        self.finish_action();
    }

    fn has_adjacent_reachable(&self, unit: usize) -> bool {
        for neighbor in self.neighbors(self.units[unit].tile) {
            if neighbor != -1 {
                let cost = self.cost(neighbor);
                if cost != -1 && i32::from(cost) <= self.units[unit].action_points {
                    return true;
                }
            }
        }
        false
    }

    fn has_followup(&self, unit: usize) -> bool {
        let category = tactical_category_of(self.units[unit].unit_type);
        if category == 9 {
            return self
                .neighbors(self.units[unit].tile)
                .iter()
                .any(|&neighbor| {
                    neighbor != -1
                        && self.tiles[neighbor as usize]
                            .occupant
                            .is_some_and(|occ| self.units[occ].side == self.units[unit].side)
                });
        }
        if category == 8 {
            return false;
        }
        let enemy = 1 - self.units[unit].side;
        self.sides[enemy as usize].units.iter().any(|&idx| {
            self.units[idx].tile >= 0
                && self.units[unit].selected
                && self.reachable_for_action(
                    self.units[unit].tile,
                    self.units[idx].tile,
                    DIRECT_FIRE[tactical_category_of(self.units[unit].unit_type) as usize] != 0.0,
                    self.unit_range(unit),
                )
        })
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
        if (side == 1 && exit_column >= self.column_count - 1) || (side == 0 && exit_column == 0) {
            // Headless unbroken-morale path leaves unitMayLeave uninitialized in retail.
            // Use 0 (do not leave) for determinism.
            let unit_may_leave = self.units[unit].state == 1;
            if unit_may_leave {
                self.units[unit].state = 2;
                self.tiles[arrived as usize].occupant = None;
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
        // Retail writes a 12-slot path buffer with no depth cap.
        if depth < 0 || depth >= out.len() as i32 {
            return -1;
        }
        if walk == goal {
            out[depth as usize] = walk;
            return depth;
        }
        let walk_cost = self.cost(walk);
        let neighbors = self.neighbors(walk);
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
                        let next_threat = self.threat.get(next_tile as usize).copied().unwrap_or(0);
                        let cur_threat = self.threat.get(cur_tile as usize).copied().unwrap_or(0);
                        if next_threat == 0 {
                            swap = if cur_threat != 0 {
                                true
                            } else {
                                state.rng.next_crt_rand() & 1 != 0
                            };
                        } else if cur_threat != 0 {
                            swap = state.rng.next_crt_rand() & 1 != 0;
                        }
                    }
                    if swap {
                        candidates[outer] = next_tile;
                        candidates[inner] = cur_tile;
                    }
                }
            }
        }
        for &candidate in candidates.iter().take(count) {
            let found = self.build_path(candidate, depth + 1, goal, out, state);
            if found != -1 {
                out[depth as usize] = walk;
                return found;
            }
        }
        -1
    }

    fn move_between(&mut self, unit: usize, from: i32, to: i32) {
        self.tiles[from as usize].occupant = None;
        self.units[unit].tile = to;
        self.tiles[to as usize].occupant = Some(unit);
    }

    fn reaction_fire(&mut self, state: &mut GameState, tile: i32) -> bool {
        let Some(occupant) = self.tiles[tile as usize].occupant else {
            return false;
        };
        let reacting = 1 - self.units[occupant].side;
        let reactors = self.sides[reacting as usize].units.clone();
        let mut fired = false;
        for reactor in reactors {
            if self.units[reactor].state == 0 && self.units[reactor].selected {
                let category = tactical_category_of(self.units[reactor].unit_type);
                if self.reachable_for_action(
                    self.units[reactor].tile,
                    tile,
                    DIRECT_FIRE[category as usize] != 0.0,
                    self.unit_range(reactor),
                ) {
                    self.resolve_action(state, reactor, tile);
                    fired = true;
                }
            }
            if self.units[occupant].strength == 0 {
                break;
            }
        }
        fired
    }

    fn resolve_action(&mut self, _state: &mut GameState, attacker: usize, target: i32) {
        let defender = self.tiles[target as usize].occupant;
        let fort_wall_targeted = self.tiles[target as usize].deploy_mark > 1
            && self.fort_strength[(target / TACTICAL_STRIDE / 2) as usize] > 0
            && defender.is_none();
        let wall = self.wall_on_firing_line(target, self.units[attacker].tile);
        let mut melee = self.neighbors(self.units[attacker].tile).contains(&target);
        if wall != 0
            && self.tiles[wall as usize].deploy_mark > 1
            && self.fort_strength[(wall / TACTICAL_STRIDE / 2) as usize] > 0
        {
            melee = false;
        }
        let attacker_category = tactical_category_of(self.units[attacker].unit_type) as usize;
        let mut strength_factor = 1.0 - f64::from(self.units[attacker].quality) * -0.1;
        strength_factor *= f64::from(BASE_ATTACK_POWER[self.units[attacker].unit_type]);
        if melee {
            strength_factor *= f64::from(MELEE_MULTIPLIER[attacker_category.min(7)]);
        }
        let attack_power = self.units[attacker].strength as f32
            * strength_factor as f32
            * ATTACK_TERRAIN[attacker_category * 5
                + self.tiles[self.units[attacker].tile as usize].terrain as usize];
        if fort_wall_targeted {
            self.consume_fort(wall, (0.001 * attack_power) as i32);
            return;
        }
        let Some(defender) = defender else {
            return;
        };
        let mut defender_category = tactical_category_of(self.units[defender].unit_type) as usize;
        let mut damage = DEFENSE_TERRAIN
            [defender_category * 5 + self.tiles[target as usize].terrain as usize]
            * DAMAGE_SCALE[self.units[defender].unit_type]
            * attack_power;
        if wall != 0
            && self.tiles[wall as usize].deploy_mark > 1
            && self.fort_strength[(wall / TACTICAL_STRIDE / 2) as usize] > 0
        {
            if DIRECT_FIRE[attacker_category] == 0.0 {
                self.consume_fort(wall, (0.001 * attack_power) as i32);
            }
            defender_category = tactical_category_of(self.units[defender].unit_type) as usize;
            damage *= COVER_DAMAGE
                [defender_category * 5 + self.tiles[wall as usize].deploy_mark as usize];
        }
        if self.tiles[target as usize].deploy_mark == 1
            && hex_distance(self.units[attacker].tile, target) > 1
        {
            damage *= COVER_DAMAGE[defender_category * 5 + 1];
        }
        let mut leader = 2.0f32;
        let defender_side = self.units[defender].side;
        for &idx in &self.sides[defender_side as usize].units {
            if self.units[idx].unit_type >= 0x1b && self.units[idx].state == 0 {
                let value = (2.0 - f64::from(self.units[idx].quality) * 0.2 - 0.2) as f32;
                if value < leader {
                    leader = value;
                }
            }
        }
        let morale_damage = leader * damage;
        self.apply_damage(defender, damage as i32, morale_damage as i32);
        self.sides[defender_side as usize].field20 = false;
    }

    fn apply_damage(&mut self, target: usize, damage_a: i32, damage_b: i32) {
        self.units[target].morale -= damage_b;
        if self.units[target].morale <= 0 {
            self.units[target].morale = 0;
            self.units[target].state = 1;
        }
        self.units[target].strength -= damage_a;
        if self.units[target].strength <= 0 {
            self.units[target].strength = 0;
            self.units[target].state = 3;
        }
        if self.units[target].state == 3 {
            let tile = self.units[target].tile;
            if tile >= 0 {
                self.tiles[tile as usize].occupant = None;
            }
            self.units[target].tile = -1;
        }
        if let Some(selected) = self.selected {
            self.units[selected].selected = false;
        }
        self.evaluate_outcome();
    }

    fn process_morale_broken(&mut self, state: &mut GameState, unit: usize) {
        let original = self.units[unit].tile;
        self.build_distance_field(self.units[unit].side == 0);
        let mut best_distance = 999;
        let mut best_tile = original;
        for tile in 0..TACTICAL_TILE_COUNT as i32 {
            if self.cost(tile) != -1
                && self.distance_field[tile as usize] != -1
                && (self.distance_field[tile as usize] < best_distance
                    || (self.distance_field[tile as usize] == best_distance
                        && state.rng.next_crt_rand() & 1 != 0))
            {
                best_distance = self.distance_field[tile as usize];
                best_tile = tile;
            }
        }
        if best_tile != self.units[unit].tile {
            self.move_toward(state, unit, best_tile);
        }
        if self.units[unit].state == 1 {
            let enemy = 1 - self.units[unit].side;
            let mut nearby = 0;
            for &idx in &self.sides[enemy as usize].units {
                if self.units[idx].state != 0 {
                    continue;
                }
                if hex_distance(self.units[unit].tile, self.units[idx].tile) < 3 {
                    nearby += (BASE_ATTACK_POWER[self.units[idx].unit_type]
                        * self.units[idx].strength as f32) as i32;
                }
            }
            let own = (BASE_ATTACK_POWER[self.units[unit].unit_type]
                * (self.units[unit].strength * 3) as f32) as i32;
            if nearby > own {
                nearby = own;
            }
            let mut destroy = true;
            if self.units[unit].tile != original {
                destroy = false;
                if nearby > 0 {
                    let remainder = state.rng.next_crt_rand() % nearby;
                    if (BASE_ATTACK_POWER[self.units[unit].unit_type]
                        * (self.units[unit].strength as f32))
                        < (remainder as f32)
                    {
                        destroy = true;
                    }
                }
            }
            if destroy {
                let strength = self.units[unit].strength;
                self.apply_damage(unit, strength, 0);
            }
        }
        self.evaluate_outcome();
        self.finish_action();
    }

    fn advance_mine_run(&mut self, unit: usize) {
        let target = self.units[unit].sap_target;
        if self.tiles[target as usize].deploy_mark <= 1 {
            self.units[unit].sap_target = -1;
            return;
        }
        let mut run = self.units[unit].tile;
        if run != target {
            loop {
                if self.tiles[run as usize].mine_run == -1 {
                    break;
                }
                run -= TACTICAL_STRIDE;
                if run == target {
                    break;
                }
            }
        }
        if run == target {
            self.tiles[self.units[unit].sap_target as usize].deploy_mark = 0;
            self.units[unit].sap_target = -1;
        } else if ((run / TACTICAL_STRIDE) & 1) != 0 {
            self.tiles[run as usize].mine_run = 0;
        } else {
            self.tiles[run as usize].mine_run = 1;
        }
        if self.units[unit].action_points == 0 {
            self.finish_action();
            return;
        }
        self.units[unit].action_points = 0;
    }

    fn mine(&mut self, state: &mut GameState, unit: usize, tile: i32) {
        let amount =
            state.rng.next_crt_rand() % 400 + self.units[unit].unit_type as i32 * 250 - 5600;
        self.consume_fort(tile, amount);
        self.finish_action();
    }

    fn dig(&mut self, state: &mut GameState, unit: usize, tile: i32) {
        let before = self.units[unit].action_points;
        self.dig_trench(unit, tile);
        self.move_toward(state, unit, tile);
        self.units[unit].action_points =
            before - BASE_ACTION_POINTS[self.units[unit].unit_type] / 2;
        self.compute_reachable(unit);
        if self.units[unit].action_points == 0 {
            self.finish_action();
        }
    }

    fn dig_trench(&mut self, unit: usize, target: i32) {
        let from = self.units[unit].tile;
        let neighbors = self.neighbors(from);
        let mut direction = 0;
        while direction < 6 && neighbors[direction] != target {
            direction += 1;
        }
        let src = self.tiles[from as usize].trench_mask;
        if src == 0 {
            self.tiles[from as usize].trench_mask = 0x80;
        } else {
            self.tiles[from as usize].trench_mask = (src & 0x7f) | 0x40;
        }
        self.tiles[from as usize].trench_mask |= 1 << direction;
        direction += 3;
        if direction > 5 {
            direction -= 6;
        }
        let dst = self.tiles[target as usize].trench_mask;
        if dst != 0 {
            self.tiles[target as usize].trench_mask = (dst & 0x7f) | 0x40;
        }
        self.tiles[target as usize].trench_mask |= 1 << direction;
    }

    fn rally(&mut self, state: &mut GameState, rallier: usize, target: usize) {
        let mut new_state = self.units[target].state;
        let mut new_morale = self.units[target].morale;
        if new_state == 0 {
            new_morale +=
                self.units[target].strength / 10 * (i32::from(self.units[rallier].quality) + 3);
        } else if new_state == 1 {
            let quality = i32::from(self.units[rallier].quality);
            if state.rng.next_crt_rand() % 100 < (quality + 5) * 10 {
                new_morale = self.units[target].strength / 10 + 20;
                new_state = 0;
            }
        }
        let strength = self.units[target].strength;
        self.units[target].state = new_state;
        self.units[target].morale = new_morale.min(strength);
        self.finish_action();
    }
}
