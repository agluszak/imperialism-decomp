use super::*;
use serde::{Deserialize, Serialize};

const TILE_COUNT: usize = 0xb4;
const TILE_STRIDE: i32 = 6;
const MOVE_COSTS: [i16; 6] = [15, 10, 20, 40, 20, 10];
const UNIT_TYPE_BY_SHIP_TYPE: [i8; 14] = [-1, -1, -1, 0, 1, -1, -1, 2, 3, 4, -1, 5, 6, 7];
const ATTACK_POWER: [f32; 8] = [3.0, 3.5, 4.0, 4.0, 8.0, 8.0, 15.0, 15.0];
const DAMAGE_SCALE: [f32; 8] = [0.045, 0.04, 0.04, 0.022, 0.02, 0.025, 0.015, 0.022];

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NavyTargeting {
    #[default]
    Hull,
    Crew,
    Sail,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NavyUnitView {
    pub ship: ShipId,
    pub side: u8,
    pub tile: i32,
    pub strength: i32,
    pub secondary_strength: i32,
    pub action_points: i32,
    pub destroyed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct NavyUnit {
    ship: ShipId,
    ship_type: ShipType,
    unit_type: usize,
    side: u8,
    tile: i32,
    strength: i32,
    secondary_strength: i32,
    base_action_points: i32,
    action_points: i32,
    quality: i16,
    order_seed: i16,
    destroyed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NavyBattle {
    forces: [TaskForceId; 2],
    nations: [NationId; 2],
    units: Vec<NavyUnit>,
    occupants: Vec<Option<usize>>,
    move_costs: Vec<i16>,
    current_side: u8,
    selected: Option<usize>,
    round: i32,
    outcome: Option<u8>,
    battlefield_column_count: i32,
    move_cost_rotation_start: usize,
    move_cost_by_direction: [i16; 6],
    targeting: [NavyTargeting; 2],
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
        for (side, force) in forces.into_iter().enumerate() {
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
                units.push(NavyUnit {
                    ship: ship_id,
                    ship_type: ship.ship_type,
                    unit_type: unit_type as usize,
                    side: side as u8,
                    tile: -2,
                    strength,
                    secondary_strength: strength,
                    base_action_points: speed * 10,
                    action_points: speed * 10,
                    // `TNavyTacUnit::InitializeFromSourceShip` never writes +0x10.
                    quality: 0,
                    order_seed: state.rng.next_crt_rand() as i16,
                    destroyed: false,
                });
            }
        }
        let battlefield_column_count = units
            .iter()
            .map(|unit| NAVY_DESCRIPTORS[unit.ship_type].calculate_weight)
            .max()
            .unwrap_or(0)
            + 11;
        let rotation = (state.rng.next_crt_rand() % 6) as usize;
        let mut move_cost_by_direction = [0; 6];
        for (offset, cost) in MOVE_COSTS.into_iter().enumerate() {
            move_cost_by_direction[(rotation + offset) % 6] = cost;
        }
        Self {
            forces,
            nations,
            units,
            occupants: vec![None; TILE_COUNT],
            move_costs: vec![-1; TILE_COUNT],
            current_side: 1,
            selected: None,
            round: 0,
            outcome: None,
            battlefield_column_count,
            move_cost_rotation_start: rotation,
            move_cost_by_direction,
            targeting: [NavyTargeting::Hull; 2],
        }
    }

    pub fn units(&self) -> impl Iterator<Item = NavyUnitView> + '_ {
        self.units.iter().map(|unit| NavyUnitView {
            ship: unit.ship,
            side: unit.side,
            tile: unit.tile,
            strength: unit.strength,
            secondary_strength: unit.secondary_strength,
            action_points: unit.action_points,
            destroyed: unit.destroyed,
        })
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

    pub fn deploy(&mut self, ship: ShipId, tile: i32) -> bool {
        let Some(unit) = self.units.iter().position(|unit| unit.ship == ship) else {
            return false;
        };
        if !(0..TILE_COUNT as i32).contains(&tile) || self.occupants[tile as usize].is_some() {
            return false;
        }
        let row = tile / 0x1d;
        let valid = if self.units[unit].side == 0 {
            (self.battlefield_column_count - 6..=self.battlefield_column_count - 5).contains(&row)
        } else {
            (5..=6).contains(&row)
        };
        if !valid {
            return false;
        }
        if self.units[unit].tile >= 0 {
            self.occupants[self.units[unit].tile as usize] = None;
        }
        self.units[unit].tile = tile;
        self.occupants[tile as usize] = Some(unit);
        true
    }

    pub fn reachable_tiles(&mut self, ship: ShipId) -> &[i16] {
        self.move_costs.fill(-1);
        let Some(unit) = self.units.iter().position(|unit| unit.ship == ship) else {
            return &self.move_costs;
        };
        let start = self.units[unit].tile;
        if !(0..TILE_COUNT as i32).contains(&start) {
            return &self.move_costs;
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
        &self.move_costs
    }

    pub fn set_targeting(&mut self, side: u8, targeting: NavyTargeting) {
        if let Some(slot) = self.targeting.get_mut(side as usize) {
            *slot = targeting;
        }
    }

    fn fire(&mut self, state: &mut GameState, attacker: ShipId, target: ShipId) -> bool {
        let Some(attacker) = self.units.iter().position(|unit| unit.ship == attacker) else {
            return false;
        };
        let Some(target) = self.units.iter().position(|unit| unit.ship == target) else {
            return false;
        };
        if self.units[attacker].destroyed
            || self.units[target].destroyed
            || self.units[attacker].side == self.units[target].side
            || self.units[attacker].tile < 0
            || self.units[target].tile < 0
        {
            return false;
        }
        let distance = navy_hit_distance(self.units[attacker].tile, self.units[target].tile);
        let range = NAVY_DESCRIPTORS[self.units[attacker].ship_type].calculate_weight;
        let ratio = distance as f64 / (range as f64 * 0.5);
        let threshold =
            (f64::from(self.units[attacker].quality) * 5.0 + 80.0 / (ratio.powi(3) + 1.0)) as f32;
        if ((state.rng.next_crt_rand() % 100) as f32) < threshold {
            let damage = DAMAGE_SCALE[self.units[target].unit_type]
                * self.units[attacker].strength as f32
                * ATTACK_POWER[self.units[attacker].unit_type];
            let targeting = self.targeting[self.units[attacker].side as usize];
            self.apply_damage(state, target, damage, targeting);
        }
        self.evaluate_outcome();
        true
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
            unit.destroyed = true;
            if unit.tile >= 0 {
                self.occupants[unit.tile as usize] = None;
                unit.tile = -1;
            }
        }
    }

    fn evaluate_outcome(&mut self) {
        let live = [0_u8, 1].map(|side| {
            self.units
                .iter()
                .any(|unit| unit.side == side && !unit.destroyed)
        });
        if live[0] && live[1] && self.round < 0x23 {
            return;
        }
        self.outcome = Some(u8::from(!(live[0] && self.round < 0x23)));
    }
}

impl GameState {
    pub fn navy_battle(&self) -> Option<&NavyBattle> {
        match &self.continuation {
            crate::turn_flow::TurnContinuation::NavalBattle(continuation) => {
                continuation.navy_battle.as_deref()
            }
            _ => None,
        }
    }

    pub fn ensure_navy_battle(&mut self) -> &NavyBattle {
        if self.navy_battle().is_none() {
            let pending = self
                .pending_naval_battle()
                .cloned()
                .expect("navy battle requires a pending encounter");
            let battle = NavyBattle::new(self, &pending);
            let crate::turn_flow::TurnContinuation::NavalBattle(continuation) =
                &mut self.continuation
            else {
                unreachable!()
            };
            continuation.navy_battle = Some(Box::new(battle));
        }
        self.navy_battle().unwrap()
    }

    pub fn deploy_navy_unit(&mut self, ship: ShipId, tile: i32) -> bool {
        let Some(mut battle) = self.take_navy_battle() else {
            return false;
        };
        let deployed = battle.deploy(ship, tile);
        self.store_navy_battle(battle);
        deployed
    }

    pub fn navy_unit_reachable_costs(&mut self, ship: ShipId) -> Vec<i16> {
        let Some(mut battle) = self.take_navy_battle() else {
            return Vec::new();
        };
        let costs = battle.reachable_tiles(ship).to_vec();
        self.store_navy_battle(battle);
        costs
    }

    pub fn set_navy_targeting(&mut self, side: u8, targeting: NavyTargeting) {
        if let Some(mut battle) = self.take_navy_battle() {
            battle.set_targeting(side, targeting);
            self.store_navy_battle(battle);
        }
    }

    pub fn fire_navy_unit(&mut self, attacker: ShipId, target: ShipId) -> bool {
        let Some(mut battle) = self.take_navy_battle() else {
            return false;
        };
        let fired = battle.fire(self, attacker, target);
        self.store_navy_battle(battle);
        fired
    }

    pub fn commit_finished_navy_battle(&mut self, story_ids: &[i32]) -> Option<crate::TurnStop> {
        let battle = self.take_navy_battle()?;
        if battle.outcome.is_none() {
            self.store_navy_battle(battle);
            return None;
        }
        for unit in &battle.units {
            if let Some(ship) = self.ships.get_mut(&unit.ship) {
                ship.strength = unit.strength.clamp(0, i32::from(i16::MAX)) as i16;
            }
        }
        for force in battle.forces {
            if let Some(force_state) = self.task_forces.get_mut(&force) {
                force_state.defeated = true;
            }
            self.prune_sunk_force_ships(force);
        }
        Some(self.resume_after_naval_battle(story_ids))
    }

    fn take_navy_battle(&mut self) -> Option<NavyBattle> {
        match &mut self.continuation {
            crate::turn_flow::TurnContinuation::NavalBattle(continuation) => {
                continuation.navy_battle.take().map(|battle| *battle)
            }
            _ => None,
        }
    }

    fn store_navy_battle(&mut self, battle: NavyBattle) {
        let crate::turn_flow::TurnContinuation::NavalBattle(continuation) = &mut self.continuation
        else {
            panic!("navy battle storage requires a pending encounter")
        };
        continuation.navy_battle = Some(Box::new(battle));
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

    fn unit(ship: usize, side: u8, tile: i32, unit_type: usize) -> NavyUnit {
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
            destroyed: false,
        }
    }

    fn battle(units: Vec<NavyUnit>) -> NavyBattle {
        let mut occupants = vec![None; TILE_COUNT];
        for (index, unit) in units.iter().enumerate() {
            if unit.tile >= 0 {
                occupants[unit.tile as usize] = Some(index);
            }
        }
        NavyBattle {
            forces: [TaskForceId::new(1), TaskForceId::new(2)],
            nations: [NationId::new(0), NationId::new(1)],
            units,
            occupants,
            move_costs: vec![-1; TILE_COUNT],
            current_side: 0,
            selected: Some(0),
            round: 0,
            outcome: None,
            battlefield_column_count: 16,
            move_cost_rotation_start: 0,
            move_cost_by_direction: MOVE_COSTS,
            targeting: [NavyTargeting::Hull; 2],
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
    fn navy_deployment_keeps_the_recovered_fixed_29_row_guard() {
        let mut attacker = unit(1, 0, -2, 0);
        attacker.tile = -2;
        let mut defender = unit(2, 1, -2, 0);
        defender.tile = -2;
        let mut battle = battle(vec![attacker, defender]);
        assert!(battle.deploy(ShipId::new(2), 5 * 0x1d));
        assert!(!(0..TILE_COUNT as i32).any(|tile| battle.deploy(ShipId::new(1), tile)));
    }

    #[test]
    fn navy_reachability_rotates_costs_for_the_first_two_ship_classes() {
        let mut battle = battle(vec![unit(1, 0, 7, 0)]);
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
        let mut battle = battle(vec![unit(1, 0, 29, 0), unit(2, 1, 31, 0)]);
        battle.apply_damage(&mut state, 1, 40.0, NavyTargeting::Hull);
        assert_eq!(battle.units[1].strength, 90);
        assert_eq!(battle.units[1].secondary_strength, 60);
        assert!(!battle.units[1].destroyed);
    }
}
