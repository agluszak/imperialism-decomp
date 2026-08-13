//! Combat-movement phase (`TArmyMgr::DoCombatMoves`) without tactical battle UI.

use crate::military_phase::{combat_class, tactical_category};
use crate::*;
use serde::{Deserialize, Serialize};

const STACK_COMPOSITION: [i16; 16] = [0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 3, 0, 0, 3, 4, 5];
const UNIT_ORDER_IDLE: i32 = 0;
const UNIT_ORDER_SLEEP: i32 = 2;

/// Land battle that retail would open as a modal tactical view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingLandBattle {
    pub province: ProvinceId,
    pub attacker_nation: NationId,
    pub defender_nation: NationId,
    pub attacker_units: Vec<MilitaryUnitId>,
    pub defender_units: Vec<MilitaryUnitId>,
}

struct ArmyStack {
    dest: ProvinceId,
    owner: NationId,
    source: ProvinceId,
    units: Vec<usize>,
    sort_key: i16,
}

struct StationedChains {
    head: ProvinceTable<Option<usize>>,
    prev: Vec<Option<usize>>,
    next: Vec<Option<usize>>,
}

impl GameState {
    /// Retail `TArmyMgr::DoCombatMoves` for a non-client host.
    ///
    /// Identical orders produce identical movement and battle-creation state.
    /// The first would-be tactical battle is stored instead of opening UI.
    pub fn do_combat_moves(&mut self) -> Option<PendingLandBattle> {
        let mut chains = StationedChains::from_units(&self.military_units);
        let stacks = self.form_stacks(&mut chains);
        let mut owner_cache = self.normalized_owner_cache();
        let battle = self.resolve_next_move(&mut chains, stacks, &mut owner_cache);
        self.pending_land_battle = battle.clone();
        if battle.is_none() {
            self.finalize_military_units_without_ui(&owner_cache);
        }
        battle
    }

    pub fn pending_land_battle(&self) -> Option<&PendingLandBattle> {
        self.pending_land_battle.as_ref()
    }

    fn form_stacks(&mut self, chains: &mut StationedChains) -> Vec<ArmyStack> {
        let mut stacks = Vec::new();
        for province in ProvinceId::all() {
            let mut unit_index = chains.head[province];
            let mut previous_target: Option<ProvinceId> = None;
            let mut previous_owner: Option<NationId> = None;
            let mut current_stack: Option<usize> = None;
            while let Some(index) = unit_index {
                let next = chains.next[index];
                let target = self.military_units[index].order.target();
                let owner = self.military_units[index].owner_nation;
                let Some(dest) = target else {
                    let strength = self.military_units[index].strength;
                    self.military_units[index].strength = if strength < 0x191 {
                        strength + 100
                    } else {
                        500
                    };
                    if let Some(major) = MajorNationId::from_nation(owner)
                        && !self.nations.majors[major].economy.diplomacy_eligible
                    {
                        set_unit_order(&mut self.military_units[index], UNIT_ORDER_SLEEP, None);
                    }
                    unit_index = next;
                    continue;
                };

                let reuse = current_stack
                    .filter(|_| previous_target == Some(dest) && previous_owner == Some(owner));
                let stack_index = if let Some(stack_index) = reuse {
                    stack_index
                } else {
                    let existing = stacks
                        .iter()
                        .position(|stack: &ArmyStack| stack.dest == dest && stack.owner == owner);
                    let stack_index = if let Some(existing) = existing {
                        existing
                    } else {
                        stacks.insert(
                            0,
                            ArmyStack {
                                dest,
                                owner,
                                source: province,
                                units: Vec::new(),
                                sort_key: 0,
                            },
                        );
                        0
                    };
                    previous_target = Some(dest);
                    previous_owner = Some(owner);
                    stack_index
                };
                stacks[stack_index].units.insert(0, index);
                current_stack = Some(stack_index);
                unit_index = next;
            }
        }

        for stack in &mut stacks {
            let mut min_class = 3_i16;
            let mut max_class = 1_i16;
            for &index in &stack.units {
                let class = combat_class(self.military_units[index].unit_type);
                min_class = min_class.min(class);
                max_class = max_class.max(class);
            }
            let composition = STACK_COMPOSITION[(min_class + max_class * 4) as usize];
            let roll = self.rng.next_crt_rand();
            stack.sort_key = (composition << 8) + (roll & 0xff) as i16;
        }
        sort_stacks_descending(&mut stacks, &mut self.rng);
        stacks
    }

    fn resolve_next_move(
        &mut self,
        chains: &mut StationedChains,
        stacks: Vec<ArmyStack>,
        owner_cache: &mut ProvinceTable<Option<NationId>>,
    ) -> Option<PendingLandBattle> {
        for stack in stacks {
            if owner_cache[stack.dest] == Some(stack.owner) {
                self.apply_uncontested_stack(chains, &stack);
                continue;
            }
            if let Some(battle) = self.try_create_land_battle(chains, &stack, owner_cache) {
                return Some(battle);
            }
        }
        None
    }

    fn try_create_land_battle(
        &mut self,
        chains: &mut StationedChains,
        stack: &ArmyStack,
        owner_cache: &mut ProvinceTable<Option<NationId>>,
    ) -> Option<PendingLandBattle> {
        let cached_owner = owner_cache[stack.dest];
        let mut our_units = Vec::new();
        for &index in &stack.units {
            if self.military_units[index].order.target() == Some(stack.dest) {
                our_units.insert(0, index);
            }
        }
        if our_units.is_empty() {
            return None;
        }

        let mut enemy_units = Vec::new();
        let mut garrison = chains.head[stack.dest];
        while let Some(index) = garrison {
            enemy_units.insert(0, index);
            garrison = chains.next[index];
        }

        let Some(cached_owner) = cached_owner else {
            self.relocate_stack_to_source(chains, stack, &our_units);
            return None;
        };
        if !self.nation_pair_war_stamp_out_of_date(stack.owner, cached_owner) {
            self.relocate_stack_to_source(chains, stack, &our_units);
            return None;
        }
        if !enemy_units.is_empty() {
            return Some(PendingLandBattle {
                province: stack.dest,
                attacker_nation: stack.owner,
                defender_nation: cached_owner,
                attacker_units: our_units
                    .iter()
                    .map(|&index| self.military_units[index].id)
                    .collect(),
                defender_units: enemy_units
                    .iter()
                    .map(|&index| self.military_units[index].id)
                    .collect(),
            });
        }

        self.apply_uncontested_indices(chains, &our_units);
        owner_cache[stack.dest] = Some(stack.owner);
        None
    }

    fn apply_uncontested_stack(&mut self, chains: &mut StationedChains, stack: &ArmyStack) {
        self.apply_uncontested_indices(chains, &stack.units);
    }

    fn apply_uncontested_indices(&mut self, chains: &mut StationedChains, units: &[usize]) {
        for &index in units {
            let dest = self.military_units[index]
                .order
                .target()
                .expect("uncontested move requires a province target");
            self.move_unit_to(chains, index, dest);
            set_unit_order(&mut self.military_units[index], UNIT_ORDER_IDLE, None);
        }
    }

    fn relocate_stack_to_source(
        &mut self,
        chains: &mut StationedChains,
        stack: &ArmyStack,
        units: &[usize],
    ) {
        for &index in units {
            set_unit_order(&mut self.military_units[index], UNIT_ORDER_IDLE, None);
            if self.military_units[index].stationed_province != Some(stack.source) {
                self.move_unit_to(chains, index, stack.source);
            }
        }
    }

    fn move_unit_to(&mut self, chains: &mut StationedChains, index: usize, dest: ProvinceId) {
        chains.unlink(index, self.military_units[index].stationed_province);
        chains.link(&self.military_units, index, Some(dest));
        self.military_units[index].stationed_province = Some(dest);
        clear_order_target(&mut self.military_units[index]);
    }

    fn normalized_owner_cache(&self) -> ProvinceTable<Option<NationId>> {
        ProvinceTable::from_fn(|province| self.normalized_province_owner(province))
    }

    fn normalized_province_owner(&self, province: ProvinceId) -> Option<NationId> {
        let owner = self.map.provinces[province].owner()?;
        match self.nations.country_status(owner) {
            Some(CountryStatus::ColonyOf(master)) => Some(master),
            _ => Some(owner),
        }
    }

    fn nation_pair_war_stamp_out_of_date(&self, source: NationId, target: NationId) -> bool {
        if self.nations.common(source).is_none() || self.nations.common(target).is_none() {
            return false;
        }
        if self.diplomacy.relationships[source][target] != DiplomaticRelationship::War {
            return false;
        }
        self.diplomacy.relationship_turns[source][target] != Some(self.turn.economic_turn as i16)
    }

    fn finalize_military_units_without_ui(
        &mut self,
        owner_cache: &ProvinceTable<Option<NationId>>,
    ) {
        for tile in &mut self.map.tiles {
            tile.per_tile_visited = 0;
        }
        for unit in &mut self.military_units {
            if unit.strength > 0 && unit.stationed_province.is_some() && unit.order.code() != 2 {
                let target = unit.order.target();
                set_unit_order(unit, UNIT_ORDER_IDLE, target);
            }
        }
        self.apply_ownership_changes(owner_cache);
    }

    fn apply_ownership_changes(&mut self, owner_cache: &ProvinceTable<Option<NationId>>) {
        for province in ProvinceId::all() {
            let Some(cached) = owner_cache[province] else {
                continue;
            };
            let Some(current) = self.map.provinces[province].owner() else {
                continue;
            };
            if cached == current {
                continue;
            }
            if matches!(
                self.nations.country_status(current),
                Some(CountryStatus::ColonyOf(master)) if master == cached
            ) {
                continue;
            }
            self.change_province_owner(province, cached);
        }
    }
}

impl StationedChains {
    fn from_units(units: &[MilitaryUnitState]) -> Self {
        let mut chains = Self {
            head: ProvinceTable::default(),
            prev: vec![None; units.len()],
            next: vec![None; units.len()],
        };
        for (index, unit) in units.iter().enumerate() {
            chains.link(units, index, unit.stationed_province);
        }
        chains
    }

    fn unlink(&mut self, index: usize, province: Option<ProvinceId>) {
        let Some(province) = province else {
            return;
        };
        if self.prev[index].is_none() {
            self.head[province] = self.next[index];
        } else if let Some(prev) = self.prev[index] {
            self.next[prev] = self.next[index];
        }
        if let Some(next) = self.next[index] {
            self.prev[next] = self.prev[index];
        }
        self.prev[index] = None;
        self.next[index] = None;
    }

    fn link(&mut self, units: &[MilitaryUnitState], index: usize, province: Option<ProvinceId>) {
        let Some(province) = province else {
            return;
        };
        let priority = tactical_category(units[index].unit_type);
        let Some(head) = self.head[province] else {
            self.head[province] = Some(index);
            self.prev[index] = None;
            self.next[index] = None;
            return;
        };
        if tactical_category(units[head].unit_type) < priority {
            let mut scan = head;
            while let Some(next) = self.next[scan] {
                if tactical_category(units[next].unit_type) < priority {
                    scan = next;
                } else {
                    break;
                }
            }
            let after = self.next[scan];
            self.prev[index] = Some(scan);
            self.next[index] = after;
            self.next[scan] = Some(index);
            if let Some(after) = after {
                self.prev[after] = Some(index);
            }
        } else {
            self.head[province] = Some(index);
            self.prev[head] = Some(index);
            self.prev[index] = None;
            self.next[index] = Some(head);
        }
    }
}

fn set_unit_order(unit: &mut MilitaryUnitState, code: i32, target: Option<ProvinceId>) {
    let targets = *unit.order.targets();
    let mirrors = *unit.order.target_mirrors();
    unit.order = if code == UNIT_ORDER_IDLE && target.is_none() {
        MilitaryOrder::idle(targets, mirrors)
    } else {
        MilitaryOrder::retail(
            MilitaryOrderCode::from_retail(code),
            target,
            targets,
            mirrors,
        )
    };
}

fn clear_order_target(unit: &mut MilitaryUnitState) {
    let code = unit.order.code();
    set_unit_order(unit, code, None);
}

fn sort_stacks_descending(stacks: &mut [ArmyStack], rng: &mut RngState) {
    if !stacks.is_empty() {
        quick_sort_stacks(stacks, 1, stacks.len() as i32, rng);
    }
}

fn quick_sort_stacks(stacks: &mut [ArmyStack], lo: i32, hi: i32, rng: &mut RngState) {
    if lo < hi {
        let pivot = partition_stacks(stacks, lo, hi, rng);
        quick_sort_stacks(stacks, lo, pivot, rng);
        quick_sort_stacks(stacks, pivot + 1, hi, rng);
    }
}

fn partition_stacks(stacks: &mut [ArmyStack], lo: i32, hi: i32, rng: &mut RngState) -> i32 {
    let mut pivot_ordinal = lo;
    if lo != hi {
        pivot_ordinal = rng.next_crt_rand() % (hi - lo).abs() + lo;
    }
    stacks.swap((lo - 1) as usize, (pivot_ordinal - 1) as usize);
    partition_stacks_core(stacks, lo, hi)
}

fn partition_stacks_core(stacks: &mut [ArmyStack], lo: i32, hi: i32) -> i32 {
    if lo >= hi {
        return hi;
    }
    let pivot = stacks[(lo - 1) as usize].sort_key;
    let mut below = lo - 1;
    let mut above = hi + 1;
    loop {
        loop {
            above -= 1;
            if compare_stack_keys(pivot, stacks[(above - 1) as usize].sort_key) > -1 {
                break;
            }
        }
        loop {
            below += 1;
            if compare_stack_keys(pivot, stacks[(below - 1) as usize].sort_key) < 1 {
                break;
            }
        }
        if above <= below {
            return above;
        }
        stacks.swap((below - 1) as usize, (above - 1) as usize);
    }
}

fn compare_stack_keys(a: i16, b: i16) -> i16 {
    if a < b {
        1
    } else if a > b {
        -1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    fn seed_province(state: &mut GameState, province: usize, owner: usize, adjacency: &[usize]) {
        state.map.provinces[ProvinceId::new(province)] = ProvinceState::new(
            Some(NationId::new(owner)),
            Some(NationId::new(owner)),
            0,
            adjacency.iter().copied().map(ProvinceId::new).collect(),
            vec![TileId::new(0); adjacency.len()],
            Some(0),
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
    }

    fn push_unit(
        state: &mut GameState,
        nation: usize,
        province: usize,
        kind: MilitaryUnitKind,
        dest: Option<usize>,
    ) -> MilitaryUnitId {
        let id = state.unit_ids.next_military();
        let province = ProvinceId::new(province);
        let order = match dest {
            Some(dest) => MilitaryOrder::retail(
                MilitaryOrderCode::from_retail(1),
                Some(ProvinceId::new(dest)),
                [Some(province); 3],
                [Some(province); 3],
            ),
            None => MilitaryOrder::idle([Some(province); 3], [Some(province); 3]),
        };
        state.military_units.push(MilitaryUnitState::new(
            id,
            NationId::new(nation),
            kind,
            Some(province),
            order,
            NationId::new(nation),
            0,
            true,
            String::new(),
            400,
            kind.spawn_era(),
            0,
            0,
        ));
        id
    }

    #[test]
    fn uncontested_redeploy_moves_the_unit_and_keeps_the_old_path() {
        let mut state = game_state();
        seed_province(&mut state, 1, 0, &[2]);
        seed_province(&mut state, 2, 0, &[1]);
        let id = push_unit(&mut state, 0, 1, MilitaryUnitKind::Regulars, Some(2));
        assert_eq!(state.do_combat_moves(), None);
        let unit = &state.military_units[0];
        assert_eq!(unit.id, id);
        assert_eq!(unit.stationed_province, Some(ProvinceId::new(2)));
        assert_eq!(unit.order.code(), 0);
        assert_eq!(unit.order.targets(), &[Some(ProvinceId::new(1)); 3]);
        assert_eq!(unit.strength, 400);
    }

    #[test]
    fn hostile_garrison_creates_pending_battle_without_moving() {
        let mut state = game_state();
        state.turn.economic_turn = 3;
        seed_province(&mut state, 1, 0, &[2]);
        seed_province(&mut state, 2, 1, &[1]);
        let attacker = push_unit(&mut state, 0, 1, MilitaryUnitKind::Regulars, Some(2));
        let defender = push_unit(&mut state, 1, 2, MilitaryUnitKind::Militia, None);
        state.diplomacy.relationships[NationId::new(0)][NationId::new(1)] =
            DiplomaticRelationship::War;
        state.diplomacy.relationships[NationId::new(1)][NationId::new(0)] =
            DiplomaticRelationship::War;
        let battle = state
            .do_combat_moves()
            .expect("hostile move creates a battle");
        assert_eq!(
            battle,
            PendingLandBattle {
                province: ProvinceId::new(2),
                attacker_nation: NationId::new(0),
                defender_nation: NationId::new(1),
                attacker_units: vec![attacker],
                defender_units: vec![defender],
            }
        );
        assert_eq!(
            state.military_units[0].stationed_province,
            Some(ProvinceId::new(1))
        );
        assert_eq!(state.military_units[0].order.code(), 1);
        assert_eq!(
            state.military_units[1].stationed_province,
            Some(ProvinceId::new(2))
        );
    }
}
