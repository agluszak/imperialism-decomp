//! Combat-movement phase (`TArmyMgr::DoCombatMoves`) without tactical battle UI.

use crate::military_phase::{combat_class, tactical_category};
use crate::*;
use serde::{Deserialize, Serialize};

const STACK_COMPOSITION: [i16; 16] = [0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 3, 0, 0, 3, 4, 5];
const UNIT_ORDER_IDLE: i32 = 0;
const UNIT_ORDER_REDEPLOY: i32 = 1;
const UNIT_ORDER_SLEEP: i32 = 2;
const EXPERIENCE_WINNER: i16 = 0x23;
const EXPERIENCE_LOSER: i16 = 0x14;
const EXPERIENCE_CAP: i16 = 0x190;

/// Land battle that retail would open as a modal tactical view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingLandBattle {
    pub province: ProvinceId,
    pub attacker_nation: NationId,
    pub defender_nation: NationId,
    pub attacker_units: Vec<MilitaryUnitId>,
    pub defender_units: Vec<MilitaryUnitId>,
}

/// Remaining `DoCombatMoves` work after a tactical battle stop.
///
/// Retail keeps `pendingUnitPool0c` and `nextStackOrdinal10` so later stacks
/// continue without reforming or re-rolling sort keys.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CombatMovesContinuation {
    stacks: Vec<ArmyStack>,
    next_stack: usize,
    owner_cache: ProvinceTable<Option<NationId>>,
    pub battle: PendingLandBattle,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct ArmyStack {
    dest: ProvinceId,
    owner: NationId,
    source: ProvinceId,
    units: Vec<usize>,
    sort_key: i16,
}

struct StationedChains {
    head: [Option<usize>; PROVINCE_COUNT],
    prev: Vec<Option<usize>>,
    next: Vec<Option<usize>>,
}

impl GameState {
    /// Retail `TArmyMgr::DoCombatMoves` for a non-client host until the first battle.
    ///
    /// Does not keep the sorted stack cursor. The turn driver uses
    /// [`Self::start_combat_moves`] and [`Self::continue_combat_moves`].
    pub fn do_combat_moves(&mut self) -> Option<PendingLandBattle> {
        self.start_combat_moves()
            .map(|continuation| continuation.battle)
    }

    pub fn start_combat_moves(&mut self) -> Option<CombatMovesContinuation> {
        let mut chains = StationedChains::from_units(&self.military_units);
        let stacks = self.form_stacks(&mut chains);
        let mut owner_cache = self.normalized_owner_cache();
        self.resolve_next_move(&mut chains, stacks, 0, &mut owner_cache)
    }

    pub fn resume_combat_moves(
        &mut self,
        continuation: CombatMovesContinuation,
    ) -> Option<CombatMovesContinuation> {
        let mut chains = StationedChains::from_units(&self.military_units);
        let mut owner_cache = *continuation.owner_cache.as_array();
        self.resolve_next_move(
            &mut chains,
            continuation.stacks,
            continuation.next_stack,
            &mut owner_cache,
        )
    }

    pub fn pending_land_battle(&self) -> Option<&PendingLandBattle> {
        match &self.continuation {
            crate::turn_flow::TurnContinuation::LandBattle(continuation) => {
                Some(&continuation.battle)
            }
            _ => None,
        }
    }

    /// `TArmyMgr::ApplyPostBattleStackOutcomeAndGrowUnitMeters` without the trailing
    /// `ResolveNextMove`. Call [`Self::continue_combat_moves`] to resume the cursor.
    pub fn resolve_land_battle(&mut self, attacker_won: bool) {
        let crate::turn_flow::TurnContinuation::LandBattle(continuation) = &self.continuation
        else {
            panic!("land-battle resolve requires a combat-moves continuation");
        };
        assert!(
            continuation.next_stack > 0,
            "combat continuation has no interrupted stack"
        );
        let stack = continuation.stacks[continuation.next_stack - 1].clone();
        let battle = continuation.battle.clone();
        let owner_cache = *continuation.owner_cache.as_array();
        let attacker_indices = battle
            .attacker_units
            .iter()
            .map(|&id| military_index(&self.military_units, id))
            .collect::<Vec<_>>();
        let defender_indices = battle
            .defender_units
            .iter()
            .map(|&id| military_index(&self.military_units, id))
            .collect::<Vec<_>>();

        let mut chains = StationedChains::from_units(&self.military_units);
        if attacker_won {
            self.redistribute_losers(&defender_indices, battle.province, &owner_cache);
            self.apply_uncontested_indices(&mut chains, &attacker_indices);
            self.grow_stack_experience(&attacker_indices, EXPERIENCE_WINNER);
            self.grow_stack_experience(&defender_indices, EXPERIENCE_LOSER);
            let crate::turn_flow::TurnContinuation::LandBattle(continuation) =
                &mut self.continuation
            else {
                unreachable!("continuation still holds the land battle");
            };
            continuation.owner_cache[battle.province] = Some(stack.owner);
        } else {
            self.relocate_stack_to_source(&mut chains, &stack, &attacker_indices);
            self.grow_stack_experience(&attacker_indices, EXPERIENCE_LOSER);
            self.grow_stack_experience(&defender_indices, EXPERIENCE_WINNER);
        }
    }

    /// Continues `DoCombatMoves` from the preserved stack cursor.
    pub fn continue_combat_moves(&mut self) -> crate::TurnStop {
        let crate::turn_flow::TurnContinuation::LandBattle(continuation) =
            std::mem::take(&mut self.continuation)
        else {
            panic!("land-battle resume requires a combat-moves continuation");
        };
        if let Some(continuation) = self.resume_combat_moves(continuation) {
            self.continuation = crate::turn_flow::TurnContinuation::LandBattle(continuation);
            return crate::TurnStop::LandBattle;
        }
        self.advance_turn()
    }

    fn form_stacks(&mut self, chains: &mut StationedChains) -> Vec<ArmyStack> {
        let mut stacks = Vec::new();
        for (tile_index, mut unit_index) in chains.head.iter().copied().enumerate() {
            let province = ProvinceId::new(tile_index as u16);
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
        mut next_stack: usize,
        owner_cache: &mut [Option<NationId>; PROVINCE_COUNT],
    ) -> Option<CombatMovesContinuation> {
        while next_stack < stacks.len() {
            let index = next_stack;
            next_stack += 1;
            let stack = &stacks[index];
            let dest_index = usize::from(stack.dest.get());
            if owner_cache[dest_index] == Some(stack.owner) {
                self.apply_uncontested_stack(chains, stack);
                continue;
            }
            if let Some(battle) = self.try_create_land_battle(chains, stack, owner_cache) {
                return Some(CombatMovesContinuation {
                    stacks,
                    next_stack,
                    owner_cache: ProvinceTable::from_array(*owner_cache),
                    battle,
                });
            }
        }
        self.finalize_military_units_without_ui(owner_cache);
        None
    }

    fn try_create_land_battle(
        &mut self,
        chains: &mut StationedChains,
        stack: &ArmyStack,
        owner_cache: &mut [Option<NationId>; PROVINCE_COUNT],
    ) -> Option<PendingLandBattle> {
        let dest_index = usize::from(stack.dest.get());
        let cached_owner = owner_cache[dest_index];
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
        let mut garrison = chains.head[dest_index];
        while let Some(index) = garrison {
            enemy_units.insert(0, index);
            garrison = chains.next[index];
        }

        if !self.nation_pair_war_stamp_out_of_date(stack.owner, cached_owner) {
            self.relocate_stack_to_source(chains, stack, &our_units);
            return None;
        }
        if !enemy_units.is_empty() {
            let defender = cached_owner.expect("war stamp requires a province owner");
            return Some(PendingLandBattle {
                province: stack.dest,
                attacker_nation: stack.owner,
                defender_nation: defender,
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
        owner_cache[dest_index] = Some(stack.owner);
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
                .expect("moving stack units have a destination");
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

    fn normalized_owner_cache(&self) -> [Option<NationId>; PROVINCE_COUNT] {
        std::array::from_fn(|index| self.normalized_province_owner(ProvinceId::new(index as u16)))
    }

    pub(crate) fn normalized_province_owner(&self, province: ProvinceId) -> Option<NationId> {
        let owner = self.map.provinces[province].owner()?;
        Some(match self.nations.country_status(owner) {
            Some(CountryStatus::ColonyOf(master)) => master,
            _ => owner,
        })
    }

    pub(crate) fn nation_pair_war_stamp_out_of_date(
        &self,
        source: NationId,
        target: Option<NationId>,
    ) -> bool {
        let Some(target) = target else {
            return false;
        };
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
        owner_cache: &[Option<NationId>; PROVINCE_COUNT],
    ) {
        for tile in self.map.tiles.iter_mut() {
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

    fn apply_ownership_changes(&mut self, owner_cache: &[Option<NationId>; PROVINCE_COUNT]) {
        for (index, &cached) in owner_cache.iter().enumerate() {
            let province = ProvinceId::new(index as u16);
            let Some(current) = self.map.provinces[province].owner() else {
                continue;
            };
            let Some(new_owner) = cached else {
                continue;
            };
            if new_owner == current {
                continue;
            }
            if matches!(
                self.nations.country_status(current),
                Some(CountryStatus::ColonyOf(master)) if master == new_owner
            ) {
                continue;
            }
            self.change_province_owner(province, new_owner);
        }
    }

    fn redistribute_losers(
        &mut self,
        defender_indices: &[usize],
        battle_site: ProvinceId,
        owner_cache: &[Option<NationId>; PROVINCE_COUNT],
    ) {
        let Some(&head) = defender_indices.first() else {
            return;
        };
        let owner = self.military_units[head].owner_nation;
        let mut candidates = [ProvinceId::new(0); 12];
        let mut count = 0_i32;
        for &adjacent in self.map.provinces[battle_site].adjacency() {
            if owner_cache[usize::from(adjacent.get())] == Some(owner) {
                candidates[count as usize] = adjacent;
                count += 1;
                if count == 12 {
                    break;
                }
            }
        }
        if count == 0 {
            return;
        }
        let chosen = candidates[(self.rng.next_crt_rand() % count) as usize];
        for &index in defender_indices {
            if tactical_category(self.military_units[index].unit_type) == 0 {
                continue;
            }
            set_unit_order(
                &mut self.military_units[index],
                UNIT_ORDER_REDEPLOY,
                Some(chosen),
            );
        }
    }

    fn grow_stack_experience(&mut self, indices: &[usize], amount: i16) {
        for &index in indices {
            let unit = &mut self.military_units[index];
            if unit.strength > 0 {
                unit.experience = (unit.experience + amount).min(EXPERIENCE_CAP);
            }
        }
    }
}

fn military_index(units: &[MilitaryUnitState], id: MilitaryUnitId) -> usize {
    units
        .iter()
        .position(|unit| unit.id == id)
        .expect("pending battle unit")
}

impl StationedChains {
    fn from_units(units: &[MilitaryUnitState]) -> Self {
        let mut chains = Self {
            head: [None; PROVINCE_COUNT],
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
        let slot = usize::from(province.get());
        if self.prev[index].is_none() {
            self.head[slot] = self.next[index];
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
        let slot = usize::from(province.get());
        let priority = tactical_category(units[index].unit_type);
        let Some(head) = self.head[slot] else {
            self.head[slot] = Some(index);
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
            self.head[slot] = Some(index);
            self.prev[head] = Some(index);
            self.prev[index] = None;
            self.next[index] = Some(head);
        }
    }
}

pub(crate) fn set_unit_order(unit: &mut MilitaryUnitState, code: i32, target: Option<ProvinceId>) {
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

    fn seed_province(state: &mut GameState, province: u16, owner: u8, adjacency: &[u16]) {
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
        nation: u8,
        province: u16,
        kind: MilitaryUnitKind,
        dest: Option<u16>,
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
        assert!(state.pending_land_battle().is_none());
    }

    #[test]
    fn combat_moves_phase_keeps_the_battle_in_continuation() {
        let mut state = game_state();
        state.turn.economic_turn = 3;
        state.turn.phase = crate::PhaseCode::COMBAT_MOVES;
        seed_province(&mut state, 1, 0, &[2]);
        seed_province(&mut state, 2, 1, &[1]);
        let attacker = push_unit(&mut state, 0, 1, MilitaryUnitKind::Regulars, Some(2));
        let defender = push_unit(&mut state, 1, 2, MilitaryUnitKind::Militia, None);
        state.diplomacy.relationships[NationId::new(0)][NationId::new(1)] =
            DiplomaticRelationship::War;
        state.diplomacy.relationships[NationId::new(1)][NationId::new(0)] =
            DiplomaticRelationship::War;
        let expected = PendingLandBattle {
            province: ProvinceId::new(2),
            attacker_nation: NationId::new(0),
            defender_nation: NationId::new(1),
            attacker_units: vec![attacker],
            defender_units: vec![defender],
        };
        assert_eq!(state.advance_turn(), crate::TurnStop::LandBattle);
        assert_eq!(state.turn.phase(), crate::PhaseCode::MILITARY_CLEANUP);
        assert_eq!(state.pending_land_battle(), Some(&expected));
        let encoded = serde_json::to_vec(&state).expect("serialize");
        let restored: GameState = serde_json::from_slice(&encoded).expect("deserialize");
        assert_eq!(restored.pending_land_battle(), Some(&expected));
        assert_eq!(state.advance_turn(), crate::TurnStop::LandBattle);
        assert_eq!(
            state.military_units[0].stationed_province,
            Some(ProvinceId::new(1))
        );
    }

    #[test]
    fn land_battle_stop_keeps_remaining_stacks_for_resume() {
        let mut state = game_state();
        state.turn.economic_turn = 3;
        state.turn.phase = crate::PhaseCode::COMBAT_MOVES;
        seed_province(&mut state, 1, 0, &[2]);
        seed_province(&mut state, 2, 1, &[1]);
        seed_province(&mut state, 3, 0, &[4]);
        seed_province(&mut state, 4, 1, &[3]);
        let first_attacker = push_unit(&mut state, 0, 1, MilitaryUnitKind::Regulars, Some(2));
        let first_defender = push_unit(&mut state, 1, 2, MilitaryUnitKind::Militia, None);
        let second_attacker = push_unit(&mut state, 0, 3, MilitaryUnitKind::Regulars, Some(4));
        let second_defender = push_unit(&mut state, 1, 4, MilitaryUnitKind::Militia, None);
        state.diplomacy.relationships[NationId::new(0)][NationId::new(1)] =
            DiplomaticRelationship::War;
        state.diplomacy.relationships[NationId::new(1)][NationId::new(0)] =
            DiplomaticRelationship::War;

        assert_eq!(state.advance_turn(), crate::TurnStop::LandBattle);
        let first = state
            .pending_land_battle()
            .cloned()
            .expect("first hostile stack creates a battle");
        assert!(
            first.attacker_units.contains(&first_attacker)
                || first.attacker_units.contains(&second_attacker)
        );

        let remaining_attacker = if first.attacker_units.contains(&first_attacker) {
            second_attacker
        } else {
            first_attacker
        };
        let remaining_defender = if first.defender_units.contains(&first_defender) {
            second_defender
        } else {
            first_defender
        };

        assert_eq!(state.continue_combat_moves(), crate::TurnStop::LandBattle);
        let second = state
            .pending_land_battle()
            .cloned()
            .expect("remaining hostile stack creates a second battle");
        assert_eq!(second.attacker_units, vec![remaining_attacker]);
        assert_eq!(second.defender_units, vec![remaining_defender]);
        assert_ne!(first.province, second.province);
    }

    fn seed_war(state: &mut GameState) {
        state.diplomacy.relationships[NationId::new(0)][NationId::new(1)] =
            DiplomaticRelationship::War;
        state.diplomacy.relationships[NationId::new(1)][NationId::new(0)] =
            DiplomaticRelationship::War;
    }

    fn battle_then_later_uncontested_state() -> (GameState, MilitaryUnitId, MilitaryUnitId) {
        let mut state = game_state();
        state.turn.economic_turn = 3;
        state.turn.phase = crate::PhaseCode::COMBAT_MOVES;
        seed_province(&mut state, 1, 0, &[2]);
        seed_province(&mut state, 2, 1, &[1]);
        seed_province(&mut state, 3, 0, &[4]);
        seed_province(&mut state, 4, 0, &[3]);
        let attacker = push_unit(&mut state, 0, 1, MilitaryUnitKind::Hussars, Some(2));
        let _defender = push_unit(&mut state, 1, 2, MilitaryUnitKind::Militia, None);
        let mover = push_unit(&mut state, 0, 3, MilitaryUnitKind::Regulars, Some(4));
        seed_war(&mut state);
        (state, attacker, mover)
    }

    #[test]
    fn later_uncontested_stack_moves_without_reforming() {
        let (mut state, attacker, mover) = battle_then_later_uncontested_state();
        assert_eq!(state.advance_turn(), crate::TurnStop::LandBattle);
        let battle = state
            .pending_land_battle()
            .cloned()
            .expect("higher-class hostile stack battles first");
        assert_eq!(battle.attacker_units, vec![attacker]);
        assert_eq!(
            state.military_units[2].stationed_province,
            Some(ProvinceId::new(3))
        );

        let crate::turn_flow::TurnContinuation::LandBattle(continuation) =
            std::mem::take(&mut state.continuation)
        else {
            panic!("combat continuation");
        };
        assert!(
            state.resume_combat_moves(continuation).is_none(),
            "remaining uncontested stack should finish combat moves"
        );
        assert_eq!(
            state.military_units[0].stationed_province,
            Some(ProvinceId::new(1)),
            "unresolved attackers stay put"
        );
        assert_eq!(state.military_units[2].id, mover);
        assert_eq!(
            state.military_units[2].stationed_province,
            Some(ProvinceId::new(4))
        );
        assert_eq!(state.military_units[2].order.code(), 0);
    }

    #[test]
    fn resolve_land_battle_then_continue_remaining_stacks() {
        let (mut state, attacker, mover) = battle_then_later_uncontested_state();
        assert_eq!(state.advance_turn(), crate::TurnStop::LandBattle);
        state.resolve_land_battle(true);
        assert_eq!(state.military_units[0].id, attacker);
        assert_eq!(
            state.military_units[0].stationed_province,
            Some(ProvinceId::new(2))
        );
        assert_eq!(state.military_units[0].order.code(), 0);
        assert_eq!(state.military_units[0].experience, EXPERIENCE_WINNER);
        assert_eq!(state.military_units[1].experience, EXPERIENCE_LOSER);
        assert_eq!(
            state.military_units[2].stationed_province,
            Some(ProvinceId::new(3))
        );

        let crate::turn_flow::TurnContinuation::LandBattle(continuation) =
            std::mem::take(&mut state.continuation)
        else {
            panic!("combat continuation");
        };
        assert!(state.resume_combat_moves(continuation).is_none());
        assert_eq!(state.military_units[2].id, mover);
        assert_eq!(
            state.military_units[2].stationed_province,
            Some(ProvinceId::new(4))
        );
    }
}
