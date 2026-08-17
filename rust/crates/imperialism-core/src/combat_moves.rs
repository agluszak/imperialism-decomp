//! Combat-movement phase (`TArmyMgr::DoCombatMoves`) without tactical battle UI.

use crate::military_phase::{combat_class, tactical_category};
use crate::*;
use serde::{Deserialize, Serialize};

const STACK_COMPOSITION: [i16; 16] = [0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 3, 0, 0, 3, 4, 5];
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
    units: Vec<MilitaryUnitId>,
    sort_key: i16,
}

struct StationedChains {
    by_province: ProvinceTable<Vec<MilitaryUnitId>>,
}

impl GameState {
    /// Retail `TArmyMgr::DoCombatMoves` for a non-client host.
    ///
    /// Identical orders produce identical movement and battle-creation state.
    /// The first would-be tactical battle is returned with the remaining stacks
    /// for the turn driver to store as [`crate::TurnContinuation::LandBattle`].
    pub fn do_combat_moves(&mut self) -> Option<CombatMovesContinuation> {
        let mut chains = StationedChains::from_units(&self.military_units);
        let stacks = self.form_stacks(&mut chains);
        let owner_cache = self.normalized_owner_cache();
        self.resolve_next_move(&mut chains, stacks, 0, owner_cache)
    }

    pub(crate) fn resume_combat_moves(
        &mut self,
        continuation: CombatMovesContinuation,
    ) -> Option<CombatMovesContinuation> {
        let mut chains = StationedChains::from_units(&self.military_units);
        self.resolve_next_move(
            &mut chains,
            continuation.stacks,
            continuation.next_stack,
            continuation.owner_cache,
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
    /// `ResolveNextMove`. Call [`Self::resume_after_land_battle`] to resume the cursor.
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
        let owner_cache = continuation.owner_cache.clone();
        let attacker_ids = battle
            .attacker_units
            .iter()
            .copied()
            .filter(|id| self.military_units.contains_key(id))
            .collect::<Vec<_>>();
        let defender_ids = battle
            .defender_units
            .iter()
            .copied()
            .filter(|id| self.military_units.contains_key(id))
            .collect::<Vec<_>>();

        // `ApplyPostBattleStackOutcomeAndGrowUnitMeters` (0x004a5ca0) builds the land
        // battle record before redistributing stacks.
        self.append_land_battle_report(
            BattleReportKind::LandBattle,
            battle.province,
            battle.attacker_nation,
            battle.defender_nation,
            &battle.attacker_units,
            &battle.defender_units,
            attacker_won,
        );

        let mut chains = StationedChains::from_units(&self.military_units);
        if attacker_won {
            self.redistribute_losers(&defender_ids, battle.province, &owner_cache);
            self.apply_uncontested_units(&mut chains, &attacker_ids);
            self.grow_stack_experience(&attacker_ids, EXPERIENCE_WINNER);
            self.grow_stack_experience(&defender_ids, EXPERIENCE_LOSER);
            let crate::turn_flow::TurnContinuation::LandBattle(continuation) =
                &mut self.continuation
            else {
                unreachable!("continuation still holds the land battle");
            };
            continuation.owner_cache[battle.province] = Some(stack.owner);
        } else {
            self.relocate_stack_to_source(&mut chains, &stack, &attacker_ids);
            self.grow_stack_experience(&attacker_ids, EXPERIENCE_LOSER);
            self.grow_stack_experience(&defender_ids, EXPERIENCE_WINNER);
        }
    }

    /// Stores a `DoCombatMoves` land-battle continuation (same as `advance_turn`).
    pub fn enter_land_battle(&mut self, continuation: CombatMovesContinuation) {
        self.continuation = crate::turn_flow::TurnContinuation::LandBattle(continuation);
    }

    /// Continues `DoCombatMoves` after the current land battle has been resolved.
    pub fn resume_after_land_battle(&mut self, story_ids: &[i32]) -> crate::TurnStop {
        let crate::turn_flow::TurnContinuation::LandBattle(continuation) =
            std::mem::take(&mut self.continuation)
        else {
            panic!("land-battle resume requires a combat-moves continuation");
        };
        if let Some(continuation) = self.resume_combat_moves(continuation) {
            self.continuation = crate::turn_flow::TurnContinuation::LandBattle(continuation);
            return crate::TurnStop::LandBattle;
        }
        self.advance_turn(story_ids)
    }

    fn form_stacks(&mut self, chains: &mut StationedChains) -> Vec<ArmyStack> {
        let mut stacks = Vec::new();
        for province in ProvinceId::all() {
            let unit_ids = chains.by_province[province].clone();
            let mut previous_target: Option<ProvinceId> = None;
            let mut previous_owner: Option<NationId> = None;
            let mut current_stack: Option<usize> = None;
            for id in unit_ids {
                let unit = self
                    .military_units
                    .get(&id)
                    .expect("stationed chain contains live unit");
                let target = unit.order.target();
                let owner = unit.owner_nation;
                let Some(dest) = target else {
                    let unit = self
                        .military_units
                        .get_mut(&id)
                        .expect("stationed chain contains live unit");
                    let strength = unit.strength;
                    unit.strength = if strength < 0x191 {
                        strength + 100
                    } else {
                        500
                    };
                    if let Some(major) = MajorNationId::from_nation(owner)
                        && !self.nations.majors[major].economy.diplomacy_eligible
                    {
                        set_unit_order(unit, MilitaryOrderCode::Sleep, None);
                    }
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
                stacks[stack_index].units.insert(0, id);
                current_stack = Some(stack_index);
            }
        }

        for stack in &mut stacks {
            let mut min_class = 3_i16;
            let mut max_class = 1_i16;
            for &id in &stack.units {
                let unit = self
                    .military_units
                    .get(&id)
                    .expect("formed stacks only contain live units");
                let class = combat_class(unit.unit_type);
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
        mut owner_cache: ProvinceTable<Option<NationId>>,
    ) -> Option<CombatMovesContinuation> {
        while next_stack < stacks.len() {
            let index = next_stack;
            next_stack += 1;
            let stack = &stacks[index];
            if owner_cache[stack.dest] == Some(stack.owner) {
                self.apply_uncontested_stack(chains, stack);
                continue;
            }
            if let Some(battle) = self.try_create_land_battle(chains, stack, &mut owner_cache) {
                return Some(CombatMovesContinuation {
                    stacks,
                    next_stack,
                    owner_cache,
                    battle,
                });
            }
        }
        self.finalize_military_units_without_ui(&owner_cache);
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
        for &id in &stack.units {
            let Some(unit) = self.military_units.get(&id) else {
                continue;
            };
            if unit.order.target() == Some(stack.dest) {
                our_units.insert(0, id);
            }
        }
        if our_units.is_empty() {
            return None;
        }

        let mut enemy_units = Vec::new();
        for &id in &chains.by_province[stack.dest] {
            enemy_units.insert(0, id);
        }

        let attacker_ids = our_units.clone();
        let defender_ids = enemy_units.clone();
        if !self.nation_pair_war_stamp_out_of_date(stack.owner, cached_owner) {
            // `TryCreateTacticalBattleViewForTileArmies` (0x004a4xxx): current war stamp
            // builds a preempted report (`sideWonFlag=0`) then relocates the stack.
            let defender = cached_owner.expect("preempted stack has a province owner");
            self.append_land_battle_report(
                BattleReportKind::PreemptedLandBattle,
                stack.dest,
                stack.owner,
                defender,
                &attacker_ids,
                &defender_ids,
                false,
            );
            self.relocate_stack_to_source(chains, stack, &our_units);
            return None;
        }
        if !enemy_units.is_empty() {
            let defender = cached_owner.expect("war stamp requires a province owner");
            return Some(PendingLandBattle {
                province: stack.dest,
                attacker_nation: stack.owner,
                defender_nation: defender,
                attacker_units: attacker_ids,
                defender_units: defender_ids,
            });
        }

        let defender = cached_owner.expect("uncontested takeover has a province owner");
        self.append_land_battle_report(
            BattleReportKind::UncontestedTakeover,
            stack.dest,
            stack.owner,
            defender,
            &attacker_ids,
            &[],
            true,
        );
        self.apply_uncontested_units(chains, &our_units);
        owner_cache[stack.dest] = Some(stack.owner);
        None
    }

    fn apply_uncontested_stack(&mut self, chains: &mut StationedChains, stack: &ArmyStack) {
        let units: Vec<_> = stack
            .units
            .iter()
            .copied()
            .filter(|id| self.military_units.contains_key(id))
            .collect();
        self.apply_uncontested_units(chains, &units);
    }

    fn apply_uncontested_units(&mut self, chains: &mut StationedChains, units: &[MilitaryUnitId]) {
        for &id in units {
            let dest = self.military_units[&id]
                .order
                .target()
                .expect("moving stack units have a destination");
            self.move_unit_to(chains, id, dest);
            set_unit_order(
                self.military_units
                    .get_mut(&id)
                    .expect("moving unit remains live"),
                MilitaryOrderCode::Idle,
                None,
            );
        }
    }

    fn relocate_stack_to_source(
        &mut self,
        chains: &mut StationedChains,
        stack: &ArmyStack,
        units: &[MilitaryUnitId],
    ) {
        for &id in units {
            set_unit_order(
                self.military_units
                    .get_mut(&id)
                    .expect("moving unit remains live"),
                MilitaryOrderCode::Idle,
                None,
            );
            if self.military_units[&id].stationed_province != Some(stack.source) {
                self.move_unit_to(chains, id, stack.source);
            }
        }
    }

    fn move_unit_to(&mut self, chains: &mut StationedChains, id: MilitaryUnitId, dest: ProvinceId) {
        let old_province = self.military_units[&id].stationed_province;
        chains.unlink(id, old_province);
        chains.link(&self.military_units, id, Some(dest));
        let unit = self
            .military_units
            .get_mut(&id)
            .expect("moving unit remains live");
        unit.stationed_province = Some(dest);
        clear_order_target(unit);
    }

    fn normalized_owner_cache(&self) -> ProvinceTable<Option<NationId>> {
        ProvinceTable::from_fn(|province| self.normalized_province_owner(province))
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
        owner_cache: &ProvinceTable<Option<NationId>>,
    ) {
        for tile in self.map.tiles.iter_mut() {
            tile.per_tile_visited = 0;
        }
        for unit in self.military_units.values_mut() {
            if unit.strength > 0
                && unit.stationed_province.is_some()
                && unit.order.code() != MilitaryOrderCode::Sleep
            {
                let target = unit.order.target();
                set_unit_order(unit, MilitaryOrderCode::Idle, target);
            }
        }
        self.apply_ownership_changes(owner_cache);
    }

    fn apply_ownership_changes(&mut self, owner_cache: &ProvinceTable<Option<NationId>>) {
        for province in ProvinceId::all() {
            let Some(current) = self.map.provinces[province].owner() else {
                continue;
            };
            let Some(new_owner) = owner_cache[province] else {
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
        defender_ids: &[MilitaryUnitId],
        battle_site: ProvinceId,
        owner_cache: &ProvinceTable<Option<NationId>>,
    ) {
        let Some(&head) = defender_ids.first() else {
            return;
        };
        let owner = self.military_units[&head].owner_nation;
        let mut candidates = [ProvinceId::new(0); 12];
        let mut count = 0_i32;
        for &adjacent in self.map.provinces[battle_site].adjacency() {
            if owner_cache[adjacent] == Some(owner) {
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
        for &id in defender_ids {
            if tactical_category(self.military_units[&id].unit_type) == 0 {
                continue;
            }
            set_unit_order(
                self.military_units
                    .get_mut(&id)
                    .expect("battle unit remains live"),
                MilitaryOrderCode::Redeploy,
                Some(chosen),
            );
        }
    }

    fn grow_stack_experience(&mut self, ids: &[MilitaryUnitId], amount: i16) {
        for &id in ids {
            let unit = self
                .military_units
                .get_mut(&id)
                .expect("battle unit remains live");
            if unit.strength > 0 {
                unit.experience = (unit.experience + amount).min(EXPERIENCE_CAP);
            }
        }
    }
}

pub(crate) fn stationed_chain_ids(
    units: &indexmap::IndexMap<MilitaryUnitId, MilitaryUnitState>,
    province: ProvinceId,
) -> Vec<MilitaryUnitId> {
    let chains = StationedChains::from_units(units);
    chains.by_province[province].clone()
}

impl StationedChains {
    fn from_units(units: &indexmap::IndexMap<MilitaryUnitId, MilitaryUnitState>) -> Self {
        let mut chains = Self {
            by_province: ProvinceTable::default(),
        };
        for (&id, unit) in units {
            chains.link(units, id, unit.stationed_province);
        }
        chains
    }

    fn unlink(&mut self, id: MilitaryUnitId, province: Option<ProvinceId>) {
        let Some(province) = province else {
            return;
        };
        self.by_province[province].retain(|&candidate| candidate != id);
    }

    fn link(
        &mut self,
        units: &indexmap::IndexMap<MilitaryUnitId, MilitaryUnitState>,
        id: MilitaryUnitId,
        province: Option<ProvinceId>,
    ) {
        let Some(province) = province else {
            return;
        };
        let priority = tactical_category(units[&id].unit_type);
        let chain = &mut self.by_province[province];
        let Some(&head) = chain.first() else {
            chain.push(id);
            return;
        };
        if tactical_category(units[&head].unit_type) < priority {
            let insertion = chain
                .iter()
                .position(|&candidate| tactical_category(units[&candidate].unit_type) >= priority)
                .unwrap_or(chain.len());
            chain.insert(insertion, id);
        } else {
            chain.insert(0, id);
        }
    }
}

pub(crate) fn set_unit_order(
    unit: &mut MilitaryUnitState,
    code: MilitaryOrderCode,
    target: Option<ProvinceId>,
) {
    let targets = *unit.order.targets();
    let mirrors = *unit.order.target_mirrors();
    unit.order = if code == MilitaryOrderCode::Idle && target.is_none() {
        MilitaryOrder::idle(targets, mirrors)
    } else {
        MilitaryOrder::retail(code, target, targets, mirrors)
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
                MilitaryOrderCode::Redeploy,
                Some(ProvinceId::new(dest)),
                [Some(province); 3],
                [Some(province); 3],
            ),
            None => MilitaryOrder::idle([Some(province); 3], [Some(province); 3]),
        };
        state.military_units.insert(
            id,
            MilitaryUnitState::new(
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
            ),
        );
        id
    }

    #[test]
    fn uncontested_redeploy_moves_the_unit_and_keeps_the_old_path() {
        let mut state = game_state();
        seed_province(&mut state, 1, 0, &[2]);
        seed_province(&mut state, 2, 0, &[1]);
        let id = push_unit(&mut state, 0, 1, MilitaryUnitKind::Regulars, Some(2));
        assert_eq!(state.do_combat_moves(), None);
        let unit = &state.military_units[&id];
        assert_eq!(unit.stationed_province, Some(ProvinceId::new(2)));
        assert_eq!(unit.order.code(), MilitaryOrderCode::Idle);
        assert_eq!(unit.order.targets(), &[Some(ProvinceId::new(1)); 3]);
        assert_eq!(unit.strength, 400);
        assert!(state.battle_reports.is_empty());
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
            .expect("hostile move creates a battle")
            .battle;
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
        assert_eq!(
            state.military_units[0].order.code(),
            MilitaryOrderCode::Redeploy
        );
        assert_eq!(
            state.military_units[1].stationed_province,
            Some(ProvinceId::new(2))
        );
        assert!(state.pending_land_battle().is_none());
        assert!(
            state.battle_reports.is_empty(),
            "land-battle records are written in ApplyPostBattleStackOutcome, not CreateTacticalBattle"
        );
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
        assert_eq!(state.advance_turn(&[]), crate::TurnStop::LandBattle);
        assert_eq!(state.turn.phase(), crate::PhaseCode::MILITARY_CLEANUP);
        assert_eq!(state.pending_land_battle(), Some(&expected));
        let encoded = serde_json::to_vec(&state).expect("serialize");
        let restored: GameState = serde_json::from_slice(&encoded).expect("deserialize");
        assert_eq!(restored.pending_land_battle(), Some(&expected));
        assert_eq!(state.advance_turn(&[]), crate::TurnStop::LandBattle);
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

        assert_eq!(state.advance_turn(&[]), crate::TurnStop::LandBattle);
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

        assert_eq!(
            state.resume_after_land_battle(&[]),
            crate::TurnStop::LandBattle
        );
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
        state
            .nations
            .append_owned_region_during_construction(NationId::new(0), ProvinceId::new(1));
        state
            .nations
            .append_owned_region_during_construction(NationId::new(1), ProvinceId::new(2));
        state
            .nations
            .append_owned_region_during_construction(NationId::new(0), ProvinceId::new(3));
        state
            .nations
            .append_owned_region_during_construction(NationId::new(0), ProvinceId::new(4));
        let attacker = push_unit(&mut state, 0, 1, MilitaryUnitKind::Hussars, Some(2));
        let _defender = push_unit(&mut state, 1, 2, MilitaryUnitKind::Militia, None);
        let mover = push_unit(&mut state, 0, 3, MilitaryUnitKind::Regulars, Some(4));
        seed_war(&mut state);
        (state, attacker, mover)
    }

    #[test]
    fn later_uncontested_stack_moves_without_reforming() {
        let (mut state, attacker, mover) = battle_then_later_uncontested_state();
        assert_eq!(state.advance_turn(&[]), crate::TurnStop::LandBattle);
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
        assert_eq!(
            state.military_units[2].order.code(),
            MilitaryOrderCode::Idle
        );
    }

    #[test]
    fn resolve_land_battle_then_continue_remaining_stacks() {
        let (mut state, attacker, mover) = battle_then_later_uncontested_state();
        assert_eq!(state.advance_turn(&[]), crate::TurnStop::LandBattle);
        state.resolve_land_battle(true);
        assert_eq!(state.military_units[0].id, attacker);
        assert_eq!(
            state.military_units[0].stationed_province,
            Some(ProvinceId::new(2))
        );
        assert_eq!(
            state.military_units[0].order.code(),
            MilitaryOrderCode::Idle
        );
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
        assert_eq!(
            state.map.provinces[ProvinceId::new(2)].owner(),
            Some(NationId::new(0))
        );
    }

    #[test]
    fn auto_resolve_writes_strengths_then_continues() {
        let mut state = game_state();
        state.turn.economic_turn = 3;
        state.turn.phase = crate::PhaseCode::COMBAT_MOVES;
        seed_province(&mut state, 1, 0, &[2]);
        seed_province(&mut state, 2, 1, &[1]);
        seed_province(&mut state, 3, 0, &[4]);
        seed_province(&mut state, 4, 0, &[3]);
        state
            .nations
            .append_owned_region_during_construction(NationId::new(0), ProvinceId::new(1));
        state
            .nations
            .append_owned_region_during_construction(NationId::new(1), ProvinceId::new(2));
        state
            .nations
            .append_owned_region_during_construction(NationId::new(0), ProvinceId::new(3));
        state
            .nations
            .append_owned_region_during_construction(NationId::new(0), ProvinceId::new(4));
        let attacker = push_unit(&mut state, 0, 1, MilitaryUnitKind::Regulars, Some(2));
        state.military_units[0].strength = 500;
        let _defender = push_unit(&mut state, 1, 2, MilitaryUnitKind::Militia, None);
        state.military_units[1].strength = 100;
        let mover = push_unit(&mut state, 0, 3, MilitaryUnitKind::Regulars, Some(4));
        seed_war(&mut state);

        assert_eq!(state.advance_turn(&[]), crate::TurnStop::LandBattle);
        let attacker_strength = state.military_units[0].strength;
        let defender_strength = state.military_units[1].strength;
        let _ = state.auto_resolve_land_battle(&[]);
        assert!(state.battle_reports_pending());
        assert_ne!(
            (
                state.military_units[0].strength,
                state.military_units[1].strength
            ),
            (attacker_strength, defender_strength),
            "ApplyChanges must write tactical strengths before post-battle"
        );
        assert_eq!(state.military_units[0].id, attacker);
        assert_eq!(state.military_units[2].id, mover);
        assert_eq!(
            state.military_units[2].stationed_province,
            Some(ProvinceId::new(4))
        );
        assert!(state.pending_land_battle().is_none());
        let attacker_xp = state.military_units[0].experience;
        let defender_xp = state.military_units[1].experience;
        assert!(
            attacker_xp == EXPERIENCE_WINNER && defender_xp == EXPERIENCE_LOSER
                || attacker_xp == EXPERIENCE_LOSER && defender_xp == EXPERIENCE_WINNER
                || attacker_xp == EXPERIENCE_WINNER && defender_xp == 0
                || attacker_xp == 0 && defender_xp == EXPERIENCE_WINNER,
            "post-battle experience must follow the Auto outcome, got {attacker_xp}/{defender_xp}"
        );
    }

    #[test]
    fn land_battle_resume_follows_unit_ids_after_roster_shift() {
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
        seed_war(&mut state);

        assert_eq!(state.advance_turn(&[]), crate::TurnStop::LandBattle);
        let first = state
            .pending_land_battle()
            .cloned()
            .expect("first hostile stack creates a battle");
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

        let dummy = push_unit(&mut state, 0, 1, MilitaryUnitKind::Minutemen, None);
        let dummy_unit = state
            .military_units
            .shift_remove(&dummy)
            .expect("dummy was pushed");
        state.military_units.shift_insert(0, dummy, dummy_unit);

        assert_eq!(
            state.resume_after_land_battle(&[]),
            crate::TurnStop::LandBattle
        );
        let second = state
            .pending_land_battle()
            .cloned()
            .expect("remaining hostile stack creates a second battle");
        assert_eq!(second.attacker_units, vec![remaining_attacker]);
        assert_eq!(second.defender_units, vec![remaining_defender]);
        assert_ne!(first.province, second.province);
    }
}
