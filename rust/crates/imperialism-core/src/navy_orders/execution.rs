use super::*;
use serde::{Deserialize, Serialize};

/// Strategic fleets handed to retail's modal naval battle view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingNavalBattle {
    pub attacker: TaskForceId,
    pub defender: TaskForceId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NavyPass {
    PatrolAgainstBlockade,
    BlockadeAgainstSail,
    Sail,
    SharedZone,
    SailAgainstMarines,
    MarinesAndRepair,
}

impl NavyPass {
    const fn next(self) -> Option<Self> {
        match self {
            Self::PatrolAgainstBlockade => Some(Self::BlockadeAgainstSail),
            Self::BlockadeAgainstSail => Some(Self::Sail),
            Self::Sail => Some(Self::SharedZone),
            Self::SharedZone => Some(Self::SailAgainstMarines),
            Self::SailAgainstMarines => Some(Self::MarinesAndRepair),
            Self::MarinesAndRepair => None,
        }
    }

    const fn is_action(self) -> bool {
        matches!(self, Self::Sail | Self::MarinesAndRepair)
    }
}

/// Exact `TNavyMgr::CarryOutOrders` semantic scan state following a modal encounter.
/// Indices address an immutable snapshot of stable force IDs, never the mutable
/// authoritative task-force vector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NavyOrdersContinuation {
    pass: NavyPass,
    forces: Vec<TaskForceId>,
    outer: usize,
    inner: usize,
    pub battle: PendingNavalBattle,
}

impl GameState {
    pub fn pending_naval_battle(&self) -> Option<&PendingNavalBattle> {
        match &self.continuation {
            crate::turn_flow::TurnContinuation::NavalBattle(continuation) => {
                Some(&continuation.battle)
            }
            _ => None,
        }
    }

    /// Continues the retained `CarryOutOrders` scan after the tactical naval
    /// battle has applied its outcome to the two authoritative task forces.
    pub fn resume_after_naval_battle(&mut self, story_ids: &[i32]) -> crate::TurnStop {
        let crate::turn_flow::TurnContinuation::NavalBattle(continuation) =
            std::mem::take(&mut self.continuation)
        else {
            panic!("naval-battle resume requires a navy-orders continuation");
        };
        if let Some(continuation) = self.resume_navy_orders(continuation) {
            self.continuation = crate::turn_flow::TurnContinuation::NavalBattle(continuation);
            return crate::TurnStop::NavalBattle;
        }
        self.advance_turn(story_ids)
    }

    pub(crate) fn give_navy_mission_orders(&mut self, mission_index: usize) {
        let Some(navy) = navy_state(&self.missions[mission_index].data) else {
            return;
        };
        let nation = self.missions[mission_index].nation;
        let navy_state_code = navy.state;
        let target = navy.target_zone;
        let mut port = navy.resolved_port_zone;
        let ships: Vec<ShipId> = navy.ships.iter().map(|ship| ship.ship).collect();
        let kind = navy_action_kind(&self.missions[mission_index].data);
        if let Some(navy) = navy_state_mut(&mut self.missions[mission_index].data) {
            for ship in &mut navy.ships {
                ship.selected = false;
            }
        }
        if ships.is_empty() {
            return;
        }

        match navy_state_code {
            2 => {
                if let Some(target) = target {
                    self.consolidate_mission_ships_to(&ships, target);
                    let force = self.combine_force_at(mission_index, nation, &ships, target);
                    if let Some(force) = force {
                        self.give_navy_action_orders(force, nation, kind);
                    }
                }
            }
            1 => {
                if let Some(target) = target {
                    self.consolidate_mission_ships_to(&ships, target);
                    let force = self.combine_force_at(mission_index, nation, &ships, target);
                    if let Some(force) = force {
                        self.task_force_mut(force)
                            .expect("mission task force exists")
                            .order = TaskForceOrder::Evade;
                    }
                }
            }
            0 => {
                if port.is_none()
                    && let Some(target) = target
                {
                    port = self.safest_nearby_zone(target, nation);
                    if let Some(navy) = navy_state_mut(&mut self.missions[mission_index].data) {
                        navy.resolved_port_zone = port;
                    }
                }
                if let Some(port) = port {
                    self.consolidate_mission_ships_to(&ships, port);
                    let force = self.combine_force_at(mission_index, nation, &ships, port);
                    if let Some(force) = force {
                        let force = self
                            .task_force_mut(force)
                            .expect("mission task force exists");
                        force.aggression = 0;
                        force.order = TaskForceOrder::Patrol;
                    }
                }
            }
            _ => {}
        }
    }

    pub(crate) fn assign_unassigned_ships_to_navy_missions(&mut self, nation: NationId) {
        while let Some(mission_index) = self.missions.iter().position(|mission| {
            mission.nation == nation && !mission.held && navy_state(&mission.data).is_some()
        }) {
            let assigned = assigned_navy_ships(&self.missions);
            let Some(ship) = self
                .ships
                .iter()
                .find(|ship| ship.nation == nation && !assigned.contains(&ship.id))
            else {
                break;
            };
            let ship = ship.id;
            if let Some(navy) = navy_state_mut(&mut self.missions[mission_index].data) {
                navy.ships.insert(
                    0,
                    SelectedShip {
                        ship,
                        selected: false,
                    },
                );
            } else {
                break;
            }
        }
    }

    /// Retail `TNavyMgr::ClearAllTransientOrders`: `RemoveStragglers` then clear
    /// selection bit 1. Sail/repair and empty task forces are freed; patrol and
    /// blockade forces remain.
    pub(crate) fn clear_all_transient_navy_orders(&mut self) {
        let mut remove = Vec::new();
        for (index, force) in self.task_forces.iter().enumerate() {
            if self.task_force_is_straggler(force) {
                remove.push(index);
            }
        }
        for index in remove.into_iter().rev() {
            let force = self.task_forces[index].id;
            self.free_task_force(force);
        }
        for ship in &mut self.ships {
            if ship.selection == 1 {
                ship.selection = 0;
            }
        }
    }

    fn task_force_is_straggler(&self, force: &TaskForceState) -> bool {
        if force.ships.is_empty() {
            return true;
        }
        match force.order {
            TaskForceOrder::None
            | TaskForceOrder::Sail
            | TaskForceOrder::Transit
            | TaskForceOrder::Escort
            | TaskForceOrder::Repair => true,
            TaskForceOrder::Marines => match force.target {
                TaskForceTarget::Province(province) => {
                    let owner = self.map.provinces[province].owner();
                    !self.nation_pair_war_stamp_out_of_date(force.nation, owner)
                }
                _ => false,
            },
            _ => false,
        }
    }

    pub(crate) fn prepare_to_carry_out_navy_orders(&mut self) {
        for province in ProvinceId::all() {
            let explored = self.map.provinces[province]
                .explored_by_majors()
                .iter()
                .any(|flag| *flag);
            if explored {
                *self.map.provinces[province].explored_by_majors_mut() =
                    MajorNationTable::default();
            }
        }
        self.make_sure_all_ships_have_orders();
        for force in &mut self.task_forces {
            force.defeated = false;
        }
    }

    /// Semantic `MakeSureAllShipsHaveOrders` normalization. Task forces are the
    /// authoritative navy-order records in core, so the retail rebuild becomes
    /// a rebuild of only ships which are not already in the committed queue.
    fn make_sure_all_ships_have_orders(&mut self) {
        for index in (0..self.task_forces.len()).rev() {
            if self.task_forces[index].order == TaskForceOrder::None {
                let force = self.task_forces[index].id;
                self.free_task_force(force);
            }
        }

        // `g_pMapActionContextListHead` is newest-first; context ordinals grow
        // at construction, so retail visits them in descending ordinal order.
        for zone_index in (0..self.ocean.zones.len()).rev() {
            let zone = OceanZoneId::new(
                u16::try_from(zone_index).expect("ocean context ordinal fits a zone id"),
            );
            let in_port = self.is_port_zone(zone);
            for nation in MajorNationId::all() {
                let ships = self
                    .ships
                    .iter()
                    .filter_map(|ship| {
                        (self.task_force_of_ship(ship.id).is_none()
                            && ship.location == zone
                            && ship.nation == nation.nation())
                        .then_some(ship.id)
                    })
                    .collect::<Vec<_>>();
                if in_port {
                    let (damaged, ready): (Vec<_>, Vec<_>) = ships.into_iter().partition(|ship| {
                        let ship = self.ship(*ship).expect("unordered ship exists");
                        i32::from(ship.strength) < NAVY_DESCRIPTORS[ship.ship_type].stock_cap
                    });
                    self.commit_rebuilt_force(
                        zone,
                        nation.nation(),
                        &damaged,
                        TaskForceOrder::Repair,
                    );
                    self.commit_rebuilt_force(
                        zone,
                        nation.nation(),
                        &ready,
                        TaskForceOrder::Escort,
                    );
                } else {
                    self.commit_rebuilt_force(
                        zone,
                        nation.nation(),
                        &ships,
                        TaskForceOrder::Transit,
                    );
                }
            }
        }
    }

    fn commit_rebuilt_force(
        &mut self,
        zone: OceanZoneId,
        nation: NationId,
        ships: &[ShipId],
        order: TaskForceOrder,
    ) {
        let Some((&first, rest)) = ships.split_first() else {
            return;
        };
        let force = self.create_task_force(zone, nation, first);
        for &ship in rest {
            self.reassign_ship_to_force(ship, force);
        }
        self.task_force_mut(force)
            .expect("rebuilt task force exists")
            .order = order;
    }

    pub(crate) fn carry_out_navy_orders(&mut self) -> Option<NavyOrdersContinuation> {
        self.carry_out_navy_orders_from(
            NavyPass::PatrolAgainstBlockade,
            self.task_forces.iter().map(|force| force.id).collect(),
            0,
            0,
        )
    }

    pub(crate) fn resume_navy_orders(
        &mut self,
        continuation: NavyOrdersContinuation,
    ) -> Option<NavyOrdersContinuation> {
        self.carry_out_navy_orders_from(
            continuation.pass,
            continuation.forces,
            continuation.outer,
            continuation.inner,
        )
    }

    fn carry_out_navy_orders_from(
        &mut self,
        mut pass: NavyPass,
        mut forces: Vec<TaskForceId>,
        mut outer: usize,
        mut inner: usize,
    ) -> Option<NavyOrdersContinuation> {
        loop {
            if pass.is_action() {
                self.execute_navy_order_pass(pass);
            } else {
                while outer < forces.len() {
                    while inner < forces.len() {
                        let outer_force = forces[outer];
                        let inner_force = forces[inner];
                        inner += 1;
                        let Some(outer_state) = self.task_force(outer_force) else {
                            continue;
                        };
                        if outer_state.defeated || !self.navy_outer_matches(pass, outer_force) {
                            continue;
                        }
                        if !self.navy_pair_matches(pass, outer_force, inner_force) {
                            continue;
                        }
                        let proceed = if pass == NavyPass::SailAgainstMarines {
                            self.navy_inline_spot(outer_force, inner_force)
                        } else {
                            self.navy_try_to_spot(outer_force, inner_force)
                        };
                        if proceed && self.navy_resolve_encounter(outer_force, inner_force) {
                            let active = self.turn.active_nation;
                            let player_involved = self
                                .task_force(outer_force)
                                .is_some_and(|force| force.nation == active)
                                || self
                                    .task_force(inner_force)
                                    .is_some_and(|f| f.nation == active);
                            if player_involved {
                                return Some(NavyOrdersContinuation {
                                    pass,
                                    forces,
                                    outer,
                                    inner,
                                    battle: PendingNavalBattle {
                                        attacker: outer_force,
                                        defender: inner_force,
                                    },
                                });
                            }
                            self.resolve_strategic_naval_battle(outer_force, inner_force);
                        }
                    }
                    outer += 1;
                    inner = 0;
                }
            }

            let Some(next) = pass.next() else {
                self.finish_carry_out_navy_orders();
                return None;
            };
            pass = next;
            forces = self.task_forces.iter().map(|force| force.id).collect();
            outer = 0;
            inner = 0;
        }
    }

    fn execute_navy_order_pass(&mut self, pass: NavyPass) {
        for index in 0..self.task_forces.len() {
            if self.task_forces[index].defeated {
                continue;
            }
            let selected = match pass {
                NavyPass::Sail => self.task_forces[index].order == TaskForceOrder::Sail,
                NavyPass::MarinesAndRepair => matches!(
                    self.task_forces[index].order,
                    TaskForceOrder::Marines | TaskForceOrder::Repair
                ),
                _ => false,
            };
            if !selected {
                continue;
            }
            match self.task_forces[index].order {
                TaskForceOrder::Sail => {
                    if let TaskForceTarget::Zone(zone) = self.task_forces[index].target {
                        let ships: Vec<ShipId> = self.task_forces[index]
                            .ships
                            .iter()
                            .map(|ship| ship.ship)
                            .collect();
                        for ship in ships {
                            if let Some(state) = self.ship_mut(ship) {
                                state.location = zone;
                            }
                        }
                    }
                }
                TaskForceOrder::Marines => {
                    if let TaskForceTarget::Province(province) = self.task_forces[index].target
                        && let Some(major) =
                            MajorNationId::from_nation(self.task_forces[index].nation)
                    {
                        self.map.provinces[province].explored_by_majors_mut()[major] = true;
                    }
                    self.task_forces[index].defeated = true;
                }
                TaskForceOrder::Repair => {
                    let ships: Vec<ShipId> = self.task_forces[index]
                        .ships
                        .iter()
                        .map(|ship| ship.ship)
                        .collect();
                    for ship in ships {
                        let Some(state) = self.ship_mut(ship) else {
                            continue;
                        };
                        let cap = ship_stock_cap(state.ship_type);
                        state.strength = (state.strength + cap / 4).min(cap);
                    }
                    self.task_forces[index].defeated = true;
                }
                _ => {}
            }
        }
    }

    fn finish_carry_out_navy_orders(&mut self) {
        self.clear_all_transient_navy_orders();
    }

    fn navy_outer_matches(&self, pass: NavyPass, force: TaskForceId) -> bool {
        let Some(entry) = self.task_force(force) else {
            return false;
        };
        match pass {
            NavyPass::PatrolAgainstBlockade | NavyPass::SharedZone => matches!(
                entry.order,
                TaskForceOrder::Patrol | TaskForceOrder::Transit
            ),
            NavyPass::BlockadeAgainstSail => entry.order == TaskForceOrder::Blockade,
            NavyPass::SailAgainstMarines => entry.order == TaskForceOrder::Sail,
            _ => false,
        }
    }

    fn navy_pair_matches(&self, pass: NavyPass, outer: TaskForceId, inner: TaskForceId) -> bool {
        let (Some(entry), Some(other)) = (self.task_force(outer), self.task_force(inner)) else {
            return false;
        };
        if !self.nation_pair_war_stamp_out_of_date(other.nation, Some(entry.nation)) {
            return false;
        }
        match pass {
            NavyPass::PatrolAgainstBlockade => {
                other.location == entry.location && other.order == TaskForceOrder::Blockade
            }
            NavyPass::BlockadeAgainstSail => {
                other.order == TaskForceOrder::Sail
                    && (other.location
                        == match entry.target {
                            TaskForceTarget::Zone(zone) => zone,
                            _ => entry.location,
                        }
                        || other.target == entry.target)
            }
            NavyPass::SharedZone => {
                other.location == entry.location && other.order != TaskForceOrder::Blockade
            }
            NavyPass::SailAgainstMarines => {
                other.location == entry.location && other.order == TaskForceOrder::Marines
            }
            _ => false,
        }
    }

    fn navy_try_to_spot(&mut self, outer: TaskForceId, inner: TaskForceId) -> bool {
        let (Some(outer_index), Some(inner_index)) =
            (self.task_force_index(outer), self.task_force_index(inner))
        else {
            return false;
        };
        if self.task_forces[outer_index].ships.is_empty()
            || self.task_forces[inner_index].ships.is_empty()
        {
            return false;
        }
        if self.task_forces[outer_index].order == TaskForceOrder::Blockade
            || matches!(
                self.task_forces[inner_index].order,
                TaskForceOrder::Blockade | TaskForceOrder::Marines
            )
        {
            return true;
        }
        let threshold = self.task_force_deci_speed(outer) - self.task_force_deci_speed(inner)
            + 50
            + (self.task_forces[outer_index].ships.len()
                + self.task_forces[inner_index].ships.len())
            .saturating_sub(10) as i32;
        self.rng.next_crt_rand() % 100 < threshold
    }

    fn navy_inline_spot(&mut self, outer: TaskForceId, inner: TaskForceId) -> bool {
        let (Some(outer), Some(inner)) = (self.task_force(outer), self.task_force(inner)) else {
            return false;
        };
        if outer.ships.is_empty() || inner.ships.is_empty() {
            return false;
        }
        // Pass E always pairs against order 5, which retail force-attempts.
        true
    }

    fn task_force_deci_speed(&self, force: TaskForceId) -> i32 {
        let mut sum = 0;
        let mut count = 0;
        let Some(force) = self.task_force(force) else {
            return 0;
        };
        for child in &force.ships {
            if child.selected {
                sum += descriptor_weight(
                    self.ship(child.ship)
                        .expect("task-force ship exists")
                        .ship_type,
                );
                count += 1;
            }
        }
        if count == 0 { 0 } else { sum * 10 / count }
    }

    fn task_force_battle_strength(&self, force: TaskForceId) -> i32 {
        self.task_force(force)
            .expect("battle task force exists")
            .ships
            .iter()
            .map(|child| {
                let ship = self.ship(child.ship).expect("task-force ship exists");
                let descriptor = NAVY_DESCRIPTORS[ship.ship_type];
                let quality = i32::from(ship.experience / 100);
                let priority = (quality + descriptor.navy_priority_weight * 10 + 5) / 10;
                let resolve = (quality + descriptor.resolve_weight * 10 + 5) / 10;
                ((priority + descriptor.calculate_weight) * 100
                    + resolve
                    + i32::from(ship.strength))
                    / descriptor.task_force_weight
            })
            .sum()
    }

    fn navy_resolve_encounter(&mut self, outer: TaskForceId, inner: TaskForceId) -> bool {
        let (Some(outer_index), Some(inner_index)) =
            (self.task_force_index(outer), self.task_force_index(inner))
        else {
            return false;
        };
        const WEIGHT: [i32; 3] = [200, 100, 50];
        let this = self.task_force_battle_strength(outer) as i16 as i32;
        let other = self.task_force_battle_strength(inner) as i16 as i32;
        let this_aggression = self.task_forces[outer_index].aggression as usize;
        let other_aggression = self.task_forces[inner_index].aggression as usize;
        if this * 100 < WEIGHT[this_aggression] * other {
            if other * 100 < WEIGHT[other_aggression] * this
                || self.task_forces[inner_index].defeated
            {
                return false;
            }
            let worst = self.task_forces[outer_index]
                .ships
                .iter()
                .filter(|child| child.selected)
                .map(|child| {
                    descriptor_weight(
                        self.ship(child.ship)
                            .expect("task-force ship exists")
                            .ship_type,
                    )
                })
                .min()
                .unwrap_or(0);
            if self.rng.next_crt_rand() % 100 < (worst + 5) * 10 - self.task_force_deci_speed(inner)
            {
                self.task_forces[outer_index].defeated = true;
                return false;
            }
            return true;
        }
        if other * 100 < WEIGHT[other_aggression] * this {
            let worst = self.task_forces[inner_index]
                .ships
                .iter()
                .filter(|child| child.selected)
                .map(|child| {
                    descriptor_weight(
                        self.ship(child.ship)
                            .expect("task-force ship exists")
                            .ship_type,
                    )
                })
                .min()
                .unwrap_or(0);
            if self.rng.next_crt_rand() % 100 < (worst + 5) * 10 - self.task_force_deci_speed(outer)
            {
                self.task_forces[inner_index].defeated = true;
                return false;
            }
        }
        true
    }

    /// Retail `TNavyMgr::ResolveStrategicBattle`, used when neither force belongs
    /// to the active nation. The tactical view is only a player-facing boundary.
    fn resolve_strategic_naval_battle(&mut self, left_id: TaskForceId, right_id: TaskForceId) {
        let (Some(left), Some(right)) = (
            self.task_force_index(left_id),
            self.task_force_index(right_id),
        ) else {
            return;
        };
        let left_start = self.task_forces[left].ships.len();
        let right_start = self.task_forces[right].ships.len();
        let max_tier = self.task_forces[left]
            .ships
            .iter()
            .chain(&self.task_forces[right].ships)
            .map(|child| {
                NAVY_DESCRIPTORS[self
                    .ship(child.ship)
                    .expect("task-force ship exists")
                    .ship_type]
                    .priority_tier
            })
            .max()
            .unwrap_or(1)
            .max(1);
        let thresholds = [1.1_f32, 0.95, 0.8];
        let left_threshold = thresholds[self.task_forces[left].aggression as usize];
        let right_threshold = thresholds[self.task_forces[right].aggression as usize];
        let mut tier = max_tier;
        let mut unreachable = false;

        loop {
            let left_bucket = self.task_force_admiral_experience_bucket(left_id);
            let right_bucket = self.task_force_admiral_experience_bucket(right_id);
            let (left_best_tier, left_ratio) =
                self.best_naval_tier_ratio(left_id, right_id, max_tier, left_bucket, right_bucket);
            let (right_best_tier, right_ratio) =
                self.best_naval_tier_ratio(right_id, left_id, max_tier, right_bucket, left_bucket);
            let left_adjust = tier_adjust(left_best_tier, left_ratio, tier, left_threshold);
            let right_adjust = tier_adjust(right_best_tier, right_ratio, tier, right_threshold);
            let left_weight =
                (left_bucket + 10) * self.task_force_active_average_weight_x10(left_id);
            let right_weight =
                (right_bucket + 10) * self.task_force_active_average_weight_x10(right_id);
            let total = left_weight + right_weight;
            if self.rng.next_crt_rand() % total < left_weight {
                tier += left_adjust;
            }
            if self.rng.next_crt_rand() % total < right_weight {
                tier += right_adjust;
            }
            tier = tier.max(1);
            if tier > max_tier {
                unreachable = true;
                break;
            }

            let left_eligible = self.task_force_count_at_or_above_tier(left_id, tier);
            let right_eligible = self.task_force_count_at_or_above_tier(right_id, tier);
            let left_count = self.task_forces[left].ships.len();
            let right_count = self.task_forces[right].ships.len();
            self.apply_naval_attrition(
                left_id,
                left_ratio,
                right_eligible.min(left_count),
                left_count,
            );
            self.apply_naval_attrition(
                right_id,
                right_ratio,
                left_eligible.min(right_count),
                right_count,
            );
            self.prune_sunk_force_ships(left_id);
            self.prune_sunk_force_ships(right_id);
            if self.task_forces[left].ships.is_empty() || self.task_forces[right].ships.is_empty() {
                break;
            }
        }

        let left_empty = self.task_forces[left].ships.is_empty();
        let right_empty = self.task_forces[right].ships.is_empty();
        if !unreachable && left_empty != right_empty {
            let (loser, winner, loser_start) = if left_empty {
                (left, right, left_start)
            } else {
                (right, left, right_start)
            };
            let remaining = self.task_forces[loser].ships.len();
            let bump = ((loser_start - remaining) * 5 + remaining) as i16;
            let winner_count = self.task_forces[winner].ships.len() as i16;
            if winner_count > 0 {
                if let Some(flagship) = self.task_forces[winner].flagship
                    && let Some(admiral) = self
                        .admirals
                        .iter_mut()
                        .find(|admiral| admiral.ship == Some(flagship))
                {
                    admiral.experience = (admiral.experience + bump).min(499);
                }
                let gain = bump * 3 / winner_count;
                for child in self.task_forces[winner].ships.clone() {
                    let ship = self.ship_mut(child.ship).expect("task-force ship exists");
                    ship.experience = (ship.experience + gain).min(499);
                }
            }
            self.task_forces[loser].defeated = true;
        }
    }

    fn task_force_admiral_experience_bucket(&self, force: TaskForceId) -> i32 {
        self.task_force(force)
            .expect("battle task force exists")
            .flagship
            .and_then(|flagship| {
                self.admirals
                    .iter()
                    .find(|admiral| admiral.ship == Some(flagship))
            })
            .map_or(0, |admiral| i32::from(admiral.experience / 100))
    }

    fn task_force_power_at_or_above_tier(&self, force: TaskForceId, tier: i32) -> f32 {
        self.task_force(force)
            .expect("battle task force exists")
            .ships
            .iter()
            .filter_map(|child| {
                let ship = self.ship(child.ship).expect("task-force ship exists");
                let descriptor = NAVY_DESCRIPTORS[ship.ship_type];
                (descriptor.priority_tier >= tier).then_some(
                    (i32::from(ship.experience / 100) + descriptor.resolve_weight * 10 + 5) / 10,
                )
            })
            .sum::<i32>() as f32
    }

    fn best_naval_tier_ratio(
        &self,
        force: TaskForceId,
        other: TaskForceId,
        max_tier: i32,
        bucket: i32,
        other_bucket: i32,
    ) -> (i32, f32) {
        let mut best_tier = 0;
        let mut best_ratio = 0.0_f32;
        for tier in 1..=max_tier {
            let power =
                self.task_force_power_at_or_above_tier(force, tier) * (1.0 + bucket as f32 * 0.1);
            let other_power = self.task_force_power_at_or_above_tier(other, tier)
                * (1.0 + other_bucket as f32 * 0.1);
            let ratio = power / other_power;
            if ratio > best_ratio {
                best_tier = tier;
                best_ratio = ratio;
            }
        }
        (best_tier, best_ratio)
    }

    fn task_force_active_average_weight_x10(&self, force: TaskForceId) -> i32 {
        let (sum, count) = self
            .task_force(force)
            .expect("battle task force exists")
            .ships
            .iter()
            .filter(|child| child.selected)
            .fold((0, 0), |(sum, count), child| {
                (
                    sum + descriptor_weight(
                        self.ship(child.ship)
                            .expect("task-force ship exists")
                            .ship_type,
                    ),
                    count + 1,
                )
            });
        if count == 0 { 0 } else { sum * 10 / count }
    }

    fn task_force_count_at_or_above_tier(&self, force: TaskForceId, tier: i32) -> usize {
        self.task_force(force)
            .expect("battle task force exists")
            .ships
            .iter()
            .filter(|child| {
                NAVY_DESCRIPTORS[self
                    .ship(child.ship)
                    .expect("task-force ship exists")
                    .ship_type]
                    .priority_tier
                    >= tier
            })
            .count()
    }

    fn apply_naval_attrition(
        &mut self,
        force: TaskForceId,
        favor_ratio: f32,
        target: usize,
        current_count: usize,
    ) {
        if target == 0 {
            return;
        }
        let ships = self
            .task_force(force)
            .expect("battle task force exists")
            .ships
            .clone();
        let mut selected = 0;
        while selected < target {
            for child in &ships {
                if selected == target {
                    break;
                }
                if current_count == target
                    || self.rng.next_crt_rand() % (current_count as i32) < target as i32
                {
                    selected += 1;
                    let roll =
                        self.rng.next_crt_rand() % 100 + self.rng.next_crt_rand() % 100 + 100;
                    let ship = self.ship_mut(child.ship).expect("task-force ship exists");
                    let damage = (0.5
                        - NAVY_DESCRIPTORS[ship.ship_type].task_force_weight as f32
                            * (roll as f32 * 0.005)
                            * favor_ratio
                            * -0.01) as i16;
                    ship.strength -= damage;
                }
            }
        }
    }

    fn prune_sunk_force_ships(&mut self, force: TaskForceId) {
        let sunk = self
            .task_force(force)
            .expect("battle task force exists")
            .ships
            .iter()
            .filter_map(|child| {
                self.ship(child.ship)
                    .is_some_and(|ship| ship.strength < 1)
                    .then_some(child.ship)
            })
            .collect::<Vec<_>>();
        for ship in sunk {
            self.remove_ship_completely(ship);
        }
    }

    fn remove_ship_completely(&mut self, ship: ShipId) {
        let Some(index) = self.ship_index(ship) else {
            return;
        };
        if let Some(force) = self.task_force_of_ship(ship) {
            self.remove_ship_from_force(ship, force);
        }
        self.ships.remove(index);
        for admiral in &mut self.admirals {
            if admiral.ship == Some(ship) {
                admiral.ship = None;
            }
        }
        for mission in &mut self.missions {
            remove_mission_ship_id(&mut mission.data, ship);
        }
    }

    fn consolidate_mission_ships_to(&mut self, ships: &[ShipId], destination: OceanZoneId) {
        let mut pending = ships.to_vec();
        while let Some(ship) = pending.pop() {
            let Some(location) = self.ship(ship).map(|ship| ship.location) else {
                continue;
            };
            let force = self.demand_exclusive_task_force(ship);
            let mut companions = Vec::new();
            pending.retain(|other| {
                let same = self
                    .ship(*other)
                    .is_some_and(|state| state.location == location);
                if same {
                    companions.push(*other);
                    false
                } else {
                    true
                }
            });
            for companion in companions {
                self.reassign_ship_to_force(companion, force);
            }
            self.order_sail_towards(force, destination);
        }
    }

    fn combine_force_at(
        &mut self,
        mission_index: usize,
        nation: NationId,
        ships: &[ShipId],
        location: OceanZoneId,
    ) -> Option<TaskForceId> {
        if let Some(existing) =
            navy_state(&self.missions[mission_index].data).and_then(|navy| navy.task_force)
            && self
                .task_force(existing)
                .is_some_and(|force| force.location != location)
        {
            self.free_task_force(existing);
            if let Some(navy) = navy_state_mut(&mut self.missions[mission_index].data) {
                navy.task_force = None;
            }
        }
        let mut force =
            navy_state(&self.missions[mission_index].data).and_then(|navy| navy.task_force);
        for &ship in ships {
            if !self
                .ship(ship)
                .is_some_and(|state| state.location == location)
            {
                continue;
            }
            if force.is_none() {
                force = Some(self.create_task_force(location, nation, ship));
            } else if let Some(force) = force {
                self.reassign_ship_to_force(ship, force);
            }
        }
        if let Some(navy) = navy_state_mut(&mut self.missions[mission_index].data) {
            navy.task_force = force;
        }
        force
    }

    fn give_navy_action_orders(
        &mut self,
        force: TaskForceId,
        nation: NationId,
        kind: NavyActionKind,
    ) {
        match kind {
            NavyActionKind::ControlSeaZone => {
                let location = self
                    .task_force(force)
                    .expect("navy action force exists")
                    .location;
                self.task_force_mut(force)
                    .expect("navy action force exists")
                    .aggression = 1;
                let blockade = self.control_sea_blockade_port(nation, location);
                if let Some(port) = blockade {
                    let force = self
                        .task_force_mut(force)
                        .expect("navy action force exists");
                    force.order = TaskForceOrder::Blockade;
                    force.target = TaskForceTarget::Zone(port);
                } else {
                    self.task_force_mut(force)
                        .expect("navy action force exists")
                        .order = TaskForceOrder::Patrol;
                }
            }
            NavyActionKind::BlockadePort { port_zone } => {
                let force = self
                    .task_force_mut(force)
                    .expect("navy action force exists");
                force.order = TaskForceOrder::Blockade;
                force.target = TaskForceTarget::Zone(port_zone);
            }
            NavyActionKind::Beachhead { target_province } => {
                let Some(owner) = self.map.provinces[target_province].owner() else {
                    return;
                };
                if self.war_stamp_stale(nation, owner) {
                    let force = self
                        .task_force_mut(force)
                        .expect("navy action force exists");
                    force.order = TaskForceOrder::Marines;
                    force.target = TaskForceTarget::Province(target_province);
                    return;
                }
                if self.at_war(nation, owner) {
                    return;
                }
                if let Some(major) = MajorNationId::from_nation(nation)
                    && self.nations.majors[major]
                        .economy
                        .diplomacy_policy_by_nation[owner]
                        != Some(DiplomacyPolicy::DeclareWar)
                {
                    self.post_policy(major, owner, DiplomacyPolicy::DeclareWar);
                }
            }
            NavyActionKind::Base => {}
        }
    }

    fn control_sea_blockade_port(
        &self,
        nation: NationId,
        location: OceanZoneId,
    ) -> Option<OceanZoneId> {
        let mut present_mask = 0_u8;
        for ship in &self.ships {
            if ship.location == location
                && let Some(major) = MajorNationId::from_nation(ship.nation)
            {
                present_mask |= 1 << major.get();
            }
        }
        let mut war_mask = 0_u8;
        let mut first_match = None;
        for other in MajorNationId::all() {
            if !self.war_stamp_stale(other.nation(), nation) {
                continue;
            }
            war_mask |= 1 << other.get();
            if let Some(port) = self.first_port_zone_for_nation(other.nation()) {
                let neighbor = self.zone(port).primary_neighbors.first().copied();
                if neighbor == Some(location) {
                    first_match = Some(port);
                }
            }
        }
        if present_mask & war_mask == 0 {
            first_match
        } else {
            None
        }
    }

    fn order_sail_towards(&mut self, force: TaskForceId, destination: OceanZoneId) {
        let Some(force_index) = self.task_force_index(force) else {
            return;
        };
        let location = self.task_forces[force_index].location;
        let mut min_weight = 10_000;
        for selected in &self.task_forces[force_index].ships {
            if !selected.selected {
                continue;
            }
            if let Some(ship) = self.ship(selected.ship) {
                min_weight = min_weight.min(descriptor_weight(ship.ship_type));
            }
        }
        let hops = if min_weight < 10_000 { min_weight } else { 0 };
        let distances = self.zone_hop_distances_from(destination);
        let mut current = location;
        for _ in 0..hops {
            let current_distance = distances[usize::from(current.get())];
            let mut stepped = false;
            for &neighbor in &self.zone(current).primary_neighbors {
                if distances[usize::from(neighbor.get())] < current_distance {
                    current = neighbor;
                    stepped = true;
                    break;
                }
            }
            if !stepped {
                break;
            }
        }
        self.task_forces[force_index].target = TaskForceTarget::Zone(current);
        self.task_forces[force_index].order = TaskForceOrder::Sail;
        self.prune_inactive_ships(force);
    }

    fn prune_inactive_ships(&mut self, force: TaskForceId) {
        let Some(force_index) = self.task_force_index(force) else {
            return;
        };
        let ships = self.task_forces[force_index].ships.clone();
        let mut kept = Vec::new();
        for selected in ships {
            if selected.selected {
                kept.push(selected);
            }
        }
        self.task_forces[force_index].ships = kept;
        self.task_forces[force_index].flagship = self.task_forces[force_index]
            .ships
            .first()
            .map(|ship| ship.ship);
    }

    pub(super) fn demand_exclusive_task_force(&mut self, ship: ShipId) -> TaskForceId {
        if let Some(force) = self.task_force_of_ship(ship)
            && self
                .task_force(force)
                .is_some_and(|force| force.ships.len() == 1)
        {
            if let Some(entry) = self
                .task_force_mut(force)
                .and_then(|force| force.ships.first_mut())
            {
                entry.selected = true;
            }
            return force;
        }
        if let Some(force) = self.task_force_of_ship(ship) {
            self.remove_ship_from_force(ship, force);
        }
        let state = self.ship(ship).expect("exclusive task-force ship exists");
        let location = state.location;
        let nation = state.nation;
        self.create_task_force(location, nation, ship)
    }

    pub(super) fn create_task_force(
        &mut self,
        location: OceanZoneId,
        nation: NationId,
        ship: ShipId,
    ) -> TaskForceId {
        let id = self.allocate_task_force_id();
        self.task_forces.insert(
            0,
            TaskForceState {
                id,
                // `TTaskForce(TZone*, short)` seeds aggression at 1, then
                // `DemocraticallyDetermineAggressionLevel` may overwrite it.
                aggression: 1,
                order: TaskForceOrder::None,
                target: TaskForceTarget::None,
                location,
                nation,
                defeated: false,
                ingot_tile: -1,
                flagship: Some(ship),
                ships: vec![SelectedShip {
                    ship,
                    selected: true,
                }],
            },
        );
        id
    }

    pub(super) fn reassign_ship_to_force(&mut self, ship: ShipId, force: TaskForceId) {
        if let Some(previous) = self.task_force_of_ship(ship)
            && previous != force
        {
            self.remove_ship_from_force(ship, previous);
        }
        let Some(force_index) = self.task_force_index(force) else {
            return;
        };
        if !self.task_forces[force_index]
            .ships
            .iter()
            .any(|entry| entry.ship == ship)
        {
            let bucket = usize::try_from(
                NAVY_DESCRIPTORS[self.ship(ship).expect("task-force ship exists").ship_type]
                    .toolbar_bucket,
            )
            .expect("navy ship has a toolbar bucket");
            let insert_at = self.task_forces[force_index]
                .ships
                .iter()
                .position(|entry| {
                    NAVY_DESCRIPTORS[self
                        .ship(entry.ship)
                        .expect("task-force ship exists")
                        .ship_type]
                        .toolbar_bucket
                        >= bucket as i32
                })
                .unwrap_or(self.task_forces[force_index].ships.len());
            self.task_forces[force_index].ships.insert(
                insert_at,
                SelectedShip {
                    ship,
                    selected: true,
                },
            );
        }
        self.elect_task_force_flagship(force);
    }

    pub(super) fn remove_ship_from_force(&mut self, ship: ShipId, force: TaskForceId) {
        if let Some(force) = self.task_force_mut(force) {
            if force.ships.iter().any(|entry| entry.ship == ship) {
                force.ships.retain(|entry| entry.ship != ship);
            }
            if force.flagship == Some(ship) {
                force.flagship = None;
            }
        }
        self.elect_task_force_flagship(force);
    }

    fn elect_task_force_flagship(&mut self, force: TaskForceId) {
        let Some(force_index) = self.task_force_index(force) else {
            return;
        };
        let flagship = self.task_forces[force_index]
            .ships
            .iter()
            .map(|entry| entry.ship)
            .reduce(|candidate, ship| self.finest_ship(ship, candidate));
        self.task_forces[force_index].flagship = flagship;
    }

    fn finest_ship(&self, ship: ShipId, candidate: ShipId) -> ShipId {
        let ship_admiral = self
            .admirals
            .iter()
            .find(|admiral| admiral.ship == Some(ship));
        let candidate_admiral = self
            .admirals
            .iter()
            .find(|admiral| admiral.ship == Some(candidate));
        match (ship_admiral, candidate_admiral) {
            (Some(left), Some(right)) if left.experience != right.experience => {
                return if left.experience > right.experience {
                    ship
                } else {
                    candidate
                };
            }
            (Some(_), None) => return ship,
            (None, Some(_)) => return candidate,
            _ => {}
        }
        let ship_state = self.ship(ship).expect("flagship candidate exists");
        let candidate_state = self.ship(candidate).expect("flagship candidate exists");
        if ship_state.ship_type != candidate_state.ship_type {
            return if ship_state.ship_type as u8 > candidate_state.ship_type as u8 {
                ship
            } else {
                candidate
            };
        }
        let ship_bucket = ship_state.experience / 100;
        let candidate_bucket = candidate_state.experience / 100;
        if ship_bucket != candidate_bucket {
            return if ship_bucket > candidate_bucket {
                ship
            } else {
                candidate
            };
        }
        if candidate_state.strength < ship_state.strength {
            ship
        } else {
            candidate
        }
    }

    pub(super) fn free_task_force(&mut self, force: TaskForceId) {
        let Some(index) = self.task_force_index(force) else {
            return;
        };
        for mission in &mut self.missions {
            if let Some(navy) = navy_state_mut(&mut mission.data)
                && navy.task_force == Some(force)
            {
                navy.task_force = None;
            }
        }
        self.task_forces.remove(index);
    }
}

fn tier_adjust(best_tier: i32, ratio: f32, candidate: i32, threshold: f32) -> i32 {
    if best_tier < candidate {
        -1
    } else if ratio >= threshold || best_tier > candidate {
        1
    } else {
        0
    }
}

fn remove_mission_ship_id(data: &mut MissionData, removed: ShipId) {
    let Some(navy) = navy_state_mut(data) else {
        return;
    };
    if navy.selected_ship == Some(removed) {
        navy.selected_ship = None;
    }
    navy.ships.retain(|child| child.ship != removed);
}

#[cfg(test)]
mod tests {
    use super::super::tests::zone;
    use super::*;
    use crate::test_support::game_state;

    fn encounter_force(
        state: &mut GameState,
        nation: NationId,
        location: OceanZoneId,
        order: TaskForceOrder,
    ) -> (ShipId, TaskForceId) {
        let ship = state.allocate_ship_id();
        let force = state.allocate_task_force_id();
        state.ships.push(ShipState {
            id: ship,
            ship_type: ShipType::Frigate,
            location,
            aggression: 1,
            nation,
            name: String::new(),
            strength: 900,
            experience: 0,
            selection: 0,
        });
        state.task_forces.push(TaskForceState {
            id: force,
            aggression: 1,
            order,
            target: TaskForceTarget::None,
            location,
            nation,
            defeated: false,
            ingot_tile: -1,
            flagship: Some(ship),
            ships: vec![SelectedShip {
                ship,
                selected: true,
            }],
        });
        (ship, force)
    }

    #[test]
    fn preparation_splits_unordered_port_ships_into_escort_then_repair() {
        let mut state = game_state();
        let nation = NationId::new(0);
        state.ocean.zones = vec![ZoneKind::PortZone(PortZone {
            zone: zone(Vec::new()),
            port_tile: TileId::new(0),
        })];
        for (index, (ship_type, strength)) in [
            (ShipType::Frigate, 1),
            (ShipType::AdvancedIronclad, i16::MAX),
        ]
        .into_iter()
        .enumerate()
        {
            state.ships.push(ShipState {
                id: ShipId::new(index),
                ship_type,
                location: OceanZoneId::new(0),
                aggression: 1,
                nation,
                name: String::new(),
                strength,
                experience: 0,
                selection: 0,
            });
        }

        state.prepare_to_carry_out_navy_orders();

        assert_eq!(state.task_forces.len(), 2);
        assert_eq!(state.task_forces[0].order, TaskForceOrder::Escort);
        assert_eq!(state.task_forces[0].ships[0].ship, ShipId::new(1));
        assert_eq!(state.task_forces[1].order, TaskForceOrder::Repair);
        assert_eq!(state.task_forces[1].ships[0].ship, ShipId::new(0));
        assert_eq!(
            state.task_force_of_ship(ShipId::new(0)),
            Some(TaskForceId::new(1))
        );
        assert_eq!(
            state.task_force_of_ship(ShipId::new(1)),
            Some(TaskForceId::new(2))
        );
    }

    #[test]
    fn freeing_a_task_force_does_not_retarget_later_references_or_reuse_its_id() {
        let mut state = game_state();
        let nation = NationId::new(0);
        let (_, removed) = encounter_force(
            &mut state,
            nation,
            OceanZoneId::new(0),
            TaskForceOrder::Patrol,
        );
        let (survivor_ship, survivor) = encounter_force(
            &mut state,
            nation,
            OceanZoneId::new(1),
            TaskForceOrder::Patrol,
        );
        state.missions.push(MissionState {
            nation,
            data: MissionData::ControlSeaZone(NavyMissionState {
                target_zone: Some(OceanZoneId::new(1)),
                resolved_port_zone: None,
                selected_ship: Some(survivor_ship),
                task_force: Some(survivor),
                state: 2,
                required_equipage_bits: [0; 4],
                ships: vec![SelectedShip {
                    ship: survivor_ship,
                    selected: false,
                }],
            }),
            path_nation: None,
            state: 2,
            importance_bits: 0,
            held: false,
            marker: 0,
        });

        state.free_task_force(removed);

        assert_eq!(state.task_forces[0].id, survivor);
        assert_eq!(state.task_force_of_ship(survivor_ship), Some(survivor));
        assert_eq!(
            navy_state(&state.missions[0].data)
                .expect("navy mission")
                .task_force,
            Some(survivor)
        );

        let ship = state.allocate_ship_id();
        state.ships.push(ShipState {
            id: ship,
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(2),
            aggression: 1,
            nation,
            name: String::new(),
            strength: 900,
            experience: 0,
            selection: 0,
        });
        let replacement = state.create_task_force(OceanZoneId::new(2), nation, ship);
        assert_ne!(replacement, removed);
    }

    #[test]
    fn naval_encounters_resume_from_the_retained_pair_cursor() {
        let mut state = game_state();
        let attacker = NationId::new(0);
        let defender = NationId::new(1);
        state.diplomacy.relationships[defender][attacker] = DiplomaticRelationship::War;
        let (_, first_attacker) = encounter_force(
            &mut state,
            attacker,
            OceanZoneId::new(0),
            TaskForceOrder::Patrol,
        );
        let (_, first_defender) = encounter_force(
            &mut state,
            defender,
            OceanZoneId::new(0),
            TaskForceOrder::Blockade,
        );
        let (_, second_attacker) = encounter_force(
            &mut state,
            attacker,
            OceanZoneId::new(1),
            TaskForceOrder::Patrol,
        );
        let (_, second_defender) = encounter_force(
            &mut state,
            defender,
            OceanZoneId::new(1),
            TaskForceOrder::Blockade,
        );

        let first = state.carry_out_navy_orders().expect("first encounter");
        assert_eq!(first.battle.attacker, first_attacker);
        assert_eq!(first.battle.defender, first_defender);
        let second = state.resume_navy_orders(first).expect("second encounter");
        assert_eq!(second.battle.attacker, second_attacker);
        assert_eq!(second.battle.defender, second_defender);
    }

    #[test]
    fn serialized_naval_resume_survives_task_force_queue_mutation() {
        let mut state = game_state();
        let attacker = NationId::new(0);
        let defender = NationId::new(1);
        state.diplomacy.relationships[defender][attacker] = DiplomaticRelationship::War;
        encounter_force(
            &mut state,
            attacker,
            OceanZoneId::new(0),
            TaskForceOrder::Patrol,
        );
        encounter_force(
            &mut state,
            defender,
            OceanZoneId::new(0),
            TaskForceOrder::Blockade,
        );
        let (_, expected_attacker) = encounter_force(
            &mut state,
            attacker,
            OceanZoneId::new(1),
            TaskForceOrder::Patrol,
        );
        let (_, expected_defender) = encounter_force(
            &mut state,
            defender,
            OceanZoneId::new(1),
            TaskForceOrder::Blockade,
        );

        let first = state.carry_out_navy_orders().expect("first encounter");
        let encoded = serde_json::to_string(&first).expect("serialize continuation");
        let first: NavyOrdersContinuation =
            serde_json::from_str(&encoded).expect("deserialize continuation");

        let loose_ship = state.allocate_ship_id();
        state.ships.push(ShipState {
            id: loose_ship,
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(9),
            aggression: 1,
            nation: attacker,
            name: String::new(),
            strength: 900,
            experience: 0,
            selection: 0,
        });
        let inserted = state.create_task_force(OceanZoneId::new(9), attacker, loose_ship);
        assert_eq!(state.task_forces[0].id, inserted);

        let second = state.resume_navy_orders(first).expect("second encounter");
        assert_eq!(second.battle.attacker, expected_attacker);
        assert_eq!(second.battle.defender, expected_defender);
    }

    #[test]
    fn invalid_navy_pass_cannot_deserialize_as_completed_execution() {
        let mut state = game_state();
        let attacker = NationId::new(0);
        let defender = NationId::new(1);
        state.diplomacy.relationships[defender][attacker] = DiplomaticRelationship::War;
        encounter_force(
            &mut state,
            attacker,
            OceanZoneId::new(0),
            TaskForceOrder::Patrol,
        );
        encounter_force(
            &mut state,
            defender,
            OceanZoneId::new(0),
            TaskForceOrder::Blockade,
        );
        let continuation = state.carry_out_navy_orders().expect("encounter");
        let mut value = serde_json::to_value(continuation).expect("serialize continuation");
        value["pass"] = serde_json::Value::String("invalid".into());
        assert!(serde_json::from_value::<NavyOrdersContinuation>(value).is_err());
    }

    #[test]
    fn sinking_non_contiguous_ships_preserves_survivor_identity() {
        let mut state = game_state();
        let nation = NationId::new(1);
        let (first_ship, force) = encounter_force(
            &mut state,
            nation,
            OceanZoneId::new(0),
            TaskForceOrder::Patrol,
        );
        let mut ships = vec![first_ship];
        for _ in 0..3 {
            let ship = state.allocate_ship_id();
            state.ships.push(ShipState {
                id: ship,
                ship_type: ShipType::Frigate,
                location: OceanZoneId::new(0),
                aggression: 1,
                nation,
                name: String::new(),
                strength: 900,
                experience: 0,
                selection: 0,
            });
            state.reassign_ship_to_force(ship, force);
            ships.push(ship);
        }
        state.admirals = ships
            .iter()
            .copied()
            .map(|ship| AdmiralState {
                nation,
                name: String::new(),
                experience: 0,
                ship: Some(ship),
            })
            .collect();
        state.missions.push(MissionState {
            nation,
            data: MissionData::ControlSeaZone(NavyMissionState {
                target_zone: Some(OceanZoneId::new(0)),
                resolved_port_zone: None,
                selected_ship: Some(ships[2]),
                task_force: Some(force),
                state: 2,
                required_equipage_bits: [0; 4],
                ships: ships
                    .iter()
                    .copied()
                    .map(|ship| SelectedShip {
                        ship,
                        selected: false,
                    })
                    .collect(),
            }),
            path_nation: None,
            state: 2,
            importance_bits: 0,
            held: false,
            marker: 0,
        });
        state.ship_mut(ships[1]).expect("ship exists").strength = 0;
        state.ship_mut(ships[3]).expect("ship exists").strength = 0;

        state.prune_sunk_force_ships(force);

        assert_eq!(
            state.ships.iter().map(|ship| ship.id).collect::<Vec<_>>(),
            vec![ships[0], ships[2]]
        );
        assert_eq!(
            state.task_force(force).expect("force survives").ships,
            vec![
                SelectedShip {
                    ship: ships[2],
                    selected: true,
                },
                SelectedShip {
                    ship: ships[0],
                    selected: true,
                },
            ]
        );
        assert_eq!(
            state.task_force(force).expect("force survives").flagship(),
            Some(ships[2])
        );
        assert_eq!(state.admirals[0].ship, Some(ships[0]));
        assert_eq!(state.admirals[1].ship, None);
        assert_eq!(state.admirals[2].ship, Some(ships[2]));
        assert_eq!(state.admirals[3].ship, None);
        let navy = navy_state(&state.missions[0].data).expect("navy mission");
        assert_eq!(navy.selected_ship, Some(ships[2]));
        assert_eq!(
            navy.ships.iter().map(|ship| ship.ship).collect::<Vec<_>>(),
            vec![ships[0], ships[2]]
        );
    }

    #[test]
    fn naval_encounter_between_inactive_nations_resolves_without_a_turn_stop() {
        let mut state = game_state();
        let left = NationId::new(1);
        let right = NationId::new(2);
        state.diplomacy.relationships[right][left] = DiplomaticRelationship::War;
        encounter_force(
            &mut state,
            left,
            OceanZoneId::new(0),
            TaskForceOrder::Patrol,
        );
        encounter_force(
            &mut state,
            right,
            OceanZoneId::new(0),
            TaskForceOrder::Blockade,
        );
        let rng_before = state.rng;

        assert_eq!(state.carry_out_navy_orders(), None);
        assert_ne!(state.rng, rng_before);
    }

    #[test]
    fn control_sea_give_orders_sails_an_assigned_frigate_one_descriptor_hop() {
        let mut state = game_state();
        let nation = NationId::new(0);
        state.ocean.zones = vec![
            ZoneKind::Zone(zone(vec![OceanZoneId::new(1)])),
            ZoneKind::Zone(zone(vec![OceanZoneId::new(0), OceanZoneId::new(2)])),
            ZoneKind::Zone(zone(vec![OceanZoneId::new(1), OceanZoneId::new(3)])),
            ZoneKind::Zone(zone(vec![OceanZoneId::new(2), OceanZoneId::new(4)])),
            ZoneKind::Zone(zone(vec![OceanZoneId::new(3)])),
        ];
        state.ships.push(ShipState {
            id: ShipId::new(0),
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(0),
            aggression: 0,
            nation,
            name: String::new(),
            strength: 900,
            experience: 0,
            selection: 0,
        });
        state.missions.push(MissionState {
            nation,
            data: MissionData::ControlSeaZone(NavyMissionState {
                target_zone: Some(OceanZoneId::new(4)),
                resolved_port_zone: None,
                selected_ship: None,
                task_force: None,
                state: 2,
                required_equipage_bits: [0; 4],
                ships: vec![SelectedShip {
                    ship: ShipId::new(0),
                    selected: false,
                }],
            }),
            path_nation: None,
            state: 2,
            importance_bits: 0,
            held: false,
            marker: 0,
        });
        state.give_navy_mission_orders(0);
        assert_eq!(state.task_forces[0].order, TaskForceOrder::Sail);
        let _ = state.carry_out_navy_orders();
        assert_eq!(state.ships[0].location, OceanZoneId::new(3));
        assert!(
            state.task_forces.is_empty(),
            "sail orders are stragglers after CarryOutOrders"
        );
    }
}
