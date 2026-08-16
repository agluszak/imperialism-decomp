use super::*;
use serde::{Deserialize, Serialize};

/// Strategic fleets handed to retail's modal naval battle view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingNavalBattle {
    pub attacker: TaskForceIndex,
    pub defender: TaskForceIndex,
}

/// Exact `TNavyMgr::CarryOutOrders` scan position following a modal encounter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NavyOrdersContinuation {
    pass: u8,
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
        let ships: Vec<ShipIndex> = navy.ships.iter().map(|ship| ship.ship).collect();
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
                        self.task_forces[force.get()].order = TaskForceOrder::Evade;
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
                        self.task_forces[force.get()].aggression = 0;
                        self.task_forces[force.get()].order = TaskForceOrder::Patrol;
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
            let Some(ship_index) = self.ships.iter().enumerate().position(|(index, ship)| {
                ship.nation == nation && !assigned.contains(&ShipIndex::new(index))
            }) else {
                break;
            };
            let ship = ShipIndex::new(ship_index);
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
            self.free_task_force(TaskForceIndex::new(index));
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
                self.free_task_force(TaskForceIndex::new(index));
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
                    .enumerate()
                    .filter_map(|(index, ship)| {
                        (ship.task_force.is_none()
                            && ship.location == zone
                            && ship.nation == nation.nation())
                        .then_some(ShipIndex::new(index))
                    })
                    .collect::<Vec<_>>();
                if in_port {
                    let (damaged, ready): (Vec<_>, Vec<_>) = ships.into_iter().partition(|ship| {
                        let ship = &self.ships[ship.get()];
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
        ships: &[ShipIndex],
        order: TaskForceOrder,
    ) {
        let Some((&first, rest)) = ships.split_first() else {
            return;
        };
        let force = self.create_task_force(zone, nation, first);
        for &ship in rest {
            self.reassign_ship_to_force(ship, force);
        }
        self.task_forces[force.get()].order = order;
    }

    pub(crate) fn carry_out_navy_orders(&mut self) -> Option<NavyOrdersContinuation> {
        self.carry_out_navy_orders_from(0, 0, 0)
    }

    pub(crate) fn resume_navy_orders(
        &mut self,
        continuation: NavyOrdersContinuation,
    ) -> Option<NavyOrdersContinuation> {
        self.carry_out_navy_orders_from(continuation.pass, continuation.outer, continuation.inner)
    }

    fn carry_out_navy_orders_from(
        &mut self,
        start_pass: u8,
        start_outer: usize,
        start_inner: usize,
    ) -> Option<NavyOrdersContinuation> {
        for pass in start_pass..6 {
            if matches!(pass, 2 | 5) {
                self.execute_navy_order_pass(
                    pass,
                    if pass == start_pass { start_outer } else { 0 },
                );
                continue;
            }
            let outer_start = if pass == start_pass { start_outer } else { 0 };
            for outer in outer_start..self.task_forces.len() {
                if !self.navy_outer_matches(pass, outer) || self.task_forces[outer].defeated {
                    continue;
                }
                let inner_start = if pass == start_pass && outer == outer_start {
                    start_inner
                } else {
                    0
                };
                for inner in inner_start..self.task_forces.len() {
                    if !self.navy_pair_matches(pass, outer, inner) {
                        continue;
                    }
                    let proceed = if pass == 4 {
                        self.navy_inline_spot(outer, inner)
                    } else {
                        self.navy_try_to_spot(outer, inner)
                    };
                    if proceed && self.navy_resolve_encounter(outer, inner) {
                        return Some(NavyOrdersContinuation {
                            pass,
                            outer,
                            inner: inner + 1,
                            battle: PendingNavalBattle {
                                attacker: TaskForceIndex::new(outer),
                                defender: TaskForceIndex::new(inner),
                            },
                        });
                    }
                    if self.task_forces[outer].defeated {
                        break;
                    }
                }
            }
        }
        self.finish_carry_out_navy_orders();
        None
    }

    fn execute_navy_order_pass(&mut self, pass: u8, start: usize) {
        let forces: Vec<usize> = (0..self.task_forces.len()).collect();
        for index in forces.into_iter().skip(start) {
            if self.task_forces[index].defeated {
                continue;
            }
            let selected = match pass {
                2 => self.task_forces[index].order == TaskForceOrder::Sail,
                5 => matches!(
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
                        let ships: Vec<ShipIndex> = self.task_forces[index]
                            .ships
                            .iter()
                            .map(|ship| ship.ship)
                            .collect();
                        for ship in ships {
                            if let Some(state) = self.ships.get_mut(ship.get()) {
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
                    let ships: Vec<ShipIndex> = self.task_forces[index]
                        .ships
                        .iter()
                        .map(|ship| ship.ship)
                        .collect();
                    for ship in ships {
                        let Some(state) = self.ships.get_mut(ship.get()) else {
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

    fn navy_outer_matches(&self, pass: u8, index: usize) -> bool {
        match pass {
            0 | 3 => matches!(
                self.task_forces[index].order,
                TaskForceOrder::Patrol | TaskForceOrder::Transit
            ),
            1 => self.task_forces[index].order == TaskForceOrder::Blockade,
            4 => self.task_forces[index].order == TaskForceOrder::Sail,
            _ => false,
        }
    }

    fn navy_pair_matches(&self, pass: u8, outer: usize, inner: usize) -> bool {
        let entry = &self.task_forces[outer];
        let other = &self.task_forces[inner];
        if !self.nation_pair_war_stamp_out_of_date(other.nation, Some(entry.nation)) {
            return false;
        }
        match pass {
            0 => other.location == entry.location && other.order == TaskForceOrder::Blockade,
            1 => {
                other.order == TaskForceOrder::Sail
                    && (other.location
                        == match entry.target {
                            TaskForceTarget::Zone(zone) => zone,
                            _ => entry.location,
                        }
                        || other.target == entry.target)
            }
            3 => other.location == entry.location && other.order != TaskForceOrder::Blockade,
            4 => other.location == entry.location && other.order == TaskForceOrder::Marines,
            _ => false,
        }
    }

    fn navy_try_to_spot(&mut self, outer: usize, inner: usize) -> bool {
        if self.task_forces[outer].ships.is_empty() || self.task_forces[inner].ships.is_empty() {
            return false;
        }
        if self.task_forces[outer].order == TaskForceOrder::Blockade
            || matches!(
                self.task_forces[inner].order,
                TaskForceOrder::Blockade | TaskForceOrder::Marines
            )
        {
            return true;
        }
        let threshold = self.task_force_deci_speed(outer) - self.task_force_deci_speed(inner)
            + 50
            + (self.task_forces[outer].ships.len() + self.task_forces[inner].ships.len())
                .saturating_sub(10) as i32;
        self.rng.next_crt_rand() % 100 < threshold
    }

    fn navy_inline_spot(&mut self, outer: usize, inner: usize) -> bool {
        if self.task_forces[outer].ships.is_empty() || self.task_forces[inner].ships.is_empty() {
            return false;
        }
        // Pass E always pairs against order 5, which retail force-attempts.
        true
    }

    fn task_force_deci_speed(&self, force: usize) -> i32 {
        let mut sum = 0;
        let mut count = 0;
        for child in &self.task_forces[force].ships {
            if child.selected {
                sum += descriptor_weight(self.ships[child.ship.get()].ship_type);
                count += 1;
            }
        }
        if count == 0 { 0 } else { sum * 10 / count }
    }

    fn task_force_battle_strength(&self, force: usize) -> i32 {
        self.task_forces[force]
            .ships
            .iter()
            .map(|child| {
                let ship = &self.ships[child.ship.get()];
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

    fn navy_resolve_encounter(&mut self, outer: usize, inner: usize) -> bool {
        const WEIGHT: [i32; 3] = [200, 100, 50];
        let this = self.task_force_battle_strength(outer) as i16 as i32;
        let other = self.task_force_battle_strength(inner) as i16 as i32;
        let this_aggression = self.task_forces[outer].aggression as usize;
        let other_aggression = self.task_forces[inner].aggression as usize;
        if this * 100 < WEIGHT[this_aggression] * other {
            if other * 100 < WEIGHT[other_aggression] * this || self.task_forces[inner].defeated {
                return false;
            }
            let worst = self.task_forces[outer]
                .ships
                .iter()
                .filter(|child| child.selected)
                .map(|child| descriptor_weight(self.ships[child.ship.get()].ship_type))
                .min()
                .unwrap_or(0);
            if self.rng.next_crt_rand() % 100 < (worst + 5) * 10 - self.task_force_deci_speed(inner)
            {
                self.task_forces[outer].defeated = true;
                return false;
            }
            return true;
        }
        if other * 100 < WEIGHT[other_aggression] * this {
            let worst = self.task_forces[inner]
                .ships
                .iter()
                .filter(|child| child.selected)
                .map(|child| descriptor_weight(self.ships[child.ship.get()].ship_type))
                .min()
                .unwrap_or(0);
            if self.rng.next_crt_rand() % 100 < (worst + 5) * 10 - self.task_force_deci_speed(outer)
            {
                self.task_forces[inner].defeated = true;
                return false;
            }
        }
        true
    }

    fn consolidate_mission_ships_to(&mut self, ships: &[ShipIndex], destination: OceanZoneId) {
        let mut pending = ships.to_vec();
        while let Some(ship) = pending.pop() {
            let Some(location) = self.ships.get(ship.get()).map(|ship| ship.location) else {
                continue;
            };
            let force = self.demand_exclusive_task_force(ship);
            let mut companions = Vec::new();
            pending.retain(|other| {
                let same = self
                    .ships
                    .get(other.get())
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
        ships: &[ShipIndex],
        location: OceanZoneId,
    ) -> Option<TaskForceIndex> {
        if let Some(existing) =
            navy_state(&self.missions[mission_index].data).and_then(|navy| navy.task_force)
            && self
                .task_forces
                .get(existing.get())
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
                .ships
                .get(ship.get())
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
        force: TaskForceIndex,
        nation: NationId,
        kind: NavyActionKind,
    ) {
        match kind {
            NavyActionKind::ControlSeaZone => {
                self.task_forces[force.get()].aggression = 1;
                let location = self.task_forces[force.get()].location;
                let blockade = self.control_sea_blockade_port(nation, location);
                if let Some(port) = blockade {
                    self.task_forces[force.get()].order = TaskForceOrder::Blockade;
                    self.task_forces[force.get()].target = TaskForceTarget::Zone(port);
                } else {
                    self.task_forces[force.get()].order = TaskForceOrder::Patrol;
                }
            }
            NavyActionKind::BlockadePort { port_zone } => {
                self.task_forces[force.get()].order = TaskForceOrder::Blockade;
                self.task_forces[force.get()].target = TaskForceTarget::Zone(port_zone);
            }
            NavyActionKind::Beachhead { target_province } => {
                let Some(owner) = self.map.provinces[target_province].owner() else {
                    return;
                };
                if self.war_stamp_stale(nation, owner) {
                    self.task_forces[force.get()].order = TaskForceOrder::Marines;
                    self.task_forces[force.get()].target =
                        TaskForceTarget::Province(target_province);
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

    fn order_sail_towards(&mut self, force: TaskForceIndex, destination: OceanZoneId) {
        let location = self.task_forces[force.get()].location;
        let mut min_weight = 10_000;
        for selected in &self.task_forces[force.get()].ships {
            if !selected.selected {
                continue;
            }
            if let Some(ship) = self.ships.get(selected.ship.get()) {
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
        self.task_forces[force.get()].target = TaskForceTarget::Zone(current);
        self.task_forces[force.get()].order = TaskForceOrder::Sail;
        self.prune_inactive_ships(force);
    }

    fn prune_inactive_ships(&mut self, force: TaskForceIndex) {
        let ships = self.task_forces[force.get()].ships.clone();
        let mut kept = Vec::new();
        for selected in ships {
            if selected.selected {
                kept.push(selected);
            } else if let Some(ship) = self.ships.get_mut(selected.ship.get()) {
                ship.task_force = None;
            }
        }
        self.task_forces[force.get()].ships = kept;
        self.task_forces[force.get()].flagship = self.task_forces[force.get()]
            .ships
            .first()
            .map(|ship| ship.ship);
    }

    pub(super) fn demand_exclusive_task_force(&mut self, ship: ShipIndex) -> TaskForceIndex {
        if let Some(force) = self.ships.get(ship.get()).and_then(|ship| ship.task_force)
            && self
                .task_forces
                .get(force.get())
                .is_some_and(|force| force.ships.len() == 1)
        {
            if let Some(entry) = self
                .task_forces
                .get_mut(force.get())
                .and_then(|force| force.ships.first_mut())
            {
                entry.selected = true;
            }
            return force;
        }
        if let Some(force) = self.ships.get(ship.get()).and_then(|ship| ship.task_force) {
            self.remove_ship_from_force(ship, force);
        }
        let location = self.ships[ship.get()].location;
        let nation = self.ships[ship.get()].nation;
        self.create_task_force(location, nation, ship)
    }

    pub(super) fn create_task_force(
        &mut self,
        location: OceanZoneId,
        nation: NationId,
        ship: ShipIndex,
    ) -> TaskForceIndex {
        self.bump_task_force_ids();
        let mut ship_counts = [0; 4];
        let bucket =
            usize::try_from(NAVY_DESCRIPTORS[self.ships[ship.get()].ship_type].toolbar_bucket)
                .expect("navy ship has a toolbar bucket");
        ship_counts[bucket] = 1;
        self.task_forces.insert(
            0,
            TaskForceState {
                // `TTaskForce(TZone*, short)` seeds aggression at 1, then
                // `DemocraticallyDetermineAggressionLevel` may overwrite it.
                aggression: 1,
                order: TaskForceOrder::None,
                target: TaskForceTarget::None,
                location,
                nation,
                ship_counts,
                defeated: false,
                ingot_tile: -1,
                flagship: Some(ship),
                ships: vec![SelectedShip {
                    ship,
                    selected: true,
                }],
            },
        );
        if let Some(state) = self.ships.get_mut(ship.get()) {
            state.task_force = Some(TaskForceIndex::new(0));
        }
        TaskForceIndex::new(0)
    }

    pub(super) fn reassign_ship_to_force(&mut self, ship: ShipIndex, force: TaskForceIndex) {
        if let Some(previous) = self.ships.get(ship.get()).and_then(|ship| ship.task_force)
            && previous != force
        {
            self.remove_ship_from_force(ship, previous);
        }
        if let Some(state) = self.ships.get_mut(ship.get()) {
            state.task_force = Some(force);
        }
        if let Some(force) = self.task_forces.get_mut(force.get())
            && !force.ships.iter().any(|entry| entry.ship == ship)
        {
            let bucket =
                usize::try_from(NAVY_DESCRIPTORS[self.ships[ship.get()].ship_type].toolbar_bucket)
                    .expect("navy ship has a toolbar bucket");
            force.ship_counts[bucket] += 1;
            force.ships.push(SelectedShip {
                ship,
                selected: true,
            });
        }
    }

    pub(super) fn remove_ship_from_force(&mut self, ship: ShipIndex, force: TaskForceIndex) {
        if let Some(force) = self.task_forces.get_mut(force.get()) {
            if force.ships.iter().any(|entry| entry.ship == ship) {
                let bucket = usize::try_from(
                    NAVY_DESCRIPTORS[self.ships[ship.get()].ship_type].toolbar_bucket,
                )
                .expect("navy ship has a toolbar bucket");
                force.ship_counts[bucket] -= 1;
                force.ships.retain(|entry| entry.ship != ship);
            }
            if force.flagship == Some(ship) {
                force.flagship = force.ships.first().map(|entry| entry.ship);
            }
        }
        if let Some(state) = self.ships.get_mut(ship.get()) {
            state.task_force = None;
        }
    }

    pub(super) fn free_task_force(&mut self, force: TaskForceIndex) {
        let index = force.get();
        if index >= self.task_forces.len() {
            return;
        }
        let ships: Vec<ShipIndex> = self.task_forces[index]
            .ships
            .iter()
            .map(|ship| ship.ship)
            .collect();
        for ship in ships {
            if let Some(state) = self.ships.get_mut(ship.get()) {
                state.task_force = None;
            }
        }
        for ship in &mut self.ships {
            if let Some(current) = ship.task_force {
                if current.get() == index {
                    ship.task_force = None;
                } else if current.get() > index {
                    ship.task_force = Some(TaskForceIndex::new(current.get() - 1));
                }
            }
        }
        for mission in &mut self.missions {
            if let Some(navy) = navy_state_mut(&mut mission.data)
                && let Some(current) = navy.task_force
            {
                if current.get() == index {
                    navy.task_force = None;
                } else if current.get() > index {
                    navy.task_force = Some(TaskForceIndex::new(current.get() - 1));
                }
            }
        }
        self.task_forces.remove(index);
    }

    fn bump_task_force_ids(&mut self) {
        for ship in &mut self.ships {
            if let Some(force) = &mut ship.task_force {
                *force = TaskForceIndex::new(force.get() + 1);
            }
        }
        for mission in &mut self.missions {
            if let Some(navy) = navy_state_mut(&mut mission.data)
                && let Some(force) = &mut navy.task_force
            {
                *force = TaskForceIndex::new(force.get() + 1);
            }
        }
    }
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
    ) {
        let ship = ShipIndex::new(state.ships.len());
        let force = TaskForceIndex::new(state.task_forces.len());
        state.ships.push(ShipState {
            ship_type: ShipType::Frigate,
            location,
            task_force: Some(force),
            aggression: 1,
            nation,
            name: String::new(),
            strength: 900,
            experience: 0,
            selection: 0,
        });
        state.task_forces.push(TaskForceState {
            aggression: 1,
            order,
            target: TaskForceTarget::None,
            location,
            nation,
            ship_counts: [0; 4],
            defeated: false,
            ingot_tile: -1,
            flagship: Some(ship),
            ships: vec![SelectedShip {
                ship,
                selected: true,
            }],
        });
    }

    #[test]
    fn preparation_splits_unordered_port_ships_into_escort_then_repair() {
        let mut state = game_state();
        let nation = NationId::new(0);
        state.ocean.zones = vec![ZoneKind::PortZone(PortZone {
            zone: zone(Vec::new()),
            port_tile: TileId::new(0),
        })];
        for (ship_type, strength) in [
            (ShipType::Frigate, 1),
            (ShipType::AdvancedIronclad, i16::MAX),
        ] {
            state.ships.push(ShipState {
                ship_type,
                location: OceanZoneId::new(0),
                task_force: None,
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
        assert_eq!(state.task_forces[0].ships[0].ship, ShipIndex::new(1));
        assert_eq!(state.task_forces[0].ship_counts.iter().sum::<i16>(), 1);
        assert_eq!(state.task_forces[1].order, TaskForceOrder::Repair);
        assert_eq!(state.task_forces[1].ships[0].ship, ShipIndex::new(0));
        assert_eq!(state.task_forces[1].ship_counts.iter().sum::<i16>(), 1);
        assert_eq!(state.ships[0].task_force, Some(TaskForceIndex::new(1)));
        assert_eq!(state.ships[1].task_force, Some(TaskForceIndex::new(0)));
    }

    #[test]
    fn naval_encounters_resume_from_the_retained_pair_cursor() {
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
        encounter_force(
            &mut state,
            attacker,
            OceanZoneId::new(1),
            TaskForceOrder::Patrol,
        );
        encounter_force(
            &mut state,
            defender,
            OceanZoneId::new(1),
            TaskForceOrder::Blockade,
        );

        let first = state.carry_out_navy_orders().expect("first encounter");
        assert_eq!(first.battle.attacker, TaskForceIndex::new(0));
        assert_eq!(first.battle.defender, TaskForceIndex::new(1));
        let second = state.resume_navy_orders(first).expect("second encounter");
        assert_eq!(second.battle.attacker, TaskForceIndex::new(2));
        assert_eq!(second.battle.defender, TaskForceIndex::new(3));
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
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(0),
            task_force: None,
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
                    ship: ShipIndex::new(0),
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
