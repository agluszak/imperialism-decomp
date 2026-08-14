//! Navy mission `GiveOrders`, hop-limited sail, and `CarryOutOrders` type 1/5/8.

use crate::city::ship_stock_cap;
use crate::*;

const UNREACHED: i16 = 0x29a;
const ORDER_SAIL: i32 = 1;
const ORDER_PATROL: i32 = 3;
const ORDER_MARINES: i32 = 5;
const ORDER_BLOCKADE: i32 = 6;
const ORDER_REPAIR: i32 = 8;
const ORDER_EVADE: i32 = 9;

const NAVY_DESCRIPTORS: [[i32; 9]; 14] = [
    [0, 0, 0, 0, 0, 0, -1, 0, 0],
    [0, 0, 100, 600, 0, 2, -1, 1, 0],
    [0, 0, 95, 1000, 0, 4, -1, 1, 0],
    [300, 5, 90, 900, 4, 0, 1, 3, 1],
    [600, 6, 80, 1700, 3, 0, 0, 2, 1],
    [0, 0, 95, 900, 0, 8, -1, 1, 0],
    [0, 0, 100, 600, 0, 4, -1, 1, 0],
    [300, 7, 80, 700, 7, 0, 2, 5, 2],
    [500, 8, 45, 1200, 5, 0, 3, 3, 2],
    [1000, 10, 40, 1800, 6, 0, 0, 4, 3],
    [0, 0, 75, 1200, 0, 16, -1, 1, 0],
    [600, 9, 50, 1000, 8, 0, 1, 6, 3],
    [2000, 13, 30, 2800, 7, 0, 3, 5, 4],
    [1800, 13, 45, 2200, 9, 0, 2, 6, 4],
];

const INDUSTRY_COST: [i16; 14] = [0, 0, 0, 2, 5, 0, 0, 3, 6, 15, 0, 8, 24, 18];

pub(crate) fn navy_category_baselines(enabled: &[bool; 14]) -> [i32; 4] {
    let mut totals = [0_i32; 4];
    let mut enabled_count = 0;
    for type_index in 1..14 {
        if NAVY_DESCRIPTORS[type_index][0] <= 0 || !enabled[type_index] {
            continue;
        }
        enabled_count += 1;
        let calc = NAVY_DESCRIPTORS[type_index][1];
        totals[0] += NAVY_DESCRIPTORS[type_index][0] * calc * calc;
        let stock = NAVY_DESCRIPTORS[type_index][3];
        let task_force = NAVY_DESCRIPTORS[type_index][2];
        totals[1] += (calc * stock * 100) / task_force;
        totals[2] += NAVY_DESCRIPTORS[type_index][4];
        totals[3] += i32::from(INDUSTRY_COST[type_index]);
    }
    if enabled_count == 0 {
        return totals;
    }
    let half = enabled_count / 2;
    [
        (totals[0] + half) / enabled_count,
        (totals[1] + half) / enabled_count,
        (totals[2] + half) / enabled_count,
        (totals[3] + half) / enabled_count,
    ]
}

pub(crate) fn ship_priority_contribution(
    ship: &ShipState,
    category: i32,
    baselines: &[i32; 4],
) -> i32 {
    let type_index = ship.ship_type as usize;
    if type_index >= NAVY_DESCRIPTORS.len() {
        return 0;
    }
    let divisor = baselines[category as usize];
    if divisor == 0 {
        return 0;
    }
    let descriptor = NAVY_DESCRIPTORS[type_index];
    match category {
        0 => {
            let quantity_term = i32::from(ship.experience / 100) + descriptor[0] * 10 + 5;
            let weight = descriptor[1];
            (quantity_term / 10 * weight * weight * 100) / divisor
        }
        1 => {
            let weight = descriptor[1];
            (weight * i32::from(ship.strength) * 10000) / (descriptor[2] * divisor)
        }
        2 => (descriptor[7] * 100) / divisor,
        3 => {
            if ship.strength < 1 {
                0
            } else {
                (i32::from(INDUSTRY_COST[type_index]) * 100) / divisor
            }
        }
        _ => 0,
    }
}

fn descriptor_weight(ship_type: ShipType) -> i32 {
    NAVY_DESCRIPTORS[ship_type as usize][7]
}

impl GameState {
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
                        self.task_forces[force.get()].order = ORDER_EVADE;
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
                        self.task_forces[force.get()].order = ORDER_PATROL;
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
                ship.nation == nation && !assigned.contains(&ShipId::new(index))
            }) else {
                break;
            };
            let ship = ShipId::new(ship_index);
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
            self.free_task_force(TaskForceId::new(index));
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
            0 | ORDER_SAIL | 4 | 7 | ORDER_REPAIR => true,
            ORDER_MARINES => match force.target {
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
        for force in &mut self.task_forces {
            force.defeated = false;
        }
    }

    pub(crate) fn carry_out_navy_orders(&mut self) {
        let forces: Vec<usize> = (0..self.task_forces.len()).collect();
        for index in forces {
            if self.task_forces[index].defeated {
                continue;
            }
            match self.task_forces[index].order {
                ORDER_SAIL => {
                    if let TaskForceTarget::Zone(zone) = self.task_forces[index].target {
                        let ships: Vec<ShipId> = self.task_forces[index]
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
                ORDER_MARINES => {
                    if let TaskForceTarget::Province(province) = self.task_forces[index].target
                        && let Some(major) =
                            MajorNationId::from_nation(self.task_forces[index].nation)
                    {
                        self.map.provinces[province].explored_by_majors_mut()[major] = true;
                    }
                    self.task_forces[index].defeated = true;
                }
                ORDER_REPAIR => {
                    let ships: Vec<ShipId> = self.task_forces[index]
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
        self.clear_all_transient_navy_orders();
    }

    fn consolidate_mission_ships_to(&mut self, ships: &[ShipId], destination: OceanZoneId) {
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
        ships: &[ShipId],
        location: OceanZoneId,
    ) -> Option<TaskForceId> {
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
        force: TaskForceId,
        nation: NationId,
        kind: NavyActionKind,
    ) {
        match kind {
            NavyActionKind::ControlSeaZone => {
                self.task_forces[force.get()].aggression = 1;
                let location = self.task_forces[force.get()].location;
                let blockade = self.control_sea_blockade_port(nation, location);
                if let Some(port) = blockade {
                    self.task_forces[force.get()].order = ORDER_BLOCKADE;
                    self.task_forces[force.get()].target = TaskForceTarget::Zone(port);
                } else {
                    self.task_forces[force.get()].order = ORDER_PATROL;
                }
            }
            NavyActionKind::BlockadePort { port_zone } => {
                self.task_forces[force.get()].order = ORDER_BLOCKADE;
                self.task_forces[force.get()].target = TaskForceTarget::Zone(port_zone);
            }
            NavyActionKind::Beachhead { target_province } => {
                let Some(owner) = self.map.provinces[target_province].owner() else {
                    return;
                };
                if self.war_stamp_stale(nation, owner) {
                    self.task_forces[force.get()].order = ORDER_MARINES;
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

    fn order_sail_towards(&mut self, force: TaskForceId, destination: OceanZoneId) {
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
        self.task_forces[force.get()].order = ORDER_SAIL;
        self.prune_inactive_ships(force);
    }

    fn prune_inactive_ships(&mut self, force: TaskForceId) {
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

    fn demand_exclusive_task_force(&mut self, ship: ShipId) -> TaskForceId {
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

    fn create_task_force(
        &mut self,
        location: OceanZoneId,
        nation: NationId,
        ship: ShipId,
    ) -> TaskForceId {
        self.bump_task_force_ids();
        self.task_forces.insert(
            0,
            TaskForceState {
                aggression: 0,
                order: 0,
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
            },
        );
        if let Some(state) = self.ships.get_mut(ship.get()) {
            state.task_force = Some(TaskForceId::new(0));
        }
        TaskForceId::new(0)
    }

    fn reassign_ship_to_force(&mut self, ship: ShipId, force: TaskForceId) {
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
            force.ships.push(SelectedShip {
                ship,
                selected: true,
            });
        }
    }

    fn remove_ship_from_force(&mut self, ship: ShipId, force: TaskForceId) {
        if let Some(force) = self.task_forces.get_mut(force.get()) {
            force.ships.retain(|entry| entry.ship != ship);
            if force.flagship == Some(ship) {
                force.flagship = force.ships.first().map(|entry| entry.ship);
            }
        }
        if let Some(state) = self.ships.get_mut(ship.get()) {
            state.task_force = None;
        }
    }

    fn free_task_force(&mut self, force: TaskForceId) {
        let index = force.get();
        if index >= self.task_forces.len() {
            return;
        }
        let ships: Vec<ShipId> = self.task_forces[index]
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
                    ship.task_force = Some(TaskForceId::new(current.get() - 1));
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
                    navy.task_force = Some(TaskForceId::new(current.get() - 1));
                }
            }
        }
        self.task_forces.remove(index);
    }

    fn bump_task_force_ids(&mut self) {
        for ship in &mut self.ships {
            if let Some(force) = &mut ship.task_force {
                *force = TaskForceId::new(force.get() + 1);
            }
        }
        for mission in &mut self.missions {
            if let Some(navy) = navy_state_mut(&mut mission.data)
                && let Some(force) = &mut navy.task_force
            {
                *force = TaskForceId::new(force.get() + 1);
            }
        }
    }

    pub(crate) fn reassess_navy_mission(&mut self, mission_index: usize) {
        match &self.missions[mission_index].data {
            MissionData::ScatteredShips(_) => self.reassess_scattered_ships(mission_index),
            MissionData::ControlSeaZone(_)
            | MissionData::Beachhead(_)
            | MissionData::BlockadePort { .. }
            | MissionData::Escort(_) => self.reassess_navy_order_mission(mission_index),
            MissionData::Invade { .. } => self.reassess_invade_mission(mission_index),
            MissionData::AttackProvince(_) | MissionData::DefendProvince { .. } => {}
        }
    }

    fn reassess_scattered_ships(&mut self, mission_index: usize) {
        self.missions[mission_index].state = 3;
        self.missions[mission_index].importance_bits = 0.001_f32.to_bits();
        let required = navy_required_from_profile(NAVY_CONTROL_PROFILE, 1.0);
        if let Some(navy) = navy_state_mut(&mut self.missions[mission_index].data) {
            navy.required_equipage_bits = required;
        }
    }

    fn reassess_invade_mission(&mut self, mission_index: usize) {
        if navy_state(&self.missions[mission_index].data).is_some() {
            self.write_control_sea_needs(mission_index);
            self.advance_navy_selection_state(mission_index);
        }
        self.missions[mission_index].state = 2;
        if let MissionData::Invade { attack, .. } = &self.missions[mission_index].data {
            let attack = attack.clone();
            self.reassess_attack_mission_fields(mission_index, &attack);
        }
        if navy_state(&self.missions[mission_index].data).is_some() {
            self.write_control_sea_needs(mission_index);
        }
    }

    fn reassess_navy_order_mission(&mut self, mission_index: usize) {
        let nation = self.missions[mission_index].nation;
        match &self.missions[mission_index].data {
            MissionData::BlockadePort { .. } => {
                self.missions[mission_index].state = 3;
            }
            MissionData::Escort(_) => {
                self.missions[mission_index].state = 2;
            }
            _ => {
                self.missions[mission_index].state =
                    self.control_sea_lifecycle_state(mission_index);
            }
        }
        match &self.missions[mission_index].data {
            MissionData::Escort(_) => {
                self.missions[mission_index].importance_bits = self.escort_importance_bits(nation);
            }
            MissionData::ControlSeaZone(navy)
            | MissionData::Beachhead(navy)
            | MissionData::BlockadePort { navy, .. } => {
                if let Some(target) = navy.target_zone
                    && let Some(major) = MajorNationId::from_nation(nation)
                {
                    self.missions[mission_index].importance_bits =
                        self.control_sea_zone_importance_bits(major, target);
                }
            }
            _ => {}
        }
        match &self.missions[mission_index].data {
            MissionData::Escort(_) => self.write_escort_needs(mission_index),
            _ => self.write_control_sea_needs(mission_index),
        }
        self.advance_navy_selection_state(mission_index);
    }

    fn control_sea_lifecycle_state(&self, mission_index: usize) -> u8 {
        let nation = self.missions[mission_index].nation;
        let Some(navy) = navy_state(&self.missions[mission_index].data) else {
            return 2;
        };
        let Some(target) = navy.target_zone else {
            return 2;
        };
        let Some(home) = self.first_port_zone_for_nation(nation) else {
            return 2;
        };
        if self.zone(home).primary_neighbors.first().copied() != Some(target) {
            return 2;
        }
        if self.hostile_navy_similarity(nation, target) > 0.0 {
            1
        } else {
            2
        }
    }

    fn escort_importance_bits(&self, nation: NationId) -> u32 {
        let Some(major) = MajorNationId::from_nation(nation) else {
            return 0;
        };
        let mut need_cap = self.nations.majors[major].economy.capacities.transport;
        if need_cap == 0 {
            need_cap = 1;
        }
        let Some(home) = self.first_port_zone_for_nation(nation) else {
            return 0;
        };
        let Some(&cached) = self.zone(home).primary_neighbors.first() else {
            return 0;
        };
        let merchant = self.nations.majors[major].economy.capacities.trade_offer;
        (self.sea_zone_importance(nation, cached) * f32::from(merchant) / f32::from(need_cap))
            .to_bits()
    }

    fn write_control_sea_needs(&mut self, mission_index: usize) {
        let nation = self.missions[mission_index].nation;
        let Some(navy) = navy_state(&self.missions[mission_index].data) else {
            return;
        };
        let Some(target) = navy.target_zone else {
            return;
        };
        let mut total = self.hostile_navy_similarity(nation, target) * 1.1;
        if total == 0.0 {
            total = 100.0;
        }
        if let Some(navy) = navy_state_mut(&mut self.missions[mission_index].data) {
            navy.required_equipage_bits = navy_required_from_profile(NAVY_CONTROL_PROFILE, total);
        }
    }

    fn write_escort_needs(&mut self, mission_index: usize) {
        let nation = self.missions[mission_index].nation;
        let year_threshold = (self.turn.economic_turn / 4) as f32 + 110.0;
        let mut total = 1.0_f32;
        for minor in MinorNationId::all() {
            if !self.escort_minor_eligible(minor.nation(), nation, year_threshold) {
                continue;
            }
            let Some(home) = self.first_port_zone_for_nation(minor.nation()) else {
                continue;
            };
            let Some(&target) = self.zone(home).primary_neighbors.first() else {
                continue;
            };
            total += self.navy_profile_similarity(
                self.hostile_navy_vector(nation, target),
                NAVY_ESCORT_PROFILE,
            );
        }
        if let Some(navy) = navy_state_mut(&mut self.missions[mission_index].data) {
            navy.required_equipage_bits = navy_required_from_profile(NAVY_ESCORT_PROFILE, total);
        }
    }

    fn escort_minor_eligible(
        &self,
        minor: NationId,
        mission_nation: NationId,
        year_threshold: f32,
    ) -> bool {
        if self.nations.common(minor).is_none() {
            return false;
        }
        match self.status_of(minor) {
            CountryStatus::ProtectorateOf(master) => master == mission_nation,
            CountryStatus::Independent | CountryStatus::ColonyOf(_) => {
                f32::from(self.diplomacy.standings[minor][mission_nation]) > year_threshold
            }
        }
    }

    fn advance_navy_selection_state(&mut self, mission_index: usize) {
        let Some(navy) = navy_state(&self.missions[mission_index].data) else {
            return;
        };
        if navy.ships.is_empty() {
            if let Some(navy) = navy_state_mut(&mut self.missions[mission_index].data) {
                navy.state = 0;
            }
            return;
        }
        let nation = self.missions[mission_index].nation;
        let target = navy.target_zone;
        let port = navy.resolved_port_zone;
        let required = navy.required_equipage_bits.map(f32::from_bits);
        let ships: Vec<ShipId> = navy.ships.iter().map(|ship| ship.ship).collect();
        let mode = navy.state;
        let next = match mode {
            0 => {
                let near = self.assigned_navy_readiness(&ships, required, target, 1, port);
                if near >= 1.0 {
                    let at_target = self.assigned_navy_readiness(&ships, required, target, 0, port);
                    if at_target >= 1.0 { 2 } else { 1 }
                } else {
                    0
                }
            }
            1 => 2,
            2 => {
                let near = self.assigned_navy_readiness(&ships, required, target, 1, port);
                if near < 0.8 {
                    if let Some(target) = target {
                        let refreshed = self.safest_nearby_zone(target, nation);
                        if let Some(navy) = navy_state_mut(&mut self.missions[mission_index].data) {
                            navy.resolved_port_zone = refreshed;
                        }
                    }
                    0
                } else {
                    2
                }
            }
            _ => mode,
        };
        if let Some(navy) = navy_state_mut(&mut self.missions[mission_index].data) {
            navy.state = next;
        }
    }

    fn assigned_navy_readiness(
        &self,
        ships: &[ShipId],
        required: [f32; 4],
        near: Option<OceanZoneId>,
        distance_threshold: i16,
        far: Option<OceanZoneId>,
    ) -> f32 {
        let vector = self.assigned_navy_category_vector(ships, near, distance_threshold, far);
        let mut numerator = 0.0;
        let mut denominator = 0.0;
        for index in 0..4 {
            numerator += (required[index] * vector[index]).sqrt();
            denominator += required[index];
        }
        if denominator == 0.0 {
            0.0
        } else {
            numerator / denominator
        }
    }

    fn assigned_navy_category_vector(
        &self,
        ships: &[ShipId],
        near: Option<OceanZoneId>,
        distance_threshold: i16,
        far: Option<OceanZoneId>,
    ) -> [f32; 4] {
        let far = far.filter(|&zone| Some(zone) != near);
        let near_distances = near.map(|zone| self.zone_hop_distances_from(zone));
        let far_distances = far.map(|zone| self.zone_hop_distances_from(zone));
        let mut vector = [0.0_f32; 4];
        for &id in ships {
            let Some(ship) = self.ships.get(id.get()) else {
                continue;
            };
            let near_ok = match &near_distances {
                None => true,
                Some(distances) => hop_distance(distances, ship.location) <= distance_threshold,
            };
            let far_ok = far_distances.as_ref().is_some_and(|distances| {
                hop_distance(distances, ship.location) <= distance_threshold
            });
            if near_ok || far_ok {
                accumulate_ship_categories(
                    ship,
                    &mut vector,
                    &self.technology.industry_enabled_by_slot,
                );
            }
        }
        vector
    }

    fn hostile_navy_similarity(&self, nation: NationId, zone: OceanZoneId) -> f32 {
        self.navy_profile_similarity(self.hostile_navy_vector(nation, zone), NAVY_CONTROL_PROFILE)
    }

    fn hostile_navy_vector(&self, nation: NationId, zone: OceanZoneId) -> [f32; 4] {
        let mut vector = [0.0_f32; 4];
        for ship in &self.ships {
            if ship.location != zone || !self.at_war(nation, ship.nation) {
                continue;
            }
            accumulate_ship_categories(
                ship,
                &mut vector,
                &self.technology.industry_enabled_by_slot,
            );
        }
        vector
    }

    fn navy_profile_similarity(&self, vector: [f32; 4], profile: [i16; 4]) -> f32 {
        let sum: f32 = vector.iter().sum();
        if sum == 0.0 {
            return 0.0;
        }
        let mut divergence = 0.0;
        for (component, &target) in vector.iter().zip(&profile) {
            divergence += (*component / sum - f32::from(target) * 0.01).abs();
        }
        sum * (1.0 - divergence * 0.5)
    }

    fn zone_hop_distances_from(&self, origin: OceanZoneId) -> Vec<i16> {
        let mut distances = vec![UNREACHED; self.ocean.zones.len()];
        let start = usize::from(origin.get());
        if start >= distances.len() {
            return distances;
        }
        distances[start] = 0;
        let mut queue = vec![origin];
        let mut head = 0;
        while head < queue.len() {
            let current = queue[head];
            head += 1;
            let current_index = usize::from(current.get());
            let next_level = distances[current_index] + 1;
            for &neighbor in &self.zone(current).primary_neighbors {
                let neighbor_index = usize::from(neighbor.get());
                if neighbor_index < distances.len() && next_level < distances[neighbor_index] {
                    distances[neighbor_index] = next_level;
                    queue.push(neighbor);
                }
            }
        }
        distances
    }

    fn safest_nearby_zone(&self, zone: OceanZoneId, nation: NationId) -> Option<OceanZoneId> {
        let mut best = None;
        let mut best_wars = -1_i32;
        for &neighbor in &self.zone(zone).primary_neighbors {
            if self.is_port_zone(neighbor) && !self.port_owned_by(neighbor, nation) {
                continue;
            }
            let mut wars = 0;
            for ship in &self.ships {
                if ship.location == neighbor && self.at_war(nation, ship.nation) {
                    wars += 1;
                }
            }
            if wars > best_wars {
                best_wars = wars;
                best = Some(neighbor);
            }
        }
        best
    }

    fn is_port_zone(&self, zone: OceanZoneId) -> bool {
        matches!(
            self.ocean.zones.get(usize::from(zone.get())),
            Some(ZoneKind::PortZone(_))
        )
    }

    fn port_owned_by(&self, zone: OceanZoneId, nation: NationId) -> bool {
        let Some(ZoneKind::PortZone(port)) = self.ocean.zones.get(usize::from(zone.get())) else {
            return false;
        };
        self.map[port.port_tile].owner_nation == Some(TileOwnerTag::from_nation(nation))
    }

    fn zone(&self, zone: OceanZoneId) -> &Zone {
        self.ocean.zones[usize::from(zone.get())].zone()
    }
}

fn assigned_navy_ships(missions: &[MissionState]) -> Vec<ShipId> {
    let mut assigned = Vec::new();
    for mission in missions {
        if let Some(navy) = navy_state(&mission.data) {
            assigned.extend(navy.ships.iter().map(|ship| ship.ship));
        }
    }
    assigned
}

fn navy_state(data: &MissionData) -> Option<&NavyMissionState> {
    match data {
        MissionData::ControlSeaZone(navy)
        | MissionData::Escort(navy)
        | MissionData::ScatteredShips(navy)
        | MissionData::Beachhead(navy) => Some(navy),
        MissionData::BlockadePort { navy, .. } => Some(navy),
        MissionData::Invade { beachhead, .. } => beachhead.as_ref(),
        MissionData::AttackProvince(_) | MissionData::DefendProvince { .. } => None,
    }
}

fn navy_state_mut(data: &mut MissionData) -> Option<&mut NavyMissionState> {
    match data {
        MissionData::ControlSeaZone(navy)
        | MissionData::Escort(navy)
        | MissionData::ScatteredShips(navy)
        | MissionData::Beachhead(navy) => Some(navy),
        MissionData::BlockadePort { navy, .. } => Some(navy),
        MissionData::Invade { beachhead, .. } => beachhead.as_mut(),
        MissionData::AttackProvince(_) | MissionData::DefendProvince { .. } => None,
    }
}

const NAVY_CONTROL_PROFILE: [i16; 4] = [40, 40, 20, 0];
const NAVY_ESCORT_PROFILE: [i16; 4] = [40, 30, 30, 0];

fn navy_required_from_profile(profile: [i16; 4], total: f32) -> [u32; 4] {
    profile.map(|weight| (f32::from(weight) * total * 0.01).to_bits())
}

fn hop_distance(distances: &[i16], zone: OceanZoneId) -> i16 {
    distances
        .get(usize::from(zone.get()))
        .copied()
        .unwrap_or(UNREACHED)
}

fn accumulate_ship_categories(ship: &ShipState, vector: &mut [f32; 4], enabled: &[bool; 14]) {
    let max_strength = ship_stock_cap(ship.ship_type);
    if max_strength == 0 {
        return;
    }
    let baselines = navy_category_baselines(enabled);
    let scale = f32::from(ship.strength / max_strength);
    vector[0] += ship_priority_contribution(ship, 0, &baselines) as f32 * scale;
    vector[1] += ship_priority_contribution(ship, 1, &baselines) as f32 * scale;
    vector[2] += ship_priority_contribution(ship, 2, &baselines) as f32 * scale;
    vector[3] += ship_priority_contribution(ship, 3, &baselines) as f32;
}

#[derive(Clone, Copy)]
enum NavyActionKind {
    ControlSeaZone,
    BlockadePort { port_zone: OceanZoneId },
    Beachhead { target_province: ProvinceId },
    Base,
}

fn navy_action_kind(data: &MissionData) -> NavyActionKind {
    match data {
        MissionData::ControlSeaZone(_) => NavyActionKind::ControlSeaZone,
        MissionData::BlockadePort { port_zone, .. } => NavyActionKind::BlockadePort {
            port_zone: *port_zone,
        },
        MissionData::Beachhead(_) => NavyActionKind::Base,
        MissionData::Invade { attack, .. } => NavyActionKind::Beachhead {
            target_province: attack.target_province,
        },
        MissionData::Escort(_) | MissionData::ScatteredShips(_) => NavyActionKind::Base,
        MissionData::AttackProvince(_) | MissionData::DefendProvince { .. } => NavyActionKind::Base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    fn zone(neighbors: Vec<OceanZoneId>) -> Zone {
        Zone {
            display_name: String::new(),
            status_code: None,
            target_tile: None,
            seed_owner: None,
            active_tile: None,
            primary_neighbors: neighbors,
            secondary_neighbors: Vec::new(),
        }
    }

    #[test]
    fn frigate_contribution_is_nonzero_for_enabled_types() {
        let enabled = [
            true, true, true, true, true, false, false, false, false, false, false, false, false,
            false,
        ];
        let baselines = navy_category_baselines(&enabled);
        let ship = ShipState {
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(0),
            task_force: None,
            aggression: 0,
            nation: NationId::new(0),
            name: String::new(),
            strength: 900,
            experience: 0,
            selection: 0,
        };
        assert!(ship_priority_contribution(&ship, 0, &baselines) > 0);
        assert!(ship_priority_contribution(&ship, 2, &baselines) > 0);
    }

    #[test]
    fn navy_capitol_warning_fires_when_hostile_ships_outscore_friendly() {
        let mut state = game_state();
        let tile = TileId::new(1);
        state.map[tile].former_owner_nation = Some(TileOwnerTag::from_nation(NationId::new(0)));
        state.ocean.zones = vec![
            ZoneKind::Zone(zone(vec![OceanZoneId::new(1)])),
            ZoneKind::PortZone(PortZone {
                zone: zone(vec![OceanZoneId::new(0)]),
                port_tile: tile,
            }),
        ];
        assert!(!state.navy_capitol_threatened(MajorNationId::new(0)));
        state.ships.push(ShipState {
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(0),
            task_force: None,
            aggression: 0,
            nation: NationId::new(1),
            name: String::new(),
            strength: 900,
            experience: 0,
            selection: 0,
        });
        state.diplomacy.relationships[NationId::new(0)][NationId::new(1)] =
            DiplomaticRelationship::War;
        assert!(state.navy_capitol_threatened(MajorNationId::new(0)));
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
        assert_eq!(state.task_forces[0].order, ORDER_SAIL);
        state.carry_out_navy_orders();
        assert_eq!(state.ships[0].location, OceanZoneId::new(3));
        assert!(
            state.task_forces.is_empty(),
            "sail orders are stragglers after CarryOutOrders"
        );
    }

    #[test]
    fn reassess_advances_navy_state_when_assigned_ships_are_on_the_target() {
        let mut state = game_state();
        let nation = NationId::new(0);
        state.nations.majors[MajorNationId::new(0)].auto = Some(AutoGreatPowerState::default());
        state.ocean.zones = vec![ZoneKind::Zone(zone(Vec::new()))];
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
                target_zone: Some(OceanZoneId::new(0)),
                resolved_port_zone: None,
                selected_ship: None,
                task_force: None,
                state: 0,
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

        state.reassess_navy_mission(0);

        let MissionData::ControlSeaZone(navy) = &state.missions[0].data else {
            panic!("expected a control-sea mission");
        };
        assert_eq!(navy.state, 2);
    }
}
