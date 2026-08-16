use super::*;

impl GameState {
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
        self.clear_all_transient_navy_orders();
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

    pub(crate) fn demand_exclusive_task_force(&mut self, ship: ShipIndex) -> TaskForceIndex {
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
            force.ships.push(SelectedShip {
                ship,
                selected: true,
            });
        }
    }

    pub(super) fn remove_ship_from_force(&mut self, ship: ShipIndex, force: TaskForceIndex) {
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
        state.carry_out_navy_orders();
        assert_eq!(state.ships[0].location, OceanZoneId::new(3));
        assert!(
            state.task_forces.is_empty(),
            "sail orders are stragglers after CarryOutOrders"
        );
    }
}
