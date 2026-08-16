use super::*;

const ORDER_SAIL: i32 = 1;
const ORDER_PATROL: i32 = 3;
const ORDER_MARINES: i32 = 5;
const ORDER_BLOCKADE: i32 = 6;
const ORDER_REPAIR: i32 = 8;
const ORDER_EVADE: i32 = 9;
const ACTION_STATE_ANCHOR: i16 = 3;
const ACTION_STATE_DOCKED_FLEET: i16 = 14;

/// Proven retail navy order kinds. Remaining codes stay as raw `TaskForceState.order`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum NavyOrder {
    /// `1` sail
    Sail = ORDER_SAIL,
    /// `3` patrol
    Patrol = ORDER_PATROL,
    /// `5` marines/invasion
    Marines = ORDER_MARINES,
    /// `6` blockade
    Blockade = ORDER_BLOCKADE,
    /// `8` repair
    Repair = ORDER_REPAIR,
    /// `9` evade
    Evade = ORDER_EVADE,
}

impl NavyOrder {
    pub const fn retail(self) -> i32 {
        self as i32
    }

    pub fn from_retail(value: i32) -> Option<Self> {
        Some(match value {
            ORDER_SAIL => Self::Sail,
            ORDER_PATROL => Self::Patrol,
            ORDER_MARINES => Self::Marines,
            ORDER_BLOCKADE => Self::Blockade,
            ORDER_REPAIR => Self::Repair,
            ORDER_EVADE => Self::Evade,
            _ => return None,
        })
    }
}

/// `TNavyToolbarCluster` class buckets (`cls0..cls3`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NavyToolbarCounts {
    pub available: [i16; 4],
    pub selected: [i16; 4],
}

/// `TNavyMgr::SelectionClick` outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NavySelectionClick {
    Ignored,
    SelectZone {
        zone: OceanZoneId,
        force: Option<TaskForceIndex>,
    },
    Intelligence {
        zone: OceanZoneId,
        code: i32,
    },
    InspectForce(TaskForceIndex),
    Roster,
}

/// `TNavyMgr::DoTileClick` outcomes. Selection is consumed before any order queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NavyTileClick {
    Ignored,
    Selection(NavySelectionClick),
    Submitted,
    Roster,
}

fn toolbar_bucket(ship_type: ShipType) -> Option<usize> {
    let bucket = NAVY_DESCRIPTORS[ship_type].toolbar_bucket;
    (0..4).contains(&bucket).then_some(bucket as usize)
}

impl GameState {
    /// `TTaskForce::Demand` / exclusive one-ship force for a loose or shared ship.
    pub fn demand_player_task_force(&mut self, ship: ShipIndex) -> TaskForceIndex {
        let force = self.demand_exclusive_task_force(ship);
        self.refresh_task_force_ship_counts(force);
        force
    }

    pub fn add_ship_to_task_force(&mut self, ship: ShipIndex, force: TaskForceIndex) {
        self.reassign_ship_to_force(ship, force);
        self.refresh_task_force_ship_counts(force);
    }

    pub fn remove_player_ship_from_force(&mut self, ship: ShipIndex, force: TaskForceIndex) {
        self.remove_ship_from_force(ship, force);
        self.refresh_task_force_ship_counts(force);
        if self
            .task_forces
            .get(force.get())
            .is_some_and(|entry| entry.ships.is_empty())
        {
            self.free_task_force(force);
        }
    }

    /// `TTaskForce::Select(TShip*, activeFlag)`.
    pub fn set_task_force_ship_selected(
        &mut self,
        force: TaskForceIndex,
        ship: ShipIndex,
        selected: bool,
    ) {
        let Some(entry) = self.task_forces.get_mut(force.get()) else {
            return;
        };
        if let Some(node) = entry.ships.iter_mut().find(|node| node.ship == ship) {
            node.selected = selected;
            if selected && let Some(state) = self.ships.get_mut(ship.get()) {
                state.selection = 0;
            }
        }
    }

    /// `TTaskForce::Select(toolbarSlot, activeFlag)`.
    pub fn select_task_force_toolbar_class(
        &mut self,
        force: TaskForceIndex,
        class: i16,
        selecting: bool,
    ) {
        let Some(entry) = self.task_forces.get(force.get()) else {
            return;
        };
        let Some(index) = entry.ships.iter().position(|node| {
            let Some(ship) = self.ships.get(node.ship.get()) else {
                return false;
            };
            toolbar_bucket(ship.ship_type) == Some(class as usize) && node.selected != selecting
        }) else {
            return;
        };
        let ship = self.task_forces[force.get()].ships[index].ship;
        self.task_forces[force.get()].ships[index].selected = selecting;
        if selecting && let Some(state) = self.ships.get_mut(ship.get()) {
            state.selection = 0;
        }
    }

    /// `TTaskForce::GetSelected` plus `shipCountsByToolbarSlot`.
    pub fn navy_toolbar_counts(&self, force: Option<TaskForceIndex>) -> NavyToolbarCounts {
        let Some(force) = force.and_then(|id| self.task_forces.get(id.get())) else {
            return NavyToolbarCounts {
                available: [0; 4],
                selected: [-1; 4],
            };
        };
        let mut counts = NavyToolbarCounts {
            available: force.ship_counts,
            selected: [0; 4],
        };
        for node in &force.ships {
            if !node.selected {
                continue;
            }
            let Some(ship) = self.ships.get(node.ship.get()) else {
                continue;
            };
            if let Some(bucket) = toolbar_bucket(ship.ship_type) {
                counts.selected[bucket] += 1;
            }
        }
        counts
    }

    /// `TTaskForce::SetAggression`.
    pub fn set_task_force_aggression(&mut self, force: TaskForceIndex, aggression: i32) {
        if !(0..=2).contains(&aggression) {
            return;
        }
        if let Some(entry) = self.task_forces.get_mut(force.get()) {
            entry.aggression = aggression;
        }
    }

    /// `TTaskForce::IsValidTarget(TZone*)`.
    pub fn navy_zone_is_valid_target(&self, force: TaskForceIndex, zone: OceanZoneId) -> bool {
        let Some(entry) = self.task_forces.get(force.get()) else {
            return false;
        };
        if !entry.ships.iter().any(|node| node.selected) {
            return false;
        }
        let mut worst = 10_000_i32;
        for node in &entry.ships {
            if !node.selected {
                continue;
            }
            let Some(ship) = self.ships.get(node.ship.get()) else {
                continue;
            };
            worst = worst.min(descriptor_weight(ship.ship_type));
        }
        let limit = if worst == 10_000 { 0 } else { worst as i16 };
        hop_distance(&self.zone_hop_distances_from(entry.location), zone) <= limit
    }

    /// `TTaskForce::IsValidTarget(Province*)`.
    pub fn navy_province_is_valid_target(
        &self,
        force: TaskForceIndex,
        province: ProvinceId,
    ) -> bool {
        let Some(entry) = self.task_forces.get(force.get()) else {
            return false;
        };
        entry.ships.iter().any(|node| node.selected)
            && self.map.provinces[province].navy_order_reachable
    }

    /// Sets the proven order kind, drops unselected ships (`FreeAvailables`), and commits.
    pub fn submit_navy_order(
        &mut self,
        force: TaskForceIndex,
        order: NavyOrder,
        target: TaskForceTarget,
    ) -> bool {
        self.free_unselected_task_force_ships(force);
        let Some(entry) = self.task_forces.get_mut(force.get()) else {
            return false;
        };
        entry.order = TaskForceOrder::from_retail(order.retail());
        entry.target = target;
        if !self.commit_player_task_force(force) {
            return false;
        }
        self.create_task_force_ingot(force);
        true
    }

    /// `TNavyMgr::CommitForce`.
    pub fn commit_player_task_force(&mut self, force: TaskForceIndex) -> bool {
        let Some(entry) = self.task_forces.get(force.get()) else {
            return false;
        };
        if entry.ships.is_empty() {
            self.free_task_force(force);
            return false;
        }
        true
    }

    /// `TTaskForce::DropShips(reserveExtraSlot)`.
    pub fn drop_task_force_ships(&mut self, force: TaskForceIndex, reserve_extra: bool) {
        let Some(entry) = self.task_forces.get(force.get()) else {
            return;
        };
        let location = entry.location;
        let nation = entry.nation;
        let selection = if reserve_extra { 1 } else { 2 };
        let selected: Vec<ShipIndex> = entry
            .ships
            .iter()
            .filter(|node| node.selected)
            .map(|node| node.ship)
            .collect();
        for ship in selected {
            if let Some(state) = self.ships.get_mut(ship.get()) {
                state.selection = selection;
            }
        }
        let loose: Vec<ShipIndex> = self
            .ships
            .iter()
            .enumerate()
            .filter(|(_, ship)| {
                ship.location == location && ship.nation == nation && ship.task_force.is_none()
            })
            .map(|(index, _)| ShipIndex::new(index))
            .collect();
        for ship in loose {
            self.reassign_ship_to_force(ship, force);
        }
        if let Some(entry) = self.task_forces.get_mut(force.get()) {
            for node in &mut entry.ships {
                let selected = self
                    .ships
                    .get(node.ship.get())
                    .is_some_and(|ship| ship.selection == 0);
                node.selected = selected;
            }
        }
        self.refresh_task_force_ship_counts(force);
    }

    pub fn cancel_task_force(&mut self, force: TaskForceIndex) {
        self.destroy_task_force_ingot(force);
        self.free_task_force(force);
    }

    /// `TNavyMgr::FreeShipsOf` (0x00556f60): cancel every queued force for `nation`.
    pub fn free_ships_of(&mut self, nation: NationId) {
        while let Some(index) = self
            .task_forces
            .iter()
            .position(|force| force.nation == nation)
        {
            self.destroy_task_force_ingot(TaskForceIndex::new(index));
            self.free_task_force(TaskForceIndex::new(index));
        }
        for ship in &mut self.ships {
            if ship.nation == nation {
                ship.selection = 0;
            }
        }
    }

    pub fn set_task_force_ingot_tile(&mut self, force: TaskForceIndex, tile: Option<TileId>) {
        if let Some(entry) = self.task_forces.get_mut(force.get()) {
            entry.ingot_tile = tile.map(|tile| tile.get() as i16).unwrap_or(-1);
        }
    }

    pub fn clear_transient_navy_orders(&mut self) {
        self.clear_all_transient_navy_orders();
    }

    /// `GetEnabledIndustryCapabilitySlotByClass` then picture `slot + 0x5e6`.
    pub fn navy_toolbar_class_picture_id(&self, class: i16) -> Option<i16> {
        for slot in (1..14).rev() {
            if ShipType::from_index(slot as u8).is_some_and(|ship_type| {
                NAVY_DESCRIPTORS[ship_type].toolbar_bucket == i32::from(class)
            }) && self.technology.industry_enabled_by_slot[slot]
            {
                return Some(slot as i16 + 0x5e6);
            }
        }
        None
    }

    /// `TOcean::GetLinkedZoneForSeaTile`.
    pub fn zone_for_sea_tile(&self, tile: TileId) -> Option<OceanZoneId> {
        let rec = &self.map[tile];
        let action = rec.action.map(TileAction::retail).unwrap_or(-1);
        if action == ACTION_STATE_ANCHOR || action == ACTION_STATE_DOCKED_FLEET {
            return self.port_zone_matching_tile(tile);
        }
        let owner = rec.owner_nation?;
        if owner.get() < 0x17 {
            return None;
        }
        let ordinal = u16::from(owner.get() - 0x17);
        (usize::from(ordinal) < self.ocean.zones.len()).then(|| OceanZoneId::new(ordinal))
    }

    /// `TOcean::EnsureSelectedTaskForceForOrderOwnerAndRefresh` / `CreateTaskForceFromNavyOrdersForNationIfEligible`.
    pub fn demand_task_force_for_zone(
        &mut self,
        zone: OceanZoneId,
        nation: NationId,
    ) -> Option<TaskForceIndex> {
        if let Some(index) = self
            .task_forces
            .iter()
            .position(|force| force.location == zone && force.nation == nation)
        {
            let force = TaskForceIndex::new(index);
            self.fill_task_force_from_loose_ships(force, true);
            return Some(force);
        }
        let ship = self.ships.iter().enumerate().find_map(|(index, ship)| {
            (ship.location == zone && ship.nation == nation && ship.task_force.is_none())
                .then_some(ShipIndex::new(index))
        })?;
        let force = self.create_task_force(zone, nation, ship);
        self.fill_task_force_from_loose_ships(force, true);
        self.democratically_determine_aggression(force);
        Some(force)
    }

    /// `TZone::CanDisplayMapOrderEntryInCurrentContext` walk via `prev18`.
    pub fn next_navy_order_zone(
        &self,
        nation: NationId,
        from: Option<OceanZoneId>,
    ) -> Option<OceanZoneId> {
        let len = self.ocean.zones.len();
        if len == 0 {
            return None;
        }
        let start = from.map(|zone| usize::from(zone.get()));
        let mut index = start.unwrap_or(len).wrapping_sub(1);
        while index < len {
            let zone = OceanZoneId::new(index as u16);
            if self.zone_can_display_map_order(zone, nation) {
                return Some(zone);
            }
            if index == 0 {
                break;
            }
            index -= 1;
        }
        None
    }

    /// `GetMapContextActionCode` (0x00559bd0 callers use the live sibling at 0x0055a020).
    pub fn navy_map_action_code(&self, tile: TileId, selected_zone: Option<OceanZoneId>) -> i32 {
        let action = self.map[tile].action.map(TileAction::retail).unwrap_or(-1);
        if action == -1 {
            return 0;
        }
        if (2..=6).contains(&action) && action != ACTION_STATE_ANCHOR {
            return 0xb;
        }
        if (7..=13).contains(&action) {
            return i32::from(action) - 5;
        }
        if (14..=21).contains(&action) {
            let resolved = self.zone_for_sea_tile(tile);
            return if resolved == selected_zone { 10 } else { 9 };
        }
        0
    }

    /// `TNavyMgr::SelectionClick`.
    pub fn navy_selection_click(
        &mut self,
        tile: TileId,
        selected_zone: Option<OceanZoneId>,
        nation: NationId,
    ) -> NavySelectionClick {
        match self.navy_map_action_code(tile, selected_zone) {
            0 => NavySelectionClick::Ignored,
            9 => {
                let Some(zone) = self.zone_for_sea_tile(tile) else {
                    return NavySelectionClick::Ignored;
                };
                let force = self.demand_task_force_for_zone(zone, nation);
                NavySelectionClick::SelectZone { zone, force }
            }
            code @ 2..=8 => self
                .zone_for_sea_tile(tile)
                .map(|zone| NavySelectionClick::Intelligence { zone, code })
                .unwrap_or(NavySelectionClick::Ignored),
            11 => self
                .task_force_whose_ingot_is_at(tile)
                .map(NavySelectionClick::InspectForce)
                .unwrap_or(NavySelectionClick::Ignored),
            10 => NavySelectionClick::Roster,
            _ => NavySelectionClick::Ignored,
        }
    }

    /// `TNavyMgr::DoTileClick`: SelectionClick first; only then queue a map order.
    pub fn navy_do_tile_click(
        &mut self,
        tile: TileId,
        force: Option<TaskForceIndex>,
        selected_zone: Option<OceanZoneId>,
        nation: NationId,
    ) -> NavyTileClick {
        let selection = self.navy_selection_click(tile, selected_zone, nation);
        if selection != NavySelectionClick::Ignored {
            return NavyTileClick::Selection(selection);
        }
        let Some(force) = force else {
            return NavyTileClick::Ignored;
        };
        match self.navy_command_for_tile(force, tile) {
            0x0a => NavyTileClick::Roster,
            0x0c => {
                self.submit_navy_order(force, NavyOrder::Patrol, TaskForceTarget::None);
                NavyTileClick::Submitted
            }
            0x0d => {
                if let Some(zone) = self.zone_for_sea_tile(tile) {
                    self.submit_navy_order(force, NavyOrder::Sail, TaskForceTarget::Zone(zone));
                    NavyTileClick::Submitted
                } else {
                    NavyTileClick::Ignored
                }
            }
            0x0e => {
                if let Some(zone) = self.zone_for_sea_tile(tile) {
                    self.submit_navy_order(force, NavyOrder::Blockade, TaskForceTarget::Zone(zone));
                    NavyTileClick::Submitted
                } else {
                    NavyTileClick::Ignored
                }
            }
            0x0f => {
                if let Some(zone) = self.zone_for_sea_tile(tile) {
                    self.submit_navy_order(force, NavyOrder::Sail, TaskForceTarget::Zone(zone));
                    NavyTileClick::Submitted
                } else {
                    NavyTileClick::Ignored
                }
            }
            0x10 => {
                if let Some(province) = self.map[tile].province {
                    self.submit_navy_order(
                        force,
                        NavyOrder::Marines,
                        TaskForceTarget::Province(province),
                    );
                    NavyTileClick::Submitted
                } else {
                    NavyTileClick::Ignored
                }
            }
            _ => NavyTileClick::Ignored,
        }
    }

    /// Non-mutating `DoTileClick` command code after SelectionClick has already missed.
    pub fn navy_command_for_tile(&self, force: TaskForceIndex, tile: TileId) -> i32 {
        if self.map[tile].terrain == TerrainKind::Water {
            let Some(zone) = self.zone_for_sea_tile(tile) else {
                return 1;
            };
            if !self.navy_zone_is_valid_target(force, zone) {
                1
            } else {
                self.navy_mouse_code_for_zone(force, zone)
            }
        } else {
            let Some(province) = self.map[tile].province else {
                return 1;
            };
            if !self.navy_province_is_valid_target(force, province) {
                1
            } else {
                self.navy_mouse_code_for_province(force, province)
            }
        }
    }

    /// `TNavyMgr::ActionCursor`.
    pub fn navy_action_cursor_token(
        &self,
        tile: TileId,
        selected_zone: Option<OceanZoneId>,
    ) -> u16 {
        Self::navy_cursor_token(self.navy_map_action_code(tile, selected_zone))
    }

    /// `TNavyMgr::SelectionCursor`.
    pub fn navy_selection_cursor_token(
        &self,
        tile: TileId,
        force: Option<TaskForceIndex>,
        selected_zone: Option<OceanZoneId>,
    ) -> u16 {
        let action = self.navy_map_action_code(tile, selected_zone);
        if action != 0 {
            return Self::navy_cursor_token(action);
        }
        let Some(force) = force else {
            return Self::navy_cursor_token(0);
        };
        Self::navy_cursor_token(self.navy_command_for_tile(force, tile))
    }

    /// `g_awMapContextActionLabelTokenByCommand`.
    pub fn navy_cursor_token(action_code: i32) -> u16 {
        const TOKENS: [u16; 17] = [
            0, 0x3f0, 0x3f2, 0x3f2, 0x3f2, 0x3f2, 0x3f2, 0x3f2, 0x3f2, 0x3f1, 0x3f3, 0x3f3, 0x3f6,
            0x3f8, 0x3f4, 0x3f5, 0x3f7,
        ];
        TOKENS
            .get(usize::try_from(action_code).unwrap_or(0))
            .copied()
            .unwrap_or(0)
    }

    fn navy_mouse_code_for_zone(&self, force: TaskForceIndex, candidate: OceanZoneId) -> i32 {
        let Some(entry) = self.task_forces.get(force.get()) else {
            return 1;
        };
        let location = entry.location;
        let candidate_is_port = matches!(
            self.ocean.zones.get(usize::from(candidate.get())),
            Some(ZoneKind::PortZone(_))
        );
        let location_is_port = matches!(
            self.ocean.zones.get(usize::from(location.get())),
            Some(ZoneKind::PortZone(_))
        );
        if candidate == location {
            return if location_is_port { 0x0c } else { 1 };
        }
        if !candidate_is_port {
            return 0x0f;
        }
        if self.port_zone_owned_by(candidate, entry.nation) {
            return 0x0d;
        }
        if self.port_zone_hostile_to(candidate, entry.nation)
            && self
                .ocean
                .zones
                .get(usize::from(candidate.get()))
                .and_then(|zone| zone.zone().primary_neighbors.first().copied())
                == Some(location)
        {
            return 0x0e;
        }
        1
    }

    fn navy_mouse_code_for_province(&self, force: TaskForceIndex, province: ProvinceId) -> i32 {
        let Some(entry) = self.task_forces.get(force.get()) else {
            return 1;
        };
        let Some(owner) = self.map.provinces[province].owner() else {
            return 1;
        };
        if self.war_stamp_stale(entry.nation, owner) {
            0x10
        } else {
            1
        }
    }

    fn port_zone_owned_by(&self, zone: OceanZoneId, nation: NationId) -> bool {
        let Some(ZoneKind::PortZone(port)) = self.ocean.zones.get(usize::from(zone.get())) else {
            return false;
        };
        self.map[port.port_tile].owner_nation == Some(TileOwnerTag::from_nation(nation))
    }

    fn port_zone_hostile_to(&self, zone: OceanZoneId, nation: NationId) -> bool {
        let Some(ZoneKind::PortZone(port)) = self.ocean.zones.get(usize::from(zone.get())) else {
            return false;
        };
        let Some(owner) = self.map[port.port_tile]
            .owner_nation
            .and_then(TileOwnerTag::nation)
        else {
            return false;
        };
        self.war_stamp_stale(owner, nation)
    }

    fn port_zone_matching_tile(&self, tile: TileId) -> Option<OceanZoneId> {
        self.ocean
            .zones
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, kind)| {
                let ZoneKind::PortZone(port) = kind else {
                    return None;
                };
                (port.zone.target_tile == Some(tile)
                    || port.zone.active_tile == Some(tile)
                    || port.port_tile == tile)
                    .then_some(OceanZoneId::new(index as u16))
            })
    }

    fn zone_can_display_map_order(&self, zone: OceanZoneId, nation: NationId) -> bool {
        self.ships.iter().any(|ship| {
            ship.location == zone
                && ship.nation == nation
                && ship.task_force.is_none()
                && ship.selection == 0
        })
    }

    fn task_force_whose_ingot_is_at(&self, tile: TileId) -> Option<TaskForceIndex> {
        let index = tile.get() as i16;
        self.task_forces
            .iter()
            .position(|force| force.ingot_tile == index)
            .map(TaskForceIndex::new)
    }

    fn fill_task_force_from_loose_ships(&mut self, force: TaskForceIndex, max_out: bool) {
        let Some(entry) = self.task_forces.get(force.get()) else {
            return;
        };
        let location = entry.location;
        let nation = entry.nation;
        let loose: Vec<ShipIndex> = self
            .ships
            .iter()
            .enumerate()
            .filter(|(_, ship)| {
                ship.location == location && ship.nation == nation && ship.task_force.is_none()
            })
            .map(|(index, _)| ShipIndex::new(index))
            .collect();
        for ship in loose {
            self.reassign_ship_to_force(ship, force);
        }
        if max_out && let Some(entry) = self.task_forces.get_mut(force.get()) {
            for node in &mut entry.ships {
                let selected = self
                    .ships
                    .get(node.ship.get())
                    .is_some_and(|ship| ship.selection == 0);
                node.selected = selected;
            }
        }
        self.refresh_task_force_ship_counts(force);
    }

    fn refresh_task_force_ship_counts(&mut self, force: TaskForceIndex) {
        let mut counts = [0_i16; 4];
        if let Some(entry) = self.task_forces.get(force.get()) {
            for node in &entry.ships {
                let Some(ship) = self.ships.get(node.ship.get()) else {
                    continue;
                };
                if let Some(bucket) = toolbar_bucket(ship.ship_type) {
                    counts[bucket] += 1;
                }
            }
        }
        if let Some(entry) = self.task_forces.get_mut(force.get()) {
            entry.ship_counts = counts;
        }
    }

    /// `TTaskForce::DemocraticallyDetermineAggressionLevel` (0x005548e0).
    fn democratically_determine_aggression(&mut self, force: TaskForceIndex) {
        let Some(entry) = self.task_forces.get(force.get()) else {
            return;
        };
        let mut sum = 0;
        let mut count = 0;
        for node in &entry.ships {
            let Some(ship) = self.ships.get(node.ship.get()) else {
                continue;
            };
            sum += ship.aggression;
            count += 1;
        }
        if let Some(entry) = self.task_forces.get_mut(force.get()) {
            entry.aggression = if count == 0 {
                0
            } else {
                (count / 2 + sum) / count
            };
        }
    }

    /// `TTaskForce::CreateIngot` (0x00556410). Evade/repair leave the marker unset.
    fn create_task_force_ingot(&mut self, force: TaskForceIndex) {
        self.destroy_task_force_ingot(force);
        let Some(entry) = self.task_forces.get(force.get()) else {
            return;
        };
        let marker_and_zone = match entry.order {
            TaskForceOrder::Sail => {
                let TaskForceTarget::Zone(zone) = entry.target else {
                    return;
                };
                Some((4_i16, zone))
            }
            TaskForceOrder::Blockade => {
                let TaskForceTarget::Zone(zone) = entry.target else {
                    return;
                };
                Some((2_i16, zone))
            }
            TaskForceOrder::Patrol => Some((5_i16, entry.location)),
            TaskForceOrder::Marines => {
                let TaskForceTarget::Province(province) = entry.target else {
                    return;
                };
                if let Some(tile) = self.map.provinces[province].city_tile() {
                    if let Some(entry) = self.task_forces.get_mut(force.get()) {
                        entry.ingot_tile = tile.get() as i16;
                    }
                    self.map[tile].action = TileAction::try_from_retail(6);
                    return;
                }
                Some((6_i16, entry.location))
            }
            _ => None,
        };
        let Some((marker, zone)) = marker_and_zone else {
            return;
        };
        let Some(tile) = self
            .ocean
            .zones
            .get(usize::from(zone.get()))
            .and_then(|zone| zone.zone().target_tile)
        else {
            return;
        };
        if let Some(entry) = self.task_forces.get_mut(force.get()) {
            entry.ingot_tile = tile.get() as i16;
        }
        self.map[tile].action = TileAction::try_from_retail(marker);
    }

    /// `TTaskForce::DestroyIngot` (0x005564f0).
    fn destroy_task_force_ingot(&mut self, force: TaskForceIndex) {
        let Some(entry) = self.task_forces.get_mut(force.get()) else {
            return;
        };
        if entry.ingot_tile < 0 {
            return;
        }
        let Some(tile) = TileId::try_new(entry.ingot_tile as u16) else {
            entry.ingot_tile = -1;
            return;
        };
        entry.ingot_tile = -1;
        self.map[tile].action = None;
    }

    /// `TTaskForce::FreeAvailables`.
    fn free_unselected_task_force_ships(&mut self, force: TaskForceIndex) {
        let Some(entry) = self.task_forces.get(force.get()) else {
            return;
        };
        let drop: Vec<ShipIndex> = entry
            .ships
            .iter()
            .filter(|node| !node.selected)
            .map(|node| node.ship)
            .collect();
        for ship in drop {
            self.remove_ship_from_force(ship, force);
        }
        self.refresh_task_force_ship_counts(force);
        if let Some(entry) = self.task_forces.get_mut(force.get()) {
            entry.flagship = entry.ships.first().map(|node| node.ship);
        }
    }
}
