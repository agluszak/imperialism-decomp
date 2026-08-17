//! Strategic army map orders (`TArmyMgr` interaction methods, not combat execution).

use crate::combat_moves::{set_unit_order, stationed_chain_ids};
use crate::military_phase::tactical_category;
use crate::*;

const UNIT_ORDER_IDLE: MilitaryOrderCode = MilitaryOrderCode::Idle;
const UNIT_ORDER_REDEPLOY: MilitaryOrderCode = MilitaryOrderCode::Redeploy;
const UNIT_ORDER_SLEEP: MilitaryOrderCode = MilitaryOrderCode::Sleep;
const UNIT_ORDER_LATR: MilitaryOrderCode = MilitaryOrderCode::Latr;
const UNIT_ORDER_DONE: MilitaryOrderCode = MilitaryOrderCode::Done;

const HEX_COL_DELTA: [i16; 6] = [1, 2, 1, -1, -2, -1];
const HEX_ROW_DELTA: [i16; 6] = [-1, 0, 1, 1, 0, -1];

/// Idle-unit modes applied by `TArmyToolbar::DoEvent` (`dfnd`/`latr`/`done`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ArmyIdleOrderMode {
    /// `dfnd` → `SetOrdersForIdleUnitsOnPendingTile(2)` / `UNIT_ORDER_SLEEP`.
    Sleep = 2,
    /// `latr` → retail unitOrder 3.
    Latr = 3,
    /// `done` → retail unitOrder 4.
    Done = 4,
}

impl ArmyIdleOrderMode {
    pub const fn order(self) -> MilitaryOrderCode {
        match self {
            Self::Sleep => MilitaryOrderCode::Sleep,
            Self::Latr => MilitaryOrderCode::Latr,
            Self::Done => MilitaryOrderCode::Done,
        }
    }
}

/// `TArmyMgr::ComputeMapCursorStateIndex` / `ComputeCivilianMapCursorStateIndex` results.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ArmyMapCursorState {
    None = 0,
    EmptyOrBlocked = 1,
    SelectProvince = 2,
    FriendlyAdjacent = 3,
    FriendlyNonAdjacent = 4,
    Hostile = 5,
    MarchOverlay = 6,
    SameProvinceCity = 7,
    SpyReport = 8,
}

impl ArmyMapCursorState {
    pub const fn retail(self) -> i32 {
        self as i32
    }

    pub fn from_retail(value: i32) -> Option<Self> {
        Some(match value {
            0 => Self::None,
            1 => Self::EmptyOrBlocked,
            2 => Self::SelectProvince,
            3 => Self::FriendlyAdjacent,
            4 => Self::FriendlyNonAdjacent,
            5 => Self::Hostile,
            6 => Self::MarchOverlay,
            7 => Self::SameProvinceCity,
            8 => Self::SpyReport,
            _ => return None,
        })
    }

    /// `g_mapCursorTokenByStateIndex_00695668` (`LookupMapCursorTokenByStateIndex`).
    pub const fn unselected_cursor_token(self) -> u16 {
        [0, 0, 1000, 0, 0, 0, 1011, 1011, 1010][self as usize]
    }

    /// `g_civilianMapCursorTokenByStateIndex_00695680`.
    pub const fn selected_cursor_token(self) -> u16 {
        [0, 1008, 1000, 1005, 1006, 1007, 1011, 1011, 1010][self as usize]
    }
}

/// `TArmyToolbar::SetProvince` category totals and available (idle) counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArmyToolbarCounts {
    pub totals: [i32; 10],
    pub available: [i32; 10],
    pub can_upgrade: bool,
}

impl ArmyToolbarCounts {
    pub fn placard_picture_id(
        self,
        nation: MajorNationId,
        state: &GameState,
        category: usize,
    ) -> i16 {
        let kind = state.technology().selected_capability_slots[nation][category];
        let mut picture = i16::from(kind as u8) + 0x4c4;
        if self.totals[category] <= 0 {
            picture += 0x1e;
        }
        picture
    }

    pub fn garrison_picture_id(self) -> i16 {
        if self.can_upgrade { 0x24d5 } else { 0x04b5 }
    }

    pub fn arrow_visible(self, category: usize) -> bool {
        self.totals[category] != 0 && category != 0
    }
}

/// Outcome of `SelectMovableUnitOnCurrentTileAndPlaySfx` / sea-lift validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmyOrderIssue {
    Issued,
    NoMovableUnits,
    InsufficientMovementBudget {
        budget: i32,
        cost: i32,
    },
    NoPort,
    NoSeaAccess,
    InsufficientSealift {
        capacity: i32,
        cost: i32,
        reinforcement: i32,
    },
}

/// `TArmyMgr::HandleMapClickByComputedCursorState` / `HandleMapClickByCivilianCursorState`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmyMapClickOutcome {
    Ignored,
    SelectedProvince(ProvinceId),
    IssuedOrders,
    SpyReport(ProvinceId),
    Garrison(ProvinceId),
    Marched,
    OrderRejected(ArmyOrderIssue),
}

impl GameState {
    /// `TArmyToolbar::SetProvince` count walk over the stationed-unit chain.
    pub fn army_toolbar_counts(&self, province: ProvinceId) -> ArmyToolbarCounts {
        let mut counts = ArmyToolbarCounts::default();
        for id in stationed_chain_ids(&self.military_units, province) {
            let unit = &self.military_units[&id];
            let category = tactical_category(unit.unit_type()) as usize;
            if category >= 10 {
                continue;
            }
            match unit.order.code() {
                UNIT_ORDER_IDLE => {
                    counts.available[category] += 1;
                    counts.totals[category] += 1;
                }
                UNIT_ORDER_SLEEP | UNIT_ORDER_LATR | UNIT_ORDER_DONE => {
                    counts.totals[category] += 1;
                }
                _ => {}
            }
            if self.unit_can_upgrade(unit) {
                counts.can_upgrade = true;
            }
        }
        counts
    }

    /// `TMilitaryUnit::CanUpgrade` (`UpgradeType() != -1`); costs are not part of eligibility.
    pub fn unit_can_upgrade(&self, unit: &MilitaryUnitState) -> bool {
        MajorNationId::from_nation(unit.owner_nation())
            .is_some_and(|nation| self.upgrade_type(nation, unit.unit_type()).is_some())
    }

    /// `TArmyMgr::SetOrdersForIdleUnitsOnPendingTile`.
    pub fn set_idle_unit_orders_on_province(
        &mut self,
        province: ProvinceId,
        mode: ArmyIdleOrderMode,
    ) {
        let ids = stationed_chain_ids(&self.military_units, province);
        for id in ids {
            if self.military_units[&id].order.code() == UNIT_ORDER_IDLE {
                set_unit_order(
                    self.military_units
                        .get_mut(&id)
                        .expect("stationed unit remains live"),
                    mode.order(),
                    None,
                );
            }
        }
    }

    /// `TArmyMgr::ActivateFirstIdleTacticalUnitByCategoryAtTile`.
    pub fn activate_first_idle_unit_by_category(
        &mut self,
        province: ProvinceId,
        category: i16,
    ) -> i16 {
        let ids = stationed_chain_ids(&self.military_units, province);
        let mut activated = false;
        let mut remaining = 0_i16;
        for id in ids {
            let unit = &self.military_units[&id];
            if tactical_category(unit.unit_type()) != category
                || unit.order.code() != UNIT_ORDER_IDLE
            {
                continue;
            }
            if activated {
                remaining += 1;
            } else {
                set_unit_order(
                    self.military_units
                        .get_mut(&id)
                        .expect("stationed unit remains live"),
                    UNIT_ORDER_DONE,
                    None,
                );
                activated = true;
            }
        }
        remaining
    }

    /// `TArmyMgr::ActivateFirstActiveTacticalUnitByCategoryAtTile`.
    pub fn activate_first_active_unit_by_category(
        &mut self,
        province: ProvinceId,
        category: i16,
    ) -> i16 {
        let ids = stationed_chain_ids(&self.military_units, province);
        let mut deactivated = false;
        let mut idle = 0_i16;
        for id in ids {
            if tactical_category(self.military_units[&id].unit_type()) != category {
                continue;
            }
            let order = self.military_units[&id].order.code();
            if order == UNIT_ORDER_IDLE {
                idle += 1;
            } else if matches!(order, UNIT_ORDER_SLEEP | UNIT_ORDER_LATR | UNIT_ORDER_DONE)
                && !deactivated
            {
                set_unit_order(
                    self.military_units
                        .get_mut(&id)
                        .expect("stationed unit remains live"),
                    UNIT_ORDER_IDLE,
                    None,
                );
                deactivated = true;
                idle += 1;
            }
        }
        idle
    }

    /// Unit mutations from `TArmyMgr::SetActiveProvinceSelection` when the province is real.
    /// Clearing selection (`None`) does not touch units.
    pub fn apply_army_province_selection(&mut self, province: Option<ProvinceId>) {
        let Some(province) = province else {
            return;
        };
        let ids = stationed_chain_ids(&self.military_units, province);
        for id in ids {
            let order = self.military_units[&id].order.code();
            if matches!(order, UNIT_ORDER_LATR | UNIT_ORDER_DONE)
                && tactical_category(self.military_units[&id].unit_type()) != 0
            {
                set_unit_order(
                    self.military_units
                        .get_mut(&id)
                        .expect("stationed unit remains live"),
                    UNIT_ORDER_IDLE,
                    None,
                );
            }
        }
    }

    /// `TArmyMgr::ClearProvinceSelectionHighlightsForNation`.
    pub fn clear_province_selection_highlights_for_nation(&mut self, nation: NationId) {
        for unit in self.military_units.values_mut() {
            if unit.owner_nation() == nation && unit.order.code() == UNIT_ORDER_LATR {
                set_unit_order(unit, UNIT_ORDER_IDLE, None);
            }
        }
    }

    /// `TArmyMgr::FindNextSelectableProvinceForNation`. Walks forward from `from` (or 0).
    pub fn find_next_selectable_army_province(
        &self,
        nation: NationId,
        from: Option<ProvinceId>,
    ) -> Option<ProvinceId> {
        let start = from.map(ProvinceId::get).unwrap_or(0);
        for id in start..ProvinceId::COUNT {
            let province = ProvinceId::new(id);
            if !self.province_permits_army_selection(province, nation) {
                continue;
            }
            if self.has_idle_movable_unit(province) {
                return Some(province);
            }
        }
        None
    }

    /// `TArmyMgr::ClearNationArmyActionModesAndCycleSelection` unit walk (cycle is app-side).
    pub fn clear_nation_army_action_modes(&mut self, nation: NationId) {
        let regions: Vec<ProvinceId> = self
            .nation(nation)
            .map(|common| common.owned_regions().to_vec())
            .unwrap_or_default();
        for province in regions {
            let ids = stationed_chain_ids(&self.military_units, province);
            for id in ids {
                let unit = &self.military_units[&id];
                if !unit.unit_type().is_militia_category()
                    && unit.order.code() != UNIT_ORDER_REDEPLOY
                {
                    set_unit_order(
                        self.military_units
                            .get_mut(&id)
                            .expect("stationed unit remains live"),
                        UNIT_ORDER_IDLE,
                        None,
                    );
                }
            }
        }
    }

    /// Unselected classifier `ComputeMapCursorStateIndex` when `pending` is `None`,
    /// otherwise `ComputeCivilianMapCursorStateIndex`.
    pub fn army_map_cursor_state(
        &self,
        nation: NationId,
        pending: Option<ProvinceId>,
        tile: TileId,
        input_flags: i32,
        has_active_selection: bool,
    ) -> ArmyMapCursorState {
        match pending {
            None => {
                self.compute_map_cursor_state_index(nation, tile, input_flags, has_active_selection)
            }
            Some(pending) => self.compute_civilian_map_cursor_state_index(nation, pending, tile),
        }
    }

    /// `TArmyMgr::HandleMapClickByComputedCursorState` (always the unselected classifier).
    pub fn handle_army_unselected_map_click(
        &mut self,
        nation: NationId,
        tile: TileId,
        input_flags: i32,
        has_active_selection: bool,
    ) -> ArmyMapClickOutcome {
        let cursor =
            self.compute_map_cursor_state_index(nation, tile, input_flags, has_active_selection);
        let province = self.map[tile].province;
        match cursor {
            ArmyMapCursorState::SelectProvince => {
                let Some(province) = province else {
                    return ArmyMapClickOutcome::Ignored;
                };
                self.apply_army_province_selection(Some(province));
                ArmyMapClickOutcome::SelectedProvince(province)
            }
            ArmyMapCursorState::MarchOverlay => {
                self.march_selected_armies(nation, tile);
                ArmyMapClickOutcome::Marched
            }
            ArmyMapCursorState::SpyReport => province
                .map(ArmyMapClickOutcome::SpyReport)
                .unwrap_or(ArmyMapClickOutcome::Ignored),
            _ => ArmyMapClickOutcome::Ignored,
        }
    }

    /// `TArmyMgr::HandleMapClickByCivilianCursorState`.
    pub fn handle_army_selected_map_click(
        &mut self,
        nation: NationId,
        pending: ProvinceId,
        tile: TileId,
    ) -> ArmyMapClickOutcome {
        let cursor = self.compute_civilian_map_cursor_state_index(nation, pending, tile);
        let Some(target) = self.map[tile].province else {
            return match cursor {
                ArmyMapCursorState::MarchOverlay => {
                    self.march_selected_armies(nation, tile);
                    ArmyMapClickOutcome::Marched
                }
                _ => ArmyMapClickOutcome::Ignored,
            };
        };
        match cursor {
            ArmyMapCursorState::SelectProvince => {
                self.apply_army_province_selection(Some(target));
                ArmyMapClickOutcome::SelectedProvince(target)
            }
            ArmyMapCursorState::FriendlyAdjacent | ArmyMapCursorState::FriendlyNonAdjacent => {
                if self.provinces_are_adjacent(pending, target) {
                    match self.select_movable_units_on_province(pending, target, false) {
                        ArmyOrderIssue::Issued => ArmyMapClickOutcome::IssuedOrders,
                        other => ArmyMapClickOutcome::OrderRejected(other),
                    }
                } else {
                    match self.commit_non_adjacent_friendly_move(nation, pending, target) {
                        ArmyOrderIssue::Issued => ArmyMapClickOutcome::IssuedOrders,
                        other => ArmyMapClickOutcome::OrderRejected(other),
                    }
                }
            }
            ArmyMapCursorState::Hostile => {
                match self.validate_hostile_order_placement(nation, pending, target) {
                    ArmyOrderIssue::Issued => ArmyMapClickOutcome::IssuedOrders,
                    other => ArmyMapClickOutcome::OrderRejected(other),
                }
            }
            ArmyMapCursorState::MarchOverlay => {
                self.march_selected_armies(nation, tile);
                ArmyMapClickOutcome::Marched
            }
            ArmyMapCursorState::SameProvinceCity => ArmyMapClickOutcome::Garrison(pending),
            ArmyMapCursorState::SpyReport => ArmyMapClickOutcome::SpyReport(target),
            _ => ArmyMapClickOutcome::Ignored,
        }
    }

    /// `TArmyMgr::SelectMovableUnitOnCurrentTileAndPlaySfx`.
    pub fn issue_army_redeploy(&mut self, from: ProvinceId, to: ProvinceId) -> ArmyOrderIssue {
        self.select_movable_units_on_province(from, to, false)
    }

    /// `TArmyMgr::ValidateOrderPlacementPrerequisitesForSelectedTile`.
    pub fn issue_army_hostile_order(
        &mut self,
        nation: NationId,
        from: ProvinceId,
        to: ProvinceId,
    ) -> ArmyOrderIssue {
        self.validate_hostile_order_placement(nation, from, to)
    }

    fn compute_map_cursor_state_index(
        &self,
        nation: NationId,
        tile: TileId,
        input_flags: i32,
        has_active_selection: bool,
    ) -> ArmyMapCursorState {
        let rec = &self.map[tile];
        if rec.per_tile_visited > 0 {
            return ArmyMapCursorState::MarchOverlay;
        }
        if input_flags != 2 {
            if has_active_selection {
                return ArmyMapCursorState::None;
            }
            if self.civilian_on_tile(tile) {
                return ArmyMapCursorState::None;
            }
        }
        if !rec.flags.contains(TileFlags::CITY_MARKER) {
            return ArmyMapCursorState::None;
        }
        if !self.event_eligible(nation) {
            return ArmyMapCursorState::SpyReport;
        }
        let Some(owner) = rec.owner_nation.and_then(TileOwnerTag::nation) else {
            return ArmyMapCursorState::SpyReport;
        };
        if owner != nation && !self.status_of(owner).is_colony_of(nation) {
            return ArmyMapCursorState::SpyReport;
        }
        ArmyMapCursorState::SelectProvince
    }

    fn compute_civilian_map_cursor_state_index(
        &self,
        _nation: NationId,
        pending: ProvinceId,
        tile: TileId,
    ) -> ArmyMapCursorState {
        let rec = &self.map[tile];
        if rec.per_tile_visited > 0 {
            return ArmyMapCursorState::MarchOverlay;
        }
        let Some(city) = rec.province else {
            return ArmyMapCursorState::EmptyOrBlocked;
        };
        let has_movable = self.has_idle_movable_unit(pending);
        if city == pending {
            return if rec.flags.contains(TileFlags::CITY_MARKER) {
                ArmyMapCursorState::SameProvinceCity
            } else {
                ArmyMapCursorState::None
            };
        }

        let pending_slot = self.normalized_province_owner(pending);
        let city_slot = self.normalized_province_owner(city);
        let mut same_owner = pending_slot.is_some() && pending_slot == city_slot;
        if !same_owner && let Some(pending_slot) = pending_slot {
            same_owner =
                city_slot.is_some_and(|slot| self.status_of(slot).is_colony_of(pending_slot));
        }

        if same_owner {
            if rec.flags.contains(TileFlags::CITY_MARKER) {
                return ArmyMapCursorState::SelectProvince;
            }
            if !has_movable {
                return ArmyMapCursorState::EmptyOrBlocked;
            }
            return if self.provinces_are_adjacent(pending, city) {
                ArmyMapCursorState::FriendlyAdjacent
            } else {
                ArmyMapCursorState::FriendlyNonAdjacent
            };
        }

        if rec.flags.contains(TileFlags::CITY_MARKER) {
            return ArmyMapCursorState::SpyReport;
        }
        if !has_movable {
            return ArmyMapCursorState::EmptyOrBlocked;
        }
        let Some(pending_owner) = pending_slot else {
            return ArmyMapCursorState::EmptyOrBlocked;
        };
        let Some(city_owner) = city_slot else {
            return ArmyMapCursorState::EmptyOrBlocked;
        };
        if !self.at_war(pending_owner, city_owner) {
            return ArmyMapCursorState::EmptyOrBlocked;
        }
        if self.provinces_are_adjacent(pending, city)
            || MajorNationId::from_nation(pending_owner)
                .is_some_and(|major| self.map.provinces[city].explored_by_majors()[major])
        {
            return ArmyMapCursorState::Hostile;
        }
        ArmyMapCursorState::EmptyOrBlocked
    }

    fn select_movable_units_on_province(
        &mut self,
        from: ProvinceId,
        to: ProvinceId,
        hostile_overlay: bool,
    ) -> ArmyOrderIssue {
        let ids = stationed_chain_ids(&self.military_units, from);
        let mut found = false;
        for id in ids {
            let unit = &self.military_units[&id];
            if unit.order.code() == UNIT_ORDER_IDLE && !unit.unit_type().is_militia_category() {
                set_unit_order(
                    self.military_units
                        .get_mut(&id)
                        .expect("stationed unit remains live"),
                    UNIT_ORDER_REDEPLOY,
                    Some(to),
                );
                found = true;
            }
        }
        if !found {
            return ArmyOrderIssue::NoMovableUnits;
        }
        self.mark_adjacent_hex_order_direction(from, to, hostile_overlay);
        ArmyOrderIssue::Issued
    }

    fn commit_non_adjacent_friendly_move(
        &mut self,
        nation: NationId,
        from: ProvinceId,
        to: ProvinceId,
    ) -> ArmyOrderIssue {
        let cost = self.idle_movable_arms_cost(from);
        if cost == 0 {
            return ArmyOrderIssue::NoMovableUnits;
        }
        let Some(major) = MajorNationId::from_nation(nation) else {
            return ArmyOrderIssue::NoMovableUnits;
        };
        let budget = self.nations.majors[major].economy.army_movement_budget;
        if cost > budget {
            return ArmyOrderIssue::InsufficientMovementBudget { budget, cost };
        }
        let issued = self.select_movable_units_on_province(from, to, false);
        if issued == ArmyOrderIssue::Issued {
            self.nations.majors[major].economy.army_movement_budget -= cost;
        }
        issued
    }

    fn validate_hostile_order_placement(
        &mut self,
        nation: NationId,
        from: ProvinceId,
        to: ProvinceId,
    ) -> ArmyOrderIssue {
        let cost = self.idle_movable_arms_cost(from);
        if cost == 0 {
            return ArmyOrderIssue::NoMovableUnits;
        }
        if !self.provinces_are_adjacent(from, to) {
            if !self.province_has_port(from) {
                return ArmyOrderIssue::NoPort;
            }
            if !self.province_has_linked_sea_access(from) {
                return ArmyOrderIssue::NoSeaAccess;
            }
            let reinforcement = self.non_adjacent_redeploy_arms_to(nation, to);
            let capacity = self.invasion_capacity(nation, to);
            if cost + reinforcement > capacity {
                return ArmyOrderIssue::InsufficientSealift {
                    capacity,
                    cost,
                    reinforcement,
                };
            }
        }
        self.select_movable_units_on_province(from, to, true)
    }

    /// Confirm-dialog decline path of `TArmyMgr::MarchSelectedArmies`.
    fn march_selected_armies(&mut self, nation: NationId, tile: TileId) {
        let direction = (i32::from(self.map[tile].per_tile_visited) - 1).rem_euclid(6);
        let Some(neighbor) = self
            .map
            .geometry()
            .neighbor(tile, HexDirection::ALL[direction as usize])
        else {
            return;
        };
        let Some(dest) = self.map[neighbor].province else {
            return;
        };
        let same_owner = self.map.provinces[dest].owner() == Some(nation);
        let mut refund = 0_i32;
        let ids: Vec<_> = self.military_units.keys().copied().collect();
        for id in ids {
            let unit = &self.military_units[&id];
            if unit.owner_nation() != nation || unit.order.target() != Some(dest) {
                continue;
            }
            if same_owner
                && unit
                    .stationed_province()
                    .is_some_and(|from| !self.provinces_are_adjacent(from, dest))
            {
                refund += unit.unit_type().arms_carried();
            }
            set_unit_order(
                self.military_units
                    .get_mut(&id)
                    .expect("ordered unit remains live"),
                UNIT_ORDER_IDLE,
                None,
            );
        }
        if refund != 0
            && let Some(major) = MajorNationId::from_nation(nation)
        {
            self.nations.majors[major].economy.army_movement_budget += refund;
        }
        let neighbors = self.map.geometry().neighbors(tile);
        for (i, neighbor) in neighbors.iter().copied().enumerate() {
            let Some(neighbor) = neighbor else {
                continue;
            };
            let flag = self.map[neighbor].per_tile_visited;
            if flag == 0 {
                continue;
            }
            if (i32::from(flag) - 1).rem_euclid(6) != ((i as i32) + 3).rem_euclid(6) {
                continue;
            }
            self.map[neighbor].per_tile_visited = 0;
        }
        self.mark_directional_overlays_for_nation_orders(nation);
    }

    fn mark_directional_overlays_for_nation_orders(&mut self, nation: NationId) {
        for tile in TileId::all() {
            self.map[tile].per_tile_visited = 0;
        }
        let orders: Vec<(ProvinceId, ProvinceId, bool)> = self
            .military_units
            .values()
            .filter(|unit| unit.owner_nation() == nation)
            .filter_map(|unit| {
                let dest = unit.order.target()?;
                let from = unit.stationed_province()?;
                let dest_owner = self.map.provinces[dest].owner()?;
                Some((from, dest, self.at_war(nation, dest_owner)))
            })
            .collect();
        for (from, dest, at_war) in orders {
            self.mark_adjacent_hex_order_direction(from, dest, at_war);
        }
    }

    /// `TMapMgr::MarkAdjacentHexOrderDirectionAndSelectTile`.
    fn mark_adjacent_hex_order_direction(
        &mut self,
        from: ProvinceId,
        to: ProvinceId,
        hostile: bool,
    ) {
        let Some(anchor) = self.map.provinces[to].city_tile() else {
            return;
        };
        let Some(from_tile) = self.map.provinces[from].city_tile() else {
            return;
        };
        let direction = direction_from_tiles(anchor, from_tile);
        let Some(overlay) = hex_area_tile(anchor, direction) else {
            return;
        };
        let mut code = ((direction as i8) + 3).rem_euclid(6) + 1;
        if hostile {
            code += 6;
        }
        self.map[overlay].per_tile_visited = code;
    }

    fn idle_movable_arms_cost(&self, province: ProvinceId) -> i32 {
        stationed_chain_ids(&self.military_units, province)
            .into_iter()
            .map(|id| &self.military_units[&id])
            .filter(|unit| {
                unit.order.code() == UNIT_ORDER_IDLE && !unit.unit_type().is_militia_category()
            })
            .map(|unit| unit.unit_type().arms_carried())
            .sum()
    }

    fn non_adjacent_redeploy_arms_to(&self, nation: NationId, dest: ProvinceId) -> i32 {
        self.military_units
            .values()
            .filter(|unit| {
                unit.owner_nation() == nation
                    && unit.order.code() == UNIT_ORDER_REDEPLOY
                    && unit.order.target() == Some(dest)
                    && unit
                        .stationed_province()
                        .is_some_and(|from| !self.provinces_are_adjacent(from, dest))
            })
            .map(|unit| unit.unit_type().arms_carried())
            .sum()
    }

    fn has_idle_movable_unit(&self, province: ProvinceId) -> bool {
        stationed_chain_ids(&self.military_units, province)
            .into_iter()
            .map(|id| &self.military_units[&id])
            .any(|unit| {
                unit.order.code() == UNIT_ORDER_IDLE && !unit.unit_type().is_militia_category()
            })
    }

    fn provinces_are_adjacent(&self, a: ProvinceId, b: ProvinceId) -> bool {
        self.map.provinces[a].adjacency().contains(&b)
    }

    fn province_permits_army_selection(&self, province: ProvinceId, nation: NationId) -> bool {
        let Some(owner) = self.map.provinces[province].owner() else {
            return false;
        };
        owner == nation || self.status_of(owner).is_colony_of(nation)
    }

    fn province_has_linked_sea_access(&self, province: ProvinceId) -> bool {
        self.map.provinces[province]
            .linked_tiles
            .iter()
            .any(|&tile| {
                self.map[tile].flags.contains(TileFlags::PORT)
                    && self.map[tile]
                        .owner_nation
                        .and_then(TileOwnerTag::nation)
                        .is_some()
                    && self.has_reachable_sea_outside_beginning_turn_mask(tile)
            })
    }

    fn civilian_on_tile(&self, tile: TileId) -> bool {
        self.civilian_units
            .values()
            .any(|unit| unit.location().tile() == Some(tile))
    }
}

fn direction_from_tiles(source: TileId, dest: TileId) -> HexDirection {
    let source = i32::from(source.get());
    let dest = i32::from(dest.get());
    let row_from = source / i32::from(STRATEGIC_MAP_WIDTH);
    let col_from = source % i32::from(STRATEGIC_MAP_WIDTH);
    let diag_from = row_from % 2 + col_from * 2;
    let row_to = dest / i32::from(STRATEGIC_MAP_WIDTH);
    let col_to = dest % i32::from(STRATEGIC_MAP_WIDTH);
    let diag_to = row_to % 2 + col_to * 2;
    if diag_from < diag_to && diag_to < diag_from + 0xd7 {
        if row_to <= row_from {
            return if row_from <= row_to {
                HexDirection::East
            } else {
                HexDirection::NorthEast
            };
        }
        return HexDirection::SouthEast;
    }
    if (diag_from <= diag_to || diag_to + 0xd7 <= diag_from) && diag_to < diag_from + 0xd7 {
        return if row_to <= row_from {
            HexDirection::NorthWest
        } else {
            HexDirection::SouthWest
        };
    }
    if row_to <= row_from {
        if row_to < row_from {
            HexDirection::NorthWest
        } else {
            HexDirection::West
        }
    } else {
        HexDirection::SouthWest
    }
}

fn hex_area_tile(anchor: TileId, direction: HexDirection) -> Option<TileId> {
    let index = i32::from(anchor.get());
    let row = index / i32::from(STRATEGIC_MAP_WIDTH);
    let col = index % i32::from(STRATEGIC_MAP_WIDTH);
    let dir = direction as usize;
    let mut hex_x = row % 2 + col * 2 + i32::from(HEX_COL_DELTA[dir]);
    let mut hex_y = i32::from(HEX_ROW_DELTA[dir]) + row;
    if hex_x > 0xd7 {
        hex_x -= 0xd9;
    } else if hex_x < 0 {
        hex_x += 0xd8;
    }
    hex_y = hex_y.clamp(0, 0x3b);
    let final_index = hex_x / 2 + hex_y * i32::from(STRATEGIC_MAP_WIDTH);
    TileId::try_new(u16::try_from(final_index).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    fn place_unit(
        state: &mut GameState,
        kind: MilitaryUnitKind,
        province: ProvinceId,
        order: i32,
    ) -> MilitaryUnitId {
        let id = MilitaryUnitId::new(state.military_units.len() as i32 + 1);
        let nation = state.turn.active_nation;
        state.military_units.insert(
            id,
            MilitaryUnitState::new(
                id,
                nation,
                kind,
                Some(province),
                if order == 0 {
                    MilitaryOrder::idle([None; 3], [None; 3])
                } else {
                    MilitaryOrder::retail(
                        MilitaryOrderCode::from_retail(order),
                        None,
                        [None; 3],
                        [None; 3],
                    )
                },
                nation,
                0,
                true,
                String::new(),
                0x1f4,
                0,
                0,
                0,
            ),
        );
        id
    }

    fn own(state: &mut GameState, province: ProvinceId) {
        let nation = state.turn.active_nation;
        state.map.provinces[province].set_owner(Some(nation));
    }

    #[test]
    fn toolbar_counts_idle_and_ordered_units() {
        let mut state = game_state();
        let province = ProvinceId::new(3);
        own(&mut state, province);
        place_unit(&mut state, MilitaryUnitKind::Regulars, province, 0);
        place_unit(&mut state, MilitaryUnitKind::Regulars, province, 2);
        place_unit(&mut state, MilitaryUnitKind::Minutemen, province, 0);
        place_unit(&mut state, MilitaryUnitKind::Hussars, province, 1);
        let counts = state.army_toolbar_counts(province);
        assert_eq!(counts.totals[2], 2);
        assert_eq!(counts.available[2], 1);
        assert_eq!(counts.totals[0], 1);
        assert_eq!(counts.available[0], 1);
        assert_eq!(counts.totals[4], 0);
        assert!(!counts.arrow_visible(0));
        assert!(counts.arrow_visible(2));
    }

    #[test]
    fn idle_order_modes_skip_already_ordered_units() {
        let mut state = game_state();
        let province = ProvinceId::new(3);
        own(&mut state, province);
        place_unit(&mut state, MilitaryUnitKind::Regulars, province, 0);
        place_unit(&mut state, MilitaryUnitKind::Regulars, province, 2);
        state.set_idle_unit_orders_on_province(province, ArmyIdleOrderMode::Latr);
        assert_eq!(
            state.military_units[0].order.code(),
            MilitaryOrderCode::Latr
        );
        assert_eq!(
            state.military_units[1].order.code(),
            MilitaryOrderCode::Sleep
        );
    }

    #[test]
    fn category_arrows_toggle_first_matching_unit() {
        let mut state = game_state();
        let province = ProvinceId::new(3);
        own(&mut state, province);
        place_unit(&mut state, MilitaryUnitKind::Regulars, province, 0);
        place_unit(&mut state, MilitaryUnitKind::Regulars, province, 0);
        let remaining = state.activate_first_idle_unit_by_category(province, 2);
        assert_eq!(remaining, 1);
        let codes: Vec<MilitaryOrderCode> = state
            .military_units
            .values()
            .map(|unit| unit.order.code())
            .collect();
        assert_eq!(
            codes
                .iter()
                .filter(|&&code| code == MilitaryOrderCode::Done)
                .count(),
            1
        );
        assert_eq!(
            codes
                .iter()
                .filter(|&&code| code == MilitaryOrderCode::Idle)
                .count(),
            1
        );
        let idle = state.activate_first_active_unit_by_category(province, 2);
        assert_eq!(idle, 2);
        assert!(
            state
                .military_units
                .values()
                .all(|unit| unit.order.code() == MilitaryOrderCode::Idle)
        );
    }

    #[test]
    fn selecting_a_province_resets_latr_and_done_non_militia() {
        let mut state = game_state();
        let province = ProvinceId::new(3);
        own(&mut state, province);
        place_unit(&mut state, MilitaryUnitKind::Regulars, province, 3);
        place_unit(&mut state, MilitaryUnitKind::Regulars, province, 4);
        place_unit(&mut state, MilitaryUnitKind::Minutemen, province, 4);
        place_unit(&mut state, MilitaryUnitKind::Regulars, province, 2);
        state.apply_army_province_selection(Some(province));
        assert_eq!(
            state.military_units[0].order.code(),
            MilitaryOrderCode::Idle
        );
        assert_eq!(
            state.military_units[1].order.code(),
            MilitaryOrderCode::Idle
        );
        assert_eq!(
            state.military_units[2].order.code(),
            MilitaryOrderCode::Done
        );
        assert_eq!(
            state.military_units[3].order.code(),
            MilitaryOrderCode::Sleep
        );
        state.apply_army_province_selection(None);
        assert_eq!(
            state.military_units[0].order.code(),
            MilitaryOrderCode::Idle
        );
    }

    #[test]
    fn find_next_selectable_walks_forward_without_wrapping() {
        let mut state = game_state();
        own(&mut state, ProvinceId::new(1));
        own(&mut state, ProvinceId::new(4));
        place_unit(
            &mut state,
            MilitaryUnitKind::Regulars,
            ProvinceId::new(4),
            0,
        );
        place_unit(
            &mut state,
            MilitaryUnitKind::Minutemen,
            ProvinceId::new(1),
            0,
        );
        assert_eq!(
            state.find_next_selectable_army_province(state.turn.active_nation, None),
            Some(ProvinceId::new(4))
        );
        assert_eq!(
            state.find_next_selectable_army_province(
                state.turn.active_nation,
                Some(ProvinceId::new(4))
            ),
            Some(ProvinceId::new(4))
        );
        state.set_idle_unit_orders_on_province(ProvinceId::new(4), ArmyIdleOrderMode::Sleep);
        assert_eq!(
            state.find_next_selectable_army_province(
                state.turn.active_nation,
                Some(ProvinceId::new(4))
            ),
            None
        );
    }

    #[test]
    fn unselected_cursor_selects_own_city_and_blocks_without_marker() {
        let mut state = game_state();
        let nation = state.turn.active_nation;
        let tile = TileId::new(10);
        state.map[tile].flags.insert(TileFlags::CITY_MARKER);
        state.map[tile].owner_nation = Some(TileOwnerTag::from_nation(nation));
        state.map[tile].province = Some(ProvinceId::new(3));
        own(&mut state, ProvinceId::new(3));
        assert_eq!(
            state.army_map_cursor_state(nation, None, tile, 0, false),
            ArmyMapCursorState::SelectProvince
        );
        assert_eq!(
            state.army_map_cursor_state(nation, None, tile, 0, true),
            ArmyMapCursorState::None
        );
        state.map[tile].flags.remove(TileFlags::CITY_MARKER);
        assert_eq!(
            state.army_map_cursor_state(nation, None, tile, 0, false),
            ArmyMapCursorState::None
        );
    }

    #[test]
    fn selected_cursor_classifies_adjacent_friendly_and_blocked_empty() {
        let mut state = game_state();
        let nation = state.turn.active_nation;
        let from = ProvinceId::new(3);
        let to = ProvinceId::new(4);
        own(&mut state, from);
        own(&mut state, to);
        state.map.provinces[from].set_adjacency(vec![to]);
        place_unit(&mut state, MilitaryUnitKind::Regulars, from, 0);
        let tile = TileId::new(20);
        state.map[tile].province = Some(to);
        assert_eq!(
            state.army_map_cursor_state(nation, Some(from), tile, 0, true),
            ArmyMapCursorState::FriendlyAdjacent
        );
        let empty = TileId::new(21);
        assert_eq!(
            state.army_map_cursor_state(nation, Some(from), empty, 0, true),
            ArmyMapCursorState::EmptyOrBlocked
        );
    }

    #[test]
    fn friendly_adjacent_click_redeploys_idle_non_militia() {
        let mut state = game_state();
        let nation = state.turn.active_nation;
        let from = ProvinceId::new(3);
        let to = ProvinceId::new(4);
        own(&mut state, from);
        own(&mut state, to);
        state.map.provinces[from].set_adjacency(vec![to]);
        state.map.provinces[from].set_city_tile(Some(TileId::new(30)));
        state.map.provinces[to].set_city_tile(Some(TileId::new(31)));
        place_unit(&mut state, MilitaryUnitKind::Regulars, from, 0);
        place_unit(&mut state, MilitaryUnitKind::Minutemen, from, 0);
        let tile = TileId::new(40);
        state.map[tile].province = Some(to);
        let outcome = state.handle_army_selected_map_click(nation, from, tile);
        assert_eq!(outcome, ArmyMapClickOutcome::IssuedOrders);
        assert_eq!(state.military_units[0].order.code(), UNIT_ORDER_REDEPLOY);
        assert_eq!(state.military_units[0].order.target(), Some(to));
        assert_eq!(
            state.military_units[1].order.code(),
            MilitaryOrderCode::Idle
        );
    }
}
