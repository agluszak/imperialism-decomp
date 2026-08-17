//! Navy mission `GiveOrders`, hop-limited sail, and `CarryOutOrders` type 1/5/8.

use crate::*;
use indexmap::IndexMap;

const UNREACHED: i16 = 0x29a;

/// Recovered navy-order descriptor columns. One semantic record; not the C++
/// dword-column layout.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NavyOrderDescriptor {
    pub(crate) resolve_weight: i32,
    pub(crate) calculate_weight: i32,
    pub(crate) task_force_weight: i32,
    pub(crate) stock_cap: i32,
    pub(crate) navy_priority_weight: i32,
    pub(crate) resource_weight: i32,
    pub(crate) toolbar_bucket: i32,
    pub(crate) descriptor_weight: i32,
    #[allow(dead_code)]
    pub(crate) priority_tier: i32,
}

#[allow(clippy::too_many_arguments)]
const fn navy_descriptor(
    resolve_weight: i32,
    calculate_weight: i32,
    task_force_weight: i32,
    stock_cap: i32,
    navy_priority_weight: i32,
    resource_weight: i32,
    toolbar_bucket: i32,
    descriptor_weight: i32,
    priority_tier: i32,
) -> NavyOrderDescriptor {
    NavyOrderDescriptor {
        resolve_weight,
        calculate_weight,
        task_force_weight,
        stock_cap,
        navy_priority_weight,
        resource_weight,
        toolbar_bucket,
        descriptor_weight,
        priority_tier,
    }
}

pub(crate) const NAVY_DESCRIPTORS: ShipTypeTable<NavyOrderDescriptor> =
    ShipTypeTable::from_array([
        navy_descriptor(0, 0, 0, 0, 0, 0, -1, 0, 0),
        navy_descriptor(0, 0, 100, 600, 0, 2, -1, 1, 0),
        navy_descriptor(0, 0, 95, 1000, 0, 4, -1, 1, 0),
        navy_descriptor(300, 5, 90, 900, 4, 0, 1, 3, 1),
        navy_descriptor(600, 6, 80, 1700, 3, 0, 0, 2, 1),
        navy_descriptor(0, 0, 95, 900, 0, 8, -1, 1, 0),
        navy_descriptor(0, 0, 100, 600, 0, 4, -1, 1, 0),
        navy_descriptor(300, 7, 80, 700, 7, 0, 2, 5, 2),
        navy_descriptor(500, 8, 45, 1200, 5, 0, 3, 3, 2),
        navy_descriptor(1000, 10, 40, 1800, 6, 0, 0, 4, 3),
        navy_descriptor(0, 0, 75, 1200, 0, 16, -1, 1, 0),
        navy_descriptor(600, 9, 50, 1000, 8, 0, 1, 6, 3),
        navy_descriptor(2000, 13, 30, 2800, 7, 0, 3, 5, 4),
        navy_descriptor(1800, 13, 45, 2200, 9, 0, 2, 6, 4),
    ]);

/// Retail industrial-cost lookup used by navy category 3. Separate from the
/// arms table even though the numbers currently match.
const INDUSTRY_COST: ShipTypeTable<i16> =
    ShipTypeTable::from_array([0, 0, 0, 2, 5, 0, 0, 3, 6, 15, 0, 8, 24, 18]);

pub(crate) fn ship_stock_cap(ship_type: ShipType) -> i16 {
    NAVY_DESCRIPTORS[ship_type].stock_cap as i16
}

pub(crate) fn ship_creates_navy_object(ship_type: ShipType) -> bool {
    NAVY_DESCRIPTORS[ship_type].toolbar_bucket >= 0
}

pub(crate) fn ship_display_stats(ship_type: ShipType) -> [i16; 6] {
    let descriptor = NAVY_DESCRIPTORS[ship_type];
    [
        descriptor.resolve_weight as i16,
        descriptor.calculate_weight as i16,
        descriptor.task_force_weight as i16,
        descriptor.stock_cap as i16,
        descriptor.navy_priority_weight as i16,
        descriptor.resource_weight as i16,
    ]
}

pub(crate) fn navy_category_baselines(enabled: &[bool; 14]) -> [i32; 4] {
    let mut totals = [0_i32; 4];
    let mut enabled_count = 0;
    for (type_index, &is_enabled) in enabled.iter().enumerate().skip(1) {
        let ship_type = ShipType::from_index(type_index as u8)
            .expect("ship type index is inside the descriptor table");
        let descriptor = NAVY_DESCRIPTORS[ship_type];
        if descriptor.resolve_weight <= 0 || !is_enabled {
            continue;
        }
        enabled_count += 1;
        let calc = descriptor.calculate_weight;
        totals[0] += descriptor.resolve_weight * calc * calc;
        totals[1] += (calc * descriptor.stock_cap * 100) / descriptor.task_force_weight;
        totals[2] += descriptor.navy_priority_weight;
        totals[3] += i32::from(INDUSTRY_COST[ship_type]);
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
    let divisor = baselines[category as usize];
    if divisor == 0 {
        return 0;
    }
    let descriptor = NAVY_DESCRIPTORS[ship.ship_type];
    match category {
        0 => {
            let quantity_term =
                i32::from(ship.experience / 100) + descriptor.resolve_weight * 10 + 5;
            let weight = descriptor.calculate_weight;
            (quantity_term / 10 * weight * weight * 100) / divisor
        }
        1 => {
            let weight = descriptor.calculate_weight;
            (weight * i32::from(ship.strength) * 10000) / (descriptor.task_force_weight * divisor)
        }
        2 => (descriptor.descriptor_weight * 100) / divisor,
        3 => {
            if ship.strength < 1 {
                0
            } else {
                (i32::from(INDUSTRY_COST[ship.ship_type]) * 100) / divisor
            }
        }
        _ => 0,
    }
}

fn descriptor_weight(ship_type: ShipType) -> i32 {
    NAVY_DESCRIPTORS[ship_type].descriptor_weight
}

mod assessment;
mod execution;
mod player;

pub use execution::{NavyOrdersContinuation, PendingNavalBattle};
pub use player::{NavyOrder, NavySelectionClick, NavyTileClick, NavyToolbarCounts};

impl GameState {
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
            for ship in self.ships.values() {
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

fn assigned_navy_ships(missions: &IndexMap<MissionId, MissionState>) -> Vec<ShipId> {
    let mut assigned = Vec::new();
    for mission in missions.values() {
        if let Some(navy) = navy_state(&mission.data) {
            assigned.extend(navy.ships.keys().copied());
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
    let scale = f32::from(ship.strength) / f32::from(max_strength);
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
pub(super) mod tests {
    use super::*;
    use crate::test_support::game_state;

    pub(super) fn zone(neighbors: Vec<OceanZoneId>) -> Zone {
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
        state.ships.insert(
            ShipId::new(0),
            ShipState {
                ship_type: ShipType::Frigate,
                location: OceanZoneId::new(0),
                aggression: 0,
                nation: NationId::new(1),
                name: String::new(),
                strength: 900,
                experience: 0,
                selection: 0,
            },
        );
        state.diplomacy.relationships[NationId::new(0)][NationId::new(1)] =
            DiplomaticRelationship::War;
        assert!(state.navy_capitol_threatened(MajorNationId::new(0)));
    }
}
