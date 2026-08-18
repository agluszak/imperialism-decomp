//! Navy mission `GiveOrders`, hop-limited sail, and `CarryOutOrders` type 1/5/8.

use crate::*;
use enum_map::{Enum, EnumMap};
use indexmap::IndexMap;

const UNREACHED: i16 = 0x29a;

#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
pub(crate) enum NavyPriorityComponent {
    Resolve,
    Strength,
    Descriptor,
    Industry,
}

impl NavyPriorityComponent {
    pub(crate) const ALL: [Self; 4] = [
        Self::Resolve,
        Self::Strength,
        Self::Descriptor,
        Self::Industry,
    ];
}

pub(crate) type NavyPriorityTable<T> = EnumMap<NavyPriorityComponent, T>;

/// Retail navy toolbar classes `cls0` through `cls3`.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[repr(i16)]
pub enum NavyToolbarClass {
    Class0,
    Class1,
    Class2,
    Class3,
}

pub type NavyToolbarClassTable<T> = EnumMap<NavyToolbarClass, T>;

impl NavyToolbarClass {
    pub const fn from_retail(value: i16) -> Option<Self> {
        match value {
            0 => Some(Self::Class0),
            1 => Some(Self::Class1),
            2 => Some(Self::Class2),
            3 => Some(Self::Class3),
            _ => None,
        }
    }
}

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
    pub(crate) toolbar_class: Option<NavyToolbarClass>,
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
    toolbar_class: Option<NavyToolbarClass>,
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
        toolbar_class,
        descriptor_weight,
        priority_tier,
    }
}

pub(crate) const NAVY_DESCRIPTORS: ShipTypeTable<NavyOrderDescriptor> =
    ShipTypeTable::from_array([
        navy_descriptor(0, 0, 0, 0, 0, 0, None, 0, 0),
        navy_descriptor(0, 0, 100, 600, 0, 2, None, 1, 0),
        navy_descriptor(0, 0, 95, 1000, 0, 4, None, 1, 0),
        navy_descriptor(300, 5, 90, 900, 4, 0, Some(NavyToolbarClass::Class1), 3, 1),
        navy_descriptor(600, 6, 80, 1700, 3, 0, Some(NavyToolbarClass::Class0), 2, 1),
        navy_descriptor(0, 0, 95, 900, 0, 8, None, 1, 0),
        navy_descriptor(0, 0, 100, 600, 0, 4, None, 1, 0),
        navy_descriptor(300, 7, 80, 700, 7, 0, Some(NavyToolbarClass::Class2), 5, 2),
        navy_descriptor(500, 8, 45, 1200, 5, 0, Some(NavyToolbarClass::Class3), 3, 2),
        navy_descriptor(
            1000,
            10,
            40,
            1800,
            6,
            0,
            Some(NavyToolbarClass::Class0),
            4,
            3,
        ),
        navy_descriptor(0, 0, 75, 1200, 0, 16, None, 1, 0),
        navy_descriptor(600, 9, 50, 1000, 8, 0, Some(NavyToolbarClass::Class1), 6, 3),
        navy_descriptor(
            2000,
            13,
            30,
            2800,
            7,
            0,
            Some(NavyToolbarClass::Class3),
            5,
            4,
        ),
        navy_descriptor(
            1800,
            13,
            45,
            2200,
            9,
            0,
            Some(NavyToolbarClass::Class2),
            6,
            4,
        ),
    ]);

/// Retail industrial-cost lookup used by navy category 3. Separate from the
/// arms table even though the numbers currently match.
const INDUSTRY_COST: ShipTypeTable<i16> =
    ShipTypeTable::from_array([0, 0, 0, 2, 5, 0, 0, 3, 6, 15, 0, 8, 24, 18]);

pub(crate) fn ship_stock_cap(ship_type: ShipType) -> i16 {
    NAVY_DESCRIPTORS[ship_type].stock_cap as i16
}

pub(crate) fn ship_creates_navy_object(ship_type: ShipType) -> bool {
    NAVY_DESCRIPTORS[ship_type].toolbar_class.is_some()
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

pub(crate) fn navy_category_baselines(
    enabled: &IndustryCapabilityTable<bool>,
) -> NavyPriorityTable<i32> {
    let mut totals = NavyPriorityTable::default();
    let mut enabled_count = 0;
    for slot in IndustryCapabilitySlot::ALL.into_iter().skip(1) {
        let ship_type = ShipType::from_index(slot.retail())
            .expect("ship type index is inside the descriptor table");
        let descriptor = NAVY_DESCRIPTORS[ship_type];
        if descriptor.resolve_weight <= 0 || !enabled[slot] {
            continue;
        }
        enabled_count += 1;
        let calc = descriptor.calculate_weight;
        totals[NavyPriorityComponent::Resolve] += descriptor.resolve_weight * calc * calc;
        totals[NavyPriorityComponent::Strength] +=
            (calc * descriptor.stock_cap * 100) / descriptor.task_force_weight;
        totals[NavyPriorityComponent::Descriptor] += descriptor.navy_priority_weight;
        totals[NavyPriorityComponent::Industry] += i32::from(INDUSTRY_COST[ship_type]);
    }
    if enabled_count == 0 {
        return totals;
    }
    let half = enabled_count / 2;
    NavyPriorityTable::from_array(
        totals
            .as_array()
            .map(|total| (total + half) / enabled_count),
    )
}

pub(crate) fn ship_priority_contribution(
    ship: &ShipState,
    category: NavyPriorityComponent,
    baselines: &NavyPriorityTable<i32>,
) -> i32 {
    let divisor = baselines[category];
    if divisor == 0 {
        return 0;
    }
    let descriptor = NAVY_DESCRIPTORS[ship.ship_type];
    match category {
        NavyPriorityComponent::Resolve => {
            let quantity_term =
                i32::from(ship.experience / 100) + descriptor.resolve_weight * 10 + 5;
            let weight = descriptor.calculate_weight;
            (quantity_term / 10 * weight * weight * 100) / divisor
        }
        NavyPriorityComponent::Strength => {
            let weight = descriptor.calculate_weight;
            (weight * i32::from(ship.strength) * 10000) / (descriptor.task_force_weight * divisor)
        }
        NavyPriorityComponent::Descriptor => (descriptor.descriptor_weight * 100) / divisor,
        NavyPriorityComponent::Industry => {
            if ship.strength < 1 {
                0
            } else {
                (i32::from(INDUSTRY_COST[ship.ship_type]) * 100) / divisor
            }
        }
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

const NAVY_CONTROL_PROFILE: NavyPriorityTable<i16> = NavyPriorityTable::from_array([40, 40, 20, 0]);
const NAVY_ESCORT_PROFILE: NavyPriorityTable<i16> = NavyPriorityTable::from_array([40, 30, 30, 0]);

fn navy_required_from_profile(profile: NavyPriorityTable<i16>, total: f32) -> [u32; 4] {
    profile
        .as_array()
        .map(|weight| (f32::from(weight) * total * 0.01).to_bits())
}

fn hop_distance(distances: &[i16], zone: OceanZoneId) -> i16 {
    distances
        .get(usize::from(zone.get()))
        .copied()
        .unwrap_or(UNREACHED)
}

fn accumulate_ship_categories(
    ship: &ShipState,
    vector: &mut NavyPriorityTable<f32>,
    enabled: &IndustryCapabilityTable<bool>,
) {
    let max_strength = ship_stock_cap(ship.ship_type);
    if max_strength == 0 {
        return;
    }
    let baselines = navy_category_baselines(enabled);
    let scale = f32::from(ship.strength) / f32::from(max_strength);
    vector[NavyPriorityComponent::Resolve] +=
        ship_priority_contribution(ship, NavyPriorityComponent::Resolve, &baselines) as f32 * scale;
    vector[NavyPriorityComponent::Strength] +=
        ship_priority_contribution(ship, NavyPriorityComponent::Strength, &baselines) as f32
            * scale;
    vector[NavyPriorityComponent::Descriptor] +=
        ship_priority_contribution(ship, NavyPriorityComponent::Descriptor, &baselines) as f32
            * scale;
    vector[NavyPriorityComponent::Industry] +=
        ship_priority_contribution(ship, NavyPriorityComponent::Industry, &baselines) as f32;
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
        let enabled = IndustryCapabilityTable::from_array([
            true, true, true, true, true, false, false, false, false, false, false, false, false,
            false,
        ]);
        let baselines = navy_category_baselines(&enabled);
        let ship = ShipState {
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(0),
            aggression: NavalAggression::Cautious,
            nation: NationId::new(0),
            name: String::new(),
            strength: 900,
            experience: 0,
            selection: ShipSelection::Available,
        };
        assert!(ship_priority_contribution(&ship, NavyPriorityComponent::Resolve, &baselines) > 0);
        assert!(
            ship_priority_contribution(&ship, NavyPriorityComponent::Descriptor, &baselines) > 0
        );
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
                aggression: NavalAggression::Cautious,
                nation: NationId::new(1),
                name: String::new(),
                strength: 900,
                experience: 0,
                selection: ShipSelection::Available,
            },
        );
        state.diplomacy.relationships[NationId::new(0)][NationId::new(1)] =
            DiplomaticRelationship::War;
        assert!(state.navy_capitol_threatened(MajorNationId::new(0)));
    }
}
