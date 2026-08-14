use crate::city::ship_stock_cap;
use crate::*;
use serde::{Deserialize, Serialize};

const MILITARY_MAINTENANCE_MULTIPLIER: i32 = 25;

const NAVY_ARMS_BY_SHIP_TYPE: ShipTypeTable<i32> =
    ShipTypeTable::from_array([0, 0, 0, 2, 5, 0, 0, 3, 6, 15, 0, 8, 24, 18]);

impl GameState {
    pub(crate) fn army_unit_power(&self, nation: NationId) -> i32 {
        self.military_units
            .iter()
            .filter(|unit| unit.nation == nation)
            .map(|unit| unit.unit_type.arms_required())
            .sum()
    }

    pub(crate) fn navy_arms(&self, nation: NationId) -> i32 {
        self.ships
            .iter()
            .filter(|ship| ship.nation == nation)
            .map(|ship| NAVY_ARMS_BY_SHIP_TYPE[ship.ship_type])
            .sum()
    }

    /// `TGreatPower::GetMilitaryPower`.
    pub(crate) fn military_power(&self, nation: MajorNationId) -> f32 {
        let army = self.army_unit_power(nation.nation()) as f32;
        let city = &self.nations.majors[nation].city;
        let reinforcement = {
            let labor = i32::from(city.population.baseline_labor.low);
            let budget = i32::from(city.population.strength).min(labor);
            let arms = i32::from(city.stockpile[ResourceKind::Arms]);
            budget
                .min(arms)
                .min((self.army_unit_power(nation.nation()) / 2).max(0)) as f32
        };
        let metalworks = i32::from(city.production_orders[CityFacilitySlot::Metalworks]);
        let production = metalworks.min((army * 0.25) as i32);
        army + reinforcement + production as f32
    }

    /// `TGreatPower::GetTotalNavalForce`.
    pub(crate) fn naval_force(&self, nation: MajorNationId) -> f32 {
        let city = &self.nations.majors[nation].city;
        let ship_production = self.technology.naval_production_capacity(
            i32::from(city.production_orders[CityFacilitySlot::LumberMill]),
            i32::from(city.production_orders[CityFacilitySlot::SteelMill]),
        );
        let navy = self.navy_arms(nation.nation()) as f32;
        let production = ship_production.min(navy as i32) as f32;
        let army = self.army_unit_power(nation.nation());
        let priority_cap = ((navy * 0.5) as i32).min(army) as f32;
        priority_cap + navy + production
    }

    pub(crate) fn military_power_score(&self, nation: MajorNationId) -> i32 {
        let nation_id = nation.nation();
        self.military_units
            .iter()
            .filter(|unit| unit.nation == nation_id)
            .map(|unit| unit.unit_type.arms_required())
            .sum::<i32>()
            + self
                .ships
                .iter()
                .filter(|ship| ship.nation == nation_id)
                .map(|ship| NAVY_ARMS_BY_SHIP_TYPE[ship.ship_type])
                .sum::<i32>()
            + 4
    }

    /// Charges one major nation for its current army and navy.
    pub fn pay_for_military(&mut self, nation: MajorNationId) {
        let arms = self.military_power_score(nation) - 4;
        let charge = arms * MILITARY_MAINTENANCE_MULTIPLIER;

        let MajorNation {
            common,
            economy: major,
            ..
        } = &mut self.nations.majors[nation];
        major.military_expenses = charge;
        common.treasury -= charge;
    }

    /// Prepends a ship the way `TShip::TShip` prepends `g_pNavyPrimaryOrderListHead`.
    pub(crate) fn insert_ship_at_head(&mut self, ship: ShipState) {
        self.bump_ship_ids();
        self.ships.insert(0, ship);
    }

    fn bump_ship_ids(&mut self) {
        for admiral in &mut self.admirals {
            if let Some(ship) = &mut admiral.ship {
                *ship = ShipId::new(ship.get() + 1);
            }
        }
        for force in &mut self.task_forces {
            if let Some(flagship) = &mut force.flagship {
                *flagship = ShipId::new(flagship.get() + 1);
            }
            for selected in &mut force.ships {
                selected.ship = ShipId::new(selected.ship.get() + 1);
            }
        }
        for mission in &mut self.missions {
            bump_mission_ship_ids(&mut mission.data);
        }
    }

    /// `TGreatPower::IsCapitolThreatened` for both land (mode 0) and navy (mode 1).
    pub(crate) fn is_capitol_threatened(&self, nation: MajorNationId) -> bool {
        self.land_capitol_threatened(nation) || self.navy_capitol_threatened(nation)
    }

    pub(crate) fn land_capitol_threatened(&self, nation: MajorNationId) -> bool {
        let Some(capitol) = self.capitol_province(nation.nation()) else {
            return false;
        };
        self.local_support_score(capitol) < self.cross_nation_support_score(capitol)
    }

    pub(crate) fn navy_capitol_threatened(&self, nation: MajorNationId) -> bool {
        let Some(port) = self.first_port_zone_for_nation(nation.nation()) else {
            return false;
        };
        let neighbors = match &self.ocean.zones[usize::from(port.get())] {
            ZoneKind::PortZone(port) => &port.zone.primary_neighbors,
            ZoneKind::Zone(zone) => &zone.primary_neighbors,
        };
        let Some(&first) = neighbors.first() else {
            return false;
        };
        self.navy_zone_similarity_score(first, |ship| ship.nation == nation.nation())
            < self.navy_zone_similarity_score(first, |ship| {
                self.diplomacy.relationships[nation.nation()][ship.nation]
                    == DiplomaticRelationship::War
            })
    }

    pub(crate) fn capitol_province(&self, nation: NationId) -> Option<ProvinceId> {
        let home = self.nations.home_tile(nation)?;
        self.map[home].province
    }

    pub(crate) fn province_mission_importance_bits(
        &self,
        province: ProvinceId,
        nation: NationId,
    ) -> u32 {
        let record = &self.map.provinces[province];
        let mut score = record.city_score() as f32;
        let adjacent = record.adjacency();
        if !adjacent.is_empty() {
            let matches = adjacent
                .iter()
                .filter(|&&neighbor| self.normalized_province_owner(neighbor) == Some(nation))
                .count();
            score *= matches as f32 / adjacent.len() as f32 + 1.0;
        }
        (score / 5000.0).to_bits()
    }

    fn local_support_score(&self, province: ProvinceId) -> f32 {
        let mut scores = ActionClassScores::default();
        for unit in self.units_stationed_in(province) {
            accumulate_unit_priority(unit, &mut scores, 1.0, PROVINCE_UNIT_ORDER_WEIGHT);
        }
        scores.similarity(TACTICAL_COMPOSITION.baseline)
    }

    pub(crate) fn cross_nation_support_score(&self, province: ProvinceId) -> f32 {
        let Some(owner) = self.map.provinces[province].owner() else {
            return 0.0;
        };
        let mut scores = ActionClassScores::default();
        let mut budget =
            MajorNationTable::from_fn(|nation| self.invasion_capacity(nation.nation(), province));
        for candidate in ProvinceId::all() {
            let Some(candidate_owner) = self.map.provinces[candidate].owner() else {
                continue;
            };
            let Some(candidate_major) = MajorNationId::from_nation(candidate_owner) else {
                continue;
            };
            if candidate_owner == owner
                || self.diplomacy.relationships[candidate_owner][owner]
                    != DiplomaticRelationship::War
            {
                continue;
            }
            if self.map.provinces[province]
                .adjacency()
                .contains(&candidate)
            {
                for unit in self.units_stationed_in(candidate) {
                    if !unit.unit_type.is_militia_category() {
                        accumulate_unit_priority(
                            unit,
                            &mut scores,
                            1.0,
                            PROVINCE_UNIT_ORDER_WEIGHT,
                        );
                    }
                }
            } else if budget[candidate_major] > 0 && self.province_has_port(candidate) {
                for unit in self.units_stationed_in(candidate) {
                    if unit.unit_type.is_militia_category() {
                        continue;
                    }
                    let cost = unit.unit_type.arms_carried();
                    let remaining = &mut budget[candidate_major];
                    if cost < *remaining {
                        accumulate_unit_priority(
                            unit,
                            &mut scores,
                            1.0,
                            PROVINCE_UNIT_ORDER_WEIGHT,
                        );
                        *remaining -= cost;
                    }
                }
            }
        }
        // IsCapitolThreatened inverts the fort/open-field row sense used by the
        // tactical projection scorer: fort present uses the open-field profile.
        let profile = if self.map.provinces[province].fort_level() > 0 {
            TACTICAL_COMPOSITION.open_field
        } else {
            TACTICAL_COMPOSITION.fort_siege
        };
        scores.similarity(profile)
    }

    pub(crate) fn units_stationed_in(
        &self,
        province: ProvinceId,
    ) -> impl Iterator<Item = &MilitaryUnitState> {
        self.military_units
            .iter()
            .filter(move |unit| unit.stationed_province() == Some(province))
    }

    fn invasion_capacity(&self, nation: NationId, province: ProvinceId) -> i32 {
        self.task_forces
            .iter()
            .filter(|force| {
                force.nation == nation
                    && force.order == 5
                    && force.target == TaskForceTarget::Province(province)
            })
            .flat_map(|force| force.ships.iter())
            .filter_map(|selected| self.ships.get(selected.ship.get()))
            .map(|ship| {
                if ship.strength > 0 {
                    NAVY_ARMS_BY_SHIP_TYPE[ship.ship_type]
                } else {
                    0
                }
            })
            .sum()
    }

    fn province_has_port(&self, province: ProvinceId) -> bool {
        self.map.provinces[province]
            .linked_tiles
            .iter()
            .any(|&tile| self.map[tile].flags.contains(TileFlags::PORT))
    }

    fn navy_zone_similarity_score(
        &self,
        zone: OceanZoneId,
        matches: impl Fn(&ShipState) -> bool,
    ) -> f32 {
        let baselines =
            crate::navy_orders::navy_category_baselines(&self.technology.industry_enabled_by_slot);
        let mut vector = [0.0_f32; 4];
        for ship in self
            .ships
            .iter()
            .filter(|ship| ship.location == zone && matches(ship))
        {
            let max_strength = ship_stock_cap(ship.ship_type);
            if max_strength == 0 {
                continue;
            }
            let scale = f32::from(ship.strength) / f32::from(max_strength);
            vector[0] +=
                crate::navy_orders::ship_priority_contribution(ship, 0, &baselines) as f32 * scale;
            vector[1] +=
                crate::navy_orders::ship_priority_contribution(ship, 1, &baselines) as f32 * scale;
            vector[2] +=
                crate::navy_orders::ship_priority_contribution(ship, 2, &baselines) as f32 * scale;
            vector[3] += crate::navy_orders::ship_priority_contribution(ship, 3, &baselines) as f32;
        }
        let sum: f32 = vector.iter().sum();
        #[allow(clippy::float_cmp)]
        if sum == 0.0 {
            return 0.0;
        }
        let mut accum = 0.0;
        for (component, &target) in vector.iter().zip(&NAVY_DISTRIBUTION_PROFILE) {
            let mut diff = *component / sum - f32::from(target) * 0.01;
            if diff <= 0.0 {
                diff = -diff;
            }
            accum += diff;
        }
        sum * (1.0 - accum * 0.5)
    }
}

fn bump_mission_ship_ids(data: &mut MissionData) {
    match data {
        MissionData::ControlSeaZone(navy)
        | MissionData::Escort(navy)
        | MissionData::ScatteredShips(navy)
        | MissionData::Beachhead(navy) => bump_navy_mission_ship_ids(navy),
        MissionData::BlockadePort { navy, .. } => bump_navy_mission_ship_ids(navy),
        MissionData::Invade { beachhead, .. } => {
            if let Some(navy) = beachhead {
                bump_navy_mission_ship_ids(navy);
            }
        }
        MissionData::AttackProvince(_) | MissionData::DefendProvince { .. } => {}
    }
}

fn bump_navy_mission_ship_ids(navy: &mut NavyMissionState) {
    if let Some(ship) = &mut navy.selected_ship {
        *ship = ShipId::new(ship.get() + 1);
    }
    for selected in &mut navy.ships {
        selected.ship = ShipId::new(selected.ship.get() + 1);
    }
}

pub(crate) const PROVINCE_UNIT_ORDER_WEIGHT: f32 = 33.0;

/// Five action-class weights (`requiredEquipageByClass` / `GetAttribute(0..4)`).
/// Classes follow the tactical AI class table: infantry, cavalry, artillery,
/// armor, and support (sappers, engineers, generals).
#[derive(Clone, Copy, Default)]
pub(crate) struct ActionClassWeights {
    infantry: i16,
    cavalry: i16,
    artillery: i16,
    armor: i16,
    support: i16,
}

impl ActionClassWeights {
    const fn new(infantry: i16, cavalry: i16, artillery: i16, armor: i16, support: i16) -> Self {
        Self {
            infantry,
            cavalry,
            artillery,
            armor,
            support,
        }
    }

    pub(crate) const fn components(self) -> [i16; 5] {
        [
            self.infantry,
            self.cavalry,
            self.artillery,
            self.armor,
            self.support,
        ]
    }
}

/// Retail `g_awTacticalCompositionReferenceProfiles_00697870` rows 0–3.
pub(crate) struct TacticalCompositions {
    pub(crate) baseline: ActionClassWeights,
    pub(crate) fort_siege: ActionClassWeights,
    pub(crate) open_field: ActionClassWeights,
    pub(crate) fort_garrison: ActionClassWeights,
}

pub(crate) const TACTICAL_COMPOSITION: TacticalCompositions = TacticalCompositions {
    baseline: ActionClassWeights::new(40, 27, 0, 17, 16),
    fort_siege: ActionClassWeights::new(27, 36, 0, 17, 20),
    open_field: ActionClassWeights::new(26, 31, 20, 23, 0),
    fort_garrison: ActionClassWeights::new(40, 22, 0, 38, 0),
};

const NAVY_DISTRIBUTION_PROFILE: [i16; 4] = [40, 40, 20, 0];

/// Per-unit-type `GetAttribute` record (`g_UnitTypeStatTable_0066EB88`).
/// The seventh retail short is unused (divisor 0) and omitted.
#[derive(Clone, Copy)]
struct UnitTypeStats {
    infantry: i16,
    cavalry: i16,
    artillery: i16,
    armor: i16,
    support: i16,
    dampen: i16,
}

impl UnitTypeStats {
    const fn new(
        infantry: i16,
        cavalry: i16,
        artillery: i16,
        armor: i16,
        support: i16,
        dampen: i16,
    ) -> Self {
        Self {
            infantry,
            cavalry,
            artillery,
            armor,
            support,
            dampen,
        }
    }

    fn class_costs(self) -> [i16; 5] {
        let scaled = self.attributes();
        [
            scaled.infantry,
            scaled.cavalry,
            scaled.artillery,
            scaled.armor,
            scaled.support,
        ]
    }

    fn attributes(self) -> ScaledUnitStats {
        ScaledUnitStats {
            infantry: scale_attribute(self.infantry, 150),
            cavalry: scale_attribute(self.cavalry, 150),
            artillery: scale_attribute(self.artillery, 65),
            armor: scale_attribute(self.armor, 75),
            support: scale_attribute(self.support, 100),
            dampen: scale_attribute(self.dampen, 250),
        }
    }
}

#[derive(Clone, Copy)]
struct ScaledUnitStats {
    infantry: i16,
    cavalry: i16,
    artillery: i16,
    armor: i16,
    support: i16,
    dampen: i16,
}

const fn scale_attribute(raw: i16, divisor: i16) -> i16 {
    (raw * 100) / divisor
}

const UNIT_TYPE_STATS: MilitaryUnitTable<UnitTypeStats> = MilitaryUnitTable::from_array([
    UnitTypeStats::new(0x0026, 0x0014, 0x0001, 0x0001, 0x000a, 0x0000),
    UnitTypeStats::new(0x0032, 0x0019, 0x0001, 0x0001, 0x0023, 0x004b),
    UnitTypeStats::new(0x004b, 0x001e, 0x0001, 0x0001, 0x000a, 0x0000),
    UnitTypeStats::new(0x005e, 0x002d, 0x0001, 0x0001, 0x000a, 0x0000),
    UnitTypeStats::new(0x0023, 0x0028, 0x0001, 0x0001, 0x0046, 0x0032),
    UnitTypeStats::new(0x0028, 0x005a, 0x0001, 0x0001, 0x003c, 0x0000),
    UnitTypeStats::new(0x000a, 0x0091, 0x001e, 0x0032, 0x0005, 0x0000),
    UnitTypeStats::new(0x001e, 0x0014, 0x003c, 0x0046, 0x0005, 0x0000),
    UnitTypeStats::new(0x005c, 0x0030, 0x0001, 0x0001, 0x0021, 0x0000),
    UnitTypeStats::new(0x0082, 0x0046, 0x0001, 0x0001, 0x006e, 0x0087),
    UnitTypeStats::new(0x00dc, 0x0050, 0x0001, 0x0001, 0x0021, 0x0000),
    UnitTypeStats::new(0x00fa, 0x0064, 0x0001, 0x0001, 0x0021, 0x0000),
    UnitTypeStats::new(0x004d, 0x0064, 0x0001, 0x0001, 0x00dc, 0x006e),
    UnitTypeStats::new(0x007d, 0x00c8, 0x0001, 0x0001, 0x00b9, 0x0000),
    UnitTypeStats::new(0x0016, 0x00fa, 0x006e, 0x00f0, 0x000a, 0x0000),
    UnitTypeStats::new(0x006e, 0x0021, 0x00b9, 0x0113, 0x000a, 0x0000),
    UnitTypeStats::new(0x00ff, 0x0082, 0x0001, 0x0001, 0x005f, 0x0000),
    UnitTypeStats::new(0x015e, 0x00be, 0x0001, 0x0001, 0x0140, 0x00f0),
    UnitTypeStats::new(0x0258, 0x00dc, 0x0001, 0x0001, 0x0064, 0x0000),
    UnitTypeStats::new(0x02a3, 0x010e, 0x0001, 0x0001, 0x0064, 0x0000),
    UnitTypeStats::new(0x015e, 0x00fa, 0x0001, 0x0001, 0x02bc, 0x0000),
    UnitTypeStats::new(0x02bc, 0x0352, 0x0001, 0x0001, 0x0226, 0x0000),
    UnitTypeStats::new(0x0064, 0x0226, 0x01f4, 0x028a, 0x0096, 0x0000),
    UnitTypeStats::new(0x0258, 0x00a0, 0x0271, 0x03c0, 0x0028, 0x0000),
    UnitTypeStats::new(0x000d, 0x000a, 0x009b, 0x0001, 0x000a, 0x0000),
    UnitTypeStats::new(0x0030, 0x0020, 0x01c2, 0x0001, 0x001e, 0x0000),
    UnitTypeStats::new(0x00f0, 0x0078, 0x04b0, 0x0001, 0x0050, 0x0000),
    UnitTypeStats::new(0, 0, 0, 0, 0, 0),
    UnitTypeStats::new(0, 0, 0, 0, 0, 0),
    UnitTypeStats::new(0, 0, 0, 0, 0, 0),
]);

impl MilitaryUnitKind {
    fn stats(self) -> UnitTypeStats {
        UNIT_TYPE_STATS[self]
    }

    pub(crate) fn class_costs(self) -> [i16; 5] {
        self.stats().class_costs()
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct ActionClassScores {
    pub(crate) infantry: f32,
    pub(crate) cavalry: f32,
    pub(crate) artillery: f32,
    pub(crate) armor: f32,
    pub(crate) support: f32,
}

impl ActionClassScores {
    pub(crate) fn components(self) -> [f32; 5] {
        [
            self.infantry,
            self.cavalry,
            self.artillery,
            self.armor,
            self.support,
        ]
    }
    pub(crate) fn similarity(self, profile: ActionClassWeights) -> f32 {
        let sum = self.infantry + self.cavalry + self.artillery + self.armor + self.support;
        #[allow(clippy::float_cmp)]
        if sum == 0.0 {
            return 0.0;
        }
        let accum = class_diff(self.infantry, profile.infantry, sum)
            + class_diff(self.cavalry, profile.cavalry, sum)
            + class_diff(self.artillery, profile.artillery, sum)
            + class_diff(self.armor, profile.armor, sum)
            + class_diff(self.support, profile.support, sum);
        sum * (1.0 - accum * 0.5)
    }
}

fn class_diff(component: f32, target: i16, sum: f32) -> f32 {
    (component / sum - f32::from(target) * 0.01).abs()
}

pub(crate) fn accumulate_unit_priority(
    unit: &MilitaryUnitState,
    scores: &mut ActionClassScores,
    mut scale: f32,
    weight: f32,
) {
    let stats = unit.unit_type().stats().attributes();
    let quality = unit.experience();
    let strength = unit.strength();
    let dampen = 1.0 - f32::from(stats.dampen) * weight * -0.0001;
    scale *= f32::from(strength) * 0.002 * (1.0 - f32::from(quality / 100) * -0.1);
    scores.infantry += f32::from(strength) * 0.002 * f32::from(stats.infantry) * scale * dampen;
    scores.cavalry += f32::from(stats.cavalry) * scale * dampen;
    scores.artillery += f32::from(stats.artillery) * scale;
    scores.armor += f32::from(stats.armor) * scale;
    scores.support += f32::from(stats.support) * scale * dampen;
}

/// A ship in primary-list order. Ship and task-force references are snapshot-local
/// ordinals because retail does not persist a stable identity for either collection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShipState {
    pub ship_type: ShipType,
    pub location: OceanZoneId,
    pub task_force: Option<TaskForceId>,
    pub aggression: i32,
    pub nation: NationId,
    pub name: String,
    pub strength: i16,
    pub experience: i16,
    pub selection: i32,
}

/// A navy secondary-order node (`TAdmiral`) in head-first list order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmiralState {
    pub nation: NationId,
    pub name: String,
    pub experience: i16,
    pub ship: Option<ShipId>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "target", rename_all = "snake_case")]
pub enum TaskForceTarget {
    None,
    Zone(OceanZoneId),
    Province(ProvinceId),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskForceState {
    pub aggression: i32,
    pub order: i32,
    pub target: TaskForceTarget,
    pub location: OceanZoneId,
    pub nation: NationId,
    pub ship_counts: [i16; 4],
    pub defeated: bool,
    pub ingot_tile: i16,
    pub flagship: Option<ShipId>,
    pub ships: Vec<SelectedShip>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectedShip {
    pub ship: ShipId,
    pub selected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArmyMissionState {
    /// Exact IEEE-754 bits retained for deterministic mission scoring.
    pub required_equipage_bits: [u32; 5],
    pub units: Vec<MilitaryUnitId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NavyMissionState {
    pub target_zone: Option<OceanZoneId>,
    pub resolved_port_zone: Option<OceanZoneId>,
    pub selected_ship: Option<ShipId>,
    pub task_force: Option<TaskForceId>,
    /// Retail target-selection state. Values 0, 1, and 2 select between the
    /// resolved port and target zone; the save field remains open until more
    /// lifecycle behavior is implemented.
    pub state: i32,
    /// Exact IEEE-754 bits retained for deterministic mission scoring.
    pub required_equipage_bits: [u32; 4],
    pub ships: Vec<SelectedShip>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttackMissionState {
    pub army: ArmyMissionState,
    pub present_province: Option<ProvinceId>,
    pub target_province: ProvinceId,
    pub amassing_province: Option<ProvinceId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MissionData {
    AttackProvince(AttackMissionState),
    Invade {
        attack: AttackMissionState,
        beachhead: Option<NavyMissionState>,
    },
    DefendProvince {
        province: ProvinceId,
        army: ArmyMissionState,
    },
    ControlSeaZone(NavyMissionState),
    Escort(NavyMissionState),
    ScatteredShips(NavyMissionState),
    BlockadePort {
        navy: NavyMissionState,
        port_zone: OceanZoneId,
    },
    Beachhead(NavyMissionState),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MissionState {
    pub nation: NationId,
    pub data: MissionData,
    pub path_nation: Option<NationId>,
    /// Open retail lifecycle code; currently produced as 2 and preserved from saves.
    pub state: u8,
    /// Exact IEEE-754 importance-score bits.
    pub importance_bits: u32,
    /// Whether retail's AI assignment pass is currently holding this mission.
    pub held: bool,
    /// Open retail mission-status byte; bit zero is consumed by current retail AI logic.
    pub marker: u8,
}
