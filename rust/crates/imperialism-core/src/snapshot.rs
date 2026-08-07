use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

pub const GAME_SNAPSHOT_SCHEMA: &str = "imperialism.game_snapshot.v1";
pub const GAME_SNAPSHOT_SECTIONS: [&str; 8] = [
    "metadata", "rng", "world", "nations", "economy", "military", "missions", "pending",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GameSnapshotV1 {
    pub schema: String,
    pub sections: Vec<String>,
    pub hashes: SnapshotHashes,
    pub metadata: SnapshotMetadata,
    pub rng: SnapshotRng,
    pub world: SnapshotWorld,
    pub nations: SnapshotNations,
    pub economy: SnapshotEconomy,
    pub military: SnapshotMilitary,
    pub missions: SnapshotMissions,
    pub pending: SnapshotPending,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotHashes {
    pub metadata: String,
    pub rng: String,
    pub world: String,
    pub nations: String,
    pub economy: String,
    pub military: String,
    pub missions: String,
    pub pending: String,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotMetadata {
    pub scenario_map_index_plus_one: i32,
    pub economic_turn: i32,
    pub turn_state: i32,
    pub difficulty: i32,
    pub active_nation: i32,
    pub selected_nation: i32,
    pub persistent_unit_id_counter: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotRng {
    pub runtime_seed: u32,
    pub crt_rand_state: u32,
    pub map_generation_lcg: u32,
    pub zone_status_lcg: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotWorld {
    pub width: u16,
    pub height: u16,
    pub wraps_horizontally: bool,
    pub tiles: Vec<TileSnapshot>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TileSnapshot(pub [i64; 10]);

impl SnapshotWorld {
    pub fn semantic_hash(&self) -> Result<String, SnapshotValidationError> {
        compact_json(self).map(|json| fnv1a_hex(json.as_bytes()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotNations {
    pub records: Vec<SnapshotNation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SnapshotNation {
    pub slot: u8,
    pub kind: String,
    pub present: bool,
    pub nation_slot: Option<i16>,
    pub encoded_nation_slot: Option<i16>,
    pub owner_nation: Option<i16>,
    pub treasury: Option<i32>,
    pub home_tile: Option<i32>,
    pub need_level_by_nation: Option<Vec<i16>>,
    pub major: Option<SnapshotMajorNation>,
}

impl Serialize for SnapshotNation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut record =
            serializer.serialize_struct("SnapshotNation", if self.present { 10 } else { 3 })?;
        record.serialize_field("slot", &self.slot)?;
        record.serialize_field("kind", &self.kind)?;
        record.serialize_field("present", &self.present)?;
        if self.present {
            record.serialize_field("nation_slot", &self.nation_slot)?;
            record.serialize_field("encoded_nation_slot", &self.encoded_nation_slot)?;
            record.serialize_field("owner_nation", &self.owner_nation)?;
            record.serialize_field("treasury", &self.treasury)?;
            record.serialize_field("home_tile", &self.home_tile)?;
            record.serialize_field("need_level_by_nation", &self.need_level_by_nation)?;
            record.serialize_field("major", &self.major)?;
        }
        record.end()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotMajorNation {
    pub diplomacy_eligible: u8,
    pub capacities: [i16; 4],
    pub grant_total_cost: i32,
    pub unfilled_trade_offer_count: i16,
    pub diplomacy_policy_by_nation: Vec<i16>,
    pub diplomacy_grant_by_nation: Vec<i16>,
    pub need_current_by_type: Vec<i16>,
    pub need_target_by_type: Vec<i16>,
    pub relation_delta_current: Vec<i16>,
    pub purchased_items_by_resource: Vec<i16>,
    pub item_potentials: Vec<i16>,
    pub unfilled_trade_turns_by_resource: Vec<i16>,
    pub transported_items_by_resource: Vec<i16>,
    pub remembered_trade_offers_by_resource: Vec<i16>,
    pub aid_allocation_matrix: Vec<i32>,
    pub budget_pool_base: i32,
    pub budget_pool_delta: i32,
    pub candidate_nation_flags: Vec<u8>,
    pub scenario_initialized: u8,
    pub turn_finished: u8,
    pub pending_action_status: Vec<i8>,
    pub pending_action_payload_by_action: Vec<i16>,
    pub diplomacy_budget_base: i32,
    pub escalation_counter: i16,
    pub pending_commitment_cost: i32,
    pub pressure_counter: i16,
    pub aid_allocation_total: i32,
    pub colony_boycott_flags: Vec<u8>,
    pub military_expenses: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotEconomy {
    pub cities: Vec<SnapshotCity>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SnapshotCity {
    pub nation: u8,
    pub present: bool,
    pub power_plant_upgrade_queued: Option<u8>,
    pub food_substitution_count: Option<i16>,
    pub starvation_population_loss: Option<i16>,
    pub serialized_state: Option<i16>,
    pub phase_counter: Option<i16>,
    pub metrics_0e: Option<Vec<i16>>,
    pub metrics_4a: Option<Vec<i16>>,
    pub order_count_by_type: Option<Vec<i16>>,
    pub rolling_item_production_score: Option<i32>,
    pub low_production: Option<u8>,
    pub low_stock: Option<u8>,
    pub reserved_by_type: Option<Vec<i16>>,
    pub home_town_tile: Option<i16>,
    pub power_available: Option<i16>,
    pub stock_by_type: Option<Vec<i16>>,
    pub production_orders: Option<Vec<i16>>,
    pub production_accum: Option<Vec<i16>>,
    pub production_flags: Option<Vec<u8>>,
    pub production_current: Option<Vec<i16>>,
    pub production_progress: Option<Vec<i16>>,
    pub population_growth_penalty_ticks: Option<i16>,
    pub unmet_resource_retries: Option<Vec<i16>>,
    pub consumed_production_input_by_type: Option<Vec<i16>>,
    pub population: Option<SnapshotPopulation>,
}

impl Serialize for SnapshotCity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut city =
            serializer.serialize_struct("SnapshotCity", if self.present { 26 } else { 2 })?;
        city.serialize_field("nation", &self.nation)?;
        city.serialize_field("present", &self.present)?;
        if self.present {
            city.serialize_field(
                "power_plant_upgrade_queued",
                &self.power_plant_upgrade_queued,
            )?;
            city.serialize_field("food_substitution_count", &self.food_substitution_count)?;
            city.serialize_field(
                "starvation_population_loss",
                &self.starvation_population_loss,
            )?;
            city.serialize_field("serialized_state", &self.serialized_state)?;
            city.serialize_field("phase_counter", &self.phase_counter)?;
            city.serialize_field("metrics_0e", &self.metrics_0e)?;
            city.serialize_field("metrics_4a", &self.metrics_4a)?;
            city.serialize_field("order_count_by_type", &self.order_count_by_type)?;
            city.serialize_field(
                "rolling_item_production_score",
                &self.rolling_item_production_score,
            )?;
            city.serialize_field("low_production", &self.low_production)?;
            city.serialize_field("low_stock", &self.low_stock)?;
            city.serialize_field("reserved_by_type", &self.reserved_by_type)?;
            city.serialize_field("home_town_tile", &self.home_town_tile)?;
            city.serialize_field("power_available", &self.power_available)?;
            city.serialize_field("stock_by_type", &self.stock_by_type)?;
            city.serialize_field("production_orders", &self.production_orders)?;
            city.serialize_field("production_accum", &self.production_accum)?;
            city.serialize_field("production_flags", &self.production_flags)?;
            city.serialize_field("production_current", &self.production_current)?;
            city.serialize_field("production_progress", &self.production_progress)?;
            city.serialize_field(
                "population_growth_penalty_ticks",
                &self.population_growth_penalty_ticks,
            )?;
            city.serialize_field("unmet_resource_retries", &self.unmet_resource_retries)?;
            city.serialize_field(
                "consumed_production_input_by_type",
                &self.consumed_production_input_by_type,
            )?;
            city.serialize_field("population", &self.population)?;
        }
        city.end()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotPopulation {
    pub count: i16,
    pub count_float_bits: u32,
    pub strength: i16,
    pub extra: i16,
    pub phase_value: i16,
    pub baseline_labor: Option<[i16; 3]>,
    pub production_labor: Option<[i16; 3]>,
    pub pending_labor_delta: Option<[i16; 3]>,
    pub predicted_need_by_resource: Vec<i16>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotMilitary {
    pub units: Vec<SnapshotMilitaryUnit>,
    pub civilians: Vec<SnapshotCivilianUnit>,
    pub ships: Vec<SnapshotShip>,
    pub task_forces: Vec<SnapshotTaskForce>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotMilitaryUnit {
    pub nation: u8,
    pub roster_index: u32,
    pub persistent_id: i32,
    pub unit_type: i16,
    pub stationed_province: i16,
    pub order: i32,
    pub order_target: i16,
    pub owner_nation: i16,
    pub roster_id: i16,
    pub registered: u8,
    pub order_target_tiles: [i16; 3],
    pub order_target_mirrors: [i16; 3],
    pub name: String,
    pub strength: i16,
    pub era: i16,
    pub experience: i16,
    pub battle_flags: i16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotCivilianUnit {
    pub nation: u8,
    pub roster_index: u32,
    pub persistent_id: i32,
    pub unit_type: i16,
    pub tile: i16,
    pub order: i32,
    pub order_target: i16,
    pub owner_nation: i16,
    pub roster_id: i16,
    pub registered: u8,
    pub remaining_turns: i16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotShip {
    pub index: u32,
    pub r#type: i16,
    pub location: i16,
    pub task_force: i32,
    pub aggression: i32,
    pub nation: i16,
    pub name: String,
    pub strength: i16,
    pub experience: i16,
    pub selection: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotTaskForce {
    pub index: u32,
    pub aggression: i32,
    pub order: i32,
    pub target_kind: i32,
    pub target: i32,
    pub location: i16,
    pub nation: i16,
    pub ship_counts: [i16; 4],
    pub ingot_tile: i16,
    pub flagship: i32,
    pub ships: Vec<[i32; 2]>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotMissions {
    pub records: Vec<SnapshotMission>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotMission {
    pub index: u32,
    pub nation: u8,
    pub queue_index: u32,
    pub class: String,
    pub source_nation: i16,
    pub path_marker: i16,
    pub state: u8,
    pub importance_bits: u32,
    pub marker: u8,
    pub army: Option<SnapshotArmyMission>,
    pub navy: Option<SnapshotNavyMission>,
    pub attack: Option<SnapshotAttackMission>,
    pub beachhead: Option<SnapshotNavyMission>,
    pub blockade_port_zone: Option<i16>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotArmyMission {
    pub present_location: i16,
    pub required_equipage_bits: [u32; 5],
    pub units: Vec<i32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotNavyMission {
    pub target_zone: i16,
    pub resolved_port_zone: i16,
    pub selected_ship: i32,
    pub task_force: i32,
    pub state: i32,
    pub required_equipage_bits: [u32; 4],
    pub ships: Vec<[i32; 2]>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotAttackMission {
    pub target_province: i16,
    pub amassing_province: i16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotPending {
    pub turn_flow_status_flags: u32,
    pub nations: Vec<SnapshotNationPending>,
    pub war_transitions: Vec<[i16; 2]>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotNationPending {
    pub nation: u8,
    pub turn_events: Vec<[i16; 2]>,
    pub proposals: Vec<[i16; 2]>,
    pub turn_summary: Vec<[i16; 4]>,
    pub turn_start_events: Vec<SnapshotTurnStartEvent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotTurnStartEvent {
    pub class: String,
    pub tag: i32,
    pub land_sale: Option<[i16; 2]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotValidationError {
    Schema(String),
    Sections(Vec<String>),
    Dimensions {
        width: u16,
        height: u16,
    },
    TileCount {
        expected: usize,
        actual: usize,
    },
    Shape(String),
    HashFormat {
        section: &'static str,
        value: String,
    },
    HashMismatch {
        section: &'static str,
        expected: String,
        actual: String,
    },
    Serialization(String),
}

impl fmt::Display for SnapshotValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(schema) => {
                write!(formatter, "unsupported game snapshot schema {schema:?}")
            }
            Self::Sections(sections) => {
                write!(formatter, "invalid game snapshot sections {sections:?}")
            }
            Self::Dimensions { width, height } => {
                write!(
                    formatter,
                    "invalid game snapshot dimensions {width}x{height}"
                )
            }
            Self::TileCount { expected, actual } => {
                write!(formatter, "expected {expected} world tiles, found {actual}")
            }
            Self::Shape(message) => formatter.write_str(message),
            Self::HashFormat { section, value } => {
                write!(formatter, "invalid {section} hash {value:?}")
            }
            Self::HashMismatch {
                section,
                expected,
                actual,
            } => write!(
                formatter,
                "{section} hash mismatch: snapshot {expected}, computed {actual}"
            ),
            Self::Serialization(message) => {
                write!(formatter, "snapshot serialization failed: {message}")
            }
        }
    }
}

impl Error for SnapshotValidationError {}

impl GameSnapshotV1 {
    pub fn validate(&self) -> Result<(), SnapshotValidationError> {
        if self.schema != GAME_SNAPSHOT_SCHEMA {
            return Err(SnapshotValidationError::Schema(self.schema.clone()));
        }
        if self.sections.iter().map(String::as_str).collect::<Vec<_>>() != GAME_SNAPSHOT_SECTIONS {
            return Err(SnapshotValidationError::Sections(self.sections.clone()));
        }
        if self.world.width != 108 || self.world.height != 60 {
            return Err(SnapshotValidationError::Dimensions {
                width: self.world.width,
                height: self.world.height,
            });
        }
        let expected = usize::from(self.world.width) * usize::from(self.world.height);
        if self.world.tiles.len() != expected {
            return Err(SnapshotValidationError::TileCount {
                expected,
                actual: self.world.tiles.len(),
            });
        }
        self.validate_nations()?;
        self.validate_economy()?;
        self.validate_military()?;
        self.validate_missions()?;
        self.validate_pending()?;
        for (section, hash) in self.hashes.iter() {
            if hash.len() != 8
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(SnapshotValidationError::HashFormat {
                    section,
                    value: hash.to_owned(),
                });
            }
        }
        Ok(())
    }

    pub fn verify_hashes(&self) -> Result<(), SnapshotValidationError> {
        self.validate()?;
        let computed = self.computed_hashes()?;
        for (section, expected, actual) in [
            ("metadata", &self.hashes.metadata, &computed.metadata),
            ("rng", &self.hashes.rng, &computed.rng),
            ("world", &self.hashes.world, &computed.world),
            ("nations", &self.hashes.nations, &computed.nations),
            ("economy", &self.hashes.economy, &computed.economy),
            ("military", &self.hashes.military, &computed.military),
            ("missions", &self.hashes.missions, &computed.missions),
            ("pending", &self.hashes.pending, &computed.pending),
            ("state", &self.hashes.state, &computed.state),
        ] {
            if expected != actual {
                return Err(SnapshotValidationError::HashMismatch {
                    section,
                    expected: expected.clone(),
                    actual: actual.clone(),
                });
            }
        }
        Ok(())
    }

    pub fn refresh_hashes(&mut self) -> Result<(), SnapshotValidationError> {
        self.hashes = self.computed_hashes()?;
        Ok(())
    }

    fn computed_hashes(&self) -> Result<SnapshotHashes, SnapshotValidationError> {
        let metadata = compact_json(&self.metadata)?;
        let rng = compact_json(&self.rng)?;
        let world = compact_json(&self.world)?;
        let nations = compact_json(&self.nations)?;
        let economy = compact_json(&self.economy)?;
        let military = compact_json(&self.military)?;
        let missions = compact_json(&self.missions)?;
        let pending = compact_json(&self.pending)?;
        let mut state = String::with_capacity(
            metadata.len()
                + rng.len()
                + world.len()
                + nations.len()
                + economy.len()
                + military.len()
                + missions.len()
                + pending.len(),
        );
        state.push_str(&metadata);
        state.push_str(&rng);
        state.push_str(&world);
        state.push_str(&nations);
        state.push_str(&economy);
        state.push_str(&military);
        state.push_str(&missions);
        state.push_str(&pending);
        Ok(SnapshotHashes {
            metadata: fnv1a_hex(metadata.as_bytes()),
            rng: fnv1a_hex(rng.as_bytes()),
            world: fnv1a_hex(world.as_bytes()),
            nations: fnv1a_hex(nations.as_bytes()),
            economy: fnv1a_hex(economy.as_bytes()),
            military: fnv1a_hex(military.as_bytes()),
            missions: fnv1a_hex(missions.as_bytes()),
            pending: fnv1a_hex(pending.as_bytes()),
            state: fnv1a_hex(state.as_bytes()),
        })
    }

    fn validate_nations(&self) -> Result<(), SnapshotValidationError> {
        if self.nations.records.len() != 23 {
            return Err(SnapshotValidationError::Shape(format!(
                "expected 23 nation records, found {}",
                self.nations.records.len()
            )));
        }
        for (slot, nation) in self.nations.records.iter().enumerate() {
            let expected_kind = if slot < 7 { "major" } else { "minor" };
            if usize::from(nation.slot) != slot || nation.kind != expected_kind {
                return Err(SnapshotValidationError::Shape(format!(
                    "invalid nation identity at slot {slot}"
                )));
            }
            if !nation.present {
                continue;
            }
            require_len(
                nation.need_level_by_nation.as_deref(),
                23,
                "nation need levels",
            )?;
            if slot < 7 {
                let major = nation.major.as_ref().ok_or_else(|| {
                    SnapshotValidationError::Shape(format!(
                        "present major nation {slot} has no major state"
                    ))
                })?;
                major.validate(slot)?;
            } else if nation.major.is_some() {
                return Err(SnapshotValidationError::Shape(format!(
                    "minor nation {slot} contains major state"
                )));
            }
        }
        Ok(())
    }

    fn validate_economy(&self) -> Result<(), SnapshotValidationError> {
        if self.economy.cities.len() != 7 {
            return Err(SnapshotValidationError::Shape(format!(
                "expected seven city records, found {}",
                self.economy.cities.len()
            )));
        }
        for (slot, city) in self.economy.cities.iter().enumerate() {
            if usize::from(city.nation) != slot {
                return Err(SnapshotValidationError::Shape(format!(
                    "invalid city identity at slot {slot}"
                )));
            }
            if city.present {
                city.validate(slot)?;
            }
        }
        Ok(())
    }

    fn validate_military(&self) -> Result<(), SnapshotValidationError> {
        let mut unit_ids = BTreeSet::new();
        let mut expected_roster = [0_u32; 23];
        for unit in &self.military.units {
            let nation = usize::from(unit.nation);
            if nation >= expected_roster.len() || unit.roster_index != expected_roster[nation] {
                return Err(SnapshotValidationError::Shape(format!(
                    "invalid military roster index for nation {}",
                    unit.nation
                )));
            }
            expected_roster[nation] += 1;
            if !unit_ids.insert(unit.persistent_id) {
                return Err(SnapshotValidationError::Shape(format!(
                    "duplicate military unit id {}",
                    unit.persistent_id
                )));
            }
        }
        let mut civilian_ids = BTreeSet::new();
        let mut expected_civilian_roster = [0_u32; 7];
        for unit in &self.military.civilians {
            let nation = usize::from(unit.nation);
            if nation >= expected_civilian_roster.len()
                || unit.roster_index != expected_civilian_roster[nation]
            {
                return Err(SnapshotValidationError::Shape(format!(
                    "invalid civilian roster index for nation {}",
                    unit.nation
                )));
            }
            expected_civilian_roster[nation] += 1;
            if unit.persistent_id < 0 || !civilian_ids.insert(unit.persistent_id) {
                return Err(SnapshotValidationError::Shape(format!(
                    "invalid or duplicate civilian unit id {}",
                    unit.persistent_id
                )));
            }
            if unit.tile < -1
                || usize::try_from(unit.tile).is_ok_and(|tile| tile >= self.world.tiles.len())
            {
                return Err(SnapshotValidationError::Shape(format!(
                    "civilian unit {} references invalid tile {}",
                    unit.persistent_id, unit.tile
                )));
            }
        }
        if unit_ids
            .iter()
            .chain(civilian_ids.iter())
            .any(|id| *id > self.metadata.persistent_unit_id_counter)
        {
            return Err(SnapshotValidationError::Shape(
                "unit id exceeds the persistent unit counter".to_owned(),
            ));
        }
        for (index, ship) in self.military.ships.iter().enumerate() {
            if usize::try_from(ship.index).ok() != Some(index) {
                return Err(SnapshotValidationError::Shape(format!(
                    "invalid ship identity at index {index}"
                )));
            }
            if ship.task_force >= 0
                && usize::try_from(ship.task_force)
                    .ok()
                    .is_none_or(|force| force >= self.military.task_forces.len())
            {
                return Err(SnapshotValidationError::Shape(format!(
                    "ship {index} references invalid task force {}",
                    ship.task_force
                )));
            }
        }
        for (index, force) in self.military.task_forces.iter().enumerate() {
            if usize::try_from(force.index).ok() != Some(index) {
                return Err(SnapshotValidationError::Shape(format!(
                    "invalid task-force identity at index {index}"
                )));
            }
            for child in &force.ships {
                if child[0] < 0
                    || usize::try_from(child[0])
                        .ok()
                        .is_none_or(|ship| ship >= self.military.ships.len())
                {
                    return Err(SnapshotValidationError::Shape(format!(
                        "task force {index} references invalid ship {}",
                        child[0]
                    )));
                }
            }
            if force.flagship >= 0
                && usize::try_from(force.flagship)
                    .ok()
                    .is_none_or(|ship| ship >= self.military.ships.len())
            {
                return Err(SnapshotValidationError::Shape(format!(
                    "task force {index} references invalid flagship {}",
                    force.flagship
                )));
            }
        }
        Ok(())
    }

    fn validate_missions(&self) -> Result<(), SnapshotValidationError> {
        let unit_ids = self
            .military
            .units
            .iter()
            .map(|unit| unit.persistent_id)
            .collect::<BTreeSet<_>>();
        let mut next_queue_index = [0_u32; 7];
        for (index, mission) in self.missions.records.iter().enumerate() {
            if usize::try_from(mission.index).ok() != Some(index) {
                return Err(SnapshotValidationError::Shape(format!(
                    "invalid mission identity at index {index}"
                )));
            }
            let nation = usize::from(mission.nation);
            if nation >= next_queue_index.len()
                || mission.queue_index != next_queue_index[nation]
                || mission.class.is_empty()
                || !(0..7).contains(&mission.source_nation)
            {
                return Err(SnapshotValidationError::Shape(format!(
                    "invalid mission queue identity at index {index}"
                )));
            }
            next_queue_index[nation] += 1;
            if let Some(army) = &mission.army {
                for unit in &army.units {
                    if !unit_ids.contains(unit) {
                        return Err(SnapshotValidationError::Shape(format!(
                            "mission {index} references invalid military unit {unit}"
                        )));
                    }
                }
            }
            if let Some(navy) = &mission.navy {
                self.validate_mission_navy(index, navy)?;
            }
            if let Some(beachhead) = &mission.beachhead {
                self.validate_mission_navy(index, beachhead)?;
            }
        }
        Ok(())
    }

    fn validate_mission_navy(
        &self,
        mission_index: usize,
        navy: &SnapshotNavyMission,
    ) -> Result<(), SnapshotValidationError> {
        for (label, value, count) in [
            ("ship", navy.selected_ship, self.military.ships.len()),
            (
                "task force",
                navy.task_force,
                self.military.task_forces.len(),
            ),
        ] {
            if value >= 0 && usize::try_from(value).ok().is_none_or(|id| id >= count) {
                return Err(SnapshotValidationError::Shape(format!(
                    "mission {mission_index} references invalid {label} {value}"
                )));
            }
        }
        for child in &navy.ships {
            if child[0] < 0
                || usize::try_from(child[0])
                    .ok()
                    .is_none_or(|ship| ship >= self.military.ships.len())
            {
                return Err(SnapshotValidationError::Shape(format!(
                    "mission {mission_index} references invalid child ship {}",
                    child[0]
                )));
            }
        }
        Ok(())
    }

    fn validate_pending(&self) -> Result<(), SnapshotValidationError> {
        if self.pending.nations.len() != 7 {
            return Err(SnapshotValidationError::Shape(format!(
                "expected seven pending nation records, found {}",
                self.pending.nations.len()
            )));
        }
        for (nation, pending) in self.pending.nations.iter().enumerate() {
            if usize::from(pending.nation) != nation {
                return Err(SnapshotValidationError::Shape(format!(
                    "invalid pending nation identity at slot {nation}"
                )));
            }
            if pending
                .turn_start_events
                .iter()
                .any(|event| event.class.is_empty())
            {
                return Err(SnapshotValidationError::Shape(format!(
                    "pending nation {nation} contains an untyped turn-start event"
                )));
            }
            for (label, records) in [
                ("turn event", pending.turn_events.as_slice()),
                ("proposal", pending.proposals.as_slice()),
            ] {
                if records.iter().any(|record| !(0..23).contains(&record[1])) {
                    return Err(SnapshotValidationError::Shape(format!(
                        "pending nation {nation} contains an invalid {label} source"
                    )));
                }
            }
            if pending.turn_start_events.iter().any(|event| {
                event
                    .land_sale
                    .is_some_and(|record| !(0..23).contains(&record[1]))
            }) {
                return Err(SnapshotValidationError::Shape(format!(
                    "pending nation {nation} contains an invalid land-sale nation"
                )));
            }
        }
        if self
            .pending
            .war_transitions
            .iter()
            .any(|pair| !(0..23).contains(&pair[0]) || !(0..23).contains(&pair[1]))
        {
            return Err(SnapshotValidationError::Shape(
                "pending war transition contains an invalid nation".to_owned(),
            ));
        }
        Ok(())
    }
}

impl SnapshotHashes {
    fn iter(&self) -> [(&'static str, &str); 9] {
        [
            ("metadata", &self.metadata),
            ("rng", &self.rng),
            ("world", &self.world),
            ("nations", &self.nations),
            ("economy", &self.economy),
            ("military", &self.military),
            ("missions", &self.missions),
            ("pending", &self.pending),
            ("state", &self.state),
        ]
    }
}

impl SnapshotMajorNation {
    fn validate(&self, slot: usize) -> Result<(), SnapshotValidationError> {
        for (values, expected, label) in [
            (
                self.diplomacy_policy_by_nation.as_slice(),
                23,
                "diplomacy policy",
            ),
            (
                self.diplomacy_grant_by_nation.as_slice(),
                23,
                "diplomacy grants",
            ),
            (self.need_current_by_type.as_slice(), 23, "current needs"),
            (self.need_target_by_type.as_slice(), 23, "target needs"),
            (
                self.relation_delta_current.as_slice(),
                23,
                "relation deltas",
            ),
            (
                self.purchased_items_by_resource.as_slice(),
                23,
                "purchased items",
            ),
            (self.item_potentials.as_slice(), 23, "item potentials"),
            (
                self.unfilled_trade_turns_by_resource.as_slice(),
                23,
                "unfilled trade turns",
            ),
            (
                self.transported_items_by_resource.as_slice(),
                23,
                "transported items",
            ),
            (
                self.remembered_trade_offers_by_resource.as_slice(),
                23,
                "remembered trade offers",
            ),
            (
                self.pending_action_payload_by_action.as_slice(),
                13,
                "pending action payloads",
            ),
        ] {
            if values.len() != expected {
                return Err(SnapshotValidationError::Shape(format!(
                    "major nation {slot} {label} has {} values, expected {expected}",
                    values.len()
                )));
            }
        }
        for (actual, expected, label) in [
            (
                self.aid_allocation_matrix.len(),
                0x170,
                "aid allocation matrix",
            ),
            (self.candidate_nation_flags.len(), 23, "candidate flags"),
            (
                self.pending_action_status.len(),
                13,
                "pending action status",
            ),
            (self.colony_boycott_flags.len(), 23, "colony boycott flags"),
        ] {
            if actual != expected {
                return Err(SnapshotValidationError::Shape(format!(
                    "major nation {slot} {label} has {actual} values, expected {expected}"
                )));
            }
        }
        Ok(())
    }
}

impl SnapshotCity {
    fn validate(&self, slot: usize) -> Result<(), SnapshotValidationError> {
        for (values, expected, label) in [
            (self.metrics_0e.as_deref(), 30, "metrics_0e"),
            (self.metrics_4a.as_deref(), 9, "metrics_4a"),
            (self.order_count_by_type.as_deref(), 14, "order counts"),
            (self.reserved_by_type.as_deref(), 23, "reservations"),
            (self.stock_by_type.as_deref(), 23, "stock"),
            (self.production_orders.as_deref(), 16, "production orders"),
            (
                self.production_accum.as_deref(),
                16,
                "production accumulation",
            ),
            (self.production_current.as_deref(), 16, "current production"),
            (
                self.production_progress.as_deref(),
                16,
                "production progress",
            ),
            (
                self.unmet_resource_retries.as_deref(),
                23,
                "resource retries",
            ),
            (
                self.consumed_production_input_by_type.as_deref(),
                23,
                "consumed production inputs",
            ),
        ] {
            require_len(values, expected, &format!("city {slot} {label}"))?;
        }
        if self.production_flags.as_ref().map(Vec::len) != Some(16) {
            return Err(SnapshotValidationError::Shape(format!(
                "city {slot} production flags must contain 16 values"
            )));
        }
        let population = self.population.as_ref().ok_or_else(|| {
            SnapshotValidationError::Shape(format!("present city {slot} has no population state"))
        })?;
        if population.predicted_need_by_resource.len() != 23 {
            return Err(SnapshotValidationError::Shape(format!(
                "city {slot} predicted needs must contain 23 values"
            )));
        }
        Ok(())
    }
}

fn require_len<T>(
    values: Option<&[T]>,
    expected: usize,
    label: &str,
) -> Result<(), SnapshotValidationError> {
    if values.map(<[T]>::len) != Some(expected) {
        return Err(SnapshotValidationError::Shape(format!(
            "{label} must contain {expected} values"
        )));
    }
    Ok(())
}

fn compact_json<T: Serialize>(value: &T) -> Result<String, SnapshotValidationError> {
    serde_json::to_string(value)
        .map_err(|error| SnapshotValidationError::Serialization(error.to_string()))
}

fn fnv1a_hex(bytes: &[u8]) -> String {
    let hash = bytes.iter().fold(2_166_136_261_u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(16_777_619)
    });
    format!("{hash:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> GameSnapshotV1 {
        let mut snapshot = GameSnapshotV1 {
            schema: GAME_SNAPSHOT_SCHEMA.to_owned(),
            sections: GAME_SNAPSHOT_SECTIONS.map(str::to_owned).to_vec(),
            hashes: SnapshotHashes::default(),
            metadata: SnapshotMetadata {
                scenario_map_index_plus_one: 0,
                economic_turn: 1,
                turn_state: 5,
                difficulty: 1,
                active_nation: 6,
                selected_nation: 6,
                persistent_unit_id_counter: 43,
            },
            rng: SnapshotRng {
                runtime_seed: 1,
                crt_rand_state: 3_018_468_955,
                map_generation_lcg: 2_556_087_536,
                zone_status_lcg: 1,
            },
            world: SnapshotWorld {
                width: 108,
                height: 60,
                wraps_horizontally: true,
                tiles: vec![TileSnapshot([0; 10]); 6480],
            },
            nations: SnapshotNations {
                records: (0_u8..23)
                    .map(|slot| SnapshotNation {
                        slot,
                        kind: if slot < 7 { "major" } else { "minor" }.to_owned(),
                        present: false,
                        nation_slot: None,
                        encoded_nation_slot: None,
                        owner_nation: None,
                        treasury: None,
                        home_tile: None,
                        need_level_by_nation: None,
                        major: None,
                    })
                    .collect(),
            },
            economy: SnapshotEconomy {
                cities: (0_u8..7)
                    .map(|nation| SnapshotCity {
                        nation,
                        present: false,
                        power_plant_upgrade_queued: None,
                        food_substitution_count: None,
                        starvation_population_loss: None,
                        serialized_state: None,
                        phase_counter: None,
                        metrics_0e: None,
                        metrics_4a: None,
                        order_count_by_type: None,
                        rolling_item_production_score: None,
                        low_production: None,
                        low_stock: None,
                        reserved_by_type: None,
                        home_town_tile: None,
                        power_available: None,
                        stock_by_type: None,
                        production_orders: None,
                        production_accum: None,
                        production_flags: None,
                        production_current: None,
                        production_progress: None,
                        population_growth_penalty_ticks: None,
                        unmet_resource_retries: None,
                        consumed_production_input_by_type: None,
                        population: None,
                    })
                    .collect(),
            },
            military: SnapshotMilitary {
                units: vec![SnapshotMilitaryUnit {
                    nation: 6,
                    roster_index: 0,
                    persistent_id: 42,
                    unit_type: 5,
                    stationed_province: 12,
                    order: 0,
                    order_target: -1,
                    owner_nation: 6,
                    roster_id: 0,
                    registered: 1,
                    order_target_tiles: [-1; 3],
                    order_target_mirrors: [-1; 3],
                    name: "First Army".to_owned(),
                    strength: 100,
                    era: 0,
                    experience: 0,
                    battle_flags: 0,
                }],
                civilians: vec![SnapshotCivilianUnit {
                    nation: 6,
                    roster_index: 0,
                    persistent_id: 43,
                    unit_type: 4,
                    tile: 10,
                    order: 0,
                    order_target: -1,
                    owner_nation: 6,
                    roster_id: 0,
                    registered: 0,
                    remaining_turns: 0,
                }],
                ships: vec![SnapshotShip {
                    index: 0,
                    r#type: 3,
                    location: 57,
                    task_force: 0,
                    aggression: 1,
                    nation: 6,
                    name: "Woopnist".to_owned(),
                    strength: 900,
                    experience: 0,
                    selection: 0,
                }],
                task_forces: vec![SnapshotTaskForce {
                    index: 0,
                    aggression: 1,
                    order: 3,
                    target_kind: 0,
                    target: -1,
                    location: 57,
                    nation: 6,
                    ship_counts: [0, 1, 0, 0],
                    ingot_tile: 2968,
                    flagship: 0,
                    ships: vec![[0, 1]],
                }],
            },
            missions: SnapshotMissions {
                records: vec![SnapshotMission {
                    index: 0,
                    nation: 0,
                    queue_index: 0,
                    class: "TInvadeMission".to_owned(),
                    source_nation: 0,
                    path_marker: -1,
                    state: 2,
                    importance_bits: 0,
                    marker: 0,
                    army: Some(SnapshotArmyMission {
                        present_location: 12,
                        required_equipage_bits: [0; 5],
                        units: vec![42],
                    }),
                    navy: None,
                    attack: Some(SnapshotAttackMission {
                        target_province: 12,
                        amassing_province: 11,
                    }),
                    beachhead: Some(SnapshotNavyMission {
                        target_zone: 57,
                        resolved_port_zone: 57,
                        selected_ship: 0,
                        task_force: 0,
                        state: 1,
                        required_equipage_bits: [0; 4],
                        ships: vec![[0, 1]],
                    }),
                    blockade_port_zone: None,
                }],
            },
            pending: SnapshotPending {
                turn_flow_status_flags: 0x40,
                nations: (0_u8..7)
                    .map(|nation| SnapshotNationPending {
                        nation,
                        turn_events: if nation == 6 { vec![[200, 3]] } else { vec![] },
                        proposals: vec![],
                        turn_summary: vec![],
                        turn_start_events: vec![],
                    })
                    .collect(),
                war_transitions: vec![],
            },
        };
        snapshot.refresh_hashes().unwrap();
        snapshot
    }

    #[test]
    fn validates_and_verifies_canonical_snapshot() {
        let snapshot = snapshot();
        assert_eq!(snapshot.hashes.metadata.len(), 8);
        assert_eq!(snapshot.hashes.rng, "cda0c2d8");
        let json = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(json["military"]["ships"][0]["type"], 3);
        snapshot.verify_hashes().unwrap();
        let state = crate::GameState::try_from(snapshot).unwrap();
        assert_eq!(state.military_units.len(), 1);
        assert_eq!(state.civilian_units.len(), 1);
        assert_eq!(state.civilian_units[0].tile, Some(crate::TileId::new(10)));
        assert_eq!(state.ships[0].task_force, Some(crate::TaskForceId::new(0)));
        assert_eq!(
            state.task_forces[0].ships,
            vec![(crate::ShipId::new(0), true)]
        );
    }

    #[test]
    fn rejects_tampered_semantic_state() {
        let mut snapshot = snapshot();
        snapshot.world.tiles[0].0[1] = 6;
        assert!(matches!(
            snapshot.verify_hashes(),
            Err(SnapshotValidationError::HashMismatch {
                section: "world",
                ..
            })
        ));
    }

    #[test]
    fn rejects_invalid_civilian_roster_state() {
        let mut snapshot = snapshot();
        snapshot.military.civilians[0].roster_index = 1;
        snapshot.refresh_hashes().unwrap();
        assert!(matches!(
            snapshot.validate(),
            Err(SnapshotValidationError::Shape(message))
                if message == "invalid civilian roster index for nation 6"
        ));
    }
}
