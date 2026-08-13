use crate::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Index, IndexMut};

const TECH_ITEM_PURCHASE_COST: TechnologyTable<i32> = TechnologyTable::from_array([
    0, 0, 1000, 1000, 1500, 1500, 1500, 1500, 3000, 3000, 3000, 6000, 7000, 10000, 12000, 12000,
    12000, 12000, 12000, 25000, 20000, 40000, 40000, 40000, 40000, 100000, 120000, 150000, 150000,
]);

/// Per-nation University capability state used by city production and recruitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct UniversityTechnologyState {
    pub available: CivilianUnitTable<bool>,
    /// Highest unlocked requirement column (0..=3) for each resource.
    pub requirement_levels: ResourceTable<u8>,
}

impl<'de> Deserialize<'de> for UniversityTechnologyState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedUniversityTechnologyState {
            available: CivilianUnitTable<bool>,
            requirement_levels: ResourceTable<u8>,
        }

        let serialized = SerializedUniversityTechnologyState::deserialize(deserializer)?;
        if serialized
            .requirement_levels
            .values()
            .any(|level| *level > 3)
        {
            return Err(serde::de::Error::custom(
                "university requirement levels must be in 0..=3",
            ));
        }
        Ok(Self {
            available: serialized.available,
            requirement_levels: serialized.requirement_levels,
        })
    }
}

impl Default for UniversityTechnologyState {
    fn default() -> Self {
        Self {
            available: CivilianUnitTable::from_array([
                true, true, true, false, true, false, false, true, false,
            ]),
            requirement_levels: ResourceTable::from_array([
                0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1,
            ]),
        }
    }
}

/// The technology capabilities consumed by one major nation's city and civilian-order rules.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CityTechnologyCapabilities {
    pub advanced_iron_working: bool,
    pub oil_drilling: bool,
    pub university: UniversityTechnologyState,
    pub primary_civilian_distance_terrain: CivilianTerrainAccess,
    pub secondary_civilian_hills: bool,
    pub secondary_civilian_swamp: bool,
    pub fort_level_cap: FortLevelCap,
}

impl Default for CityTechnologyCapabilities {
    fn default() -> Self {
        Self {
            advanced_iron_working: false,
            oil_drilling: false,
            university: UniversityTechnologyState::default(),
            primary_civilian_distance_terrain: CivilianTerrainAccess::default(),
            secondary_civilian_hills: false,
            secondary_civilian_swamp: false,
            fort_level_cap: FortLevelCap::ONE,
        }
    }
}

pub const TECHNOLOGY_COUNT: usize = 29;

/// Open bounded identity of one of the 29 technology slots.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TechnologyId(usize);

impl TechnologyId {
    pub const COUNT: usize = TECHNOLOGY_COUNT;

    pub const fn new(value: usize) -> Self {
        assert!(value < Self::COUNT, "technology ID is out of range");
        Self(value)
    }

    pub const fn try_new(value: usize) -> Option<Self> {
        if value < Self::COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn index(self) -> usize {
        self.0
    }

    pub fn all() -> impl DoubleEndedIterator<Item = Self> + ExactSizeIterator {
        (0..Self::COUNT).map(Self::new)
    }
}

impl<'de> Deserialize<'de> for TechnologyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = usize::deserialize(deserializer)?;
        Self::try_new(value).ok_or_else(|| {
            serde::de::Error::custom(format_args!(
                "technology ID {value} is out of range 0..={}",
                Self::COUNT - 1
            ))
        })
    }
}

/// Values stored in the 29-slot technology table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TechnologyTable<T>([T; TECHNOLOGY_COUNT]);

impl<T> TechnologyTable<T> {
    pub const fn from_array(values: [T; TECHNOLOGY_COUNT]) -> Self {
        Self(values)
    }

    pub fn from_fn(mut function: impl FnMut(TechnologyId) -> T) -> Self {
        Self(std::array::from_fn(|index| {
            function(TechnologyId::new(index))
        }))
    }

    pub const fn as_array(&self) -> &[T; TECHNOLOGY_COUNT] {
        &self.0
    }
}

impl<T: Default + Copy> Default for TechnologyTable<T> {
    fn default() -> Self {
        Self([T::default(); TECHNOLOGY_COUNT])
    }
}

impl<T> Index<TechnologyId> for TechnologyTable<T> {
    type Output = T;

    fn index(&self, technology: TechnologyId) -> &Self::Output {
        &self.0[technology.index()]
    }
}

impl<T> IndexMut<TechnologyId> for TechnologyTable<T> {
    fn index_mut(&mut self, technology: TechnologyId) -> &mut Self::Output {
        &mut self.0[technology.index()]
    }
}

impl<T: Serialize> Serialize for TechnologyTable<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.0.iter())
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for TechnologyTable<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<T>::deserialize(deserializer)?;
        let actual = values.len();
        let values: [T; TECHNOLOGY_COUNT] = values.try_into().map_err(|_| {
            serde::de::Error::invalid_length(actual, &"exactly 29 technology entries")
        })?;
        Ok(Self::from_array(values))
    }
}

const RANDOM_START_PRIORITY_RANGES: [(i16, i16); TECHNOLOGY_COUNT - 3] = [
    (1, 5),
    (6, 10),
    (6, 10),
    (6, 10),
    (6, 10),
    (11, 15),
    (11, 15),
    (16, 20),
    (21, 25),
    (21, 25),
    (26, 30),
    (26, 30),
    (31, 35),
    (31, 35),
    (36, 40),
    (41, 45),
    (41, 45),
    (46, 50),
    (51, 55),
    (56, 60),
    (56, 60),
    (56, 60),
    (61, 65),
    (61, 65),
    (66, 70),
    (66, 70),
];

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnologyResearchStatus {
    #[default]
    NotStarted,
    Pending,
    Researched,
}

/// Global technology milestones and the city capabilities of every major nation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TechnologyState {
    pub advanced_iron_working: bool,
    pub marine_engineering: bool,
    pub scheduled_unlock_turn_by_technology: TechnologyTable<i16>,
    pub global_unlocks_by_technology: TechnologyTable<bool>,
    pub research_status_by_nation: MajorNationTable<TechnologyTable<TechnologyResearchStatus>>,
    pub industry_enabled_by_slot: [bool; 14],
    pub military_unit_ability_active_by_nation: MajorNationTable<MilitaryUnitTable<bool>>,
    pub city_capabilities_by_nation: MajorNationTable<CityTechnologyCapabilities>,
    /// Retail `TTechMgr::activeZoneIndex1d4`: the hull spawned by a navy-growth reward.
    pub navy_growth_ship_type: ShipType,
}

impl Default for TechnologyState {
    fn default() -> Self {
        Self {
            advanced_iron_working: false,
            marine_engineering: false,
            scheduled_unlock_turn_by_technology: TechnologyTable::from_array([0; TECHNOLOGY_COUNT]),
            global_unlocks_by_technology: TechnologyTable::from_array([
                true, true, true, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false,
            ]),
            research_status_by_nation: MajorNationTable::from_fn(|_| {
                let mut status = TechnologyTable::from_array(
                    [TechnologyResearchStatus::NotStarted; TECHNOLOGY_COUNT],
                );
                status[TechnologyId::new(0)] = TechnologyResearchStatus::Researched;
                status[TechnologyId::new(1)] = TechnologyResearchStatus::Researched;
                status[TechnologyId::new(2)] = TechnologyResearchStatus::Researched;
                status
            }),
            industry_enabled_by_slot: [
                true, true, true, true, true, false, false, false, false, false, false, false,
                false, false,
            ],
            military_unit_ability_active_by_nation: MajorNationTable::from_fn(|_| {
                MilitaryUnitTable::from_array([
                    true, true, true, true, true, true, true, true, false, false, false, false,
                    false, false, false, false, false, false, false, false, false, false, false,
                    false, true, false, false, true, false, false,
                ])
            }),
            city_capabilities_by_nation: MajorNationTable::default(),
            navy_growth_ship_type: ShipType::ShipOfTheLine,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CivilianTerrainAccess {
    pub hills: bool,
    pub mountain: bool,
    pub swamp: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FortLevelCap(i8);

impl FortLevelCap {
    pub const ONE: Self = Self(1);
    pub const TWO: Self = Self(2);
    pub const THREE: Self = Self(3);

    pub const fn get(self) -> i8 {
        self.0
    }
}

impl<'de> Deserialize<'de> for FortLevelCap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match i8::deserialize(deserializer)? {
            1 => Ok(Self::ONE),
            2 => Ok(Self::TWO),
            3 => Ok(Self::THREE),
            value => Err(serde::de::Error::custom(format!(
                "fort level cap {value} is outside 1..=3"
            ))),
        }
    }
}

impl Default for FortLevelCap {
    fn default() -> Self {
        Self::ONE
    }
}

impl TechnologyState {
    pub(crate) fn for_random_start(seed: u32) -> Self {
        let mut state = Self::default();
        let mut rng = RetailLcg::from_state(seed);
        for (offset, &(start_group, end_group)) in RANDOM_START_PRIORITY_RANGES.iter().enumerate() {
            let technology = TechnologyId::new(offset + 3);
            let range_start = start_group * 4;
            let range_span = (end_group - start_group) * 4 + 1;
            loop {
                let candidate = (rng.next_sample_15() % range_span as u32) as i16 + range_start;
                if !state.scheduled_unlock_turn_by_technology.as_array()[..technology.index()]
                    .contains(&candidate)
                {
                    state.scheduled_unlock_turn_by_technology[technology] = candidate;
                    break;
                }
            }
        }
        state
    }

    pub fn oil_drilling_available(&self) -> bool {
        self.global_unlocks_by_technology[TechnologyId::new(0x13)]
    }

    /// Selects the production-capacity term used by retail's naval-force score.
    pub const fn naval_production_capacity(
        &self,
        lumber_mill_capacity: i32,
        steel_mill_capacity: i32,
    ) -> i32 {
        if self.marine_engineering {
            steel_mill_capacity
        } else if self.advanced_iron_working {
            (lumber_mill_capacity + steel_mill_capacity) / 2
        } else {
            lumber_mill_capacity
        }
    }
}

impl GameState {
    /// Mirrors `TTechMgr::CheckForAdvances`.
    pub fn check_technology_advances(&mut self) {
        let economic_turn = self.turn.economic_turn;
        for tech_id in TechnologyId::all().skip(3) {
            if !self.technology.global_unlocks_by_technology[tech_id] {
                if i32::from(self.technology.scheduled_unlock_turn_by_technology[tech_id])
                    == economic_turn
                {
                    apply_city_order_capability_unlock(&mut self.technology, tech_id);
                    self.pending
                        .queue_newspaper_event(PendingNewspaperEvent::Miscellaneous {
                            audience: None,
                            story_code: tech_id.index() as i32,
                        });
                }
                continue;
            }

            for nation in MajorNationId::all() {
                if !self.nation_slot_eligible_for_event_processing(nation) {
                    continue;
                }
                if self.nations.major(nation).economy.diplomacy_eligible {
                    continue;
                }
                if self.technology.research_status_by_nation[nation][tech_id]
                    == TechnologyResearchStatus::Researched
                {
                    continue;
                }
                self.nations.major_mut(nation).common.treasury -= TECH_ITEM_PURCHASE_COST[tech_id];
                self.technology.research_status_by_nation[nation][tech_id] =
                    TechnologyResearchStatus::Pending;
                // FIXME: retail also stamps `capRowsE4a6.completionYearOffsetByTechId`
                // to `economicTurn / 4`. That field is not in the semantic model.
            }
        }
    }

    pub fn first_pending_technology_unlock(&self, nation: NationId) -> Option<TechnologyId> {
        let nation = MajorNationId::from_nation(nation)?;
        TechnologyId::all().find(|&tech_id| {
            self.technology.research_status_by_nation[nation][tech_id]
                == TechnologyResearchStatus::Pending
        })
    }

    /// Mirrors `TTechMgr::ConsumeFirstPendingAbilityUnlock` for one nation.
    pub fn acknowledge_technology_unlock(&mut self, nation: MajorNationId) -> Option<TechnologyId> {
        let tech_id = self.first_pending_technology_unlock(nation.nation())?;
        self.apply_ability_unlock(tech_id, nation);
        Some(tech_id)
    }

    pub(crate) fn apply_technology_advances_phase(&mut self) {
        self.check_technology_advances();
        // FIXME: retail ORs `turnFlowStatusFlags` with `0x40` when `marker262` is
        // unchanged (map toolbar new-tech chrome). `marker262` is not modeled.
        self.consume_non_interactive_technology_unlocks();
    }

    pub(crate) fn consume_interactive_technology_unlock(&mut self) -> Option<TechnologyId> {
        let nation = MajorNationId::from_nation(self.turn.active_nation)?;
        if self.nations.major(nation).economy.diplomacy_eligible
            && self.nation_slot_eligible_for_event_processing(nation)
        {
            self.acknowledge_technology_unlock(nation)
        } else {
            None
        }
    }

    pub(crate) fn consume_non_interactive_technology_unlocks(&mut self) {
        let active = MajorNationId::from_nation(self.turn.active_nation);
        for nation in MajorNationId::all() {
            // FIXME: retail skips the drain when the slot is active, cooldown < 1, and
            // terrain-eligible — not when diplomacyEligibilityA0 is set.
            let interactive = active == Some(nation)
                && self.nations.major(nation).economy.diplomacy_eligible
                && self.nation_slot_eligible_for_event_processing(nation);
            if interactive {
                continue;
            }
            while self.acknowledge_technology_unlock(nation).is_some() {}
        }
    }

    fn nation_slot_eligible_for_event_processing(&self, nation: MajorNationId) -> bool {
        !matches!(
            self.nations.major(nation).common.status(),
            CountryStatus::ProtectorateOf(_)
        )
    }

    fn apply_ability_unlock(&mut self, tech_id: TechnologyId, nation: MajorNationId) {
        // FIXME: `HandleAbilityUnlock` also upgrades developed-tile civilian class,
        // navy/score `UpdateSelectionAndRecalculateScores`, unit-order cost profiles,
        // and `TMilitaryUnit::Upgrade()`. First turn usually has nothing Pending.
        if self.technology.research_status_by_nation[nation][tech_id]
            == TechnologyResearchStatus::Researched
        {
            return;
        }
        self.technology.research_status_by_nation[nation][tech_id] =
            TechnologyResearchStatus::Researched;

        let difficulty = self.turn.difficulty as u8;
        let era_offset =
            if difficulty >= 3 && !self.nations.major(nation).economy.diplomacy_eligible {
                i16::from(difficulty) - 2
            } else {
                0
            };

        match tech_id.index() {
            3 => self.set_requirement_level(nation, ResourceKind::Cotton, 1),
            2 => self.set_requirement_level(nation, ResourceKind::Grain, 1),
            5 => {
                self.set_requirement_level(nation, ResourceKind::Coal, 2);
                self.set_requirement_level(nation, ResourceKind::Iron, 2);
                self.set_requirement_level(nation, ResourceKind::Gold, 2);
                self.set_requirement_level(nation, ResourceKind::Gems, 2);
            }
            6 => {
                self.set_requirement_level(nation, ResourceKind::Timber, 1);
                self.set_university_available(nation, CivilianUnitKind::Forester, true);
            }
            0xa => {
                self.set_requirement_level(nation, ResourceKind::Fruit, 2);
                self.set_requirement_level(nation, ResourceKind::Grain, 2);
            }
            7 => {
                self.set_requirement_level(nation, ResourceKind::Livestock, 1);
                self.set_requirement_level(nation, ResourceKind::Wool, 1);
                self.set_university_available(nation, CivilianUnitKind::Rancher, true);
            }
            8 => {
                self.set_requirement_level(nation, ResourceKind::Cotton, 2);
                self.set_requirement_level(nation, ResourceKind::Wool, 2);
            }
            0xc => self.set_requirement_level(nation, ResourceKind::Timber, 2),
            0x11 => self.set_requirement_level(nation, ResourceKind::Grain, 3),
            0x12 => self.set_requirement_level(nation, ResourceKind::Fruit, 3),
            0x14 => self.set_requirement_level(nation, ResourceKind::Livestock, 2),
            0xb => {
                self.activate_military_ability(nation, MilitaryUnitKind::Scouts);
                self.activate_military_ability(nation, MilitaryUnitKind::Sharpshooters);
                self.activate_military_ability(nation, MilitaryUnitKind::CombatEngineers);
                self.activate_military_ability(nation, MilitaryUnitKind::GeneralEra2);
            }
            0x10 => {
                self.set_requirement_level(nation, ResourceKind::Cotton, 3);
                self.set_requirement_level(nation, ResourceKind::Wool, 3);
            }
            0xd => {
                self.activate_military_ability(nation, MilitaryUnitKind::FieldArtillery);
                self.activate_military_ability(nation, MilitaryUnitKind::SiegeArtillery);
                self.add_era_arms(nation, era_offset, 10);
            }
            0x17 => {
                self.set_requirement_level(nation, ResourceKind::Coal, 3);
                self.set_requirement_level(nation, ResourceKind::Iron, 3);
                self.set_requirement_level(nation, ResourceKind::Gold, 3);
                self.set_requirement_level(nation, ResourceKind::Gems, 3);
                self.set_requirement_level(nation, ResourceKind::Timber, 3);
                self.activate_military_ability(nation, MilitaryUnitKind::Saboteurs);
            }
            0x13 => {
                self.set_requirement_level(nation, ResourceKind::Oil, 1);
                self.set_university_available(nation, CivilianUnitKind::Driller, true);
            }
            0xe => {
                self.activate_military_ability(nation, MilitaryUnitKind::Militia);
                self.activate_military_ability(nation, MilitaryUnitKind::CarbineCavalry);
                self.activate_military_ability(nation, MilitaryUnitKind::RifleInfantry);
                self.activate_military_ability(nation, MilitaryUnitKind::Guards);
                self.add_era_arms(nation, era_offset, 10);
            }
            0x1a => {
                self.set_requirement_level(nation, ResourceKind::Oil, 2);
                self.set_requirement_level(nation, ResourceKind::Livestock, 3);
            }
            0x16 => {
                self.activate_military_ability(nation, MilitaryUnitKind::MobileArtillery);
                self.activate_military_ability(nation, MilitaryUnitKind::RailroadGuns);
                self.add_era_arms(nation, era_offset, 20);
            }
            0x1c => {
                self.set_requirement_level(nation, ResourceKind::Oil, 3);
                self.activate_military_ability(nation, MilitaryUnitKind::MechanizedInfantry);
                self.activate_military_ability(nation, MilitaryUnitKind::Armor);
            }
            0x19 => {
                self.activate_military_ability(nation, MilitaryUnitKind::Conscripts);
                self.activate_military_ability(nation, MilitaryUnitKind::Rangers);
                self.activate_military_ability(nation, MilitaryUnitKind::Infantry);
                self.activate_military_ability(nation, MilitaryUnitKind::MachineGunners);
                self.activate_military_ability(nation, MilitaryUnitKind::GeneralEra3);
                self.add_era_arms(nation, era_offset, 20);
            }
            _ => {}
        }
        sync_city_capabilities_from_research(&mut self.technology, nation);
    }

    fn set_requirement_level(&mut self, nation: MajorNationId, resource: ResourceKind, level: u8) {
        self.technology.city_capabilities_by_nation[nation]
            .university
            .requirement_levels[resource] = level;
    }

    fn set_university_available(
        &mut self,
        nation: MajorNationId,
        kind: CivilianUnitKind,
        available: bool,
    ) {
        self.technology.city_capabilities_by_nation[nation]
            .university
            .available[kind] = available;
    }

    fn activate_military_ability(&mut self, nation: MajorNationId, kind: MilitaryUnitKind) {
        self.technology.military_unit_ability_active_by_nation[nation][kind] = true;
    }

    fn add_era_arms(&mut self, nation: MajorNationId, era_offset: i16, scale: i16) {
        if era_offset == 0 {
            return;
        }
        self.nations
            .city_mut(nation)
            .stockpile
            .wrapping_add_and_verify(ResourceKind::Arms, era_offset * scale);
    }
}

fn apply_city_order_capability_unlock(technology: &mut TechnologyState, tech_id: TechnologyId) {
    // FIXME: retail also writes `marker262`, `techSelectorShort1d2`, and
    // `activePrerequisitePair264` (techs 0xb / 0x16).
    technology.global_unlocks_by_technology[tech_id] = true;
    match tech_id.index() {
        9 => {
            technology.industry_enabled_by_slot[7] = true;
            technology.industry_enabled_by_slot[5] = true;
        }
        4 => technology.industry_enabled_by_slot[6] = true,
        0xf => {
            technology.industry_enabled_by_slot[8] = true;
            technology.advanced_iron_working = true;
            technology.navy_growth_ship_type = ShipType::Ironclad;
        }
        0x15 => {
            technology.industry_enabled_by_slot[9] = true;
            technology.navy_growth_ship_type = ShipType::AdvancedIronclad;
        }
        0x18 => {
            technology.industry_enabled_by_slot[0xb] = true;
            technology.industry_enabled_by_slot[0xa] = true;
            technology.marine_engineering = true;
        }
        0x1b => {
            technology.industry_enabled_by_slot[0xc] = true;
            technology.industry_enabled_by_slot[0xd] = true;
            technology.navy_growth_ship_type = ShipType::Dreadnought;
        }
        _ => {}
    }
}

fn sync_city_capabilities_from_research(technology: &mut TechnologyState, nation: MajorNationId) {
    let status = technology.research_status_by_nation[nation];
    let researched =
        |tech_id: usize| status[TechnologyId::new(tech_id)] == TechnologyResearchStatus::Researched;
    let started =
        |tech_id: usize| status[TechnologyId::new(tech_id)] != TechnologyResearchStatus::NotStarted;
    let capabilities = &mut technology.city_capabilities_by_nation[nation];
    capabilities.advanced_iron_working = researched(0x0f);
    capabilities.oil_drilling = researched(0x13);
    capabilities.primary_civilian_distance_terrain = CivilianTerrainAccess {
        hills: researched(12),
        swamp: researched(6),
        mountain: researched(23),
    };
    capabilities.secondary_civilian_hills = researched(11);
    capabilities.secondary_civilian_swamp = researched(5);
    capabilities.fort_level_cap = if started(0x16) {
        FortLevelCap::THREE
    } else if started(0x0b) {
        FortLevelCap::TWO
    } else {
        FortLevelCap::ONE
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_start_schedule_matches_the_native_seed_one_table() {
        assert_eq!(
            TechnologyState::for_random_start(1).scheduled_unlock_turn_by_technology,
            TechnologyTable::from_array([
                0, 0, 0, 19, 40, 38, 34, 28, 48, 47, 68, 99, 89, 114, 115, 140, 136, 155, 164, 169,
                192, 210, 228, 237, 240, 252, 249, 273, 279,
            ]),
        );
    }

    #[test]
    fn naval_production_capacity_follows_the_technology_priority_order() {
        for (advanced_iron_working, marine_engineering, expected) in [
            (false, false, 7),
            (true, false, 5),
            (false, true, 4),
            (true, true, 4),
        ] {
            let technology = TechnologyState {
                advanced_iron_working,
                marine_engineering,
                ..Default::default()
            };
            assert_eq!(technology.naval_production_capacity(7, 4), expected);
        }
    }

    #[test]
    fn check_for_advances_unlocks_a_scheduled_technology_and_queues_news() {
        let mut state = crate::test_support::game_state();
        state.technology.scheduled_unlock_turn_by_technology[TechnologyId::new(4)] = 1;
        state.check_technology_advances();

        assert!(state.technology.global_unlocks_by_technology[TechnologyId::new(4)]);
        assert!(state.technology.industry_enabled_by_slot[6]);
        assert_eq!(
            state.pending.newspaper_events,
            [PendingNewspaperEvent::Miscellaneous {
                audience: None,
                story_code: 4,
            }]
        );
    }

    #[test]
    fn check_for_advances_charges_ai_nations_for_already_unlocked_technology() {
        let mut state = crate::test_support::game_state();
        let ai = MajorNationId::new(1);
        state.nations.major_mut(ai).economy.controller = MajorNationController::Computer;
        state.nations.major_mut(ai).economy.diplomacy_eligible = false;
        state.nations.major_mut(ai).common.treasury = 50_000;
        state.technology.global_unlocks_by_technology[TechnologyId::new(3)] = true;
        state.check_technology_advances();

        assert_eq!(state.nations.major(ai).common.treasury, 49_000);
        assert_eq!(
            state.technology.research_status_by_nation[ai][TechnologyId::new(3)],
            TechnologyResearchStatus::Pending
        );
        assert_eq!(
            state.technology.research_status_by_nation[MajorNationId::new(0)][TechnologyId::new(3)],
            TechnologyResearchStatus::NotStarted
        );
    }

    #[test]
    fn ironclad_unlock_advances_the_navy_growth_hull() {
        let mut state = crate::test_support::game_state();
        state.technology.scheduled_unlock_turn_by_technology[TechnologyId::new(0xf)] = 1;
        state.check_technology_advances();
        assert_eq!(state.technology.navy_growth_ship_type, ShipType::Ironclad);
    }
}
