use crate::*;
use enum_map::Enum;
use serde::{Deserialize, Deserializer, Serialize};

const TECH_ITEM_PURCHASE_COST: [i32; TECHNOLOGY_COUNT] = [
    0, 0, 1000, 1000, 1500, 1500, 1500, 1500, 3000, 3000, 3000, 6000, 7000, 10000, 12000, 12000,
    12000, 12000, 12000, 25000, 20000, 40000, 40000, 40000, 40000, 100000, 120000, 150000, 150000,
];

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
pub struct TechnologyId(u8);

impl TechnologyId {
    pub const COUNT: u8 = TECHNOLOGY_COUNT as u8;

    pub const fn new(value: u8) -> Self {
        assert!(value < Self::COUNT, "technology ID is out of range");
        Self(value)
    }

    pub const fn try_new(value: u8) -> Option<Self> {
        if value < Self::COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

impl<'de> Deserialize<'de> for TechnologyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::try_new(value).ok_or_else(|| {
            serde::de::Error::custom(format_args!(
                "technology ID {value} is out of range 0..={}",
                Self::COUNT - 1
            ))
        })
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
    pub scheduled_unlock_turn_by_technology: [i16; TECHNOLOGY_COUNT],
    pub global_unlocks_by_technology: [bool; TECHNOLOGY_COUNT],
    pub research_status_by_nation: MajorNationTable<[TechnologyResearchStatus; TECHNOLOGY_COUNT]>,
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
            scheduled_unlock_turn_by_technology: [0; TECHNOLOGY_COUNT],
            global_unlocks_by_technology: [
                true, true, true, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false,
            ],
            research_status_by_nation: MajorNationTable::from_fn(|_| {
                let mut status = [TechnologyResearchStatus::NotStarted; TECHNOLOGY_COUNT];
                status[0] = TechnologyResearchStatus::Researched;
                status[1] = TechnologyResearchStatus::Researched;
                status[2] = TechnologyResearchStatus::Researched;
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
            let technology = offset + 3;
            let range_start = start_group * 4;
            let range_span = (end_group - start_group) * 4 + 1;
            loop {
                let candidate = (rng.next_sample_15() % range_span as u32) as i16 + range_start;
                if !state.scheduled_unlock_turn_by_technology[..technology].contains(&candidate) {
                    state.scheduled_unlock_turn_by_technology[technology] = candidate;
                    break;
                }
            }
        }
        state
    }

    pub const fn oil_drilling_available(&self) -> bool {
        self.global_unlocks_by_technology[0x13]
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
    #[allow(clippy::needless_range_loop)]
    pub fn check_technology_advances(&mut self) {
        let economic_turn = self.turn.economic_turn;
        for tech_id in 3..TECHNOLOGY_COUNT {
            if !self.technology.global_unlocks_by_technology[tech_id] {
                if i32::from(self.technology.scheduled_unlock_turn_by_technology[tech_id])
                    == economic_turn
                {
                    apply_city_order_capability_unlock(&mut self.technology, tech_id);
                    self.pending
                        .queue_newspaper_event(PendingNewspaperEvent::Miscellaneous {
                            audience: None,
                            story_code: tech_id as i32,
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
        self.technology.research_status_by_nation[nation]
            .iter()
            .position(|status| *status == TechnologyResearchStatus::Pending)
            .map(|tech_id| TechnologyId::new(tech_id as u8))
    }

    /// Mirrors `TTechMgr::ConsumeFirstPendingAbilityUnlock` for one nation.
    pub fn acknowledge_technology_unlock(&mut self, nation: MajorNationId) -> Option<TechnologyId> {
        let tech_id = self.first_pending_technology_unlock(nation.nation())?;
        self.apply_ability_unlock(tech_id.index(), nation);
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

    fn apply_ability_unlock(&mut self, tech_id: usize, nation: MajorNationId) {
        // FIXME: `HandleAbilityUnlock` also performs navy/score
        // `UpdateSelectionAndRecalculateScores`, unit-order cost-profile changes,
        // and `TMilitaryUnit::Upgrade()` for the corresponding technologies.
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

        match tech_id {
            3 => self.set_requirement_level(nation, 0, 1),
            2 => self.set_requirement_level(nation, 0x11, 1),
            5 => {
                self.set_requirement_level(nation, 3, 2);
                self.set_requirement_level(nation, 4, 2);
                self.set_requirement_level(nation, 0x16, 2);
                self.set_requirement_level(nation, 0x15, 2);
            }
            6 => {
                self.set_requirement_level(nation, 2, 1);
                self.set_university_available(nation, 3, true);
            }
            0xa => {
                self.set_requirement_level(nation, 0x12, 2);
                self.set_requirement_level(nation, 0x11, 2);
            }
            7 => {
                self.set_requirement_level(nation, 0x14, 1);
                self.set_requirement_level(nation, 1, 1);
                self.set_university_available(nation, 5, true);
            }
            8 => {
                self.set_requirement_level(nation, 0, 2);
                self.set_requirement_level(nation, 1, 2);
            }
            0xc => self.set_requirement_level(nation, 2, 2),
            0x11 => self.set_requirement_level(nation, 0x11, 3),
            0x12 => self.set_requirement_level(nation, 0x12, 3),
            0x14 => self.set_requirement_level(nation, 0x14, 2),
            0xb => {
                self.activate_military_ability(nation, 0xc);
                self.activate_military_ability(nation, 9);
                self.activate_military_ability(nation, 0x19);
                self.activate_military_ability(nation, 0x1c);
            }
            0x10 => {
                self.set_requirement_level(nation, 0, 3);
                self.set_requirement_level(nation, 1, 3);
            }
            0xd => {
                self.activate_military_ability(nation, 0xe);
                self.activate_military_ability(nation, 0xf);
                self.add_era_arms(nation, era_offset, 10);
            }
            0x17 => {
                self.set_requirement_level(nation, 3, 3);
                self.set_requirement_level(nation, 4, 3);
                self.set_requirement_level(nation, 0x16, 3);
                self.set_requirement_level(nation, 0x15, 3);
                self.set_requirement_level(nation, 2, 3);
                self.activate_military_ability(nation, 0x1a);
            }
            0x13 => {
                self.set_requirement_level(nation, 6, 1);
                self.set_university_available(nation, 8, true);
            }
            0xe => {
                self.activate_military_ability(nation, 8);
                self.activate_military_ability(nation, 0xd);
                self.activate_military_ability(nation, 0xa);
                self.activate_military_ability(nation, 0xb);
                self.add_era_arms(nation, era_offset, 10);
            }
            0x1a => {
                self.set_requirement_level(nation, 6, 2);
                self.set_requirement_level(nation, 0x14, 3);
            }
            0x16 => {
                self.activate_military_ability(nation, 0x16);
                self.activate_military_ability(nation, 0x17);
                self.add_era_arms(nation, era_offset, 20);
            }
            0x1c => {
                self.set_requirement_level(nation, 6, 3);
                self.activate_military_ability(nation, 0x14);
                self.activate_military_ability(nation, 0x15);
            }
            0x19 => {
                self.activate_military_ability(nation, 0x10);
                self.activate_military_ability(nation, 0x11);
                self.activate_military_ability(nation, 0x12);
                self.activate_military_ability(nation, 0x13);
                self.activate_military_ability(nation, 0x1d);
                self.add_era_arms(nation, era_offset, 20);
            }
            _ => {}
        }
        self.upgrade_owned_surface_development(nation);
        sync_city_capabilities_from_research(&mut self.technology, nation);
    }

    fn upgrade_owned_surface_development(&mut self, nation: MajorNationId) {
        let requirements = self.technology.city_capabilities_by_nation[nation]
            .university
            .requirement_levels;
        let owner = TileOwnerTag::from_nation(nation.nation());
        for tile in self.map.tiles.iter_mut() {
            if tile.owner_nation != Some(owner) || !tile.flags.contains(TileFlags::BASE_TRANSPORT) {
                continue;
            }
            let level = tile
                .edge_resources
                .into_iter()
                .flatten()
                .filter(|resource| !crate::ai_civilian::extractive_resource(*resource))
                .map(|resource| requirements[resource])
                .max()
                .unwrap_or(0);
            if tile.development.surface.get() < level {
                tile.development.surface = DevelopmentLevel::new(level);
            }
        }
    }

    fn set_requirement_level(&mut self, nation: MajorNationId, resource: usize, level: u8) {
        let resource = ResourceKind::from_index(resource as u8)
            .expect("technology unlock uses a retail resource index");
        self.technology.city_capabilities_by_nation[nation]
            .university
            .requirement_levels[resource] = level;
    }

    fn set_university_available(&mut self, nation: MajorNationId, kind: usize, available: bool) {
        let kind = CivilianUnitKind::from_usize(kind);
        self.technology.city_capabilities_by_nation[nation]
            .university
            .available[kind] = available;
    }

    fn activate_military_ability(&mut self, nation: MajorNationId, ability: usize) {
        let kind = MilitaryUnitKind::from_usize(ability);
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

fn apply_city_order_capability_unlock(technology: &mut TechnologyState, tech_id: usize) {
    // FIXME: retail also writes `marker262`, `techSelectorShort1d2`, and
    // `activePrerequisitePair264` (techs 0xb / 0x16).
    technology.global_unlocks_by_technology[tech_id] = true;
    match tech_id {
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
    let researched = |tech_id: usize| status[tech_id] == TechnologyResearchStatus::Researched;
    let started = |tech_id: usize| status[tech_id] != TechnologyResearchStatus::NotStarted;
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
            [
                0, 0, 0, 19, 40, 38, 34, 28, 48, 47, 68, 99, 89, 114, 115, 140, 136, 155, 164, 169,
                192, 210, 228, 237, 240, 252, 249, 273, 279,
            ]
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
        state.technology.scheduled_unlock_turn_by_technology[4] = 1;
        state.check_technology_advances();

        assert!(state.technology.global_unlocks_by_technology[4]);
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
        state.technology.global_unlocks_by_technology[3] = true;
        state.check_technology_advances();

        assert_eq!(state.nations.major(ai).common.treasury, 49_000);
        assert_eq!(
            state.technology.research_status_by_nation[ai][3],
            TechnologyResearchStatus::Pending
        );
        assert_eq!(
            state.technology.research_status_by_nation[MajorNationId::new(0)][3],
            TechnologyResearchStatus::NotStarted
        );
    }

    #[test]
    fn ironclad_unlock_advances_the_navy_growth_hull() {
        let mut state = crate::test_support::game_state();
        state.technology.scheduled_unlock_turn_by_technology[0xf] = 1;
        state.check_technology_advances();
        assert_eq!(state.technology.navy_growth_ship_type, ShipType::Ironclad);
    }
}
