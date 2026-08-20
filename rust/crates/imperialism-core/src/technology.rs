use crate::*;
use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const TECH_ITEM_PURCHASE_COST: TechnologyTable<i32> = TechnologyTable::from_array([
    0, 0, 1000, 1000, 1500, 1500, 1500, 1500, 3000, 3000, 3000, 6000, 7000, 10000, 12000, 12000,
    12000, 12000, 12000, 25000, 20000, 40000, 40000, 40000, 40000, 100000, 120000, 150000, 150000,
]);
const TECH_ITEM_PREREQUISITES: TechnologyTable<(u8, u8)> = TechnologyTable::from_array([
    (0, 0),
    (0, 0),
    (0, 0),
    (0, 0),
    (0, 0),
    (1, 0),
    (1, 0),
    (0, 0),
    (7, 3),
    (0, 0),
    (2, 0),
    (0, 0),
    (6, 0),
    (0, 0),
    (11, 0),
    (0, 0),
    (8, 0),
    (10, 0),
    (10, 0),
    (0, 0),
    (7, 0),
    (15, 0),
    (13, 0),
    (5, 12),
    (9, 10),
    (14, 0),
    (19, 0),
    (24, 0),
    (26, 0),
]);

/// Per-nation University capability state used by city production and recruitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct UniversityTechnologyState {
    pub available: CivilianUnitTable<bool>,
    /// Highest unlocked requirement column (0..=3) for each resource.
    pub requirement_levels: ResourceTable<UniversityRequirementLevel>,
}

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Enum, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum UniversityRequirementLevel {
    #[default]
    None,
    One,
    Two,
    Three,
}

impl UniversityRequirementLevel {
    pub const fn from_retail(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::One),
            2 => Some(Self::Two),
            3 => Some(Self::Three),
            _ => None,
        }
    }

    pub const fn retail(self) -> u8 {
        match self {
            Self::None => 0,
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
        }
    }
}

impl<'de> Deserialize<'de> for UniversityTechnologyState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedUniversityTechnologyState {
            available: CivilianUnitTable<bool>,
            requirement_levels: ResourceTable<UniversityRequirementLevel>,
        }

        let serialized = SerializedUniversityTechnologyState::deserialize(deserializer)?;
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
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::One,
                UniversityRequirementLevel::One,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::One,
                UniversityRequirementLevel::One,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::None,
                UniversityRequirementLevel::One,
                UniversityRequirementLevel::One,
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
            fort_level_cap: FortLevelCap::One,
        }
    }
}

/// The 29 retail technology slots. Numeric discriminants match save/oracle IDs;
/// string group `0x2712` uses the same order via `GetString` (offset + 1).
#[derive(
    Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum Technology {
    ScientistsHaveDiscovered = 0,
    HighPressureSteamEngine = 1,
    SeedDrill = 2,
    CottonGin = 3,
    StreamlinedHulls = 4,
    SquareSetTimbering = 5,
    IronRailroadBridge = 6,
    FeedGrasses = 7,
    SpinningJenny = 8,
    Paddlewheels = 9,
    SteelPlows = 10,
    BessemerConverter = 11,
    CompoundSteamEngine = 12,
    RifledArtillery = 13,
    BreechLoadingRifles = 14,
    AdvancedIronWorking = 15,
    PowerLoom = 16,
    MechanicalReaper = 17,
    CommercialFertilizer = 18,
    OilDrilling = 19,
    BarbedWire = 20,
    SteelArmorPlate = 21,
    LargeArtillery = 22,
    Dynamite = 23,
    MarineEngineering = 24,
    MachineGuns = 25,
    Chemistry = 26,
    ImprovedRangeFinding = 27,
    InternalCombustion = 28,
}

impl Technology {
    pub const LENGTH: usize = enum_map::enum_len::<Self>();

    pub const fn retail(self) -> u8 {
        match self {
            Self::ScientistsHaveDiscovered => 0,
            Self::HighPressureSteamEngine => 1,
            Self::SeedDrill => 2,
            Self::CottonGin => 3,
            Self::StreamlinedHulls => 4,
            Self::SquareSetTimbering => 5,
            Self::IronRailroadBridge => 6,
            Self::FeedGrasses => 7,
            Self::SpinningJenny => 8,
            Self::Paddlewheels => 9,
            Self::SteelPlows => 10,
            Self::BessemerConverter => 11,
            Self::CompoundSteamEngine => 12,
            Self::RifledArtillery => 13,
            Self::BreechLoadingRifles => 14,
            Self::AdvancedIronWorking => 15,
            Self::PowerLoom => 16,
            Self::MechanicalReaper => 17,
            Self::CommercialFertilizer => 18,
            Self::OilDrilling => 19,
            Self::BarbedWire => 20,
            Self::SteelArmorPlate => 21,
            Self::LargeArtillery => 22,
            Self::Dynamite => 23,
            Self::MarineEngineering => 24,
            Self::MachineGuns => 25,
            Self::Chemistry => 26,
            Self::ImprovedRangeFinding => 27,
            Self::InternalCombustion => 28,
        }
    }

    pub fn from_index(index: u8) -> Option<Self> {
        (usize::from(index) < Self::LENGTH).then(|| Self::from_usize(usize::from(index)))
    }

    pub fn all() -> impl DoubleEndedIterator<Item = Self> + ExactSizeIterator {
        (0..Self::LENGTH).map(Self::from_usize)
    }
}

pub type TechnologyTable<T> = EnumMap<Technology, T>;

const RANDOM_START_PRIORITY_RANGES: [(i16, i16); Technology::LENGTH - 3] = [
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TechnologyResearchToggle {
    Purchased,
    Refunded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TechnologyResearchRejection {
    Locked,
    MissingPrerequisite,
    AlreadyResearched,
    InsufficientFunds,
}

/// Global technology milestones and the city capabilities of every major nation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TechnologyState {
    pub advanced_iron_working: bool,
    pub marine_engineering: bool,
    pub scheduled_unlock_turn_by_technology: TechnologyTable<i16>,
    pub global_unlocks_by_technology: TechnologyTable<bool>,
    /// Retail `marker262`, the most recently applied global capability unlock.
    pub latest_global_unlock: Technology,
    pub research_status_by_nation: MajorNationTable<TechnologyTable<TechnologyResearchStatus>>,
    /// Retail `capRowsE4a6.completionYearOffsetByTechId`, stamped when a nation
    /// receives the technology and consumed by technology-history presentation.
    pub completion_year_by_nation: MajorNationTable<TechnologyTable<i16>>,
    pub industry_enabled_by_slot: IndustryCapabilityTable<bool>,
    pub military_unit_ability_active_by_nation: MajorNationTable<MilitaryUnitTable<bool>>,
    /// Retail `TTechMgr::capRowsB333`: enabled ship resource types by nation.
    pub selected_ship_types_by_nation: MajorNationTable<ShipTypeTable<bool>>,
    /// Retail `TTechMgr::nationCapRows1e8`: the selected ability id in each
    /// tactical group. Generals are spawned by army-growth rewards.
    pub selected_capability_slots: MajorNationTable<ArmyCategoryTable<MilitaryUnitKind>>,
    pub city_capabilities_by_nation: MajorNationTable<CityTechnologyCapabilities>,
    /// Retail `TTechMgr::activeZoneIndex1d4`: the hull spawned by a navy-growth reward.
    pub navy_growth_ship_type: ShipType,
}

impl Default for TechnologyState {
    fn default() -> Self {
        Self {
            advanced_iron_working: false,
            marine_engineering: false,
            scheduled_unlock_turn_by_technology: TechnologyTable::from_array(
                [0; Technology::LENGTH],
            ),
            global_unlocks_by_technology: TechnologyTable::from_array([
                true, true, true, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false,
            ]),
            latest_global_unlock: Technology::SeedDrill,
            research_status_by_nation: MajorNationTable::from_fn(|_| {
                TechnologyTable::from_array(std::array::from_fn(|index| {
                    if index < 3 {
                        TechnologyResearchStatus::Researched
                    } else {
                        TechnologyResearchStatus::NotStarted
                    }
                }))
            }),
            completion_year_by_nation: MajorNationTable::default(),
            industry_enabled_by_slot: IndustryCapabilityTable::from_array([
                true, true, true, true, true, false, false, false, false, false, false, false,
                false, false,
            ]),
            military_unit_ability_active_by_nation: MajorNationTable::from_fn(|_| {
                MilitaryUnitTable::from_array([
                    true, true, true, true, true, true, true, true, false, false, false, false,
                    false, false, false, false, false, false, false, false, false, false, false,
                    false, true, false, false, true, false, false,
                ])
            }),
            selected_ship_types_by_nation: MajorNationTable::from_fn(|_| {
                ShipTypeTable::from_array([
                    true, true, true, true, true, false, false, false, false, false, false, false,
                    false, false,
                ])
            }),
            selected_capability_slots: MajorNationTable::from_fn(|_| {
                default_selected_capability_slots()
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(i8)]
pub enum FortLevelCap {
    #[default]
    One = 1,
    Two = 2,
    Three = 3,
}

impl FortLevelCap {
    pub const fn level(self) -> FortLevel {
        match self {
            Self::One => FortLevel::One,
            Self::Two => FortLevel::Two,
            Self::Three => FortLevel::Three,
        }
    }

    pub const fn get(self) -> i8 {
        self.level().retail()
    }
}

impl Serialize for FortLevelCap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i8(self.get())
    }
}

impl<'de> Deserialize<'de> for FortLevelCap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match i8::deserialize(deserializer)? {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            3 => Ok(Self::Three),
            value => Err(serde::de::Error::custom(format!(
                "fort level cap {value} is outside 1..=3"
            ))),
        }
    }
}

impl TechnologyState {
    pub(crate) fn for_random_start(seed: u32) -> Self {
        let mut state = Self::default();
        let mut rng = RetailLcg::from_state(seed);
        for (technology, (start_group, end_group)) in
            Technology::all().skip(3).zip(RANDOM_START_PRIORITY_RANGES)
        {
            let range_start = start_group * 4;
            let range_span = (end_group - start_group) * 4 + 1;
            loop {
                let candidate = (rng.next_sample_15() % range_span as u32) as i16 + range_start;
                if !Technology::all()
                    .take_while(|&prior| prior != technology)
                    .any(|prior| state.scheduled_unlock_turn_by_technology[prior] == candidate)
                {
                    state.scheduled_unlock_turn_by_technology[technology] = candidate;
                    break;
                }
            }
        }
        state
    }

    pub fn oil_drilling_available(&self) -> bool {
        self.global_unlocks_by_technology[Technology::OilDrilling]
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
    pub fn technology_purchase_cost(technology: Technology) -> i32 {
        TECH_ITEM_PURCHASE_COST[technology]
    }

    pub fn missing_technology_prerequisites(
        &self,
        nation: MajorNationId,
        technology: Technology,
    ) -> [Option<Technology>; 2] {
        let (primary, secondary) = TECH_ITEM_PREREQUISITES[technology];
        let mut missing = [None, None];
        for (output, id) in missing.iter_mut().zip([primary, secondary]) {
            let prerequisite = Technology::from_index(id).expect("retail prerequisite id");
            if self.technology.research_status_by_nation[nation][prerequisite]
                != TechnologyResearchStatus::Researched
            {
                *output = Some(prerequisite);
            }
        }
        missing
    }

    pub fn technology_prerequisites_completed(
        &self,
        nation: MajorNationId,
        technology: Technology,
    ) -> bool {
        self.missing_technology_prerequisites(nation, technology)
            .into_iter()
            .all(|prerequisite| prerequisite.is_none())
    }

    /// Mirrors `TTechItemView::DoEvent` and the paired `TTechMgr`
    /// purchase/refund operations used by the technology store.
    pub fn toggle_technology_research(
        &mut self,
        nation: MajorNationId,
        technology: Technology,
    ) -> Result<TechnologyResearchToggle, TechnologyResearchRejection> {
        if !self.technology.global_unlocks_by_technology[technology] {
            return Err(TechnologyResearchRejection::Locked);
        }
        match self.technology.research_status_by_nation[nation][technology] {
            TechnologyResearchStatus::Researched => {
                return Err(TechnologyResearchRejection::AlreadyResearched);
            }
            TechnologyResearchStatus::Pending => {
                self.nations.major_mut(nation).common.treasury +=
                    TECH_ITEM_PURCHASE_COST[technology];
                self.technology.research_status_by_nation[nation][technology] =
                    TechnologyResearchStatus::NotStarted;
                self.technology.completion_year_by_nation[nation][technology] = 0;
                return Ok(TechnologyResearchToggle::Refunded);
            }
            TechnologyResearchStatus::NotStarted => {}
        }
        if !self.technology_prerequisites_completed(nation, technology) {
            return Err(TechnologyResearchRejection::MissingPrerequisite);
        }
        let cost = TECH_ITEM_PURCHASE_COST[technology];
        let major = self.nations.major(nation);
        if cost
            > major
                .economy
                .available_diplomacy_budget(major.common.treasury)
        {
            return Err(TechnologyResearchRejection::InsufficientFunds);
        }
        self.nations.major_mut(nation).common.treasury -= cost;
        self.technology.research_status_by_nation[nation][technology] =
            TechnologyResearchStatus::Pending;
        self.technology.completion_year_by_nation[nation][technology] =
            (self.turn.economic_turn / 4) as i16;
        Ok(TechnologyResearchToggle::Purchased)
    }

    /// Mirrors `TTechMgr::CheckForAdvances`.
    pub fn check_technology_advances(&mut self) {
        let economic_turn = self.turn.economic_turn;
        for tech_id in Technology::all().skip(3) {
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
                self.technology.completion_year_by_nation[nation][tech_id] =
                    (economic_turn / 4) as i16;
            }
        }
    }

    pub fn first_pending_technology_unlock(&self, nation: NationId) -> Option<Technology> {
        let nation = MajorNationId::from_nation(nation)?;
        Technology::all().find(|&tech| {
            self.technology.research_status_by_nation[nation][tech]
                == TechnologyResearchStatus::Pending
        })
    }

    /// Mirrors `TTechMgr::ConsumeFirstPendingAbilityUnlock` for one nation.
    pub fn acknowledge_technology_unlock(&mut self, nation: MajorNationId) -> Option<Technology> {
        let tech_id = self.first_pending_technology_unlock(nation.nation())?;
        self.apply_ability_unlock(tech_id, nation);
        Some(tech_id)
    }

    pub(crate) fn apply_technology_advances_phase(&mut self) {
        let marker_before = self.technology.latest_global_unlock;
        self.check_technology_advances();
        if self.technology.latest_global_unlock == marker_before {
            self.turn.turn_flow_status_flags |= 0x40;
        }
        self.consume_non_interactive_technology_unlocks();
    }

    pub(crate) fn consume_interactive_technology_unlock(&mut self) -> Option<Technology> {
        let nation = MajorNationId::from_nation(self.turn.active_nation)?;
        if self.turn.turn_cooldown_defer_counter < 1
            && self.nation_slot_eligible_for_event_processing(nation)
        {
            self.turn.turn_cooldown_defer_counter = 0;
            self.acknowledge_technology_unlock(nation)
        } else {
            None
        }
    }

    pub(crate) fn consume_non_interactive_technology_unlocks(&mut self) {
        let active = MajorNationId::from_nation(self.turn.active_nation);
        for nation in MajorNationId::all() {
            let interactive = active == Some(nation)
                && self.turn.turn_cooldown_defer_counter < 1
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

    fn apply_ability_unlock(&mut self, tech_id: Technology, nation: MajorNationId) {
        if self.technology.research_status_by_nation[nation][tech_id]
            == TechnologyResearchStatus::Researched
        {
            return;
        }
        self.technology.research_status_by_nation[nation][tech_id] =
            TechnologyResearchStatus::Researched;

        let difficulty = self.turn.difficulty.retail();
        let era_offset =
            if difficulty >= 3 && !self.nations.major(nation).economy.diplomacy_eligible {
                i16::from(difficulty) - 2
            } else {
                0
            };

        match tech_id {
            Technology::StreamlinedHulls => {
                self.update_naval_capability(ShipType::Clipper, nation);
            }
            Technology::CottonGin => self.set_requirement_level(
                nation,
                ResourceKind::Cotton,
                UniversityRequirementLevel::One,
            ),
            Technology::SeedDrill => self.set_requirement_level(
                nation,
                ResourceKind::Grain,
                UniversityRequirementLevel::One,
            ),
            Technology::SquareSetTimbering => {
                self.set_requirement_level(
                    nation,
                    ResourceKind::Coal,
                    UniversityRequirementLevel::Two,
                );
                self.set_requirement_level(
                    nation,
                    ResourceKind::Iron,
                    UniversityRequirementLevel::Two,
                );
                self.set_requirement_level(
                    nation,
                    ResourceKind::Gold,
                    UniversityRequirementLevel::Two,
                );
                self.set_requirement_level(
                    nation,
                    ResourceKind::Gems,
                    UniversityRequirementLevel::Two,
                );
            }
            Technology::IronRailroadBridge => {
                self.set_requirement_level(
                    nation,
                    ResourceKind::Timber,
                    UniversityRequirementLevel::One,
                );
                self.set_university_available(nation, CivilianUnitKind::Forester, true);
            }
            Technology::SteelPlows => {
                self.set_requirement_level(
                    nation,
                    ResourceKind::Fruit,
                    UniversityRequirementLevel::Two,
                );
                self.set_requirement_level(
                    nation,
                    ResourceKind::Grain,
                    UniversityRequirementLevel::Two,
                );
            }
            Technology::FeedGrasses => {
                self.set_requirement_level(
                    nation,
                    ResourceKind::Livestock,
                    UniversityRequirementLevel::One,
                );
                self.set_requirement_level(
                    nation,
                    ResourceKind::Wool,
                    UniversityRequirementLevel::One,
                );
                self.set_university_available(nation, CivilianUnitKind::Rancher, true);
            }
            Technology::SpinningJenny => {
                self.set_requirement_level(
                    nation,
                    ResourceKind::Cotton,
                    UniversityRequirementLevel::Two,
                );
                self.set_requirement_level(
                    nation,
                    ResourceKind::Wool,
                    UniversityRequirementLevel::Two,
                );
            }
            Technology::Paddlewheels => {
                self.update_naval_capability(ShipType::Raider, nation);
                self.update_naval_capability(ShipType::Paddlewheeler, nation);
            }
            Technology::CompoundSteamEngine => self.set_requirement_level(
                nation,
                ResourceKind::Timber,
                UniversityRequirementLevel::Two,
            ),
            Technology::MechanicalReaper => self.set_requirement_level(
                nation,
                ResourceKind::Grain,
                UniversityRequirementLevel::Three,
            ),
            Technology::CommercialFertilizer => self.set_requirement_level(
                nation,
                ResourceKind::Fruit,
                UniversityRequirementLevel::Three,
            ),
            Technology::BarbedWire => self.set_requirement_level(
                nation,
                ResourceKind::Livestock,
                UniversityRequirementLevel::Two,
            ),
            Technology::BessemerConverter => {
                self.activate_military_ability(nation, MilitaryUnitKind::Scouts);
                self.activate_military_ability(nation, MilitaryUnitKind::Sharpshooters);
                self.activate_military_ability(nation, MilitaryUnitKind::CombatEngineers);
                self.activate_military_ability(nation, MilitaryUnitKind::GeneralEra2);
            }
            Technology::AdvancedIronWorking => {
                self.update_naval_capability(ShipType::Ironclad, nation);
            }
            Technology::PowerLoom => {
                self.set_requirement_level(
                    nation,
                    ResourceKind::Cotton,
                    UniversityRequirementLevel::Three,
                );
                self.set_requirement_level(
                    nation,
                    ResourceKind::Wool,
                    UniversityRequirementLevel::Three,
                );
            }
            Technology::RifledArtillery => {
                self.activate_military_ability(nation, MilitaryUnitKind::FieldArtillery);
                self.activate_military_ability(nation, MilitaryUnitKind::SiegeArtillery);
                self.add_era_arms(nation, era_offset, 10);
            }
            Technology::SteelArmorPlate => {
                self.update_naval_capability(ShipType::AdvancedIronclad, nation);
            }
            Technology::Dynamite => {
                self.set_requirement_level(
                    nation,
                    ResourceKind::Coal,
                    UniversityRequirementLevel::Three,
                );
                self.set_requirement_level(
                    nation,
                    ResourceKind::Iron,
                    UniversityRequirementLevel::Three,
                );
                self.set_requirement_level(
                    nation,
                    ResourceKind::Gold,
                    UniversityRequirementLevel::Three,
                );
                self.set_requirement_level(
                    nation,
                    ResourceKind::Gems,
                    UniversityRequirementLevel::Three,
                );
                self.set_requirement_level(
                    nation,
                    ResourceKind::Timber,
                    UniversityRequirementLevel::Three,
                );
                self.activate_military_ability(nation, MilitaryUnitKind::Saboteurs);
            }
            Technology::OilDrilling => {
                self.set_requirement_level(
                    nation,
                    ResourceKind::Oil,
                    UniversityRequirementLevel::One,
                );
                self.set_university_available(nation, CivilianUnitKind::Driller, true);
            }
            Technology::BreechLoadingRifles => {
                self.activate_military_ability(nation, MilitaryUnitKind::Militia);
                self.activate_military_ability(nation, MilitaryUnitKind::CarbineCavalry);
                self.activate_military_ability(nation, MilitaryUnitKind::RifleInfantry);
                self.activate_military_ability(nation, MilitaryUnitKind::Guards);
                self.add_era_arms(nation, era_offset, 10);
            }
            Technology::Chemistry => {
                self.set_requirement_level(
                    nation,
                    ResourceKind::Oil,
                    UniversityRequirementLevel::Two,
                );
                self.set_requirement_level(
                    nation,
                    ResourceKind::Livestock,
                    UniversityRequirementLevel::Three,
                );
            }
            Technology::LargeArtillery => {
                self.activate_military_ability(nation, MilitaryUnitKind::MobileArtillery);
                self.activate_military_ability(nation, MilitaryUnitKind::RailroadGuns);
                self.add_era_arms(nation, era_offset, 20);
            }
            Technology::MarineEngineering => {
                self.update_naval_capability(ShipType::ArmoredCruiser, nation);
                self.update_naval_capability(ShipType::Freighter, nation);
            }
            Technology::ImprovedRangeFinding => {
                self.update_naval_capability(ShipType::Dreadnought, nation);
                self.update_naval_capability(ShipType::Battlecruiser, nation);
            }
            Technology::InternalCombustion => {
                self.set_requirement_level(
                    nation,
                    ResourceKind::Oil,
                    UniversityRequirementLevel::Three,
                );
                self.activate_military_ability(nation, MilitaryUnitKind::MechanizedInfantry);
                self.activate_military_ability(nation, MilitaryUnitKind::Armor);
            }
            Technology::MachineGuns => {
                self.activate_military_ability(nation, MilitaryUnitKind::Conscripts);
                self.activate_military_ability(nation, MilitaryUnitKind::Rangers);
                self.activate_military_ability(nation, MilitaryUnitKind::Infantry);
                self.activate_military_ability(nation, MilitaryUnitKind::MachineGunners);
                self.activate_military_ability(nation, MilitaryUnitKind::GeneralEra3);
                self.add_era_arms(nation, era_offset, 20);
            }
            _ => {}
        }
        self.upgrade_owned_surface_development(nation);
        sync_city_capabilities_from_research(&mut self.technology, nation);
    }

    /// Retail `TTechMgr::UpdateSelectionAndRecalculateScores`.
    fn update_naval_capability(&mut self, ship_type: ShipType, nation: MajorNationId) {
        let group = crate::navy_orders::NAVY_DESCRIPTORS[ship_type].toolbar_class;
        for candidate in (0..ShipType::LENGTH).map(ShipType::from_usize) {
            if candidate != ship_type
                && crate::navy_orders::NAVY_DESCRIPTORS[candidate].toolbar_class == group
            {
                self.technology.selected_ship_types_by_nation[nation][candidate] = false;
            }
        }
        self.technology.selected_ship_types_by_nation[nation][ship_type] = true;

        const ORDER_SLOT_BY_SHIP_TYPE: [usize; ShipType::LENGTH] =
            [0, 0, 1, 4, 5, 2, 3, 6, 7, 7, 2, 6, 7, 6];
        let slot = ORDER_SLOT_BY_SHIP_TYPE[usize::from(ship_type.retail())];
        if slot >= 6 {
            let advanced = ShipOrderSlot::from_usize(slot);
            let advanced_type = self.nations.city(nation).orders.ships[advanced].ship_type;
            if advanced_type != ShipType::NoShip {
                let carried = ShipOrderSlot::from_usize(slot - 2);
                let displaced = self.nations.city(nation).orders.ships[carried].ship_type;
                self.technology.selected_ship_types_by_nation[nation][displaced] = false;
                self.nations.city_mut(nation).orders.ships[carried].ship_type = advanced_type;
            }
        } else if ship_type == ShipType::Freighter {
            let orders = &mut self.nations.city_mut(nation).orders.ships;
            orders[ShipOrderSlot::MerchantEarlyPrimary].ship_type = ShipType::Paddlewheeler;
            orders[ShipOrderSlot::MerchantEarlySecondary].ship_type = ShipType::Clipper;
            orders[ShipOrderSlot::MerchantAdvancedSecondary].ship_type = ShipType::NoShip;
        }
        self.nations.city_mut(nation).orders.ships[ShipOrderSlot::from_usize(slot)].ship_type =
            ship_type;

        let owner = nation.nation();
        let retired = self
            .ships_in_retail_order()
            .filter_map(|(id, ship)| {
                (ship.nation == owner
                    && !self.technology.selected_ship_types_by_nation[nation][ship.ship_type])
                    .then_some((id, ship.experience / 100))
            })
            .collect::<Vec<_>>();
        let score = retired
            .iter()
            .map(|(_, score)| i32::from(*score))
            .sum::<i32>();
        for (ship, _) in retired {
            self.retire_ship_and_reassign_admiral(ship);
        }

        let survivors = self
            .ships_in_retail_order()
            .filter_map(|(id, ship)| (ship.nation == owner).then_some(id))
            .collect::<Vec<_>>();
        if !survivors.is_empty() {
            let gain = (score / survivors.len() as i32) as i16;
            for ship in survivors {
                let experience = &mut self
                    .ship_mut(ship)
                    .expect("surviving ship exists")
                    .experience;
                *experience = experience.wrapping_add(gain).min(499);
            }
        }
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
                .unwrap_or(UniversityRequirementLevel::None);
            if tile.development.surface.get() < level.retail() {
                tile.development.surface = DevelopmentLevel::new(level.retail());
            }
        }
    }

    fn set_requirement_level(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
        level: UniversityRequirementLevel,
    ) {
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

    /// Retail `TTechMgr::ActivateSlotAndUpdateUI`.
    pub fn activate_slot_and_update_ui(&mut self, nation: MajorNationId, kind: MilitaryUnitKind) {
        self.activate_military_ability(nation, kind);
    }

    fn activate_military_ability(&mut self, nation: MajorNationId, kind: MilitaryUnitKind) {
        self.technology.military_unit_ability_active_by_nation[nation][kind] = true;
        let group = crate::military_phase::tactical_category(kind);
        self.technology.selected_capability_slots[nation][group] = kind;
        if let Some(category) = military_recruitment_category(group) {
            let previous =
                self.nations.city(nation).orders.military_recruitment[category].unit_kind;
            if previous != kind {
                self.technology.military_unit_ability_active_by_nation[nation][previous] = false;
            }
            self.nations.city_mut(nation).orders.military_recruitment[category].unit_kind = kind;
        } else if self.nation_is_eligible_for_optional_phase(nation.nation()) {
            self.upgrade_matching_category_units(nation, group);
        }
    }

    fn upgrade_matching_category_units(&mut self, nation: MajorNationId, group: ArmyUnitCategory) {
        let mut ids = Vec::new();
        for (&id, unit) in &self.military_units {
            if unit.nation() == nation.nation()
                && crate::military_phase::tactical_category(unit.unit_type()) == group
            {
                ids.push(id);
            }
        }
        for id in ids {
            self.upgrade_military_unit(nation, id);
        }
    }

    fn upgrade_military_unit(&mut self, nation: MajorNationId, id: MilitaryUnitId) -> bool {
        let Some(candidate) = self.upgrade_type(nation, self.military_units[&id].unit_type())
        else {
            return false;
        };
        let (arms_cost, cash_cost, fuel_cost) = upgrade_resource_costs(candidate);
        let city = self.nations.city(nation);
        if arms_cost > city.stockpile[ResourceKind::Arms] {
            return false;
        }
        if fuel_cost > city.stockpile[ResourceKind::Fuel] {
            return false;
        }
        let diplomacy_eligible = self.nations.majors[&nation].economy.diplomacy_eligible;
        let treasury = self.nations.majors[&nation].common.treasury;
        if diplomacy_eligible
            && i32::from(cash_cost)
                > self.nations.majors[&nation]
                    .economy
                    .available_diplomacy_budget(treasury)
        {
            return false;
        }
        self.nations
            .city_mut(nation)
            .stockpile
            .wrapping_add_and_verify(ResourceKind::Arms, -arms_cost);
        self.nations
            .city_mut(nation)
            .stockpile
            .wrapping_add_and_verify(ResourceKind::Fuel, -fuel_cost);
        self.nations.majors[&nation].common.treasury -= i32::from(cash_cost);
        self.military_units
            .get_mut(&id)
            .expect("upgraded unit remains present")
            .unit_type = candidate;
        true
    }

    pub(crate) fn upgrade_type(
        &self,
        nation: MajorNationId,
        unit_type: MilitaryUnitKind,
    ) -> Option<MilitaryUnitKind> {
        let candidate = unit_type.upgrade_successor()?;
        let active = &self.technology.military_unit_ability_active_by_nation[nation];
        if !active[candidate] && active[unit_type] {
            return None;
        }
        Some(candidate)
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

fn military_recruitment_category(group: ArmyUnitCategory) -> Option<MilitaryRecruitmentCategory> {
    match group {
        ArmyUnitCategory::LightInfantry => Some(MilitaryRecruitmentCategory::LightInfantry),
        ArmyUnitCategory::LineInfantry => Some(MilitaryRecruitmentCategory::RegularInfantry),
        ArmyUnitCategory::EliteInfantry => Some(MilitaryRecruitmentCategory::HeavyInfantry),
        ArmyUnitCategory::LightCavalry => Some(MilitaryRecruitmentCategory::LightCavalry),
        ArmyUnitCategory::HeavyCavalry => Some(MilitaryRecruitmentCategory::HeavyCavalry),
        ArmyUnitCategory::FieldArtillery => Some(MilitaryRecruitmentCategory::LightArtillery),
        ArmyUnitCategory::SiegeArtillery => Some(MilitaryRecruitmentCategory::HeavyArtillery),
        ArmyUnitCategory::Engineers => Some(MilitaryRecruitmentCategory::Demolitionist),
        ArmyUnitCategory::Garrison | ArmyUnitCategory::Generals => None,
    }
}

pub(crate) const fn default_selected_capability_slots() -> ArmyCategoryTable<MilitaryUnitKind> {
    ArmyCategoryTable::from_array([
        MilitaryUnitKind::Minutemen,
        MilitaryUnitKind::Skirmishers,
        MilitaryUnitKind::Regulars,
        MilitaryUnitKind::Grenadiers,
        MilitaryUnitKind::Hussars,
        MilitaryUnitKind::Cuirassiers,
        MilitaryUnitKind::LightArtillery,
        MilitaryUnitKind::Artillery,
        MilitaryUnitKind::Sappers,
        MilitaryUnitKind::GeneralEra1,
    ])
}

fn upgrade_resource_costs(kind: MilitaryUnitKind) -> (i16, i16, i16) {
    match military_recruitment_spec(kind) {
        Some(spec) => {
            let fuel = spec
                .secondary
                .filter(|cost| cost.resource == ResourceKind::Fuel)
                .map(|cost| cost.per_unit())
                .unwrap_or(0);
            (spec.primary.per_unit(), spec.cash_per_unit, fuel)
        }
        None => (0, 0, 0),
    }
}

fn apply_city_order_capability_unlock(technology: &mut TechnologyState, tech_id: Technology) {
    technology.latest_global_unlock = tech_id;
    technology.global_unlocks_by_technology[tech_id] = true;
    match tech_id {
        Technology::Paddlewheels => {
            technology.industry_enabled_by_slot[IndustryCapabilitySlot::Shipyard] = true;
            technology.industry_enabled_by_slot[IndustryCapabilitySlot::FurnitureFactory] = true;
        }
        Technology::StreamlinedHulls => {
            technology.industry_enabled_by_slot[IndustryCapabilitySlot::OilRefinery] = true
        }
        Technology::AdvancedIronWorking => {
            technology.industry_enabled_by_slot[IndustryCapabilitySlot::Armory] = true;
            technology.advanced_iron_working = true;
            technology.navy_growth_ship_type = ShipType::Ironclad;
        }
        Technology::SteelArmorPlate => {
            technology.industry_enabled_by_slot[IndustryCapabilitySlot::TradeSchool] = true;
            technology.navy_growth_ship_type = ShipType::AdvancedIronclad;
        }
        Technology::MarineEngineering => {
            technology.industry_enabled_by_slot[IndustryCapabilitySlot::PowerPlant] = true;
            technology.industry_enabled_by_slot[IndustryCapabilitySlot::University] = true;
            technology.marine_engineering = true;
        }
        Technology::ImprovedRangeFinding => {
            technology.industry_enabled_by_slot[IndustryCapabilitySlot::FoodProcessing] = true;
            technology.industry_enabled_by_slot[IndustryCapabilitySlot::Warehouse] = true;
            technology.navy_growth_ship_type = ShipType::Dreadnought;
        }
        _ => {}
    }
}

fn sync_city_capabilities_from_research(technology: &mut TechnologyState, nation: MajorNationId) {
    let status = &technology.research_status_by_nation[nation];
    let researched = |tech| status[tech] == TechnologyResearchStatus::Researched;
    let started = |tech| status[tech] != TechnologyResearchStatus::NotStarted;
    let capabilities = &mut technology.city_capabilities_by_nation[nation];
    capabilities.advanced_iron_working = researched(Technology::AdvancedIronWorking);
    capabilities.oil_drilling = researched(Technology::OilDrilling);
    capabilities.primary_civilian_distance_terrain = CivilianTerrainAccess {
        hills: researched(Technology::CompoundSteamEngine),
        swamp: researched(Technology::IronRailroadBridge),
        mountain: researched(Technology::Dynamite),
    };
    capabilities.secondary_civilian_hills = researched(Technology::BessemerConverter);
    capabilities.secondary_civilian_swamp = researched(Technology::SquareSetTimbering);
    capabilities.fort_level_cap = if started(Technology::LargeArtillery) {
        FortLevelCap::Three
    } else if started(Technology::BessemerConverter) {
        FortLevelCap::Two
    } else {
        FortLevelCap::One
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
            ])
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
        state.technology.scheduled_unlock_turn_by_technology[Technology::StreamlinedHulls] = 1;
        state.check_technology_advances();

        assert!(state.technology.global_unlocks_by_technology[Technology::StreamlinedHulls]);
        assert!(state.technology.industry_enabled_by_slot[IndustryCapabilitySlot::OilRefinery]);
        assert_eq!(
            state.pending.newspaper_events,
            [PendingNewspaperEvent::Miscellaneous {
                audience: None,
                story_code: Technology::StreamlinedHulls as i32,
            }]
        );
    }

    #[test]
    fn technology_phase_sets_status_bit_only_when_global_marker_is_unchanged() {
        let mut unchanged = crate::test_support::game_state();
        unchanged.apply_technology_advances_phase();
        assert_eq!(unchanged.turn.turn_flow_status_flags & 0x40, 0x40);

        let mut unlocked = crate::test_support::game_state();
        unlocked.turn.economic_turn = 12;
        unlocked.technology.scheduled_unlock_turn_by_technology[Technology::CottonGin] = 12;
        unlocked.apply_technology_advances_phase();
        assert_eq!(
            unlocked.technology.latest_global_unlock,
            Technology::CottonGin
        );
        assert_eq!(unlocked.turn.turn_flow_status_flags & 0x40, 0);
    }

    #[test]
    fn default_global_unlock_marker_matches_retail_initialization() {
        assert_eq!(
            TechnologyState::default().latest_global_unlock,
            Technology::SeedDrill
        );
    }

    #[test]
    fn technology_store_purchase_and_refund_are_inverse_operations() {
        let mut state = crate::test_support::game_state();
        let nation = MajorNationId::new(0);
        let technology = Technology::CottonGin;
        state.technology.global_unlocks_by_technology[technology] = true;
        state.nations.major_mut(nation).common.treasury = 10_000;
        state.turn.economic_turn = 8;

        assert_eq!(
            state.toggle_technology_research(nation, technology),
            Ok(TechnologyResearchToggle::Purchased)
        );
        assert_eq!(state.nations.major(nation).common.treasury, 9_000);
        assert_eq!(
            state.technology.research_status_by_nation[nation][technology],
            TechnologyResearchStatus::Pending
        );
        assert_eq!(
            state.technology.completion_year_by_nation[nation][technology],
            2
        );

        assert_eq!(
            state.toggle_technology_research(nation, technology),
            Ok(TechnologyResearchToggle::Refunded)
        );
        assert_eq!(state.nations.major(nation).common.treasury, 10_000);
        assert_eq!(
            state.technology.research_status_by_nation[nation][technology],
            TechnologyResearchStatus::NotStarted
        );
        assert_eq!(
            state.technology.completion_year_by_nation[nation][technology],
            0
        );
    }

    #[test]
    fn technology_store_rejects_an_unaffordable_purchase() {
        let mut state = crate::test_support::game_state();
        let nation = MajorNationId::new(0);
        let technology = Technology::CottonGin;
        state.technology.global_unlocks_by_technology[technology] = true;
        state.nations.major_mut(nation).common.treasury = 999;
        state
            .nations
            .major_mut(nation)
            .economy
            .diplomacy_budget_base = 0;

        assert_eq!(
            state.toggle_technology_research(nation, technology),
            Err(TechnologyResearchRejection::InsufficientFunds)
        );
        assert_eq!(state.nations.major(nation).common.treasury, 999);
    }

    #[test]
    fn check_for_advances_charges_ai_nations_for_already_unlocked_technology() {
        let mut state = crate::test_support::game_state();
        let ai = MajorNationId::new(1);
        state.nations.major_mut(ai).economy.diplomacy_eligible = false;
        state.nations.major_mut(ai).common.treasury = 50_000;
        state.turn.economic_turn = 44;
        state.technology.global_unlocks_by_technology[Technology::CottonGin] = true;
        state.check_technology_advances();

        assert_eq!(state.nations.major(ai).common.treasury, 49_000);
        assert_eq!(
            state.technology.research_status_by_nation[ai][Technology::CottonGin],
            TechnologyResearchStatus::Pending
        );
        assert_eq!(
            state.technology.completion_year_by_nation[ai][Technology::CottonGin],
            11
        );
        assert_eq!(
            state.technology.research_status_by_nation[MajorNationId::new(0)]
                [Technology::CottonGin],
            TechnologyResearchStatus::NotStarted
        );
    }

    #[test]
    fn active_technology_report_uses_cooldown_not_diplomacy_eligibility() {
        let mut state = crate::test_support::game_state();
        let active = MajorNationId::new(0);
        state.nations.major_mut(active).economy.diplomacy_eligible = false;
        state.technology.research_status_by_nation[active][Technology::CottonGin] =
            TechnologyResearchStatus::Pending;
        state.technology.completion_year_by_nation[active][Technology::CottonGin] = 77;

        state.consume_non_interactive_technology_unlocks();
        assert_eq!(
            state.first_pending_technology_unlock(active.nation()),
            Some(Technology::CottonGin)
        );
        assert_eq!(
            state.consume_interactive_technology_unlock(),
            Some(Technology::CottonGin)
        );
        assert_eq!(
            state.technology.completion_year_by_nation[active][Technology::CottonGin],
            77
        );
    }

    #[test]
    fn positive_turn_cooldown_drains_active_unlock_without_a_report() {
        let mut state = crate::test_support::game_state();
        let active = MajorNationId::new(0);
        state.turn.turn_cooldown_defer_counter = 1;
        state.technology.research_status_by_nation[active][Technology::CottonGin] =
            TechnologyResearchStatus::Pending;

        state.consume_non_interactive_technology_unlocks();
        assert_eq!(state.first_pending_technology_unlock(active.nation()), None);
        assert_eq!(state.consume_interactive_technology_unlock(), None);
    }

    #[test]
    fn ironclad_unlock_advances_the_navy_growth_hull() {
        let mut state = crate::test_support::game_state();
        state.technology.scheduled_unlock_turn_by_technology[Technology::AdvancedIronWorking] = 1;
        state.check_technology_advances();
        assert_eq!(state.technology.navy_growth_ship_type, ShipType::Ironclad);
    }

    #[test]
    fn naval_unlocks_replace_retail_shipyard_rows_and_selection_flags() {
        let mut state = crate::test_support::game_state();
        let nation = MajorNationId::new(0);
        for technology in [
            Technology::Paddlewheels,
            Technology::AdvancedIronWorking,
            Technology::SteelArmorPlate,
            Technology::MarineEngineering,
            Technology::ImprovedRangeFinding,
        ] {
            state.technology.research_status_by_nation[nation][technology] =
                TechnologyResearchStatus::Pending;
            assert_eq!(
                state.acknowledge_technology_unlock(nation),
                Some(technology)
            );
        }

        let selected = &state.technology.selected_ship_types_by_nation[nation];
        for ship_type in (0..ShipType::LENGTH).map(ShipType::from_usize) {
            assert_eq!(
                selected[ship_type],
                matches!(
                    ship_type,
                    ShipType::AdvancedIronclad
                        | ShipType::Freighter
                        | ShipType::ArmoredCruiser
                        | ShipType::Dreadnought
                        | ShipType::Battlecruiser
                ),
                "unexpected final selection for {ship_type:?}"
            );
        }
        let orders = &state.nations.city(nation).orders.ships;
        assert_eq!(
            orders[ShipOrderSlot::MerchantEarlyPrimary].ship_type,
            ShipType::Paddlewheeler
        );
        assert_eq!(
            orders[ShipOrderSlot::MerchantEarlySecondary].ship_type,
            ShipType::Clipper
        );
        assert_eq!(
            orders[ShipOrderSlot::MerchantAdvancedPrimary].ship_type,
            ShipType::Freighter
        );
        assert_eq!(
            orders[ShipOrderSlot::WarshipEarlyPrimary].ship_type,
            ShipType::ArmoredCruiser
        );
        assert_eq!(
            orders[ShipOrderSlot::WarshipEarlySecondary].ship_type,
            ShipType::AdvancedIronclad
        );
        assert_eq!(
            orders[ShipOrderSlot::WarshipAdvancedPrimary].ship_type,
            ShipType::Battlecruiser
        );
        assert_eq!(
            orders[ShipOrderSlot::WarshipAdvancedSecondary].ship_type,
            ShipType::Dreadnought
        );
    }

    #[test]
    fn activating_a_later_general_writes_the_selected_capability_slot() {
        let mut state = crate::test_support::game_state();
        let nation = MajorNationId::new(0);
        state.technology.research_status_by_nation[nation][Technology::BessemerConverter] =
            TechnologyResearchStatus::Pending;
        assert_eq!(
            state.acknowledge_technology_unlock(nation),
            Some(Technology::BessemerConverter)
        );
        assert_eq!(
            state.technology.selected_capability_slots[nation][ArmyUnitCategory::Generals],
            MilitaryUnitKind::GeneralEra2
        );
        assert!(
            state.technology.military_unit_ability_active_by_nation[nation]
                [MilitaryUnitKind::GeneralEra2]
        );
    }

    #[test]
    fn activating_a_recruitment_ability_rewrites_the_city_order_unit_kind() {
        let mut state = crate::test_support::game_state();
        let nation = MajorNationId::new(0);
        assert_eq!(
            state.nations.city(nation).orders.military_recruitment
                [MilitaryRecruitmentCategory::LightInfantry]
                .unit_kind,
            MilitaryUnitKind::Skirmishers
        );
        state.activate_slot_and_update_ui(nation, MilitaryUnitKind::Sharpshooters);
        assert_eq!(
            state.nations.city(nation).orders.military_recruitment
                [MilitaryRecruitmentCategory::LightInfantry]
                .unit_kind,
            MilitaryUnitKind::Sharpshooters
        );
        assert!(
            !state.technology.military_unit_ability_active_by_nation[nation]
                [MilitaryUnitKind::Skirmishers]
        );
    }

    #[test]
    fn activating_a_later_general_upgrades_existing_matching_units() {
        let mut state = crate::test_support::game_state();
        let nation = MajorNationId::new(0);
        let province = ProvinceId::new(0);
        state.military_units.insert(
            MilitaryUnitId::new(1),
            MilitaryUnitState::new(
                nation.nation(),
                MilitaryUnitKind::GeneralEra1,
                Some(province),
                MilitaryOrder::idle([Some(province); 3], [Some(province); 3]),
                nation.nation(),
                1,
                true,
                String::new(),
                500,
                MilitaryEra::First,
                0,
                0,
            ),
        );
        state.activate_slot_and_update_ui(nation, MilitaryUnitKind::GeneralEra2);
        assert_eq!(
            state.military_units[0].unit_type(),
            MilitaryUnitKind::GeneralEra2
        );
    }
}
