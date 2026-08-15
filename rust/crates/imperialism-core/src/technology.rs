use crate::*;
use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Deserializer, Serialize};

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
    /// Retail `TTechMgr::nationCapRows1e8`: the selected ability id in each
    /// tactical group. Slot 9 is the general spawned by army-growth rewards.
    pub selected_capability_slots: MajorNationTable<[MilitaryUnitKind; 10]>,
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
            research_status_by_nation: MajorNationTable::from_fn(|_| {
                TechnologyTable::from_array(std::array::from_fn(|index| {
                    if index < 3 {
                        TechnologyResearchStatus::Researched
                    } else {
                        TechnologyResearchStatus::NotStarted
                    }
                }))
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
        for (technology, (start_group, end_group)) in
            Technology::all().skip(3).zip(RANDOM_START_PRIORITY_RANGES)
        {
            let range_start = start_group * 4;
            let range_span = (end_group - start_group) * 4 + 1;
            loop {
                let candidate = (rng.next_sample_15() % range_span as u32) as i16 + range_start;
                if !Technology::all()
                    .take(technology as usize)
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
                            story_code: i32::from(tech_id as u8),
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
        self.check_technology_advances();
        // FIXME: retail ORs `turnFlowStatusFlags` with `0x40` when `marker262` is
        // unchanged (map toolbar new-tech chrome). `marker262` is not modeled.
        self.consume_non_interactive_technology_unlocks();
    }

    pub(crate) fn consume_interactive_technology_unlock(&mut self) -> Option<Technology> {
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

    fn apply_ability_unlock(&mut self, tech_id: Technology, nation: MajorNationId) {
        // FIXME: `HandleAbilityUnlock` also upgrades developed-tile civilian class,
        // navy/score `UpdateSelectionAndRecalculateScores`, city TUnitOrder cost
        // profiles, and `TMilitaryUnit::Upgrade()`.
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
            Technology::CottonGin => self.set_requirement_level(nation, ResourceKind::Cotton, 1),
            Technology::SeedDrill => self.set_requirement_level(nation, ResourceKind::Grain, 1),
            Technology::SquareSetTimbering => {
                self.set_requirement_level(nation, ResourceKind::Coal, 2);
                self.set_requirement_level(nation, ResourceKind::Iron, 2);
                self.set_requirement_level(nation, ResourceKind::Gold, 2);
                self.set_requirement_level(nation, ResourceKind::Gems, 2);
            }
            Technology::IronRailroadBridge => {
                self.set_requirement_level(nation, ResourceKind::Timber, 1);
                self.set_university_available(nation, CivilianUnitKind::Forester, true);
            }
            Technology::SteelPlows => {
                self.set_requirement_level(nation, ResourceKind::Fruit, 2);
                self.set_requirement_level(nation, ResourceKind::Grain, 2);
            }
            Technology::FeedGrasses => {
                self.set_requirement_level(nation, ResourceKind::Livestock, 1);
                self.set_requirement_level(nation, ResourceKind::Wool, 1);
                self.set_university_available(nation, CivilianUnitKind::Rancher, true);
            }
            Technology::SpinningJenny => {
                self.set_requirement_level(nation, ResourceKind::Cotton, 2);
                self.set_requirement_level(nation, ResourceKind::Wool, 2);
            }
            Technology::CompoundSteamEngine => {
                self.set_requirement_level(nation, ResourceKind::Timber, 2)
            }
            Technology::MechanicalReaper => {
                self.set_requirement_level(nation, ResourceKind::Grain, 3)
            }
            Technology::CommercialFertilizer => {
                self.set_requirement_level(nation, ResourceKind::Fruit, 3)
            }
            Technology::BarbedWire => {
                self.set_requirement_level(nation, ResourceKind::Livestock, 2)
            }
            Technology::BessemerConverter => {
                self.activate_military_ability(nation, MilitaryUnitKind::Scouts);
                self.activate_military_ability(nation, MilitaryUnitKind::Sharpshooters);
                self.activate_military_ability(nation, MilitaryUnitKind::CombatEngineers);
                self.activate_military_ability(nation, MilitaryUnitKind::GeneralEra2);
            }
            Technology::PowerLoom => {
                self.set_requirement_level(nation, ResourceKind::Cotton, 3);
                self.set_requirement_level(nation, ResourceKind::Wool, 3);
            }
            Technology::RifledArtillery => {
                self.activate_military_ability(nation, MilitaryUnitKind::FieldArtillery);
                self.activate_military_ability(nation, MilitaryUnitKind::SiegeArtillery);
                self.add_era_arms(nation, era_offset, 10);
            }
            Technology::Dynamite => {
                self.set_requirement_level(nation, ResourceKind::Coal, 3);
                self.set_requirement_level(nation, ResourceKind::Iron, 3);
                self.set_requirement_level(nation, ResourceKind::Gold, 3);
                self.set_requirement_level(nation, ResourceKind::Gems, 3);
                self.set_requirement_level(nation, ResourceKind::Timber, 3);
                self.activate_military_ability(nation, MilitaryUnitKind::Saboteurs);
            }
            Technology::OilDrilling => {
                self.set_requirement_level(nation, ResourceKind::Oil, 1);
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
                self.set_requirement_level(nation, ResourceKind::Oil, 2);
                self.set_requirement_level(nation, ResourceKind::Livestock, 3);
            }
            Technology::LargeArtillery => {
                self.activate_military_ability(nation, MilitaryUnitKind::MobileArtillery);
                self.activate_military_ability(nation, MilitaryUnitKind::RailroadGuns);
                self.add_era_arms(nation, era_offset, 20);
            }
            Technology::InternalCombustion => {
                self.set_requirement_level(nation, ResourceKind::Oil, 3);
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

    /// Retail `TTechMgr::ActivateSlotAndUpdateUI`.
    pub fn activate_slot_and_update_ui(&mut self, nation: MajorNationId, kind: MilitaryUnitKind) {
        self.activate_military_ability(nation, kind);
    }

    fn activate_military_ability(&mut self, nation: MajorNationId, kind: MilitaryUnitKind) {
        self.technology.military_unit_ability_active_by_nation[nation][kind] = true;
        let group = crate::military_phase::tactical_category(kind);
        if (0..10).contains(&group) {
            self.technology.selected_capability_slots[nation][group as usize] = kind;
        }
        if (1..9).contains(&group) {
            let category = MilitaryRecruitmentCategory::from_usize((group - 1) as usize);
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

    fn upgrade_matching_category_units(&mut self, nation: MajorNationId, group: i16) {
        let mut indexes = Vec::new();
        for (index, unit) in self.military_units.iter().enumerate() {
            if unit.nation() == nation.nation()
                && crate::military_phase::tactical_category(unit.unit_type()) == group
            {
                indexes.push(index);
            }
        }
        for index in indexes {
            self.upgrade_military_unit(nation, index);
        }
    }

    fn upgrade_military_unit(&mut self, nation: MajorNationId, index: usize) -> bool {
        let Some(candidate) = self.upgrade_type(nation, self.military_units[index].unit_type())
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
        let diplomacy_eligible = self.nations.majors[nation].economy.diplomacy_eligible;
        let treasury = self.nations.majors[nation].common.treasury;
        if diplomacy_eligible
            && i32::from(cash_cost)
                > self.nations.majors[nation]
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
        self.nations.majors[nation].common.treasury -= i32::from(cash_cost);
        self.military_units[index].unit_type = candidate;
        true
    }

    fn upgrade_type(
        &self,
        nation: MajorNationId,
        unit_type: MilitaryUnitKind,
    ) -> Option<MilitaryUnitKind> {
        let candidate = if (unit_type as u8) < MilitaryUnitKind::Conscripts as u8 {
            MilitaryUnitKind::from_index(unit_type as u8 + 8)
        } else if matches!(
            unit_type,
            MilitaryUnitKind::Sappers
                | MilitaryUnitKind::CombatEngineers
                | MilitaryUnitKind::GeneralEra1
                | MilitaryUnitKind::GeneralEra2
        ) {
            MilitaryUnitKind::from_index(unit_type as u8 + 1)
        } else {
            None
        }?;
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

pub(crate) const fn default_selected_capability_slots() -> [MilitaryUnitKind; 10] {
    [
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
    ]
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
    // FIXME: retail also writes `marker262`, `techSelectorShort1d2`, and
    // `activePrerequisitePair264` (techs 0xb / 0x16).
    technology.global_unlocks_by_technology[tech_id] = true;
    match tech_id {
        Technology::Paddlewheels => {
            technology.industry_enabled_by_slot[7] = true;
            technology.industry_enabled_by_slot[5] = true;
        }
        Technology::StreamlinedHulls => technology.industry_enabled_by_slot[6] = true,
        Technology::AdvancedIronWorking => {
            technology.industry_enabled_by_slot[8] = true;
            technology.advanced_iron_working = true;
            technology.navy_growth_ship_type = ShipType::Ironclad;
        }
        Technology::SteelArmorPlate => {
            technology.industry_enabled_by_slot[9] = true;
            technology.navy_growth_ship_type = ShipType::AdvancedIronclad;
        }
        Technology::MarineEngineering => {
            technology.industry_enabled_by_slot[0xb] = true;
            technology.industry_enabled_by_slot[0xa] = true;
            technology.marine_engineering = true;
        }
        Technology::ImprovedRangeFinding => {
            technology.industry_enabled_by_slot[0xc] = true;
            technology.industry_enabled_by_slot[0xd] = true;
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
        FortLevelCap::THREE
    } else if started(Technology::BessemerConverter) {
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
        state.nations.major_mut(ai).economy.diplomacy_eligible = false;
        state.nations.major_mut(ai).common.treasury = 50_000;
        state.technology.global_unlocks_by_technology[Technology::CottonGin] = true;
        state.check_technology_advances();

        assert_eq!(state.nations.major(ai).common.treasury, 49_000);
        assert_eq!(
            state.technology.research_status_by_nation[ai][Technology::CottonGin],
            TechnologyResearchStatus::Pending
        );
        assert_eq!(
            state.technology.research_status_by_nation[MajorNationId::new(0)]
                [Technology::CottonGin],
            TechnologyResearchStatus::NotStarted
        );
    }

    #[test]
    fn ironclad_unlock_advances_the_navy_growth_hull() {
        let mut state = crate::test_support::game_state();
        state.technology.scheduled_unlock_turn_by_technology[Technology::AdvancedIronWorking] = 1;
        state.check_technology_advances();
        assert_eq!(state.technology.navy_growth_ship_type, ShipType::Ironclad);
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
            state.technology.selected_capability_slots[nation][9],
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
        state.military_units.push(MilitaryUnitState::new(
            MilitaryUnitId::new(1),
            nation.nation(),
            MilitaryUnitKind::GeneralEra1,
            Some(province),
            MilitaryOrder::idle([Some(province); 3], [Some(province); 3]),
            nation.nation(),
            1,
            true,
            String::new(),
            500,
            0,
            0,
            0,
        ));
        state.activate_slot_and_update_ui(nation, MilitaryUnitKind::GeneralEra2);
        assert_eq!(
            state.military_units[0].unit_type(),
            MilitaryUnitKind::GeneralEra2
        );
    }
}
