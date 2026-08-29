use crate::*;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Every nation slot, split into the two populations that carry different
/// domain state. Major entity membership mirrors retail's nullable live-slot table.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Nations {
    pub(crate) majors: IndexMap<MajorNationId, MajorNation>,
    pub(crate) minors: IndexMap<MinorNationId, MinorNation>,
}

impl Nations {
    pub fn new(
        majors: impl Into<IndexMap<MajorNationId, MajorNation>>,
        minors: impl Into<IndexMap<MinorNationId, MinorNation>>,
    ) -> Self {
        Self {
            majors: majors.into(),
            minors: minors.into(),
        }
    }

    pub fn major(&self, nation: crate::MajorNationId) -> &MajorNation {
        &self.majors[&nation]
    }

    pub(crate) fn major_mut(&mut self, nation: crate::MajorNationId) -> &mut MajorNation {
        &mut self.majors[&nation]
    }

    pub fn major_is_present(&self, nation: MajorNationId) -> bool {
        self.majors.contains_key(&nation)
    }

    pub(crate) fn remove_major(&mut self, nation: MajorNationId) -> MajorNation {
        self.majors
            .shift_remove(&nation)
            .expect("removed major must exist")
    }

    pub(crate) fn city(&self, nation: crate::MajorNationId) -> &CityState {
        &self.majors[&nation].city
    }

    pub(crate) fn city_mut(&mut self, nation: crate::MajorNationId) -> &mut CityState {
        &mut self.majors[&nation].city
    }

    pub fn majors(&self) -> impl ExactSizeIterator<Item = &MajorNation> {
        self.majors.values()
    }

    pub fn minor(&self, nation: MinorNationId) -> Option<&MinorNation> {
        self.minors.get(&nation)
    }

    pub fn minor_count(&self) -> usize {
        self.minors.len()
    }

    /// Returns the normalized display name used by retail nation-facing UI.
    pub fn display_name(&self, nation: NationId) -> Option<&str> {
        self.common(nation)
            .map(|common| common.display_name.as_str())
    }

    pub fn country_status(&self, nation: NationId) -> Option<crate::CountryStatus> {
        self.common(nation).map(NationCommonState::status)
    }

    pub fn owned_region_count(&self, nation: NationId) -> Option<usize> {
        self.common(nation)
            .map(NationCommonState::owned_region_count)
    }

    pub fn home_tile(&self, nation: NationId) -> Option<TileId> {
        self.common(nation).and_then(|common| common.home_tile)
    }

    /// `TCountry::overlayAnchorTileCache8c`, as loaded from the save or computed.
    pub fn overlay_anchor_tile(&self, nation: NationId) -> Option<TileId> {
        self.common(nation)?.overlay_anchor_tile
    }

    pub(crate) fn common(&self, nation: NationId) -> Option<&NationCommonState> {
        if let Some(nation) = MajorNationId::from_nation(nation) {
            self.majors.get(&nation).map(|nation| &nation.common)
        } else {
            self.minors
                .get(&MinorNationId::new(nation.get()))
                .map(|nation| &nation.common)
        }
    }

    /// Slot-ordered iterator over the countries that exist in this game, with
    /// each country's `NationId`. Use this instead of iterating every numeric
    /// slot and probing `display_name` as an existence test.
    pub fn common_states(&self) -> impl Iterator<Item = (NationId, &NationCommonState)> {
        NationId::all().filter_map(|nation| self.common(nation).map(|common| (nation, common)))
    }

    pub(crate) fn common_mut(&mut self, nation: NationId) -> Option<&mut NationCommonState> {
        if let Some(nation) = MajorNationId::from_nation(nation) {
            self.majors
                .get_mut(&nation)
                .map(|nation| &mut nation.common)
        } else {
            self.minors
                .get_mut(&MinorNationId::new(nation.get()))
                .map(|nation| &mut nation.common)
        }
    }

    pub(crate) fn append_owned_region_during_construction(
        &mut self,
        nation: NationId,
        province: ProvinceId,
    ) {
        self.common_mut(nation)
            .expect("constructed province owner must be present")
            .owned_regions
            .push(province);
    }

    pub(crate) fn set_country_status(&mut self, nation: NationId, status: crate::CountryStatus) {
        self.common_mut(nation)
            .expect("country status requires the nation to be present")
            .status = status;
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AutoGreatPowerState {
    pub province_targets: ProvinceTable<AiTargetState>,
    pub zone_targets: Vec<AiTargetState>,
    pub trade: AiTradeState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MajorNation {
    pub auto: Option<AutoGreatPowerState>,
    pub common: NationCommonState,
    pub economy: GreatPowerState,
    pub city: CityState,
    /// Retail `TGreatPower::townMarkerList`, in its observable list order.
    pub towns: IndexMap<TileId, TownState>,
}

impl MajorNation {
    pub fn is_auto(&self) -> bool {
        self.auto.is_some()
    }

    /// Builds a random-game start major nation from the resolved starting
    /// `treasury`, whether the slot is the `human` player, and its scenario
    /// `city`. Normal+ human homes remain unset until capital selection places them;
    /// Introductory/Easy and AI homes are placed during random-game construction.
    pub(crate) fn for_random_start(
        nation: MajorNationId,
        treasury: i32,
        human: bool,
        difficulty: Difficulty,
        foreign_minister_personality: ForeignMinisterPersonality,
        city: CityState,
        display_name: String,
    ) -> Self {
        let mut town = TownState::for_frog_city(TileId::new(0), nation.nation());
        if human {
            town.name = "Frog City".to_owned();
        }
        Self {
            auto: (!human).then(AutoGreatPowerState::default),
            common: NationCommonState::from_parts(
                display_name,
                crate::CountryStatus::Independent,
                Vec::new(),
                treasury,
                None,
                NationTable::default(),
            ),
            economy: GreatPowerState::for_random_start(
                human,
                difficulty,
                foreign_minister_personality,
            ),
            city,
            towns: [(TileId::new(0), town)].into_iter().collect(),
        }
    }

    /// Retail `TGreatPower::AddProvince`.
    pub(crate) fn add_province(&mut self, province: ProvinceId) {
        self.common.add_province(province);
        if self.common.owned_regions.len() >= 9
            && self.economy.pending_actions[PendingActionKind::ConqueredCapitalArmoryUpgrade]
                .progress()
                .has_reached(PendingActionProgress::Handled)
            && !self.economy.pending_actions[PendingActionKind::ConquestMonumentArmory]
                .progress()
                .has_reached(PendingActionProgress::Handled)
        {
            self.economy.pending_actions[PendingActionKind::ConquestMonumentArmory].queue();
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MinorNation {
    pub common: NationCommonState,
    pub consortium_members: [MinorNationId; 4],
    pub trade: MinorTradeState,
}

impl MinorNation {
    /// Retail `TMinor::LoseProvince`.
    pub(crate) fn lose_province(&mut self, province: ProvinceId) {
        self.common.lose_province(province);
    }

    /// Retail `TMinor::AddProvince`.
    pub(crate) fn add_province(&mut self, province: ProvinceId) {
        self.common.add_province(province);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NationCommonState {
    pub display_name: String,
    status: crate::CountryStatus,
    owned_regions: Vec<ProvinceId>,
    pub treasury: i32,
    pub home_tile: Option<TileId>,
    /// `TCountry::overlayAnchorTileCache8c`: lazily computed diplomacy-map
    /// overlay anchor, serialized with the save. `None` means the retail `-1`
    /// sentinel (not yet computed).
    pub overlay_anchor_tile: Option<TileId>,
    pub trade_policy_by_nation: NationTable<TradePolicyScore>,
    pub unit_name_ordinal_by_type: crate::MilitaryUnitTable<i16>,
    pub unit_name_counter: i16,
}

impl NationCommonState {
    pub fn from_parts(
        display_name: String,
        status: crate::CountryStatus,
        owned_regions: Vec<ProvinceId>,
        treasury: i32,
        home_tile: Option<TileId>,
        trade_policy_by_nation: NationTable<TradePolicyScore>,
    ) -> Self {
        Self {
            display_name,
            status,
            owned_regions,
            treasury,
            home_tile,
            overlay_anchor_tile: None,
            trade_policy_by_nation,
            unit_name_ordinal_by_type: crate::MilitaryUnitTable::from_array(
                [1; crate::MilitaryUnitKind::LENGTH],
            ),
            unit_name_counter: 1,
        }
    }

    pub const fn status(&self) -> crate::CountryStatus {
        self.status
    }

    pub fn owned_regions(&self) -> &[ProvinceId] {
        &self.owned_regions
    }

    pub fn owned_region_count(&self) -> usize {
        self.owned_regions.len()
    }

    pub(crate) fn lose_province(&mut self, province: ProvinceId) {
        let position = self
            .owned_regions
            .iter()
            .position(|&owned| owned == province)
            .expect("owned province requires one ordered-index entry");
        self.owned_regions.remove(position);
    }

    fn add_province(&mut self, province: ProvinceId) {
        self.owned_regions.push(province);
    }
}
