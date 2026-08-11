use crate::*;
use serde::{Deserialize, Serialize};

/// Every nation slot, split into the two populations that carry different
/// domain state. Every major slot is a complete major nation; minor slots may
/// still be absent until their save projection is normalized separately.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Nations {
    pub(crate) majors: Box<MajorNationTable<MajorNation>>,
    pub(crate) minors: MinorNationTable<Option<MinorNation>>,
}

impl Nations {
    pub fn new(
        majors: MajorNationTable<MajorNation>,
        minors: MinorNationTable<Option<MinorNation>>,
    ) -> Self {
        Self {
            majors: Box::new(majors),
            minors,
        }
    }

    pub fn major(&self, nation: crate::MajorNationId) -> &MajorNation {
        &self.majors[nation]
    }

    pub(crate) fn major_mut(&mut self, nation: crate::MajorNationId) -> &mut MajorNation {
        &mut self.majors[nation]
    }

    pub(crate) fn city(&self, nation: crate::MajorNationId) -> &CityState {
        &self.majors[nation].city
    }

    pub(crate) fn city_mut(&mut self, nation: crate::MajorNationId) -> &mut CityState {
        &mut self.majors[nation].city
    }

    pub fn majors(&self) -> impl ExactSizeIterator<Item = &MajorNation> {
        self.majors.iter()
    }

    pub fn minor(&self, nation: MinorNationId) -> Option<&MinorNation> {
        self.minors[nation].as_ref()
    }

    pub fn minor_count(&self) -> usize {
        self.minors.iter().flatten().count()
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

    pub(crate) fn common(&self, nation: NationId) -> Option<&NationCommonState> {
        if let Some(nation) = MajorNationId::from_nation(nation) {
            Some(&self.majors[nation].common)
        } else {
            self.minors[MinorNationId::new(nation.get())]
                .as_ref()
                .map(|nation| &nation.common)
        }
    }

    pub(crate) fn common_mut(&mut self, nation: NationId) -> Option<&mut NationCommonState> {
        if let Some(nation) = MajorNationId::from_nation(nation) {
            Some(&mut self.majors[nation].common)
        } else {
            self.minors[MinorNationId::new(nation.get())]
                .as_mut()
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

    pub(crate) fn transfer_owned_region_index(
        &mut self,
        old_owner: NationId,
        new_owner: NationId,
        province: ProvinceId,
    ) {
        let old_position = self
            .common(old_owner)
            .expect("owned province requires its owner nation to be present")
            .owned_regions
            .iter()
            .position(|&owned| owned == province)
            .expect("owned province requires one ordered-index entry");
        self.common_mut(old_owner)
            .expect("owned province requires its owner nation to be present")
            .owned_regions
            .remove(old_position);
        self.common_mut(new_owner)
            .expect("province transfer requires the new owner to be present")
            .owned_regions
            .push(province);
    }

    pub(crate) fn set_country_status(&mut self, nation: NationId, status: crate::CountryStatus) {
        self.common_mut(nation)
            .expect("country status requires the nation to be present")
            .status = status;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MajorNation {
    pub(crate) common: NationCommonState,
    pub(crate) economy: GreatPowerState,
    pub(crate) city: CityState,
}

impl MajorNation {
    pub const fn from_parts(
        common: NationCommonState,
        economy: GreatPowerState,
        city: CityState,
    ) -> Self {
        Self {
            common,
            economy,
            city,
        }
    }

    /// Builds a random-game start major nation from the resolved starting
    /// `treasury`, whether the slot is the `human` player, and its scenario
    /// `city`. Homes are unset until capital selection places them.
    pub(crate) fn for_random_start(
        treasury: i32,
        human: bool,
        foreign_minister_personality: ForeignMinisterPersonality,
        city: CityState,
    ) -> Self {
        Self {
            common: NationCommonState::from_parts(
                String::new(),
                crate::CountryStatus::Independent,
                Vec::new(),
                treasury,
                None,
                NationTable::default(),
            ),
            economy: GreatPowerState::for_random_start(human, foreign_minister_personality),
            city,
        }
    }

    pub const fn common(&self) -> &NationCommonState {
        &self.common
    }

    pub const fn economy(&self) -> &GreatPowerState {
        &self.economy
    }

    pub const fn city(&self) -> &CityState {
        &self.city
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MinorNation {
    pub common: NationCommonState,
    pub consortium_members: [MinorNationId; 4],
    pub trade: MinorTradeState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NationCommonState {
    pub display_name: String,
    status: crate::CountryStatus,
    owned_regions: Vec<ProvinceId>,
    pub treasury: i32,
    pub home_tile: Option<TileId>,
    pub trade_policy_by_nation: NationTable<TradePolicyScore>,
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
            trade_policy_by_nation,
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MajorNationController {
    Human,
    Computer,
}
impl MajorNationController {
    pub(crate) const fn is_human(self) -> bool {
        matches!(self, Self::Human)
    }
}
