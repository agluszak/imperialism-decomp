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

    pub(crate) fn set_country_status(&mut self, nation: NationId, status: crate::CountryStatus) {
        self.common_mut(nation)
            .expect("country status requires the nation to be present")
            .status = status;
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MajorNationKind {
    GreatPower,
    AutoGreatPower,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MajorNation {
    pub kind: MajorNationKind,
    pub common: NationCommonState,
    pub economy: GreatPowerState,
    pub city: CityState,
    /// Retail `TGreatPower::townMarkerList`, in its observable list order.
    pub towns: Vec<TownState>,
}

impl MajorNation {
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
            kind: if human {
                MajorNationKind::GreatPower
            } else {
                MajorNationKind::AutoGreatPower
            },
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
            towns: vec![town],
        }
    }

    /// Retail `TGreatPower::LoseProvince` after any `TAutoGreatPower`
    /// pre-dispatch work has run.
    pub(crate) fn lose_province(
        &mut self,
        nation: MajorNationId,
        province: ProvinceId,
        map: &MapMgr,
        civilian_units: &mut Vec<CivilianUnitState>,
        military_units: &mut Vec<MilitaryUnitState>,
        missions: &mut [MissionState],
    ) {
        self.common.lose_province(province);

        let nation = nation.nation();
        // `KillUnitsIn` first pass: tracked civilian orders whose tile is in the lost
        // province. Military `tileIndex06` is a province id and is not used here.
        civilian_units.retain(|unit| {
            unit.nation != nation
                || unit
                    .location
                    .tile()
                    .is_none_or(|tile| map[tile].province != Some(province))
        });

        // Second pass frees already-detached military units (`tileIndex06 == -1`).
        // Units still stationed in the lost province stay on the map.
        military_units.retain(|unit| unit.nation != nation || unit.stationed_province.is_some());
        let remaining: Vec<_> = military_units.iter().map(|unit| unit.id).collect();
        for mission in missions.iter_mut() {
            if mission.nation != nation {
                continue;
            }
            let army = match &mut mission.data {
                MissionData::DefendProvince { army, .. } => army,
                MissionData::AttackProvince(attack) => &mut attack.army,
                MissionData::Invade { attack, .. } => &mut attack.army,
                _ => continue,
            };
            army.units
                .retain(|id| remaining.iter().any(|present| present == id));
        }
    }

    /// Retail `TGreatPower::AddProvince`.
    pub(crate) fn add_province(&mut self, province: ProvinceId) {
        self.common.add_province(province);
        if self.common.owned_regions.len() >= 9
            && self.economy.pending_actions[PendingActionKind::ConqueredCapitalArmoryUpgrade]
                .status()
                .has_reached(PendingActionStatus::completed(0))
            && !self.economy.pending_actions[PendingActionKind::ConquestMonumentArmory]
                .status()
                .has_reached(PendingActionStatus::completed(0))
        {
            self.economy.pending_actions[PendingActionKind::ConquestMonumentArmory].queue(-1);
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
    pub(crate) fn lose_province(
        &mut self,
        province: ProvinceId,
        map: &mut MapMgr,
        major_nations: &MajorNationTable<MajorNation>,
        diplomacy: &DiplomacyState,
        civilian_units: &mut Vec<CivilianUnitState>,
    ) {
        self.common.lose_province(province);
        let new_owner = map.provinces[province]
            .owner()
            .expect("lost province requires its newly assigned owner");
        let linked_tiles = map.provinces[province].linked_tiles.clone();

        for &tile in &linked_tiles {
            map[tile].secondary_owner_nation = None;
        }

        // `KillEnemyCiviliansIn`: developers at war are sent home; the other
        // enemy civilian orders are freed. The following deport pass then acts
        // on every remaining foreign major, matching includeAllPolicyTargets=1.
        for &tile in &linked_tiles {
            let mut index = 0;
            while index < civilian_units.len() {
                let unit = &civilian_units[index];
                let Some(owner) = MajorNationId::from_nation(unit.owner_nation) else {
                    index += 1;
                    continue;
                };
                if unit.location.tile() != Some(tile)
                    || unit.owner_nation == new_owner
                    || diplomacy.relationships[new_owner][unit.owner_nation]
                        != DiplomaticRelationship::War
                {
                    index += 1;
                    continue;
                }
                if unit.unit_type == CivilianUnitKind::Developer {
                    civilian_units[index].location = CivilianLocation::OnMap(
                        major_nations[owner]
                            .common
                            .home_tile
                            .expect("foreign developer requires its owner's home town"),
                    );
                    index += 1;
                } else {
                    civilian_units.remove(index);
                }
            }
        }

        for &tile in &linked_tiles {
            let mut index = 0;
            while index < civilian_units.len() {
                let unit = &civilian_units[index];
                let Some(owner) = MajorNationId::from_nation(unit.owner_nation) else {
                    index += 1;
                    continue;
                };
                if unit.location.tile() != Some(tile) || unit.owner_nation == new_owner {
                    index += 1;
                    continue;
                }
                let home = major_nations[owner]
                    .common
                    .home_tile
                    .expect("deported civilian requires its owner's home town");
                if let Some(destination) =
                    map.find_reachable_recruit_spawn_tile(civilian_units, home, false)
                {
                    civilian_units[index].order = CivilianWorkOrder::Idle;
                    civilian_units[index].location = CivilianLocation::OnMap(destination);
                    index += 1;
                } else {
                    civilian_units.remove(index);
                }
            }
        }
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
    pub trade_policy_by_nation: NationTable<TradePolicyScore>,
    /// Retail `TCountry::unitNameOrdinalByType`.
    pub unit_name_ordinal_by_type: [i16; MilitaryUnitKind::LENGTH],
    /// Retail `TCountry::unitNameCounter84`.
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
            trade_policy_by_nation,
            unit_name_ordinal_by_type: [1; MilitaryUnitKind::LENGTH],
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

    fn lose_province(&mut self, province: ProvinceId) {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MajorNationController {
    Human,
    Computer,
}

impl MajorNationController {
    pub const fn is_human(self) -> bool {
        matches!(self, Self::Human)
    }
}
