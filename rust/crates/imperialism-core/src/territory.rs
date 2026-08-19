use crate::{
    AiTargetState, ArmyMissionState, DiplomaticRelationship, GameState, MajorNationId,
    MajorNationTable, MapMgr, MinorNationId, MissionData, MissionState, NationId, ProvinceId,
    ResourceTable, TileId,
};
use enum_map::{Enum, EnumMap};
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};

const REGION_CLASS_COUNT: usize = 24;

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvinceDevelopmentStage {
    #[default]
    None,
    Village,
    Town,
}

impl ProvinceDevelopmentStage {
    pub const fn from_retail(value: i8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Village),
            2 => Some(Self::Town),
            _ => None,
        }
    }

    pub const fn retail(self) -> i8 {
        match self {
            Self::None => 0,
            Self::Village => 1,
            Self::Town => 2,
        }
    }
}

/// Retail province fort levels.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Enum, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FortLevel {
    #[default]
    None,
    One,
    Two,
    Three,
}

pub type FortLevelTable<T> = EnumMap<FortLevel, T>;

impl FortLevel {
    pub const fn from_retail(value: i8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::One),
            2 => Some(Self::Two),
            3 => Some(Self::Three),
            _ => None,
        }
    }

    pub const fn retail(self) -> i8 {
        match self {
            Self::None => 0,
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
        }
    }

    pub const fn next(self) -> Option<Self> {
        match self {
            Self::None => Some(Self::One),
            Self::One => Some(Self::Two),
            Self::Two => Some(Self::Three),
            Self::Three => None,
        }
    }
}

/// A country's current relationship to an imperial master.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "nation", rename_all = "snake_case")]
pub enum CountryStatus {
    #[default]
    Independent,
    ProtectorateOf(NationId),
    ColonyOf(NationId),
}

impl CountryStatus {
    pub(crate) fn is_colony_of(self, nation: NationId) -> bool {
        matches!(self, Self::ColonyOf(master) if master == nation)
    }
}

/// One entry in retail's fixed 384-record province table.
///
/// The optional fields are independent: retail has no separate active-record bit.
/// Adjacency preserves the stored prefix order and is limited to the twelve slots
/// present in each retail record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProvinceState {
    #[serde(deserialize_with = "deserialize_required_option")]
    owner: Option<NationId>,
    #[serde(deserialize_with = "deserialize_required_option")]
    former_owner: Option<NationId>,
    development_stage: ProvinceDevelopmentStage,
    adjacency: Vec<ProvinceId>,
    pub adjacency_anchor_tiles: Vec<TileId>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub region_class: Option<u8>,
    fort_level: FortLevel,
    #[serde(deserialize_with = "deserialize_required_option")]
    city_tile: Option<TileId>,
    pub last_turn_tick: i32,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub secondary_neighbor_tile: Option<TileId>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub primary_neighbor_tile: Option<TileId>,
    /// Retail `Province::linkedTileIndices42`, in table-construction order.
    pub linked_tiles: Vec<TileId>,
    resource_development_by_type: Box<ResourceTable<i32>>,
    explored_by_majors: MajorNationTable<bool>,
    city_score: i32,
    pub navy_order_reachable: bool,
    pub resource_presence_mask: i8,
    pub name: String,
}

impl Default for ProvinceState {
    fn default() -> Self {
        Self {
            owner: None,
            former_owner: None,
            development_stage: ProvinceDevelopmentStage::None,
            adjacency: Vec::new(),
            adjacency_anchor_tiles: Vec::new(),
            region_class: None,
            fort_level: FortLevel::None,
            city_tile: None,
            last_turn_tick: 999,
            secondary_neighbor_tile: None,
            primary_neighbor_tile: None,
            linked_tiles: Vec::new(),
            resource_development_by_type: Box::default(),
            explored_by_majors: MajorNationTable::default(),
            city_score: 0,
            navy_order_reachable: false,
            resource_presence_mask: 0,
            name: String::new(),
        }
    }
}

impl ProvinceState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner: Option<NationId>,
        former_owner: Option<NationId>,
        development_stage: ProvinceDevelopmentStage,
        adjacency: Vec<ProvinceId>,
        adjacency_anchor_tiles: Vec<TileId>,
        region_class: Option<u8>,
        fort_level: FortLevel,
        city_tile: Option<TileId>,
        last_turn_tick: i32,
        secondary_neighbor_tile: Option<TileId>,
        primary_neighbor_tile: Option<TileId>,
        linked_tiles: Vec<TileId>,
        resource_development_by_type: ResourceTable<i32>,
        explored_by_majors: MajorNationTable<bool>,
        city_score: i32,
        navy_order_reachable: bool,
        resource_presence_mask: i8,
        name: String,
    ) -> Self {
        Self {
            owner,
            former_owner,
            development_stage,
            adjacency,
            adjacency_anchor_tiles,
            region_class,
            fort_level,
            city_tile,
            last_turn_tick,
            secondary_neighbor_tile,
            primary_neighbor_tile,
            linked_tiles,
            resource_development_by_type: Box::new(resource_development_by_type),
            explored_by_majors,
            city_score,
            navy_order_reachable,
            resource_presence_mask,
            name,
        }
    }

    pub const fn owner(&self) -> Option<NationId> {
        self.owner
    }

    pub const fn former_owner(&self) -> Option<NationId> {
        self.former_owner
    }

    pub const fn development_stage(&self) -> ProvinceDevelopmentStage {
        self.development_stage
    }

    pub fn adjacency(&self) -> &[ProvinceId] {
        &self.adjacency
    }

    pub const fn fort_level(&self) -> FortLevel {
        self.fort_level
    }

    pub(crate) fn increment_fort_level(&mut self) {
        self.fort_level = self
            .fort_level
            .next()
            .expect("cannot build beyond the maximum retail fort level");
    }

    pub const fn city_tile(&self) -> Option<TileId> {
        self.city_tile
    }

    pub const fn resource_development_by_type(&self) -> &ResourceTable<i32> {
        &self.resource_development_by_type
    }

    pub(crate) fn resource_development_by_type_mut(&mut self) -> &mut ResourceTable<i32> {
        &mut self.resource_development_by_type
    }

    pub(crate) fn set_development_stage(&mut self, stage: ProvinceDevelopmentStage) {
        self.development_stage = stage;
    }

    pub const fn explored_by_majors(&self) -> &MajorNationTable<bool> {
        &self.explored_by_majors
    }

    pub(crate) fn explored_by_majors_mut(&mut self) -> &mut MajorNationTable<bool> {
        &mut self.explored_by_majors
    }

    pub const fn city_score(&self) -> i32 {
        self.city_score
    }

    pub(crate) fn set_city_score(&mut self, city_score: i32) {
        self.city_score = city_score;
    }

    pub(crate) fn set_owner(&mut self, new_owner: Option<NationId>) {
        self.owner = new_owner;
    }

    #[cfg(test)]
    pub(crate) fn set_adjacency(&mut self, adjacency: Vec<ProvinceId>) {
        self.adjacency = adjacency;
    }

    #[cfg(test)]
    pub(crate) fn set_city_tile(&mut self, city_tile: Option<TileId>) {
        self.city_tile = city_tile;
    }
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl MapMgr {
    /// Direct and second-degree branches of retail
    /// `IsNodeTypeLinkUnavailableAndNoActiveMapActionContext`.
    fn province_has_nation_graph_link(&self, province: ProvinceId, nation: NationId) -> bool {
        let record = &self.provinces[province];
        if record
            .adjacency
            .iter()
            .any(|&adjacent| self.provinces[adjacent].owner == Some(nation))
        {
            return true;
        }

        record.owner == Some(nation)
            && record
                .adjacency
                .iter()
                .any(|&adjacent| !self.provinces[adjacent].adjacency.is_empty())
    }
}

impl GameState {
    /// Retail `IsNodeTypeLinkUnavailableAndNoActiveMapActionContext`, inverted to
    /// "available": graph link or an ocean context that lists the province.
    pub(crate) fn province_mission_node_available(
        &self,
        province: ProvinceId,
        nation: MajorNationId,
    ) -> bool {
        self.map
            .province_has_nation_graph_link(province, nation.nation())
            || self.ocean.context_containing_province(province).is_some()
    }

    /// Retail `TMapMgr::ChangeProvinceOwner` and its ordered virtual country dispatch.
    pub fn change_province_owner(&mut self, province: ProvinceId, new_owner: NationId) {
        self.nations
            .common(new_owner)
            .expect("province owner change requires the new owner to be present");

        let old_owner = self.map.provinces[province]
            .owner()
            .expect("province owner change requires a current owner");
        let linked_tiles = self.map.provinces[province].linked_tiles.clone();

        for &tile in &linked_tiles {
            self.map.set_owner(&mut self.nations, tile, new_owner);
        }
        self.map.provinces[province].set_owner(Some(new_owner));

        if let Some(old_owner) = NationId::as_major(old_owner) {
            if let Some(auto) = self.nations.majors[&old_owner].auto.as_mut() {
                if let Some(id) = self.missions.iter().find_map(|(&id, mission)| {
                    (mission.nation == old_owner.nation()
                        && matches!(
                            &mission.data,
                            MissionData::DefendProvince { province: target, .. }
                                if *target == province
                        ))
                    .then_some(id)
                }) {
                    self.missions.shift_remove(&id);
                }
                auto.province_targets[province] = AiTargetState::Unmarked;
            }
            self.nations.majors[&old_owner].lose_province(
                old_owner,
                province,
                &self.map,
                &mut self.civilian_units,
                &mut self.military_units,
                &mut self.missions,
            );
        } else {
            let old_owner = old_owner.expect_minor();
            self.nations
                .minors
                .get_mut(&old_owner)
                .expect("owned province requires its minor nation to be present")
                .lose_province(province);
            self.handle_minor_province_loss(&linked_tiles, new_owner);
        }

        if let Some(new_owner) = NationId::as_major(new_owner) {
            self.nations.majors[&new_owner].add_province(province);
            if self.nations.majors[&new_owner].is_auto() {
                let available = self.province_mission_node_available(province, new_owner);
                let targets = &mut self.nations.majors[&new_owner]
                    .auto
                    .as_mut()
                    .expect("automatic great power requires auto state")
                    .province_targets;
                targets[province] = if available {
                    AiTargetState::Candidate
                } else {
                    AiTargetState::Unmarked
                };
                if available {
                    let id = self.object_ids.mission();
                    self.insert_mission(
                        id,
                        MissionState {
                            nation: new_owner.nation(),
                            data: MissionData::DefendProvince {
                                province,
                                army: ArmyMissionState {
                                    required_equipage_bits: [0; 5],
                                    units: IndexSet::new(),
                                },
                            },
                            path_nation: None,
                            state: 2,
                            importance_bits: 0,
                            held: false,
                            marker: 0,
                        },
                    );
                    self.nations.majors[&new_owner]
                        .auto
                        .as_mut()
                        .expect("automatic great power requires auto state")
                        .province_targets[province] = AiTargetState::MissionQueued;
                }
            }
        } else {
            self.nations
                .minors
                .get_mut(&new_owner.expect_minor())
                .expect("province owner change requires the destination minor nation")
                .add_province(province);
        }
    }

    fn handle_minor_province_loss(&mut self, linked_tiles: &[TileId], new_owner: NationId) {
        for &tile in linked_tiles {
            self.map[tile].secondary_owner_nation = None;
        }

        // `KillEnemyCiviliansIn`: developers at war are sent home; other enemy
        // civilian orders are freed. The remaining foreign majors are then deported.
        for &tile in linked_tiles {
            for id in self.civilian_units.keys().copied().collect::<Vec<_>>() {
                let Some(unit) = self.civilian_units.get(&id) else {
                    continue;
                };
                let Some(owner) = NationId::as_major(unit.owner_nation) else {
                    continue;
                };
                if unit.location.tile() != Some(tile)
                    || unit.owner_nation == new_owner
                    || self.diplomacy.relationships[new_owner][unit.owner_nation]
                        != DiplomaticRelationship::War
                {
                    continue;
                }
                if unit.unit_type == crate::CivilianUnitKind::Developer {
                    let home = self.nations.majors[&owner]
                        .common
                        .home_tile
                        .expect("foreign developer requires its owner's home town");
                    self.civilian_units
                        .get_mut(&id)
                        .expect("civilian remained present")
                        .location = crate::CivilianLocation::OnMap(home);
                } else {
                    self.civilian_units.shift_remove(&id);
                }
            }
        }

        for &tile in linked_tiles {
            for id in self.civilian_units.keys().copied().collect::<Vec<_>>() {
                let Some(unit) = self.civilian_units.get(&id) else {
                    continue;
                };
                let Some(owner) = NationId::as_major(unit.owner_nation) else {
                    continue;
                };
                if unit.location.tile() != Some(tile) || unit.owner_nation == new_owner {
                    continue;
                }
                let home = self.nations.majors[&owner]
                    .common
                    .home_tile
                    .expect("deported civilian requires its owner's home town");
                if let Some(destination) = self.find_reachable_recruit_spawn_tile(home, false) {
                    let unit = self
                        .civilian_units
                        .get_mut(&id)
                        .expect("civilian remained present");
                    unit.order = crate::CivilianWorkOrder::Idle;
                    unit.location = crate::CivilianLocation::OnMap(destination);
                } else {
                    self.civilian_units.shift_remove(&id);
                }
            }
        }
    }

    /// Changes only retail's encoded country-status field.
    ///
    /// The surrounding diplomacy, army, and province effects belong to the
    /// concrete protectorate, colony, or independence operation that invokes it.
    pub fn set_country_status(&mut self, nation: NationId, status: CountryStatus) {
        self.nations.set_country_status(nation, status);
    }

    /// Retail `TMapMgr::DoNationTerritoriesShareRegionClass`.
    ///
    /// Direct holdings are visited in their retained order. Colony holdings are
    /// appended by minor-nation slot order; protectorates do not participate.
    pub fn do_nation_territories_share_region_class(
        &self,
        nation_a: NationId,
        nation_b: NationId,
    ) -> bool {
        let mut region_class_seen = [false; REGION_CLASS_COUNT];
        let nation_a_common = self
            .nations
            .common(nation_a)
            .expect("territory comparison requires nation A to be present");
        self.mark_owned_region_classes(nation_a_common.owned_regions(), &mut region_class_seen);
        for minor in MinorNationId::all() {
            if let Some(common) = self.nations.common(minor.nation())
                && common.status().is_colony_of(nation_a)
            {
                self.mark_owned_region_classes(common.owned_regions(), &mut region_class_seen);
            }
        }

        let nation_b_common = self
            .nations
            .common(nation_b)
            .expect("territory comparison requires nation B to be present");
        if self.any_owned_region_class_seen(nation_b_common.owned_regions(), &region_class_seen) {
            return true;
        }
        for minor in MinorNationId::all() {
            if let Some(common) = self.nations.common(minor.nation())
                && common.status().is_colony_of(nation_b)
                && self.any_owned_region_class_seen(common.owned_regions(), &region_class_seen)
            {
                return true;
            }
        }
        false
    }

    /// Retail `TMapMgr::AreNationsBorderLinked`.
    ///
    /// The check is deliberately directional and compares the adjacent province's
    /// direct owner without folding colonies or protectorates into their masters.
    pub fn are_nations_border_linked(&self, nation_a: NationId, nation_b: NationId) -> bool {
        let nation_a_common = self
            .nations
            .common(nation_a)
            .expect("border comparison requires nation A to be present");
        nation_a_common.owned_regions().iter().any(|&province| {
            self.map.provinces[province]
                .adjacency()
                .iter()
                .any(|&adjacent| self.map.provinces[adjacent].owner() == Some(nation_b))
        })
    }

    fn mark_owned_region_classes(
        &self,
        owned_regions: &[ProvinceId],
        region_class_seen: &mut [bool; REGION_CLASS_COUNT],
    ) {
        for &province in owned_regions {
            let region_class = self.map.provinces[province]
                .region_class
                .expect("owned province has no region class");
            region_class_seen[usize::from(region_class)] = true;
        }
    }

    fn any_owned_region_class_seen(
        &self,
        owned_regions: &[ProvinceId],
        region_class_seen: &[bool; REGION_CLASS_COUNT],
    ) -> bool {
        owned_regions.iter().any(|&province| {
            let region_class = self.map.provinces[province]
                .region_class
                .expect("owned province has no region class");
            region_class_seen[usize::from(region_class)]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AutoGreatPowerState, MinorNation, ProvinceTable, TileContext};

    fn set_owned(state: &mut GameState, nation: NationId, provinces: &[usize]) {
        let common = state.nations.common(nation).unwrap().clone();
        let status = common.status();
        *state.nations.common_mut(nation).unwrap() = crate::NationCommonState::from_parts(
            common.display_name,
            status,
            provinces.iter().copied().map(ProvinceId::new).collect(),
            common.treasury,
            common.home_tile,
            common.trade_policy_by_nation,
        );
    }

    fn set_province(
        state: &mut GameState,
        province: usize,
        owner: Option<NationId>,
        adjacency: &[usize],
        region_class: Option<u8>,
    ) {
        let adjacent: Vec<ProvinceId> = adjacency.iter().copied().map(ProvinceId::new).collect();
        let mut row = crate::test_support::owned_province(
            owner.expect("territory fixture provinces are owned"),
            &adjacent,
        );
        row.region_class = region_class;
        state.map.provinces[ProvinceId::new(province)] = row;
    }

    fn add_minor(
        state: &mut GameState,
        minor: MinorNationId,
        status: CountryStatus,
        owned: &[usize],
    ) {
        state.nations.minors.insert(
            minor,
            MinorNation {
                common: {
                    let template = &state.nations.majors[&crate::MajorNationId::new(0)].common;
                    crate::NationCommonState::from_parts(
                        template.display_name.clone(),
                        status,
                        owned.iter().copied().map(ProvinceId::new).collect(),
                        template.treasury,
                        template.home_tile,
                        template.trade_policy_by_nation.clone(),
                    )
                },
                consortium_members: [minor; 4],
                trade: Default::default(),
            },
        );
    }

    fn gp(id: usize) -> NationId {
        MajorNationId::new(id).nation()
    }

    fn mn(id: usize) -> NationId {
        MinorNationId::new(id).nation()
    }

    #[test]
    fn province_owner_change_updates_map_country_and_town_state_in_retail_order() {
        let mut state = crate::test_support::game_state();
        state.map.provinces = ProvinceTable::default();
        set_owned(&mut state, MajorNationId::new(0).nation(), &[5, 2]);
        set_province(&mut state, 5, Some(gp(0)), &[], Some(0));
        set_province(&mut state, 2, Some(gp(0)), &[], Some(0));
        state.map.provinces[ProvinceId::new(2)].former_owner = Some(MajorNationId::new(6).nation());
        set_owned(&mut state, MajorNationId::new(1).nation(), &[9]);
        set_province(&mut state, 9, Some(gp(1)), &[], Some(0));
        for tile in [20, 21] {
            state.map[TileId::new(tile)].province = Some(ProvinceId::new(2));
            state.map[TileId::new(tile)].owner_nation =
                Some(TileContext::from(MajorNationId::new(0)));
        }
        state.map[TileId::new(20)].flags = crate::TileFlags::from_bits_retain(0x14);
        state.nations.majors[&MajorNationId::new(0)].towns.insert(
            TileId::new(20),
            crate::TownState::for_frog_city(TileId::new(20), MajorNationId::new(0).nation()),
        );
        state.map.provinces[ProvinceId::new(2)].linked_tiles =
            vec![TileId::new(20), TileId::new(21)];
        state.map[TileId::new(22)].province = Some(ProvinceId::new(5));
        state.map[TileId::new(22)].owner_nation = Some(TileContext::from(MajorNationId::new(0)));

        state.change_province_owner(ProvinceId::new(2), MajorNationId::new(1).nation());

        assert_eq!(
            state
                .nations
                .major(crate::MajorNationId::new(0))
                .common
                .owned_regions(),
            [ProvinceId::new(5)]
        );
        assert_eq!(
            state
                .nations
                .major(crate::MajorNationId::new(1))
                .common
                .owned_regions(),
            [ProvinceId::new(9), ProvinceId::new(2)]
        );
        assert_eq!(
            state.map.provinces[ProvinceId::new(2)].owner(),
            Some(MajorNationId::new(1).nation())
        );
        assert_eq!(
            state.map.provinces[ProvinceId::new(2)].former_owner(),
            Some(MajorNationId::new(6).nation())
        );
        for tile in [20, 21] {
            assert_eq!(
                state.map[TileId::new(tile)].owner_nation,
                Some(TileContext::from(MajorNationId::new(1)))
            );
        }
        assert_eq!(
            state.map[TileId::new(22)].owner_nation,
            Some(TileContext::from(MajorNationId::new(0)))
        );
        assert_eq!(state.map[TileId::new(20)].owner_border_mask, 0x3d);
        assert!(
            !state.nations.majors[&MajorNationId::new(0)]
                .towns
                .contains_key(&TileId::new(20))
        );
        let moved_town = state.nations.majors[&MajorNationId::new(1)]
            .towns
            .get(&TileId::new(20))
            .unwrap();
        assert_eq!(moved_town.owner_nation, MajorNationId::new(1).nation());
        state.change_province_owner(ProvinceId::new(9), MajorNationId::new(1).nation());
        assert_eq!(
            state
                .nations
                .major(crate::MajorNationId::new(1))
                .common
                .owned_regions(),
            [ProvinceId::new(2), ProvinceId::new(9)]
        );

        state.set_country_status(
            MajorNationId::new(1).nation(),
            CountryStatus::ProtectorateOf(MajorNationId::new(0).nation()),
        );
        assert_eq!(
            state.nations.country_status(MajorNationId::new(1).nation()),
            Some(CountryStatus::ProtectorateOf(
                MajorNationId::new(0).nation()
            ))
        );
    }

    #[test]
    fn automatic_great_power_add_queues_the_retail_defense_mission_and_reward() {
        let mut state = crate::test_support::game_state();
        state.map.provinces = ProvinceTable::default();
        set_owned(&mut state, MajorNationId::new(0).nation(), &[2]);
        set_province(&mut state, 2, Some(gp(0)), &[10], Some(0));
        state.map.provinces[ProvinceId::new(2)].linked_tiles = vec![TileId::new(20)];
        state.map[TileId::new(20)].province = Some(ProvinceId::new(2));
        state.map[TileId::new(20)].owner_nation = Some(TileContext::from(MajorNationId::new(0)));

        let destination_regions: Vec<usize> = (10..18).collect();
        set_owned(
            &mut state,
            MajorNationId::new(1).nation(),
            &destination_regions,
        );
        for province in destination_regions {
            set_province(&mut state, province, Some(gp(1)), &[], Some(0));
        }
        let destination = &mut state.nations.majors[&MajorNationId::new(1)];
        destination.auto = Some(AutoGreatPowerState::default());
        destination.economy.pending_actions.conquered_capital_armory = crate::FlagPending::Handled;
        state.civilian_units.insert(
            crate::CivilianUnitId::new(1),
            crate::CivilianUnitState::new(
                MajorNationId::new(0).nation(),
                crate::CivilianUnitKind::Miner,
                crate::CivilianLocation::OnMap(TileId::new(20)),
                crate::CivilianWorkOrder::Idle,
                MajorNationId::new(0).nation(),
                0,
                false,
            )
            .unwrap(),
        );

        state.change_province_owner(ProvinceId::new(2), MajorNationId::new(1).nation());

        assert!(state.civilian_units.is_empty());
        assert_eq!(
            state.nations.majors[&MajorNationId::new(1)]
                .common
                .owned_regions(),
            [
                ProvinceId::new(10),
                ProvinceId::new(11),
                ProvinceId::new(12),
                ProvinceId::new(13),
                ProvinceId::new(14),
                ProvinceId::new(15),
                ProvinceId::new(16),
                ProvinceId::new(17),
                ProvinceId::new(2),
            ]
        );
        let reward = state.nations.majors[&MajorNationId::new(1)]
            .economy
            .pending_actions
            .conquest_monument_armory;
        assert_eq!(reward, crate::FlagPending::Queued);
        assert_eq!(
            state.nations.majors[&MajorNationId::new(1)]
                .auto
                .as_ref()
                .unwrap()
                .province_targets[ProvinceId::new(2)],
            AiTargetState::MissionQueued
        );
        assert!(matches!(
            state.missions.values().collect::<Vec<_>>().as_slice(),
            [MissionState {
                nation,
                data: MissionData::DefendProvince { province, .. },
                ..
            }] if *nation == MajorNationId::new(1).nation() && *province == ProvinceId::new(2)
        ));
    }

    #[test]
    fn minor_loss_clears_overlay_and_deports_foreign_civilians() {
        let mut state = crate::test_support::game_state();
        state.map.provinces = ProvinceTable::default();
        add_minor(
            &mut state,
            MinorNationId::new(0),
            CountryStatus::Independent,
            &[2],
        );
        set_province(&mut state, 2, Some(mn(0)), &[], Some(0));
        state.map.provinces[ProvinceId::new(2)].linked_tiles = vec![TileId::new(20)];
        state.map[TileId::new(20)].province = Some(ProvinceId::new(2));
        state.map[TileId::new(20)].owner_nation = Some(TileContext::from(MinorNationId::new(0)));
        state.map[TileId::new(20)].secondary_owner_nation = Some(MajorNationId::new(2));
        set_owned(&mut state, MajorNationId::new(1).nation(), &[]);
        state.map[TileId::new(1)].owner_nation = Some(TileContext::from(MajorNationId::new(2)));
        state.civilian_units.insert(
            crate::CivilianUnitId::new(1),
            crate::CivilianUnitState::new(
                MajorNationId::new(2).nation(),
                crate::CivilianUnitKind::Miner,
                crate::CivilianLocation::OnMap(TileId::new(20)),
                crate::CivilianWorkOrder::Sleep,
                MajorNationId::new(2).nation(),
                0,
                false,
            )
            .unwrap(),
        );

        state.change_province_owner(ProvinceId::new(2), MajorNationId::new(1).nation());

        assert!(
            state.nations.minors[&MinorNationId::new(0)]
                .common
                .owned_regions()
                .is_empty()
        );
        assert_eq!(state.map[TileId::new(20)].secondary_owner_nation, None);
        assert_eq!(
            state.civilian_units[&crate::CivilianUnitId::new(1)].location(),
            crate::CivilianLocation::OnMap(TileId::new(1))
        );
        assert_eq!(
            state.civilian_units[&crate::CivilianUnitId::new(1)].order,
            crate::CivilianWorkOrder::Idle
        );
    }

    #[test]
    fn territory_class_comparison_includes_colonies_in_retail_order_only() {
        let mut state = crate::test_support::game_state();
        state.map.provinces = ProvinceTable::default();
        set_owned(&mut state, MajorNationId::new(0).nation(), &[9, 2]);
        set_province(&mut state, 9, Some(gp(0)), &[], Some(5));
        set_province(&mut state, 2, Some(gp(0)), &[], Some(3));
        add_minor(
            &mut state,
            MinorNationId::new(0),
            CountryStatus::ColonyOf(MajorNationId::new(0).nation()),
            &[8],
        );
        set_province(&mut state, 8, Some(mn(0)), &[], Some(7));
        add_minor(
            &mut state,
            MinorNationId::new(1),
            CountryStatus::ProtectorateOf(MajorNationId::new(0).nation()),
            &[7],
        );
        set_province(&mut state, 7, Some(mn(1)), &[], Some(11));

        set_owned(&mut state, MajorNationId::new(1).nation(), &[1]);
        set_province(&mut state, 1, Some(gp(1)), &[], Some(7));
        set_owned(&mut state, MajorNationId::new(2).nation(), &[3]);
        set_province(&mut state, 3, Some(gp(2)), &[], Some(11));
        set_owned(&mut state, MajorNationId::new(3).nation(), &[4]);
        set_province(&mut state, 4, Some(gp(3)), &[], Some(3));
        set_owned(&mut state, MajorNationId::new(4).nation(), &[5]);
        set_province(&mut state, 5, Some(gp(4)), &[], Some(13));
        add_minor(
            &mut state,
            MinorNationId::new(2),
            CountryStatus::ColonyOf(MajorNationId::new(4).nation()),
            &[6],
        );
        set_province(&mut state, 6, Some(mn(2)), &[], Some(5));

        assert!(state.do_nation_territories_share_region_class(
            MajorNationId::new(0).nation(),
            MajorNationId::new(1).nation()
        ));
        assert!(!state.do_nation_territories_share_region_class(
            MajorNationId::new(0).nation(),
            MajorNationId::new(2).nation()
        ));
        assert!(state.do_nation_territories_share_region_class(
            MajorNationId::new(0).nation(),
            MajorNationId::new(3).nation()
        ));
        assert!(state.do_nation_territories_share_region_class(
            MajorNationId::new(0).nation(),
            MajorNationId::new(4).nation()
        ));
    }

    #[test]
    fn border_link_uses_owned_and_adjacency_order_with_direct_owners() {
        let mut state = crate::test_support::game_state();
        state.map.provinces = ProvinceTable::default();
        set_owned(&mut state, MajorNationId::new(0).nation(), &[10, 4]);
        set_province(&mut state, 10, Some(gp(0)), &[12, 3], Some(0));
        set_province(&mut state, 12, Some(gp(2)), &[], Some(0));
        set_province(&mut state, 3, Some(gp(1)), &[], Some(0));
        set_province(&mut state, 4, Some(gp(0)), &[5, 6], Some(0));
        set_province(&mut state, 5, Some(gp(3)), &[], Some(0));
        set_province(&mut state, 6, Some(mn(0)), &[], Some(0));
        add_minor(
            &mut state,
            MinorNationId::new(0),
            CountryStatus::ColonyOf(MajorNationId::new(4).nation()),
            &[],
        );

        assert!(state.are_nations_border_linked(
            MajorNationId::new(0).nation(),
            MajorNationId::new(1).nation()
        ));
        assert!(state.are_nations_border_linked(
            MajorNationId::new(0).nation(),
            MajorNationId::new(3).nation()
        ));
        assert!(!state.are_nations_border_linked(
            MajorNationId::new(0).nation(),
            MajorNationId::new(4).nation()
        ));
    }

    #[test]
    fn isolated_province_is_unavailable_without_an_ocean_context() {
        let mut state = crate::test_support::game_state();
        state.map.provinces = ProvinceTable::default();
        set_owned(&mut state, MajorNationId::new(0).nation(), &[2]);
        set_province(&mut state, 2, Some(gp(0)), &[], Some(0));
        state.map.provinces[ProvinceId::new(2)].linked_tiles = vec![TileId::new(20)];
        state.map[TileId::new(20)].province = Some(ProvinceId::new(2));
        state.map[TileId::new(20)].owner_nation = Some(TileContext::from(MajorNationId::new(0)));
        set_owned(&mut state, MajorNationId::new(1).nation(), &[10]);
        set_province(&mut state, 10, Some(gp(1)), &[], Some(0));
        let destination = &mut state.nations.majors[&MajorNationId::new(1)];
        destination.auto = Some(AutoGreatPowerState::default());

        state.change_province_owner(ProvinceId::new(2), MajorNationId::new(1).nation());
        assert_eq!(
            state.nations.majors[&MajorNationId::new(1)]
                .auto
                .as_ref()
                .unwrap()
                .province_targets[ProvinceId::new(2)],
            AiTargetState::Unmarked
        );
        assert!(state.missions.is_empty());
    }

    #[test]
    fn isolated_province_is_available_when_an_ocean_context_contains_it() {
        let mut state = crate::test_support::game_state();
        state.map.provinces = ProvinceTable::default();
        set_owned(&mut state, MajorNationId::new(0).nation(), &[2]);
        set_province(&mut state, 2, Some(gp(0)), &[], Some(0));
        state.map.provinces[ProvinceId::new(2)].linked_tiles = vec![TileId::new(20)];
        state.map[TileId::new(20)].province = Some(ProvinceId::new(2));
        state.map[TileId::new(20)].owner_nation = Some(TileContext::from(MajorNationId::new(0)));
        set_owned(&mut state, MajorNationId::new(1).nation(), &[10]);
        set_province(&mut state, 10, Some(gp(1)), &[], Some(0));
        let destination = &mut state.nations.majors[&MajorNationId::new(1)];
        destination.auto = Some(AutoGreatPowerState::default());
        state.ocean.zones.push(crate::ZoneKind::Zone(crate::Zone {
            display_name: String::new(),
            status_code: None,
            target_tile: None,
            seed_owner: None,
            active_tile: None,
            primary_neighbors: Vec::new(),
            secondary_neighbors: vec![ProvinceId::new(2)],
        }));

        state.change_province_owner(ProvinceId::new(2), MajorNationId::new(1).nation());
        assert_eq!(
            state.nations.majors[&MajorNationId::new(1)]
                .auto
                .as_ref()
                .unwrap()
                .province_targets[ProvinceId::new(2)],
            AiTargetState::MissionQueued
        );
        assert!(matches!(
            state.missions.values().collect::<Vec<_>>().as_slice(),
            [MissionState {
                nation,
                data: MissionData::DefendProvince { province, .. },
                ..
            }] if *nation == MajorNationId::new(1).nation() && *province == ProvinceId::new(2)
        ));
    }

    #[test]
    fn lose_province_kills_civilians_and_off_map_units_but_keeps_stationed_military() {
        let mut state = crate::test_support::game_state();
        state.map.provinces = ProvinceTable::default();
        set_owned(&mut state, MajorNationId::new(0).nation(), &[5, 2]);
        set_province(&mut state, 5, Some(gp(0)), &[], Some(0));
        set_province(&mut state, 2, Some(gp(0)), &[], Some(0));
        set_owned(&mut state, MajorNationId::new(1).nation(), &[9]);
        set_province(&mut state, 9, Some(gp(1)), &[], Some(0));
        state.map.provinces[ProvinceId::new(2)].linked_tiles = vec![TileId::new(20)];
        state.map[TileId::new(20)].province = Some(ProvinceId::new(2));
        state.map[TileId::new(20)].owner_nation = Some(TileContext::from(MajorNationId::new(0)));
        state.civilian_units.insert(
            crate::CivilianUnitId::new(1),
            crate::CivilianUnitState::new(
                MajorNationId::new(0).nation(),
                crate::CivilianUnitKind::Miner,
                crate::CivilianLocation::OnMap(TileId::new(20)),
                crate::CivilianWorkOrder::Idle,
                MajorNationId::new(0).nation(),
                0,
                false,
            )
            .unwrap(),
        );
        let stationed = crate::MilitaryUnitId::new(1);
        let detached = crate::MilitaryUnitId::new(2);
        state.military_units.insert(
            stationed,
            crate::MilitaryUnitState::new(
                MajorNationId::new(0).nation(),
                crate::MilitaryUnitKind::Minutemen,
                Some(ProvinceId::new(2)),
                crate::MilitaryOrder::idle([None; 3], [None; 3]),
                MajorNationId::new(0).nation(),
                0,
                true,
                String::new(),
                500,
                crate::MilitaryEra::First,
                0,
                0,
            ),
        );
        state.military_units.insert(
            detached,
            crate::MilitaryUnitState::new(
                MajorNationId::new(0).nation(),
                crate::MilitaryUnitKind::Minutemen,
                None,
                crate::MilitaryOrder::idle([None; 3], [None; 3]),
                MajorNationId::new(0).nation(),
                0,
                true,
                String::new(),
                500,
                crate::MilitaryEra::First,
                0,
                0,
            ),
        );

        state.change_province_owner(ProvinceId::new(2), MajorNationId::new(1).nation());

        assert!(state.civilian_units.is_empty());
        assert_eq!(state.military_units.len(), 1);
        assert!(state.military_units.contains_key(&stationed));
        assert_eq!(
            state.military_units[&stationed].stationed_province(),
            Some(ProvinceId::new(2))
        );
    }
}
