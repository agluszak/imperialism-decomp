use crate::{
    GameState, MajorNationTable, MinorNationId, NationId, ProvinceId, ResourceTable, TileId,
};
use serde::{Deserialize, Serialize};

const REGION_CLASS_COUNT: usize = 24;
const MAX_ADJACENT_PROVINCES: usize = 12;

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
    fn is_colony_of(self, nation: NationId) -> bool {
        matches!(self, Self::ColonyOf(master) if master == nation)
    }
}

/// One entry in retail's fixed 384-record province table.
///
/// The optional fields are independent: retail has no separate active-record bit.
/// Adjacency preserves the stored prefix order and is limited to the twelve slots
/// present in each retail record.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ProvinceState {
    owner: Option<NationId>,
    former_owner: Option<NationId>,
    development_stage: i8,
    adjacency: Vec<ProvinceId>,
    region_class: Option<u8>,
    fort_level: i8,
    city_tile: Option<TileId>,
    resource_development_by_type: Box<ResourceTable<i16>>,
    explored_by_majors: MajorNationTable<bool>,
    city_score: i32,
}

impl ProvinceState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner: Option<NationId>,
        former_owner: Option<NationId>,
        development_stage: i8,
        adjacency: Vec<ProvinceId>,
        region_class: Option<u8>,
        fort_level: i8,
        city_tile: Option<TileId>,
        resource_development_by_type: ResourceTable<i16>,
        explored_by_majors: MajorNationTable<bool>,
        city_score: i32,
    ) -> Result<Self, ProvinceStateError> {
        if adjacency.len() > MAX_ADJACENT_PROVINCES {
            return Err(ProvinceStateError::TooManyAdjacentProvinces {
                actual: adjacency.len(),
            });
        }
        if let Some(region_class) = region_class
            && usize::from(region_class) >= REGION_CLASS_COUNT
        {
            return Err(ProvinceStateError::InvalidRegionClass {
                value: region_class,
            });
        }
        if !(0..=3).contains(&fort_level) {
            return Err(ProvinceStateError::InvalidFortLevel { value: fort_level });
        }
        Ok(Self {
            owner,
            former_owner,
            development_stage,
            adjacency,
            region_class,
            fort_level,
            city_tile,
            resource_development_by_type: Box::new(resource_development_by_type),
            explored_by_majors,
            city_score,
        })
    }

    pub const fn owner(&self) -> Option<NationId> {
        self.owner
    }

    pub const fn former_owner(&self) -> Option<NationId> {
        self.former_owner
    }

    pub const fn development_stage(&self) -> i8 {
        self.development_stage
    }

    pub fn adjacency(&self) -> &[ProvinceId] {
        &self.adjacency
    }

    pub const fn region_class(&self) -> Option<u8> {
        self.region_class
    }

    pub const fn fort_level(&self) -> i8 {
        self.fort_level
    }

    pub const fn city_tile(&self) -> Option<TileId> {
        self.city_tile
    }

    pub const fn resource_development_by_type(&self) -> &ResourceTable<i16> {
        &self.resource_development_by_type
    }

    pub const fn explored_by_majors(&self) -> &MajorNationTable<bool> {
        &self.explored_by_majors
    }

    pub(crate) fn clear_explored_by_majors(&mut self) {
        self.explored_by_majors = MajorNationTable::default();
    }

    pub const fn city_score(&self) -> i32 {
        self.city_score
    }

    pub(crate) fn set_city_score(&mut self, value: i32) {
        self.city_score = value;
    }
}

impl<'de> Deserialize<'de> for ProvinceState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedProvinceState {
            #[serde(deserialize_with = "deserialize_required_option")]
            owner: Option<NationId>,
            #[serde(deserialize_with = "deserialize_required_option")]
            former_owner: Option<NationId>,
            development_stage: i8,
            adjacency: Vec<ProvinceId>,
            #[serde(deserialize_with = "deserialize_required_option")]
            region_class: Option<u8>,
            fort_level: i8,
            #[serde(deserialize_with = "deserialize_required_option")]
            city_tile: Option<TileId>,
            resource_development_by_type: ResourceTable<i16>,
            explored_by_majors: MajorNationTable<bool>,
            city_score: i32,
        }

        let province = SerializedProvinceState::deserialize(deserializer)?;
        Self::new(
            province.owner,
            province.former_owner,
            province.development_stage,
            province.adjacency,
            province.region_class,
            province.fort_level,
            province.city_tile,
            province.resource_development_by_type,
            province.explored_by_majors,
            province.city_score,
        )
        .map_err(serde::de::Error::custom)
    }
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProvinceStateError {
    #[error("province has {actual} adjacent provinces; maximum is {MAX_ADJACENT_PROVINCES}")]
    TooManyAdjacentProvinces { actual: usize },
    #[error("province region class {value} is outside 0..={}", REGION_CLASS_COUNT - 1)]
    InvalidRegionClass { value: u8 },
    #[error("province fort level {value} is outside 0..=3")]
    InvalidFortLevel { value: i8 },
}

impl GameState {
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
        self.mark_owned_region_classes(&nation_a_common.owned_regions, &mut region_class_seen);
        for slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = MinorNationId::new(slot);
            if let Some(common) = self.nations.common(minor.nation())
                && common.status.is_colony_of(nation_a)
            {
                self.mark_owned_region_classes(&common.owned_regions, &mut region_class_seen);
            }
        }

        let nation_b_common = self
            .nations
            .common(nation_b)
            .expect("territory comparison requires nation B to be present");
        if self.any_owned_region_class_seen(&nation_b_common.owned_regions, &region_class_seen) {
            return true;
        }
        for slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = MinorNationId::new(slot);
            if let Some(common) = self.nations.common(minor.nation())
                && common.status.is_colony_of(nation_b)
                && self.any_owned_region_class_seen(&common.owned_regions, &region_class_seen)
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
        nation_a_common.owned_regions.iter().any(|&province| {
            self.provinces[province]
                .adjacency()
                .iter()
                .any(|&adjacent| self.provinces[adjacent].owner() == Some(nation_b))
        })
    }

    fn mark_owned_region_classes(
        &self,
        owned_regions: &[ProvinceId],
        region_class_seen: &mut [bool; REGION_CLASS_COUNT],
    ) {
        for &province in owned_regions {
            let region_class = self.provinces[province]
                .region_class()
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
            let region_class = self.provinces[province]
                .region_class()
                .expect("owned province has no region class");
            region_class_seen[usize::from(region_class)]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MinorNation, ProvinceTable};

    fn set_owned(state: &mut GameState, nation: NationId, provinces: &[u16]) {
        state.nations.common_mut(nation).unwrap().owned_regions =
            provinces.iter().copied().map(ProvinceId::new).collect();
    }

    fn set_province(
        state: &mut GameState,
        province: u16,
        owner: Option<u8>,
        adjacency: &[u16],
        region_class: Option<u8>,
    ) {
        state.provinces[ProvinceId::new(province)] = ProvinceState::new(
            owner.map(NationId::new),
            owner.map(NationId::new),
            0,
            adjacency.iter().copied().map(ProvinceId::new).collect(),
            region_class,
            0,
            None,
            ResourceTable::default(),
            MajorNationTable::default(),
            0,
        )
        .unwrap();
    }

    fn add_minor(state: &mut GameState, slot: u8, status: CountryStatus, owned: &[u16]) {
        let minor = MinorNationId::new(slot);
        state.nations.minors[minor] = Some(MinorNation {
            common: crate::NationCommonState {
                status,
                owned_regions: owned.iter().copied().map(ProvinceId::new).collect(),
                ..state.nations.majors[crate::MajorNationId::new(0)]
                    .common
                    .clone()
            },
            consortium_members: [minor; 4],
            trade: Default::default(),
        });
    }

    #[test]
    fn country_status_has_one_strict_semantic_json_shape() {
        assert_eq!(
            serde_json::to_value(CountryStatus::Independent).unwrap(),
            serde_json::json!({"kind": "independent"})
        );
        assert_eq!(
            serde_json::to_value(CountryStatus::ColonyOf(NationId::new(6))).unwrap(),
            serde_json::json!({"kind": "colony_of", "nation": 6})
        );
    }

    #[test]
    fn province_state_deserialization_enforces_retail_bounds() {
        let thirteen_neighbors: Vec<u16> = (0..13).collect();
        let value = serde_json::json!({
            "owner": null,
            "former_owner": null,
            "adjacency": thirteen_neighbors,
            "region_class": null,
            "fort_level": 0,
            "city_tile": null,
            "resource_development_by_type": ResourceTable::<i16>::default(),
            "city_score": 0,
        });
        assert!(serde_json::from_value::<ProvinceState>(value).is_err());

        let value = serde_json::json!({
            "owner": null,
            "former_owner": null,
            "adjacency": [],
            "region_class": 24,
            "fort_level": 0,
            "city_tile": null,
            "resource_development_by_type": ResourceTable::<i16>::default(),
            "city_score": 0,
        });
        assert!(serde_json::from_value::<ProvinceState>(value).is_err());

        for missing in ["owner", "former_owner", "adjacency", "region_class"] {
            let mut value = serde_json::json!({
                "owner": null,
                "former_owner": null,
                "adjacency": [],
                "region_class": null,
            });
            value.as_object_mut().unwrap().remove(missing);
            assert!(
                serde_json::from_value::<ProvinceState>(value).is_err(),
                "missing {missing} must not be treated as an implicit default"
            );
        }
    }

    #[test]
    fn territory_class_comparison_includes_colonies_in_retail_order_only() {
        let mut state = crate::test_support::game_state();
        state.provinces = ProvinceTable::default();
        set_owned(&mut state, NationId::new(0), &[9, 2]);
        set_province(&mut state, 9, Some(0), &[], Some(5));
        set_province(&mut state, 2, Some(0), &[], Some(3));
        add_minor(
            &mut state,
            7,
            CountryStatus::ColonyOf(NationId::new(0)),
            &[8],
        );
        set_province(&mut state, 8, Some(7), &[], Some(7));
        add_minor(
            &mut state,
            8,
            CountryStatus::ProtectorateOf(NationId::new(0)),
            &[7],
        );
        set_province(&mut state, 7, Some(8), &[], Some(11));

        set_owned(&mut state, NationId::new(1), &[1]);
        set_province(&mut state, 1, Some(1), &[], Some(7));
        set_owned(&mut state, NationId::new(2), &[3]);
        set_province(&mut state, 3, Some(2), &[], Some(11));
        set_owned(&mut state, NationId::new(3), &[4]);
        set_province(&mut state, 4, Some(3), &[], Some(3));
        set_owned(&mut state, NationId::new(4), &[5]);
        set_province(&mut state, 5, Some(4), &[], Some(13));
        add_minor(
            &mut state,
            9,
            CountryStatus::ColonyOf(NationId::new(4)),
            &[6],
        );
        set_province(&mut state, 6, Some(9), &[], Some(5));

        assert!(state.do_nation_territories_share_region_class(NationId::new(0), NationId::new(1)));
        assert!(
            !state.do_nation_territories_share_region_class(NationId::new(0), NationId::new(2))
        );
        assert!(state.do_nation_territories_share_region_class(NationId::new(0), NationId::new(3)));
        assert!(state.do_nation_territories_share_region_class(NationId::new(0), NationId::new(4)));
    }

    #[test]
    fn border_link_uses_owned_and_adjacency_order_with_direct_owners() {
        let mut state = crate::test_support::game_state();
        state.provinces = ProvinceTable::default();
        set_owned(&mut state, NationId::new(0), &[10, 4]);
        set_province(&mut state, 10, Some(0), &[12, 3], Some(0));
        set_province(&mut state, 12, Some(2), &[], Some(0));
        set_province(&mut state, 3, Some(1), &[], Some(0));
        set_province(&mut state, 4, Some(0), &[5, 6], Some(0));
        set_province(&mut state, 5, Some(3), &[], Some(0));
        set_province(&mut state, 6, Some(7), &[], Some(0));
        add_minor(
            &mut state,
            7,
            CountryStatus::ColonyOf(NationId::new(4)),
            &[],
        );

        assert!(state.are_nations_border_linked(NationId::new(0), NationId::new(1)));
        assert!(state.are_nations_border_linked(NationId::new(0), NationId::new(3)));
        assert!(!state.are_nations_border_linked(NationId::new(0), NationId::new(4)));
    }
}
