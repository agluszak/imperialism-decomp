//! App-local mapping from `imperialism-core` semantic values to typed retail
//! resource identities. Loading stays in `RetailUiAssets` / `RetailAssets`.

use imperialism_core::{
    CityFacilitySlot, CivilianUnitKind, MilitaryUnitKind, ResourceKind, ShipType, Technology,
};
use imperialism_formats::{PictureId, StringGroup, StringResourceId};

const CITY_BUILDING_NAMES: StringGroup = StringGroup::new(0x2719);
const SHIP_NAMES: StringGroup = StringGroup::new(0x2716);
const SHIP_DESCRIPTIONS: StringGroup = StringGroup::new(0x2752);
const RESOURCE_NAMES: StringGroup = StringGroup::new(0x2711);
const TECHNOLOGY_NAMES: StringGroup = StringGroup::new(0x2712);
const TECHNOLOGY_DESCRIPTIONS: StringGroup = StringGroup::new(0x274e);
const CIVILIAN_NAMES: StringGroup = StringGroup::new(0x2718);
const CIVILIAN_DESCRIPTIONS: StringGroup = StringGroup::new(0x2751);
const MILITARY_UNIT_NAMES: StringGroup = StringGroup::new(0x2717);
const MILITARY_UNIT_DESCRIPTIONS: StringGroup = StringGroup::new(0x2750);

const SHIP_DETAIL_PICTURES: PictureId = PictureId::new(0x266a);
const MATERIAL_PICTURES: PictureId = PictureId::new(700);

pub(crate) trait ShipTypeRetailResources {
    fn name_string(self) -> StringResourceId;
    fn description_string(self) -> StringResourceId;
    fn detail_picture(self) -> PictureId;
}

impl ShipTypeRetailResources for ShipType {
    fn name_string(self) -> StringResourceId {
        SHIP_NAMES.entry(u16::from(self.retail()) + 1)
    }

    fn description_string(self) -> StringResourceId {
        SHIP_DESCRIPTIONS.entry(u16::from(self.retail()))
    }

    fn detail_picture(self) -> PictureId {
        SHIP_DETAIL_PICTURES.offset(i16::from(self.retail()))
    }
}

pub(crate) trait CityFacilityRetailResources {
    fn name_string(self) -> StringResourceId;
}

impl CityFacilityRetailResources for CityFacilitySlot {
    fn name_string(self) -> StringResourceId {
        CITY_BUILDING_NAMES.offset(u16::from(self.retail()))
    }
}

pub(crate) trait ResourceKindRetailResources {
    fn name_string(self) -> StringResourceId;
    fn material_picture(self) -> PictureId;
}

impl ResourceKindRetailResources for ResourceKind {
    fn name_string(self) -> StringResourceId {
        RESOURCE_NAMES.offset(u16::from(self.retail()))
    }

    fn material_picture(self) -> PictureId {
        MATERIAL_PICTURES.offset(i16::from(self.retail()))
    }
}

pub(crate) trait TechnologyRetailResources {
    fn name_string(self) -> StringResourceId;
    fn description_string(self) -> StringResourceId;
}

impl TechnologyRetailResources for Technology {
    fn name_string(self) -> StringResourceId {
        TECHNOLOGY_NAMES.offset(u16::from(self.retail()))
    }

    fn description_string(self) -> StringResourceId {
        TECHNOLOGY_DESCRIPTIONS.entry(u16::from(self.retail()))
    }
}

pub(crate) trait CivilianUnitKindRetailResources {
    fn name_string(self) -> StringResourceId;
    fn description_string(self) -> StringResourceId;
}

impl CivilianUnitKindRetailResources for CivilianUnitKind {
    fn name_string(self) -> StringResourceId {
        CIVILIAN_NAMES.offset(u16::from(self.retail()))
    }

    fn description_string(self) -> StringResourceId {
        CIVILIAN_DESCRIPTIONS.offset(u16::from(self.retail()))
    }
}

pub(crate) trait MilitaryUnitKindRetailResources {
    fn name_string(self) -> StringResourceId;
    fn description_string(self) -> StringResourceId;
}

impl MilitaryUnitKindRetailResources for MilitaryUnitKind {
    fn name_string(self) -> StringResourceId {
        MILITARY_UNIT_NAMES.offset(u16::from(self.retail()))
    }

    fn description_string(self) -> StringResourceId {
        MILITARY_UNIT_DESCRIPTIONS.offset(u16::from(self.retail()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ship_type_maps_to_recovered_shipyard_resources() {
        assert_eq!(
            ShipType::Clipper.name_string(),
            StringGroup::new(0x2716).entry(7)
        );
        assert_eq!(
            ShipType::Clipper.description_string(),
            StringGroup::new(0x2752).entry(6)
        );
        assert_eq!(
            ShipType::Clipper.detail_picture(),
            PictureId::new(0x266a + 6)
        );
    }

    #[test]
    fn city_facility_maps_to_one_based_building_name_indexes() {
        assert_eq!(
            CityFacilitySlot::OilRefinery.name_string(),
            StringGroup::new(0x2719).entry(7)
        );
        assert_eq!(
            CityFacilitySlot::Shipyard.name_string(),
            StringGroup::new(0x2719).entry(8)
        );
        assert_eq!(
            CityFacilitySlot::Armory.name_string(),
            StringGroup::new(0x2719).entry(9)
        );
    }

    #[test]
    fn resource_kind_maps_to_material_name_and_picture() {
        assert_eq!(
            ResourceKind::Coal.name_string(),
            StringGroup::new(0x2711).entry(4)
        );
        assert_eq!(
            ResourceKind::Coal.material_picture(),
            PictureId::new(700 + 3)
        );
    }

    #[test]
    fn technology_maps_to_name_and_description_groups() {
        assert_eq!(
            Technology::CottonGin.name_string(),
            StringGroup::new(0x2712).entry(4)
        );
        assert_eq!(
            Technology::CottonGin.description_string(),
            StringGroup::new(0x274e).entry(3)
        );
    }

    #[test]
    fn civilian_unit_maps_to_name_and_description_groups() {
        assert_eq!(
            CivilianUnitKind::Engineer.name_string(),
            StringGroup::new(0x2718).entry(5)
        );
        assert_eq!(
            CivilianUnitKind::Engineer.description_string(),
            StringGroup::new(0x2751).entry(5)
        );
    }

    #[test]
    fn military_unit_maps_to_name_and_description_groups() {
        assert_eq!(
            MilitaryUnitKind::Regulars.name_string(),
            StringGroup::new(0x2717).entry(3)
        );
        assert_eq!(
            MilitaryUnitKind::Regulars.description_string(),
            StringGroup::new(0x2750).entry(3)
        );
    }
}
