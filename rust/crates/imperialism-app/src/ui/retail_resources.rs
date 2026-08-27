//! App-local mapping from `imperialism-core` semantic values to typed retail
//! resource identities. Loading stays in `RetailUiAssets` / `RetailAssets`.

use imperialism_core::{
    CityFacilitySlot, CivilianUnitKind, MilitaryUnitKind, ResourceKind, ShipType, Technology,
    TechnologyTable,
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
const TECHNOLOGY_STORE_PICTURES: PictureId = PictureId::new(0x08ff);
const TECHNOLOGY_HISTORY_PICTURES: PictureId = PictureId::new(0x0944);
const TECHNOLOGY_STATUS_PICTURES: PictureId = PictureId::new(0x897);
const CIVILIAN_PORTRAIT_PICTURES: PictureId = PictureId::new(0x438);
const ARMORY_PLACARD_PICTURES: PictureId = PictureId::new(0x1d9c);
const CITY_CONSTRUCTION_PICTURES: PictureId = PictureId::new(9250);
const TACTICAL_UNIT_PORTRAIT_PICTURES: PictureId = PictureId::new(0xf1e);

/// Retail ability-status frame remapping used by the technology-advance screen.
const TECHNOLOGY_STATUS_FRAME: TechnologyTable<i16> = TechnologyTable::from_array([
    0, 1, 3, 2, 7, 5, 6, 9, 10, 4, 8, 16, 12, 19, 22, 11, 17, 13, 14, 21, 15, 18, 26, 20, 23, 28,
    24, 25, 27,
]);

pub(crate) trait ShipTypeRetailResources {
    fn name_string(self) -> StringResourceId;
    fn description_string(self) -> StringResourceId;
    fn detail_picture(self) -> PictureId;
    fn navy_toolbar_picture(self) -> PictureId;
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

    fn navy_toolbar_picture(self) -> PictureId {
        PictureId::new(0x5e6).offset(i16::from(self.retail()))
    }
}

pub(crate) trait CityFacilityRetailResources {
    fn name_string(self) -> StringResourceId;
    fn construction_picture(self, level: u8) -> PictureId;
}

impl CityFacilityRetailResources for CityFacilitySlot {
    fn name_string(self) -> StringResourceId {
        CITY_BUILDING_NAMES.offset(u16::from(self.retail()))
    }

    fn construction_picture(self, level: u8) -> PictureId {
        CITY_CONSTRUCTION_PICTURES.offset(i16::from(self.retail()) * 5 + i16::from(level))
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
    fn store_idle_picture(self) -> PictureId;
    fn store_active_picture(self) -> PictureId;
    fn history_picture(self) -> PictureId;
    fn status_picture(self) -> PictureId;
}

impl TechnologyRetailResources for Technology {
    fn name_string(self) -> StringResourceId {
        TECHNOLOGY_NAMES.offset(u16::from(self.retail()))
    }

    fn description_string(self) -> StringResourceId {
        TECHNOLOGY_DESCRIPTIONS.entry(u16::from(self.retail()))
    }

    fn store_idle_picture(self) -> PictureId {
        TECHNOLOGY_STORE_PICTURES.offset(i16::from(self.retail()) * 2)
    }

    fn store_active_picture(self) -> PictureId {
        TECHNOLOGY_STORE_PICTURES.offset(i16::from(self.retail()) * 2 + 1)
    }

    fn history_picture(self) -> PictureId {
        TECHNOLOGY_HISTORY_PICTURES.offset(i16::from(self.retail()))
    }

    fn status_picture(self) -> PictureId {
        TECHNOLOGY_STATUS_PICTURES.offset(TECHNOLOGY_STATUS_FRAME[self])
    }
}

pub(crate) trait CivilianUnitKindRetailResources {
    fn name_string(self) -> StringResourceId;
    fn description_string(self) -> StringResourceId;
    fn portrait_picture(self) -> PictureId;
}

impl CivilianUnitKindRetailResources for CivilianUnitKind {
    fn name_string(self) -> StringResourceId {
        CIVILIAN_NAMES.offset(u16::from(self.retail()))
    }

    fn description_string(self) -> StringResourceId {
        CIVILIAN_DESCRIPTIONS.offset(u16::from(self.retail()))
    }

    fn portrait_picture(self) -> PictureId {
        CIVILIAN_PORTRAIT_PICTURES.offset(i16::from(self.retail()))
    }
}

pub(crate) trait MilitaryUnitKindRetailResources {
    fn name_string(self) -> StringResourceId;
    fn description_string(self) -> StringResourceId;
    fn armory_placard_picture(self) -> PictureId;
    fn tactical_portrait_picture(self, defender_side: bool) -> PictureId;
}

impl MilitaryUnitKindRetailResources for MilitaryUnitKind {
    fn name_string(self) -> StringResourceId {
        MILITARY_UNIT_NAMES.offset(u16::from(self.retail()))
    }

    fn description_string(self) -> StringResourceId {
        MILITARY_UNIT_DESCRIPTIONS.offset(u16::from(self.retail()))
    }

    fn armory_placard_picture(self) -> PictureId {
        ARMORY_PLACARD_PICTURES.offset(i16::from(self.retail()))
    }

    fn tactical_portrait_picture(self, defender_side: bool) -> PictureId {
        TACTICAL_UNIT_PORTRAIT_PICTURES
            .offset(i16::from(self.retail()) * 2 + i16::from(defender_side))
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
    fn technology_maps_to_name_description_and_pictures() {
        assert_eq!(
            Technology::CottonGin.name_string(),
            StringGroup::new(0x2712).entry(4)
        );
        assert_eq!(
            Technology::CottonGin.description_string(),
            StringGroup::new(0x274e).entry(3)
        );
        assert_eq!(
            Technology::CottonGin.store_idle_picture(),
            PictureId::new(0x08ff + 3 * 2)
        );
        assert_eq!(
            Technology::CottonGin.store_active_picture(),
            PictureId::new(0x0900 + 3 * 2)
        );
        assert_eq!(
            Technology::CottonGin.history_picture(),
            PictureId::new(0x0944 + 3)
        );
        assert_eq!(
            Technology::CottonGin.status_picture(),
            PictureId::new(0x897 + 2)
        );
    }

    #[test]
    fn civilian_unit_maps_to_name_description_and_portrait() {
        assert_eq!(
            CivilianUnitKind::Engineer.name_string(),
            StringGroup::new(0x2718).entry(5)
        );
        assert_eq!(
            CivilianUnitKind::Engineer.description_string(),
            StringGroup::new(0x2751).entry(5)
        );
        assert_eq!(
            CivilianUnitKind::Engineer.portrait_picture(),
            PictureId::new(0x438 + 5)
        );
    }

    #[test]
    fn military_unit_maps_to_name_description_and_pictures() {
        assert_eq!(
            MilitaryUnitKind::Regulars.name_string(),
            StringGroup::new(0x2717).entry(3)
        );
        assert_eq!(
            MilitaryUnitKind::Regulars.description_string(),
            StringGroup::new(0x2750).entry(3)
        );
        assert_eq!(
            MilitaryUnitKind::Regulars.armory_placard_picture(),
            PictureId::new(0x1d9c + 3)
        );
        assert_eq!(
            MilitaryUnitKind::Regulars.tactical_portrait_picture(true),
            PictureId::new(0xf1e + 3 * 2 + 1)
        );
    }

    #[test]
    fn city_facility_maps_to_construction_pictures() {
        assert_eq!(
            CityFacilitySlot::OilRefinery.construction_picture(0),
            PictureId::new(9250 + 6 * 5)
        );
        assert_eq!(
            CityFacilitySlot::Armory.construction_picture(2),
            PictureId::new(9250 + 8 * 5 + 2)
        );
    }
}
