//! App-local mapping from `imperialism-core` semantic values to typed retail
//! resource identities. Loading stays in `RetailUiAssets` / `RetailAssets`.

use enum_map::Enum;
use imperialism_core::{
    ArmyUnitCategory, CityFacilitySlot, CivilianUnitKind, CivilianUnitTable,
    EngineerConstructionChoice, FortLevel, MilitaryOrderCode, MilitaryUnitKind, NavalAggression,
    PlayerDiplomacyRejection, ResourceKind, ShipType, TaskForceOrder, Technology, TechnologyTable,
    TurnAlert,
};
use imperialism_formats::{PictureId, SoundId, StringGroup, StringResourceId};

const CITY_BUILDING_NAMES: StringGroup = StringGroup::new(0x2719);
const CITY_CONSTRUCTION_HEADLINES: StringGroup = StringGroup::new(0x2422);
const SHIP_NAMES: StringGroup = StringGroup::new(0x2716);
const SHIP_PLURAL_NAMES: StringGroup = StringGroup::new(0x271a);
const SHIP_DESCRIPTIONS: StringGroup = StringGroup::new(0x2752);
const RESOURCE_NAMES: StringGroup = StringGroup::new(0x2711);
const TECHNOLOGY_NAMES: StringGroup = StringGroup::new(0x2712);
const TECHNOLOGY_DESCRIPTIONS: StringGroup = StringGroup::new(0x274e);
const CIVILIAN_NAMES: StringGroup = StringGroup::new(0x2718);
const CIVILIAN_DESCRIPTIONS: StringGroup = StringGroup::new(0x2751);
const CIVILIAN_WORK_ACTIONS: StringGroup = StringGroup::new(0x2725);
const CIVILIAN_DISBAND: StringGroup = StringGroup::new(0x274d);
const CIVILIAN_WORK_REPORT: StringGroup = StringGroup::new(0x2724);
const ENGINEER_CONSTRUCTION: StringGroup = StringGroup::new(0x1c20);
const MILITARY_UNIT_NAMES: StringGroup = StringGroup::new(0x2717);
const MILITARY_UNIT_DESCRIPTIONS: StringGroup = StringGroup::new(0x2750);
const TURN_ALERTS: StringGroup = StringGroup::new(0x2753);
const DIPLOMACY_NOTICES: StringGroup = StringGroup::new(0x2754);
const FLEET_REPORT: StringGroup = StringGroup::new(0x2762);
const GARRISON_ORDERS: StringGroup = StringGroup::new(0x272c);
const ARMY_COMPOSITION: StringGroup = StringGroup::new(0x2726);

const SHIP_DETAIL_PICTURES: PictureId = PictureId::new(0x266a);
const MATERIAL_PICTURES: PictureId = PictureId::new(700);
const TECHNOLOGY_STORE_PICTURES: PictureId = PictureId::new(0x08ff);
const TECHNOLOGY_HISTORY_PICTURES: PictureId = PictureId::new(0x0944);
const TECHNOLOGY_STATUS_PICTURES: PictureId = PictureId::new(0x897);
const CIVILIAN_PORTRAIT_PICTURES: PictureId = PictureId::new(0x438);
const CIVILIAN_UNIVERSITY_PREVIEW_PICTURES: PictureId = PictureId::new(400);
const ARMORY_PLACARD_PICTURES: PictureId = PictureId::new(0x1d9c);
const ARMY_TOOLBAR_PLACARD_PICTURES: PictureId = PictureId::new(0x4c4);
const CITY_CONSTRUCTION_PICTURES: PictureId = PictureId::new(9250);
const CITY_VIEW_PICTURES: PictureId = PictureId::new(7000);
const CITY_VIEW_EXPANDING_PICTURES: PictureId = PictureId::new(7300);
const CITY_HIT_MASK_PICTURES: PictureId = PictureId::new(7100);
const TACTICAL_UNIT_PORTRAIT_PICTURES: PictureId = PictureId::new(0xf1e);
const CIVILIAN_SPRITE_CLASS: CivilianUnitTable<u8> =
    CivilianUnitTable::from_array([2, 3, 1, 6, 0, 7, 5, 4, 8]);

/// Retail ability-status frame remapping used by the technology-advance screen.
const TECHNOLOGY_STATUS_FRAME: TechnologyTable<i16> = TechnologyTable::from_array([
    0, 1, 3, 2, 7, 5, 6, 9, 10, 4, 8, 16, 12, 19, 22, 11, 17, 13, 14, 21, 15, 18, 26, 20, 23, 28,
    24, 25, 27,
]);

pub(crate) trait ShipTypeRetailResources {
    fn name_string(self) -> StringResourceId;
    fn plural_name_string(self) -> StringResourceId;
    fn description_string(self) -> StringResourceId;
    fn detail_picture(self) -> PictureId;
    fn navy_toolbar_picture(self) -> PictureId;
}

impl ShipTypeRetailResources for ShipType {
    fn name_string(self) -> StringResourceId {
        SHIP_NAMES.entry(u16::from(self.retail()) + 1)
    }

    fn plural_name_string(self) -> StringResourceId {
        SHIP_PLURAL_NAMES.offset(u16::from(self.retail()))
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
    fn construction_headline_string(self) -> StringResourceId;
    fn construction_picture(self, level: u8) -> PictureId;
    fn city_view_picture(self, level: i16, expanding: bool) -> PictureId;
    fn city_hit_mask_picture(self, level: i16) -> PictureId;
}

impl CityFacilityRetailResources for CityFacilitySlot {
    fn name_string(self) -> StringResourceId {
        CITY_BUILDING_NAMES.offset(u16::from(self.retail()))
    }

    fn construction_headline_string(self) -> StringResourceId {
        StringGroup::new(CITY_CONSTRUCTION_HEADLINES.get() + u16::from(self.retail())).entry(1)
    }

    fn construction_picture(self, level: u8) -> PictureId {
        CITY_CONSTRUCTION_PICTURES.offset(i16::from(self.retail()) * 5 + i16::from(level))
    }

    fn city_view_picture(self, level: i16, expanding: bool) -> PictureId {
        let offset = i16::from(self.retail());
        let normal = level == 0 || offset > 5 || !expanding || !self.is_capacity_center();
        let base = if normal {
            CITY_VIEW_PICTURES
        } else {
            CITY_VIEW_EXPANDING_PICTURES
        };
        base.offset(level * 16 + offset)
    }

    fn city_hit_mask_picture(self, level: i16) -> PictureId {
        CITY_HIT_MASK_PICTURES.offset(level * 16 + i16::from(self.retail()))
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
    fn history_text_id(self) -> u16;
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

    fn history_text_id(self) -> u16 {
        u16::from(self.retail()) + 0x08fc
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
    fn work_action_string(self) -> StringResourceId;
    fn disband_confirmation_string(self) -> StringResourceId;
    fn work_report_template_string(self) -> StringResourceId;
    fn portrait_picture(self) -> PictureId;
    fn university_preview_picture(self) -> PictureId;
}

impl CivilianUnitKindRetailResources for CivilianUnitKind {
    fn name_string(self) -> StringResourceId {
        CIVILIAN_NAMES.offset(u16::from(self.retail()))
    }

    fn description_string(self) -> StringResourceId {
        CIVILIAN_DESCRIPTIONS.offset(u16::from(self.retail()))
    }

    fn work_action_string(self) -> StringResourceId {
        CIVILIAN_WORK_ACTIONS.offset(u16::from(self.retail()))
    }

    fn disband_confirmation_string(self) -> StringResourceId {
        CIVILIAN_DISBAND.offset(if self == CivilianUnitKind::Developer {
            5
        } else {
            4
        })
    }

    fn work_report_template_string(self) -> StringResourceId {
        CIVILIAN_WORK_REPORT.offset(if self == CivilianUnitKind::Developer {
            5
        } else {
            7
        })
    }

    fn portrait_picture(self) -> PictureId {
        CIVILIAN_PORTRAIT_PICTURES.offset(i16::from(self.retail()))
    }

    fn university_preview_picture(self) -> PictureId {
        CIVILIAN_UNIVERSITY_PREVIEW_PICTURES.offset(i16::from(CIVILIAN_SPRITE_CLASS[self]))
    }
}

pub(crate) trait EngineerConstructionChoiceRetailResources {
    fn picture(self) -> PictureId;
    fn label_string(self, fort_level: FortLevel) -> StringResourceId;
    fn confirm_sound(self) -> SoundId;
}

impl EngineerConstructionChoiceRetailResources for EngineerConstructionChoice {
    fn picture(self) -> PictureId {
        match self {
            Self::Fort => PictureId::new(0x1c2a),
            Self::Rail => PictureId::new(0x1c2c),
            Self::Port => PictureId::new(0x1c2e),
        }
    }

    fn label_string(self, fort_level: FortLevel) -> StringResourceId {
        ENGINEER_CONSTRUCTION.offset(match self {
            Self::Fort => u16::from(fort_level.retail()) + 3,
            Self::Rail => 1,
            Self::Port => 2,
        })
    }

    fn confirm_sound(self) -> SoundId {
        match self {
            Self::Fort => SoundId::new(0x232c),
            Self::Rail => SoundId::new(0x232a),
            Self::Port => SoundId::new(0x232b),
        }
    }
}

pub(crate) trait TurnAlertRetailResources {
    fn title_string(self) -> StringResourceId;
    fn body_string(self) -> StringResourceId;
}

impl TurnAlertRetailResources for TurnAlert {
    fn title_string(self) -> StringResourceId {
        TURN_ALERTS.entry(match self {
            Self::LandCapitolThreatened => 0x28,
            Self::NavalCapitolThreatened => 0x2a,
            Self::Treasury { prompt_code } => (prompt_code - 1) as u16,
            Self::CommodityShortage => 0x46,
            Self::TransportShortage => 0x22,
            Self::Starvation => 0x20,
        })
    }

    fn body_string(self) -> StringResourceId {
        TURN_ALERTS.entry(match self {
            Self::LandCapitolThreatened => 0x29,
            Self::NavalCapitolThreatened => 0x2b,
            Self::Treasury { prompt_code } => prompt_code as u16,
            Self::CommodityShortage => 0x47,
            Self::TransportShortage => 0x23,
            Self::Starvation => 0x21,
        })
    }
}

pub(crate) trait PlayerDiplomacyRejectionRetailResources {
    fn notice_string(self) -> StringResourceId;
}

impl PlayerDiplomacyRejectionRetailResources for PlayerDiplomacyRejection {
    fn notice_string(self) -> StringResourceId {
        DIPLOMACY_NOTICES.offset((self.proposal_mode() - 1) as u16)
    }
}

pub(crate) trait NavalAggressionRetailResources {
    fn fleet_report_string(self) -> StringResourceId;
}

impl NavalAggressionRetailResources for NavalAggression {
    fn fleet_report_string(self) -> StringResourceId {
        FLEET_REPORT.offset(self.retail() as u16 + 4)
    }
}

pub(crate) trait MilitaryOrderCodeRetailResources {
    fn name_string(self) -> StringResourceId;
}

impl MilitaryOrderCodeRetailResources for MilitaryOrderCode {
    fn name_string(self) -> StringResourceId {
        GARRISON_ORDERS.offset(self.get() as u16)
    }
}

pub(crate) trait ArmyUnitCategoryRetailResources {
    fn composition_name_string(self) -> StringResourceId;
}

impl ArmyUnitCategoryRetailResources for ArmyUnitCategory {
    fn composition_name_string(self) -> StringResourceId {
        ARMY_COMPOSITION.offset(self.into_usize() as u16)
    }
}

pub(crate) trait TaskForceOrderRetailResources {
    fn friendly_orders_string(self) -> StringResourceId;
}

impl TaskForceOrderRetailResources for TaskForceOrder {
    fn friendly_orders_string(self) -> StringResourceId {
        FLEET_REPORT.offset(match self {
            Self::Sail => 0xb,
            Self::Patrol => 1,
            Self::Marines => 2,
            Self::Blockade => 0x39,
            _ => 3,
        })
    }
}

pub(crate) trait MilitaryUnitKindRetailResources {
    fn name_string(self) -> StringResourceId;
    fn description_string(self) -> StringResourceId;
    fn armory_placard_picture(self) -> PictureId;
    fn army_toolbar_placard_picture(self, empty: bool) -> PictureId;
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

    fn army_toolbar_placard_picture(self, empty: bool) -> PictureId {
        let picture = ARMY_TOOLBAR_PLACARD_PICTURES.offset(i16::from(self.retail()));
        if empty { picture.offset(0x1e) } else { picture }
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
    fn technology_status_picture_uses_nonlinear_frame_table() {
        assert_eq!(
            Technology::CottonGin.status_picture(),
            PictureId::new(0x897 + 2)
        );
        assert_eq!(TECHNOLOGY_STATUS_FRAME[Technology::CottonGin], 2);
    }

    #[test]
    fn civilian_university_preview_uses_sprite_class_table() {
        assert_eq!(
            CivilianUnitKind::Engineer.university_preview_picture(),
            PictureId::new(400)
        );
        assert_eq!(
            CivilianUnitKind::Miner.university_preview_picture(),
            PictureId::new(402)
        );
        assert_eq!(CIVILIAN_SPRITE_CLASS[CivilianUnitKind::Engineer], 0);
        assert_eq!(CIVILIAN_SPRITE_CLASS[CivilianUnitKind::Miner], 2);
    }

    #[test]
    fn city_view_picture_selects_expanding_atlas_for_capacity_centers() {
        assert_eq!(
            CityFacilitySlot::TextileMill.city_view_picture(2, false),
            PictureId::new(7000 + 2 * 16)
        );
        assert_eq!(
            CityFacilitySlot::TextileMill.city_view_picture(2, true),
            PictureId::new(7300 + 2 * 16)
        );
    }

    #[test]
    fn army_toolbar_placard_applies_empty_offset() {
        assert_eq!(
            MilitaryUnitKind::Regulars.army_toolbar_placard_picture(false),
            PictureId::new(0x4c4 + 2)
        );
        assert_eq!(
            MilitaryUnitKind::Regulars.army_toolbar_placard_picture(true),
            PictureId::new(0x4c4 + 2 + 0x1e)
        );
    }

    #[test]
    fn technology_history_text_id_is_raw_text_resource() {
        assert_eq!(Technology::CottonGin.history_text_id(), 3 + 0x08fc);
    }
}
