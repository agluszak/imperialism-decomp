//! Typed retail picture and atlas mappings for dynamic families.
//!
//! Callers pass a game concept; this module owns the PictureId / atlas-cell
//! relation. Fixed one-off pictures stay as `PictureId::new` at the call site.

use crate::PictureId;
use enum_map::{Enum, EnumMap};
use imperialism_core::{
    CivilianUnitKind, CivilianUnitTable, MajorNationId, MajorNationTable, NationId, ResourceKind,
    ResourceTable, TileContext,
};

const OWNER_FLAG_CELL_WIDTH: i32 = 9;
const SETUP_FLAG_WIDTH: f32 = 32.0;
const SETUP_FLAG_HEIGHT: f32 = 24.0;

const DIALOG_COATS: MajorNationTable<PictureId> = MajorNationTable::from_array([
    PictureId::new(9500),
    PictureId::new(9501),
    PictureId::new(9502),
    PictureId::new(9503),
    PictureId::new(9504),
    PictureId::new(9505),
    PictureId::new(9506),
]);

const SETUP_COATS: MajorNationTable<PictureId> = MajorNationTable::from_array([
    PictureId::new(0x11c6),
    PictureId::new(0x11c7),
    PictureId::new(0x11c8),
    PictureId::new(0x11c9),
    PictureId::new(0x11ca),
    PictureId::new(0x11cb),
    PictureId::new(0x11cc),
]);

const FLEET_ATLAS: EnumMap<FleetVisualEra, MajorNationTable<PictureId>> = EnumMap::from_array([
    MajorNationTable::from_array([
        PictureId::new(1380),
        PictureId::new(1381),
        PictureId::new(1382),
        PictureId::new(1383),
        PictureId::new(1384),
        PictureId::new(1385),
        PictureId::new(1386),
    ]),
    MajorNationTable::from_array([
        PictureId::new(1387),
        PictureId::new(1388),
        PictureId::new(1389),
        PictureId::new(1390),
        PictureId::new(1391),
        PictureId::new(1392),
        PictureId::new(1393),
    ]),
    MajorNationTable::from_array([
        PictureId::new(1394),
        PictureId::new(1395),
        PictureId::new(1396),
        PictureId::new(1397),
        PictureId::new(1398),
        PictureId::new(1399),
        PictureId::new(1400),
    ]),
]);

const ARMY_COUNT_PICTURES: EnumMap<ArmyCountBucket, PictureId> = EnumMap::from_array([
    PictureId::new(570),
    PictureId::new(572),
    PictureId::new(574),
    PictureId::new(576),
]);

const OWNER_FLAG_STRIP: PictureId = PictureId::new(580);
const SETUP_FLAG_STRIP: PictureId = PictureId::new(8699);

const OWNER_FLAG_X: MajorNationTable<i32> =
    MajorNationTable::from_array([0, 9, 18, 27, 36, 45, 54]);
const NEUTRAL_OWNER_FLAG_X: i32 = 63;

const SETUP_FLAG_X: MajorNationTable<f32> =
    MajorNationTable::from_array([0.0, 32.0, 64.0, 96.0, 128.0, 160.0, 192.0]);

const CIVILIAN_IDLE: CivilianUnitTable<PictureId> = CivilianUnitTable::from_array([
    PictureId::new(402),
    PictureId::new(403),
    PictureId::new(401),
    PictureId::new(406),
    PictureId::new(400),
    PictureId::new(407),
    PictureId::new(405),
    PictureId::new(404),
    PictureId::new(408),
]);
const CIVILIAN_SELECTED: CivilianUnitTable<PictureId> = CivilianUnitTable::from_array([
    PictureId::new(411),
    PictureId::new(412),
    PictureId::new(410),
    PictureId::new(415),
    PictureId::new(409),
    PictureId::new(416),
    PictureId::new(414),
    PictureId::new(413),
    PictureId::new(417),
]);
const CIVILIAN_WORKING: CivilianUnitTable<PictureId> = CivilianUnitTable::from_array([
    PictureId::new(420),
    PictureId::new(421),
    PictureId::new(419),
    PictureId::new(424),
    PictureId::new(418),
    PictureId::new(425),
    PictureId::new(423),
    PictureId::new(422),
    PictureId::new(426),
]);
const CIVILIAN_ANIMATED: CivilianUnitTable<PictureId> = CivilianUnitTable::from_array([
    PictureId::new(14_000),
    PictureId::new(14_005),
    PictureId::new(14_011),
    PictureId::new(14_015),
    PictureId::new(14_021),
    PictureId::new(14_026),
    PictureId::new(14_030),
    PictureId::new(14_035),
    PictureId::new(14_040),
]);

const RESOURCE_ICONS: ResourceTable<PictureId> = ResourceTable::from_array([
    PictureId::new(700),
    PictureId::new(701),
    PictureId::new(702),
    PictureId::new(703),
    PictureId::new(704),
    PictureId::new(705),
    PictureId::new(706),
    PictureId::new(707),
    PictureId::new(708),
    PictureId::new(709),
    PictureId::new(710),
    PictureId::new(711),
    PictureId::new(712),
    PictureId::new(713),
    PictureId::new(714),
    PictureId::new(715),
    PictureId::new(716),
    PictureId::new(717),
    PictureId::new(718),
    PictureId::new(719),
    PictureId::new(720),
    PictureId::new(721),
    PictureId::new(722),
]);

/// Fleet sprite sheet chosen from researched naval-construction techs.
#[derive(Clone, Copy, Debug, Enum, Eq, Hash, PartialEq)]
pub enum FleetVisualEra {
    Early,
    Ironclad,
    Modern,
}

impl FleetVisualEra {
    pub fn from_research(advanced_iron_working: bool, marine_engineering: bool) -> Self {
        if marine_engineering {
            Self::Modern
        } else if advanced_iron_working {
            Self::Ironclad
        } else {
            Self::Early
        }
    }
}

/// Owner strip in the army/civilian flag atlas. Minors and missing owners share Neutral.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OwnerBadge {
    Major(MajorNationId),
    Neutral,
}

impl OwnerBadge {
    pub fn from_tile_owner(owner: Option<TileContext>) -> Self {
        match owner
            .and_then(TileContext::nation)
            .and_then(NationId::as_major)
        {
            Some(id) => Self::Major(id),
            None => Self::Neutral,
        }
    }
}

/// Displayed army-count badge on a province capital.
#[derive(Clone, Copy, Debug, Enum, Eq, Hash, PartialEq)]
pub enum ArmyCountBucket {
    Empty,
    Few,
    Several,
    Many,
}

impl ArmyCountBucket {
    pub fn from_displayed_count(displayed: u16) -> Self {
        match displayed {
            0 => Self::Empty,
            1..=5 => Self::Few,
            6..=10 => Self::Several,
            _ => Self::Many,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CivilianPosePicture {
    Idle,
    Selected,
    Working,
    Animated,
}

/// Dynamic picture families keyed by gameplay identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetailPicture {
    DialogCoat(MajorNationId),
    SetupCoat(MajorNationId),
    FleetAtlas {
        nation: MajorNationId,
        era: FleetVisualEra,
    },
    ArmyCount(ArmyCountBucket),
    OwnerFlagStrip,
    SetupFlagStrip,
    Civilian {
        kind: CivilianUnitKind,
        pose: CivilianPosePicture,
    },
    CivilianAnimation {
        kind: CivilianUnitKind,
        frame: u8,
    },
    ResourceIcon(ResourceKind),
}

pub fn retail_picture(picture: RetailPicture) -> PictureId {
    match picture {
        RetailPicture::DialogCoat(nation) => DIALOG_COATS[nation],
        RetailPicture::SetupCoat(nation) => SETUP_COATS[nation],
        RetailPicture::FleetAtlas { nation, era } => FLEET_ATLAS[era][nation],
        RetailPicture::ArmyCount(bucket) => ARMY_COUNT_PICTURES[bucket],
        RetailPicture::OwnerFlagStrip => OWNER_FLAG_STRIP,
        RetailPicture::SetupFlagStrip => SETUP_FLAG_STRIP,
        RetailPicture::Civilian { kind, pose } => match pose {
            CivilianPosePicture::Idle => CIVILIAN_IDLE[kind],
            CivilianPosePicture::Selected => CIVILIAN_SELECTED[kind],
            CivilianPosePicture::Working => CIVILIAN_WORKING[kind],
            CivilianPosePicture::Animated => CIVILIAN_ANIMATED[kind],
        },
        RetailPicture::CivilianAnimation { kind, frame } => {
            PictureId::new(CIVILIAN_ANIMATED[kind].get() + i16::from(frame))
        }
        RetailPicture::ResourceIcon(resource) => RESOURCE_ICONS[resource],
    }
}

/// One cell inside a packed retail atlas.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RetailAtlasCell {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

pub fn owner_flag_source_x(badge: OwnerBadge) -> i32 {
    match badge {
        OwnerBadge::Major(nation) => OWNER_FLAG_X[nation],
        OwnerBadge::Neutral => NEUTRAL_OWNER_FLAG_X,
    }
}

pub fn owner_flag_cell_width() -> i32 {
    OWNER_FLAG_CELL_WIDTH
}

pub fn setup_flag_cell(nation: MajorNationId) -> RetailAtlasCell {
    RetailAtlasCell {
        x: SETUP_FLAG_X[nation],
        y: 0.0,
        width: SETUP_FLAG_WIDTH,
        height: SETUP_FLAG_HEIGHT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialog_and_setup_coats_are_distinct_families() {
        assert_eq!(
            retail_picture(RetailPicture::DialogCoat(MajorNationId::new(0))),
            PictureId::new(9500)
        );
        assert_eq!(
            retail_picture(RetailPicture::DialogCoat(MajorNationId::new(6))),
            PictureId::new(9506)
        );
        assert_eq!(
            retail_picture(RetailPicture::SetupCoat(MajorNationId::new(0))),
            PictureId::new(0x11c6)
        );
        assert_eq!(
            retail_picture(RetailPicture::SetupCoat(MajorNationId::new(6))),
            PictureId::new(0x11cc)
        );
    }

    #[test]
    fn fleet_atlas_is_a_nation_by_era_table() {
        let nation = MajorNationId::new(3);
        assert_eq!(
            retail_picture(RetailPicture::FleetAtlas {
                nation,
                era: FleetVisualEra::Early,
            }),
            PictureId::new(1383)
        );
        assert_eq!(
            retail_picture(RetailPicture::FleetAtlas {
                nation,
                era: FleetVisualEra::Modern,
            }),
            PictureId::new(1397)
        );
    }

    #[test]
    fn owner_badges_do_not_use_a_flat_slot() {
        assert_eq!(
            owner_flag_source_x(OwnerBadge::from_tile_owner(Some(TileContext::from(
                MajorNationId::new(3)
            )))),
            27
        );
        assert_eq!(
            owner_flag_source_x(OwnerBadge::from_tile_owner(Some(TileContext::from(
                imperialism_core::MinorNationId::new(1)
            )))),
            NEUTRAL_OWNER_FLAG_X
        );
        assert_eq!(
            owner_flag_source_x(OwnerBadge::from_tile_owner(None)),
            NEUTRAL_OWNER_FLAG_X
        );
    }

    #[test]
    fn civilian_idle_pictures_follow_kind_not_a_class_offset() {
        assert_eq!(
            retail_picture(RetailPicture::Civilian {
                kind: CivilianUnitKind::Engineer,
                pose: CivilianPosePicture::Idle,
            }),
            PictureId::new(400)
        );
        assert_eq!(
            retail_picture(RetailPicture::Civilian {
                kind: CivilianUnitKind::Farmer,
                pose: CivilianPosePicture::Idle,
            }),
            PictureId::new(401)
        );
        assert_eq!(
            retail_picture(RetailPicture::CivilianAnimation {
                kind: CivilianUnitKind::Engineer,
                frame: 2,
            }),
            PictureId::new(14_023)
        );
    }

    #[test]
    fn resource_icons_are_a_kind_table() {
        assert_eq!(
            retail_picture(RetailPicture::ResourceIcon(ResourceKind::Cotton)),
            PictureId::new(700)
        );
        assert_eq!(
            retail_picture(RetailPicture::ResourceIcon(ResourceKind::Gold)),
            PictureId::new(722)
        );
    }
}
