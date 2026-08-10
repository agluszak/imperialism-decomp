//! Fixed retail recipes and cost tables for city orders.

use crate::*;
use super::*;
use enum_map::{Enum, EnumMap};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecruitmentOrderSpec {
    pub primary: ResourceCost,
    pub secondary: Option<ResourceCost>,
    pub cash_per_unit: i16,
    pub workforce: SkillBand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaterialOrderSpec {
    pub primary: ResourceKind,
    pub secondary: ResourceKind,
    pub production_slot: CityFacilitySlot,
}

pub const fn transport_capacity_order_spec() -> MaterialOrderSpec {
    MaterialOrderSpec {
        primary: ResourceKind::Lumber,
        secondary: ResourceKind::Steel,
        production_slot: CityFacilitySlot::Transport,
    }
}

pub const fn expansion_order_spec(_target: ExpandableFacility) -> MaterialOrderSpec {
    MaterialOrderSpec {
        primary: ResourceKind::Lumber,
        secondary: ResourceKind::Steel,
        production_slot: CityFacilitySlot::Transport,
    }
}

pub const fn item_order_spec(output: ManufacturedItem) -> ItemOrderSpec {
    let (inputs, production_slot) = match output {
        ManufacturedItem::Fabric => (
            ItemInputs::Either(ResourceKind::Wool, ResourceKind::Cotton),
            CityFacilitySlot::TextileMill,
        ),
        ManufacturedItem::Lumber => (
            ItemInputs::Double(ResourceKind::Timber),
            CityFacilitySlot::LumberMill,
        ),
        ManufacturedItem::Paper => (
            ItemInputs::Double(ResourceKind::Timber),
            CityFacilitySlot::LumberMill,
        ),
        ManufacturedItem::Steel => (
            ItemInputs::Both(ResourceKind::Iron, ResourceKind::Coal),
            CityFacilitySlot::SteelMill,
        ),
        ManufacturedItem::Fuel => (
            ItemInputs::Double(ResourceKind::Oil),
            CityFacilitySlot::OilRefinery,
        ),
        ManufacturedItem::Clothing => (
            ItemInputs::Double(ResourceKind::Fabric),
            CityFacilitySlot::ClothingFactory,
        ),
        ManufacturedItem::Furniture => (
            ItemInputs::Double(ResourceKind::Lumber),
            CityFacilitySlot::FurnitureFactory,
        ),
        ManufacturedItem::Hardware | ManufacturedItem::Arms => (
            ItemInputs::Double(ResourceKind::Steel),
            CityFacilitySlot::Metalworks,
        ),
    };
    ItemOrderSpec {
        output: output.resource(),
        inputs,
        production_slot,
    }
}

pub const fn civilian_recruitment_spec(kind: CivilianUnitKind) -> RecruitmentOrderSpec {
    let cash_per_unit = match kind {
        CivilianUnitKind::Miner => 1_500,
        CivilianUnitKind::Prospector => 500,
        CivilianUnitKind::Farmer
        | CivilianUnitKind::Forester
        | CivilianUnitKind::Rancher
        | CivilianUnitKind::Fisherman => 1_000,
        CivilianUnitKind::Engineer => 2_000,
        CivilianUnitKind::Developer => 2_000,
        CivilianUnitKind::Driller => 5_000,
    };
    RecruitmentOrderSpec {
        primary: ResourceCost::new(ResourceKind::Paper, 2),
        secondary: None,
        cash_per_unit,
        workforce: SkillBand::High,
    }
}

/// `g_anUniversityRequirementIdByRecruitRow`, retained as semantic resource kinds.
pub const CIVILIAN_RESOURCE_SPECIALTIES: CivilianUnitTable<[Option<ResourceKind>; 4]> =
    EnumMap::from_array([
        [
            Some(ResourceKind::Coal),
            Some(ResourceKind::Iron),
            Some(ResourceKind::Gems),
            Some(ResourceKind::Gold),
        ],
        [None; 4],
        [
            Some(ResourceKind::Cotton),
            Some(ResourceKind::Grain),
            Some(ResourceKind::Fruit),
            None,
        ],
        [Some(ResourceKind::Timber), None, None, None],
        [None; 4],
        [
            Some(ResourceKind::Wool),
            Some(ResourceKind::Livestock),
            None,
            None,
        ],
        [Some(ResourceKind::Fish), None, None, None],
        [None; 4],
        [Some(ResourceKind::Oil), None, None, None],
    ]);

/// `g_abUniversityRequirementLevelById` over the semantic resource domain.
pub const fn resource_development_yield(resource: ResourceKind, level: u8) -> i16 {
    const YIELDS: [[i16; 4]; ResourceKind::LENGTH] = [
        [1, 2, 3, 4],
        [1, 2, 3, 4],
        [1, 2, 3, 4],
        [0, 2, 4, 6],
        [0, 2, 4, 6],
        [1, 1, 1, 1],
        [0, 2, 4, 6],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [1, 2, 3, 4],
        [1, 2, 3, 4],
        [1, 2, 3, 4],
        [1, 2, 3, 4],
        [0, 1, 2, 3],
        [0, 1, 2, 3],
    ];

    assert!(level <= 3, "resource development level must be in 0..=3");
    YIELDS[resource as usize][level as usize]
}

pub const fn military_recruitment_category(
    unit_kind: MilitaryUnitKind,
) -> Option<MilitaryRecruitmentCategory> {
    match unit_kind {
        MilitaryUnitKind::Skirmishers
        | MilitaryUnitKind::Sharpshooters
        | MilitaryUnitKind::Rangers => Some(MilitaryRecruitmentCategory::LightInfantry),
        MilitaryUnitKind::Regulars
        | MilitaryUnitKind::RifleInfantry
        | MilitaryUnitKind::Infantry => Some(MilitaryRecruitmentCategory::RegularInfantry),
        MilitaryUnitKind::Grenadiers
        | MilitaryUnitKind::Guards
        | MilitaryUnitKind::MachineGunners => Some(MilitaryRecruitmentCategory::HeavyInfantry),
        MilitaryUnitKind::Hussars
        | MilitaryUnitKind::Scouts
        | MilitaryUnitKind::MechanizedInfantry => Some(MilitaryRecruitmentCategory::LightCavalry),
        MilitaryUnitKind::Cuirassiers
        | MilitaryUnitKind::CarbineCavalry
        | MilitaryUnitKind::Armor => Some(MilitaryRecruitmentCategory::HeavyCavalry),
        MilitaryUnitKind::LightArtillery
        | MilitaryUnitKind::FieldArtillery
        | MilitaryUnitKind::MobileArtillery => Some(MilitaryRecruitmentCategory::LightArtillery),
        MilitaryUnitKind::Artillery
        | MilitaryUnitKind::SiegeArtillery
        | MilitaryUnitKind::RailroadGuns => Some(MilitaryRecruitmentCategory::HeavyArtillery),
        MilitaryUnitKind::Sappers
        | MilitaryUnitKind::CombatEngineers
        | MilitaryUnitKind::Saboteurs => Some(MilitaryRecruitmentCategory::Demolitionist),
        MilitaryUnitKind::Minutemen
        | MilitaryUnitKind::Militia
        | MilitaryUnitKind::Conscripts
        | MilitaryUnitKind::GeneralEra1
        | MilitaryUnitKind::GeneralEra2
        | MilitaryUnitKind::GeneralEra3 => None,
    }
}

pub const fn military_recruitment_spec(
    unit_kind: MilitaryUnitKind,
) -> Option<RecruitmentOrderSpec> {
    let (primary_per_unit, secondary, cash_per_unit, workforce) = match unit_kind {
        MilitaryUnitKind::Skirmishers => (1, None, 200, SkillBand::Low),
        MilitaryUnitKind::Regulars => (1, None, 500, SkillBand::Low),
        MilitaryUnitKind::Grenadiers => (1, None, 1_000, SkillBand::Medium),
        MilitaryUnitKind::Hussars => (1, Some((ResourceKind::Horses, 1)), 100, SkillBand::Low),
        MilitaryUnitKind::Cuirassiers => {
            (1, Some((ResourceKind::Horses, 1)), 500, SkillBand::Medium)
        }
        MilitaryUnitKind::LightArtillery => {
            (2, Some((ResourceKind::Horses, 1)), 1_000, SkillBand::Medium)
        }
        MilitaryUnitKind::Artillery => (2, None, 1_000, SkillBand::Medium),
        MilitaryUnitKind::Sharpshooters | MilitaryUnitKind::RifleInfantry => {
            (2, None, 3_000, SkillBand::Low)
        }
        MilitaryUnitKind::Guards => (2, None, 4_000, SkillBand::Medium),
        MilitaryUnitKind::Scouts => (2, Some((ResourceKind::Horses, 1)), 2_000, SkillBand::Low),
        MilitaryUnitKind::CarbineCavalry => {
            (2, Some((ResourceKind::Horses, 1)), 3_500, SkillBand::Medium)
        }
        MilitaryUnitKind::FieldArtillery => {
            (4, Some((ResourceKind::Horses, 1)), 5_000, SkillBand::Medium)
        }
        MilitaryUnitKind::SiegeArtillery
        | MilitaryUnitKind::Rangers
        | MilitaryUnitKind::Infantry => (4, None, 5_000, SkillBand::Medium),
        MilitaryUnitKind::MachineGunners => (4, None, 7_000, SkillBand::Medium),
        MilitaryUnitKind::MechanizedInfantry => {
            (4, Some((ResourceKind::Fuel, 4)), 5_000, SkillBand::Medium)
        }
        MilitaryUnitKind::Armor => (10, Some((ResourceKind::Fuel, 4)), 9_000, SkillBand::Medium),
        MilitaryUnitKind::MobileArtillery => {
            (6, Some((ResourceKind::Fuel, 4)), 5_000, SkillBand::Medium)
        }
        MilitaryUnitKind::RailroadGuns => (8, None, 9_000, SkillBand::Medium),
        MilitaryUnitKind::Sappers => (2, None, 5_000, SkillBand::High),
        MilitaryUnitKind::CombatEngineers => (2, None, 7_000, SkillBand::High),
        MilitaryUnitKind::Saboteurs => (3, None, 9_000, SkillBand::High),
        MilitaryUnitKind::Minutemen
        | MilitaryUnitKind::Militia
        | MilitaryUnitKind::Conscripts
        | MilitaryUnitKind::GeneralEra1
        | MilitaryUnitKind::GeneralEra2
        | MilitaryUnitKind::GeneralEra3 => return None,
    };
    Some(RecruitmentOrderSpec {
        primary: ResourceCost::new(ResourceKind::Arms, primary_per_unit),
        secondary: match secondary {
            Some((resource, per_unit)) => Some(ResourceCost::new(resource, per_unit)),
            None => None,
        },
        cash_per_unit,
        workforce,
    })
}

pub fn ship_order_costs(ship_type: ShipType) -> ResourceTable<i16> {
    const LUMBER: [i16; 14] = [0, 4, 7, 5, 8, 6, 6, 6, 4, 8, 0, 2, 0, 0];
    const FABRIC: [i16; 14] = [0, 2, 3, 2, 3, 0, 2, 0, 0, 0, 0, 0, 0, 0];
    const ARMS: [i16; 14] = [0, 0, 0, 2, 5, 0, 0, 3, 6, 15, 0, 8, 24, 18];
    const STEEL: [i16; 14] = [0, 0, 0, 0, 0, 2, 0, 0, 4, 10, 8, 6, 30, 22];
    const COAL: [i16; 14] = [0, 0, 0, 0, 0, 10, 0, 10, 10, 20, 20, 20, 0, 0];
    const FUEL: [i16; 14] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 20];

    let mut costs = ResourceTable::default();
    let index = ship_type as usize;
    costs[ResourceKind::Lumber] = LUMBER[index];
    costs[ResourceKind::Fabric] = FABRIC[index];
    costs[ResourceKind::Arms] = ARMS[index];
    costs[ResourceKind::Steel] = STEEL[index];
    costs[ResourceKind::Coal] = COAL[index];
    costs[ResourceKind::Fuel] = FUEL[index];
    costs
}
