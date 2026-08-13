//! Fixed retail recipes and cost tables for city orders.

use super::*;
use crate::*;
use enum_map::EnumMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecruitmentOrderSpec {
    pub primary: ResourceCost,
    pub secondary: Option<ResourceCost>,
    pub cash_per_unit: i16,
    pub workforce: SkillBand,
}

pub(crate) const TRANSPORT_CAPACITY_INPUTS: (ResourceKind, ResourceKind) =
    (ResourceKind::Lumber, ResourceKind::Steel);
pub(crate) const EXPANSION_INPUTS: (ResourceKind, ResourceKind) =
    (ResourceKind::Lumber, ResourceKind::Steel);

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
pub fn resource_development_yield(resource: ResourceKind, level: u8) -> i16 {
    const YIELDS: ResourceTable<[i16; 4]> = ResourceTable::from_array([
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
    ]);

    assert!(level <= 3, "resource development level must be in 0..=3");
    YIELDS[resource][level as usize]
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

pub fn ship_order_costs(ship_type: ShipType) -> ShipMaterials {
    const COSTS: ShipTypeTable<ShipMaterials> = ShipTypeTable::from_array([
        ShipMaterials {
            lumber: 0,
            fabric: 0,
            arms: 0,
            steel: 0,
            coal: 0,
            fuel: 0,
        },
        ShipMaterials {
            lumber: 4,
            fabric: 2,
            arms: 0,
            steel: 0,
            coal: 0,
            fuel: 0,
        },
        ShipMaterials {
            lumber: 7,
            fabric: 3,
            arms: 0,
            steel: 0,
            coal: 0,
            fuel: 0,
        },
        ShipMaterials {
            lumber: 5,
            fabric: 2,
            arms: 2,
            steel: 0,
            coal: 0,
            fuel: 0,
        },
        ShipMaterials {
            lumber: 8,
            fabric: 3,
            arms: 5,
            steel: 0,
            coal: 0,
            fuel: 0,
        },
        ShipMaterials {
            lumber: 6,
            fabric: 0,
            arms: 0,
            steel: 2,
            coal: 10,
            fuel: 0,
        },
        ShipMaterials {
            lumber: 6,
            fabric: 2,
            arms: 0,
            steel: 0,
            coal: 0,
            fuel: 0,
        },
        ShipMaterials {
            lumber: 6,
            fabric: 0,
            arms: 3,
            steel: 0,
            coal: 10,
            fuel: 0,
        },
        ShipMaterials {
            lumber: 4,
            fabric: 0,
            arms: 6,
            steel: 4,
            coal: 10,
            fuel: 0,
        },
        ShipMaterials {
            lumber: 8,
            fabric: 0,
            arms: 15,
            steel: 10,
            coal: 20,
            fuel: 0,
        },
        ShipMaterials {
            lumber: 0,
            fabric: 0,
            arms: 0,
            steel: 8,
            coal: 20,
            fuel: 0,
        },
        ShipMaterials {
            lumber: 2,
            fabric: 0,
            arms: 8,
            steel: 6,
            coal: 20,
            fuel: 0,
        },
        ShipMaterials {
            lumber: 0,
            fabric: 0,
            arms: 24,
            steel: 30,
            coal: 0,
            fuel: 20,
        },
        ShipMaterials {
            lumber: 0,
            fabric: 0,
            arms: 18,
            steel: 22,
            coal: 0,
            fuel: 20,
        },
    ]);

    COSTS[ship_type]
}
