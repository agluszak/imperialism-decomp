//! City production-order state types.

use crate::*;
use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionConstraint {
    Resources,
    Workforce,
    Capacity,
    Treasury,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionProgress {
    pub quantity: i16,
    pub tracking_by_resource: ResourceTable<i16>,
    pub reserved_workforce: i16,
    pub limiting_constraint: ProductionConstraint,
    pub accumulated_value: i32,
}

impl Default for ProductionProgress {
    fn default() -> Self {
        Self {
            quantity: 0,
            tracking_by_resource: ResourceTable::default(),
            reserved_workforce: 0,
            limiting_constraint: ProductionConstraint::Resources,
            accumulated_value: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemInputs {
    Double(ResourceKind),
    Both(ResourceKind, ResourceKind),
    Either(ResourceKind, ResourceKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ItemOrderSpec {
    pub output: ResourceKind,
    pub inputs: ItemInputs,
    pub production_slot: CityFacilitySlot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum CapacityTarget {
    Production(CityFacilitySlot),
    Transport,
    RegionalPopulation,
}

#[allow(dead_code)]
impl CapacityTarget {
    pub const fn slot(self) -> CityFacilitySlot {
        match self {
            Self::Production(slot) => slot,
            Self::Transport => CityFacilitySlot::Transport,
            Self::RegionalPopulation => CityFacilitySlot::RegionalPopulation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum ExpansionTarget {
    Production(CityFacilitySlot),
    RegionalPopulation,
}

#[allow(dead_code)]
impl ExpansionTarget {
    pub const fn slot(self) -> CityFacilitySlot {
        match self {
            Self::Production(slot) => slot,
            Self::RegionalPopulation => CityFacilitySlot::RegionalPopulation,
        }
    }
}

/// Mutable state shared by ordinary item, capacity, and expansion orders.
/// Their recipes and targets are fixed retail definitions and are not copied
/// into every city snapshot.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestedCityOrderState {
    pub progress: ProductionProgress,
    pub requested_quantity: i16,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PowerPlantOrderState {
    pub progress: ProductionProgress,
    pub desired_quantity: i16,
}

#[derive(Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingLevel {
    Medium,
    High,
}

impl TrainingLevel {
    pub(crate) const fn input_band(self) -> SkillBand {
        match self {
            Self::Medium => SkillBand::Low,
            Self::High => SkillBand::Medium,
        }
    }
}

pub type TrainingOrderTable<T> = EnumMap<TrainingLevel, T>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceCost {
    pub resource: ResourceKind,
    per_unit: i16,
}
impl ResourceCost {
    pub const fn new(resource: ResourceKind, per_unit: i16) -> Self {
        assert!(per_unit != 0, "resource cost per unit must be nonzero");
        Self { resource, per_unit }
    }
    pub const fn per_unit(self) -> i16 {
        self.per_unit
    }
}

/// One of the eight persistent armory categories. Technology replaces the
/// current unit recipe within a category without changing the category's
/// identity or order quantity.
#[derive(Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MilitaryRecruitmentCategory {
    LightInfantry,
    RegularInfantry,
    HeavyInfantry,
    LightCavalry,
    HeavyCavalry,
    LightArtillery,
    HeavyArtillery,
    Demolitionist,
}

pub type MilitaryRecruitOrderTable<T> = EnumMap<MilitaryRecruitmentCategory, T>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MilitaryRecruitOrderState {
    pub unit_kind: MilitaryUnitKind,
    pub progress: ProductionProgress,
}

/// The eight persistent shipyard rows. Retail upgrades the current ship type
/// in a row, so row identity and current product are both authoritative.
#[derive(Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShipOrderSlot {
    MerchantEarlyPrimary,
    MerchantEarlySecondary,
    MerchantAdvancedPrimary,
    MerchantAdvancedSecondary,
    WarshipEarlyPrimary,
    WarshipEarlySecondary,
    WarshipAdvancedPrimary,
    WarshipAdvancedSecondary,
}

pub type ShipOrderTable<T> = EnumMap<ShipOrderSlot, T>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShipOrderState {
    pub ship_type: ShipType,
    pub progress: ProductionProgress,
}

/// Retail's descriptor-derived Shipyard values, including its separate hull table.
pub const fn ship_display_stats(ship_type: ShipType) -> [i16; 6] {
    const STATS: [[i16; 6]; 14] = [
        [0, 0, 0, 0, 0, 0],
        [0, 0, 0, 25, 0, 2],
        [0, 0, 5, 40, 0, 4],
        [3, 5, 10, 35, 4, 0],
        [6, 6, 20, 65, 3, 0],
        [0, 0, 5, 35, 0, 8],
        [0, 0, 0, 25, 0, 4],
        [3, 7, 20, 30, 7, 0],
        [5, 8, 55, 50, 5, 0],
        [10, 10, 60, 70, 6, 0],
        [0, 0, 25, 45, 0, 16],
        [6, 9, 50, 40, 8, 0],
        [20, 13, 70, 115, 7, 0],
        [18, 13, 55, 90, 9, 0],
    ];

    STATS[ship_type as usize]
}

pub const fn ship_type_is_valid_for_order_slot(slot: ShipOrderSlot, ship_type: ShipType) -> bool {
    match slot {
        ShipOrderSlot::MerchantEarlyPrimary => matches!(
            ship_type,
            ShipType::NoShip | ShipType::Trader | ShipType::Paddlewheeler
        ),
        ShipOrderSlot::MerchantEarlySecondary => {
            matches!(
                ship_type,
                ShipType::NoShip | ShipType::Indiaman | ShipType::Clipper
            )
        }
        ShipOrderSlot::MerchantAdvancedPrimary => {
            matches!(
                ship_type,
                ShipType::NoShip | ShipType::Paddlewheeler | ShipType::Freighter
            )
        }
        ShipOrderSlot::MerchantAdvancedSecondary => {
            matches!(ship_type, ShipType::NoShip | ShipType::Clipper)
        }
        ShipOrderSlot::WarshipEarlyPrimary => {
            matches!(ship_type, ShipType::NoShip | ShipType::Frigate)
        }
        ShipOrderSlot::WarshipEarlySecondary => {
            matches!(ship_type, ShipType::NoShip | ShipType::ShipOfTheLine)
        }
        ShipOrderSlot::WarshipAdvancedPrimary => matches!(
            ship_type,
            ShipType::NoShip
                | ShipType::Raider
                | ShipType::ArmoredCruiser
                | ShipType::Battlecruiser
        ),
        ShipOrderSlot::WarshipAdvancedSecondary => matches!(
            ship_type,
            ShipType::NoShip
                | ShipType::Ironclad
                | ShipType::AdvancedIronclad
                | ShipType::Dreadnought
        ),
    }
}

/// The one authoritative mutable order set for a city. Collection keys are
/// semantic retail identities; the private 61-pointer constructor layout is
/// decoded only at the format and C++ capture boundaries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CityOrders {
    pub items: ResourceTable<Option<RequestedCityOrderState>>,
    pub civilian_recruitment: CivilianUnitTable<ProductionProgress>,
    pub military_recruitment: MilitaryRecruitOrderTable<MilitaryRecruitOrderState>,
    pub ships: ShipOrderTable<ShipOrderState>,
    pub training: TrainingOrderTable<ProductionProgress>,
    pub expansions: ProductionTable<Option<RequestedCityOrderState>>,
    pub food_processing: ProductionProgress,
    pub power_plant: PowerPlantOrderState,
    pub transport_capacity: RequestedCityOrderState,
    pub population_growth: ProductionProgress,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManufacturedItem {
    Fabric,
    Lumber,
    Paper,
    Steel,
    Fuel,
    Clothing,
    Furniture,
    Hardware,
    Arms,
}

impl ManufacturedItem {
    pub const ALL: [Self; 9] = [
        Self::Fabric,
        Self::Lumber,
        Self::Paper,
        Self::Steel,
        Self::Fuel,
        Self::Clothing,
        Self::Furniture,
        Self::Hardware,
        Self::Arms,
    ];

    pub const fn resource(self) -> ResourceKind {
        match self {
            Self::Fabric => ResourceKind::Fabric,
            Self::Lumber => ResourceKind::Lumber,
            Self::Paper => ResourceKind::Paper,
            Self::Steel => ResourceKind::Steel,
            Self::Fuel => ResourceKind::Fuel,
            Self::Clothing => ResourceKind::Clothing,
            Self::Furniture => ResourceKind::Furniture,
            Self::Hardware => ResourceKind::Hardware,
            Self::Arms => ResourceKind::Arms,
        }
    }

    pub const fn try_from_resource(kind: ResourceKind) -> Option<Self> {
        match kind {
            ResourceKind::Fabric => Some(Self::Fabric),
            ResourceKind::Lumber => Some(Self::Lumber),
            ResourceKind::Paper => Some(Self::Paper),
            ResourceKind::Steel => Some(Self::Steel),
            ResourceKind::Fuel => Some(Self::Fuel),
            ResourceKind::Clothing => Some(Self::Clothing),
            ResourceKind::Furniture => Some(Self::Furniture),
            ResourceKind::Hardware => Some(Self::Hardware),
            ResourceKind::Arms => Some(Self::Arms),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpandableFacility {
    TextileMill,
    ClothingFactory,
    SteelMill,
    Metalworks,
    LumberMill,
    FurnitureFactory,
    OilRefinery,
}

impl ExpandableFacility {
    pub const ALL: [Self; 7] = [
        Self::TextileMill,
        Self::ClothingFactory,
        Self::SteelMill,
        Self::Metalworks,
        Self::LumberMill,
        Self::FurnitureFactory,
        Self::OilRefinery,
    ];

    pub const fn slot(self) -> CityFacilitySlot {
        match self {
            Self::TextileMill => CityFacilitySlot::TextileMill,
            Self::ClothingFactory => CityFacilitySlot::ClothingFactory,
            Self::SteelMill => CityFacilitySlot::SteelMill,
            Self::Metalworks => CityFacilitySlot::Metalworks,
            Self::LumberMill => CityFacilitySlot::LumberMill,
            Self::FurnitureFactory => CityFacilitySlot::FurnitureFactory,
            Self::OilRefinery => CityFacilitySlot::OilRefinery,
        }
    }

    pub const fn try_from_slot(slot: CityFacilitySlot) -> Option<Self> {
        match slot {
            CityFacilitySlot::TextileMill => Some(Self::TextileMill),
            CityFacilitySlot::ClothingFactory => Some(Self::ClothingFactory),
            CityFacilitySlot::SteelMill => Some(Self::SteelMill),
            CityFacilitySlot::Metalworks => Some(Self::Metalworks),
            CityFacilitySlot::LumberMill => Some(Self::LumberMill),
            CityFacilitySlot::FurnitureFactory => Some(Self::FurnitureFactory),
            CityFacilitySlot::OilRefinery => Some(Self::OilRefinery),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CityOrderId {
    Item(ManufacturedItem),
    CivilianRecruit(CivilianUnitKind),
    MilitaryRecruit(MilitaryRecruitmentCategory),
    Ship(ShipOrderSlot),
    Training(TrainingLevel),
    Expansion(ExpandableFacility),
    FoodProcessing,
    PowerPlant,
    TransportCapacity,
    PopulationGrowth,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CityOrderStatus {
    pub quantity: i16,
    pub requested_quantity: i16,
    pub maximum: i16,
    pub limiting_constraint: ProductionConstraint,
}

/// Result of an explicit city-order quantity change.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CityOrderChange {
    Applied(CityOrderStatus),
    Rejected(CityOrderStatus),
}

impl CityOrderChange {
    pub const fn status(self) -> CityOrderStatus {
        match self {
            Self::Applied(status) | Self::Rejected(status) => status,
        }
    }

    pub const fn applied(self) -> bool {
        matches!(self, Self::Applied(_))
    }
}

pub(crate) fn military_order(unit_kind: MilitaryUnitKind) -> MilitaryRecruitOrderState {
    MilitaryRecruitOrderState {
        unit_kind,
        progress: ProductionProgress::default(),
    }
}

impl Default for CityOrders {
    fn default() -> Self {
        let mut items = ResourceTable::default();
        for output in ManufacturedItem::ALL {
            items[output.resource()] = Some(RequestedCityOrderState::default());
        }

        let military_recruitment = MilitaryRecruitOrderTable::from_array([
            military_order(MilitaryUnitKind::Skirmishers),
            military_order(MilitaryUnitKind::Regulars),
            military_order(MilitaryUnitKind::Grenadiers),
            military_order(MilitaryUnitKind::Hussars),
            military_order(MilitaryUnitKind::Cuirassiers),
            military_order(MilitaryUnitKind::LightArtillery),
            military_order(MilitaryUnitKind::Artillery),
            military_order(MilitaryUnitKind::Sappers),
        ]);

        let ships = ShipOrderTable::from_array([
            ShipOrderState::new(ShipType::Trader),
            ShipOrderState::new(ShipType::Indiaman),
            ShipOrderState::new(ShipType::NoShip),
            ShipOrderState::new(ShipType::NoShip),
            ShipOrderState::new(ShipType::Frigate),
            ShipOrderState::new(ShipType::ShipOfTheLine),
            ShipOrderState::new(ShipType::NoShip),
            ShipOrderState::new(ShipType::NoShip),
        ]);

        let mut expansions = ProductionTable::default();
        for facility in ExpandableFacility::ALL {
            expansions[facility.slot()] = Some(RequestedCityOrderState::default());
        }

        Self {
            items,
            civilian_recruitment: CivilianUnitTable::default(),
            military_recruitment,
            ships,
            training: TrainingOrderTable::default(),
            expansions,
            food_processing: ProductionProgress::default(),
            power_plant: PowerPlantOrderState::default(),
            transport_capacity: RequestedCityOrderState::default(),
            population_growth: ProductionProgress::default(),
        }
    }
}

impl ShipOrderState {
    const fn new(ship_type: ShipType) -> Self {
        Self {
            ship_type,
            progress: ProductionProgress {
                quantity: 0,
                tracking_by_resource: ResourceTable::from_array([0; ResourceKind::LENGTH]),
                reserved_workforce: 0,
                limiting_constraint: ProductionConstraint::Resources,
                accumulated_value: 0,
            },
        }
    }
}
