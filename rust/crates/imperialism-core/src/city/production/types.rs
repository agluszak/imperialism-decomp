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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrderLimit {
    pub maximum: i16,
    pub constraint: ProductionConstraint,
}

impl OrderLimit {
    /// Keep this limit when `maximum` is not strictly smaller, matching retail
    /// tie-breaking that preserves the earlier constraint.
    pub fn min_with(&mut self, maximum: i16, constraint: ProductionConstraint) {
        if maximum < self.maximum {
            self.maximum = maximum;
            self.constraint = constraint;
        }
    }
}

/// Outcome of applying an absolute city-order quantity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CityOrderUpdate {
    Applied,
    Rejected(OrderLimit),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionProgress {
    pub quantity: i16,
    pub limiting_constraint: ProductionConstraint,
}

impl Default for ProductionProgress {
    fn default() -> Self {
        Self {
            quantity: 0,
            limiting_constraint: ProductionConstraint::Resources,
        }
    }
}

impl ProductionProgress {
    /// Record `limit.constraint` and commit `quantity` when it is in `0..=limit.maximum`.
    /// Returns the signed delta on success. Rejection still updates the constraint.
    pub(crate) fn try_set(&mut self, limit: OrderLimit, quantity: i16) -> Option<i16> {
        self.limiting_constraint = limit.constraint;
        self.try_set_within(limit.maximum, quantity)
    }

    /// Commit `quantity` when it is in `0..=maximum`. Returns the signed delta on success.
    pub(crate) fn try_set_within(&mut self, maximum: i16, quantity: i16) -> Option<i16> {
        let delta = quantity - self.quantity;
        if quantity > maximum || quantity < 0 {
            return None;
        }
        self.quantity = quantity;
        Some(delta)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ItemInputs {
    Double(ResourceKind),
    Both(ResourceKind, ResourceKind),
    Either(ResourceKind, ResourceKind),
}

/// Mutable state shared by ordinary item, capacity, and expansion orders.
/// Their recipes and targets are fixed retail definitions and are not copied
/// into every city snapshot.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestedCityOrderState {
    pub progress: ProductionProgress,
    pub requested_quantity: i16,
    pub tracking_by_resource: ResourceTable<i16>,
    pub accumulated_value: i32,
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

/// The six resources retail spends on a ship order.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShipMaterials {
    pub lumber: i16,
    pub fabric: i16,
    pub arms: i16,
    pub steel: i16,
    pub coal: i16,
    pub fuel: i16,
}

impl ShipMaterials {
    pub const fn iter(self) -> [(ResourceKind, i16); 6] {
        [
            (ResourceKind::Lumber, self.lumber),
            (ResourceKind::Fabric, self.fabric),
            (ResourceKind::Arms, self.arms),
            (ResourceKind::Steel, self.steel),
            (ResourceKind::Coal, self.coal),
            (ResourceKind::Fuel, self.fuel),
        ]
    }
}

impl std::ops::Index<ResourceKind> for ShipMaterials {
    type Output = i16;
    fn index(&self, resource: ResourceKind) -> &Self::Output {
        match resource {
            ResourceKind::Lumber => &self.lumber,
            ResourceKind::Fabric => &self.fabric,
            ResourceKind::Arms => &self.arms,
            ResourceKind::Steel => &self.steel,
            ResourceKind::Coal => &self.coal,
            ResourceKind::Fuel => &self.fuel,
            _ => panic!("ship materials do not include {resource:?}"),
        }
    }
}

impl std::ops::IndexMut<ResourceKind> for ShipMaterials {
    fn index_mut(&mut self, resource: ResourceKind) -> &mut Self::Output {
        match resource {
            ResourceKind::Lumber => &mut self.lumber,
            ResourceKind::Fabric => &mut self.fabric,
            ResourceKind::Arms => &mut self.arms,
            ResourceKind::Steel => &mut self.steel,
            ResourceKind::Coal => &mut self.coal,
            ResourceKind::Fuel => &mut self.fuel,
            _ => panic!("ship materials do not include {resource:?}"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShipOrderState {
    pub ship_type: ShipType,
    pub progress: ProductionProgress,
    pub materials: ShipMaterials,
}

/// Retail `TNavyOrderResourceDescriptor::StockCap`.
pub(crate) fn ship_stock_cap(ship_type: ShipType) -> i16 {
    crate::navy_orders::ship_stock_cap(ship_type)
}

/// Retail toolbar bucket ≥ 0. Merchants are -1 and `CreateNavy` returns no ship.
pub(crate) fn ship_creates_navy_object(ship_type: ShipType) -> bool {
    crate::navy_orders::ship_creates_navy_object(ship_type)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShipCapabilities {
    pub resolve_weight: i16,
    pub calculation_weight: i16,
    pub task_force_weight: i16,
    pub stock_capacity: i16,
    pub navy_priority_weight: i16,
    pub resource_weight: i16,
}

pub fn ship_capabilities(ship_type: ShipType) -> ShipCapabilities {
    crate::navy_orders::ship_capabilities(ship_type)
}

/// The one authoritative mutable order set for a city. Collection keys are
/// semantic retail identities; the private 61-pointer constructor layout is
/// decoded only at the format and C++ capture boundaries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CityOrders {
    pub items: ItemOrderTable<RequestedCityOrderState>,
    pub civilian_recruitment: CivilianUnitTable<ProductionProgress>,
    pub military_recruitment: MilitaryRecruitOrderTable<MilitaryRecruitOrderState>,
    pub ships: ShipOrderTable<ShipOrderState>,
    pub training: TrainingOrderTable<ProductionProgress>,
    pub expansions: ExpansionOrderTable<RequestedCityOrderState>,
    pub food_processing: ProductionProgress,
    pub power_plant: PowerPlantOrderState,
    pub transport_capacity: RequestedCityOrderState,
    pub population_growth: ProductionProgress,
}

#[derive(Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, PartialEq, Serialize)]
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

    pub const fn facility(self) -> CityFacilitySlot {
        match self {
            Self::Fabric => CityFacilitySlot::TextileMill,
            Self::Lumber | Self::Paper => CityFacilitySlot::LumberMill,
            Self::Steel => CityFacilitySlot::SteelMill,
            Self::Fuel => CityFacilitySlot::OilRefinery,
            Self::Clothing => CityFacilitySlot::ClothingFactory,
            Self::Furniture => CityFacilitySlot::FurnitureFactory,
            Self::Hardware | Self::Arms => CityFacilitySlot::Metalworks,
        }
    }

    pub(crate) const fn inputs(self) -> ItemInputs {
        match self {
            Self::Fabric => ItemInputs::Either(ResourceKind::Wool, ResourceKind::Cotton),
            Self::Lumber | Self::Paper => ItemInputs::Double(ResourceKind::Timber),
            Self::Steel => ItemInputs::Both(ResourceKind::Iron, ResourceKind::Coal),
            Self::Fuel => ItemInputs::Double(ResourceKind::Oil),
            Self::Clothing => ItemInputs::Double(ResourceKind::Fabric),
            Self::Furniture => ItemInputs::Double(ResourceKind::Lumber),
            Self::Hardware | Self::Arms => ItemInputs::Double(ResourceKind::Steel),
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

pub type ItemOrderTable<T> = EnumMap<ManufacturedItem, T>;

#[derive(Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, PartialEq, Serialize)]
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

pub type ExpansionOrderTable<T> = EnumMap<ExpandableFacility, T>;

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

    pub const fn fallback_for_zero_ratio_roll(roll: i32) -> Self {
        match roll % 3 {
            0 => Self::TextileMill,
            1 => Self::ClothingFactory,
            _ => Self::SteelMill,
        }
    }

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

pub(crate) fn military_order(unit_kind: MilitaryUnitKind) -> MilitaryRecruitOrderState {
    MilitaryRecruitOrderState {
        unit_kind,
        progress: ProductionProgress::default(),
    }
}

impl Default for CityOrders {
    fn default() -> Self {
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

        Self {
            items: ItemOrderTable::default(),
            civilian_recruitment: CivilianUnitTable::default(),
            military_recruitment,
            ships,
            training: TrainingOrderTable::default(),
            expansions: ExpansionOrderTable::default(),
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
                limiting_constraint: ProductionConstraint::Resources,
            },
            materials: ShipMaterials {
                lumber: 0,
                fabric: 0,
                arms: 0,
                steel: 0,
                coal: 0,
                fuel: 0,
            },
        }
    }
}
