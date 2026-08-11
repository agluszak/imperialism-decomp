//! Deterministic city production-order state and rules.

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
    pub production_slot: ProductionSlot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
enum CapacityTarget {
    Production(ProductionSlot),
    Transport,
    RegionalPopulation,
}

#[allow(dead_code)]
impl CapacityTarget {
    pub const fn slot(self) -> ProductionSlot {
        match self {
            Self::Production(slot) => slot,
            Self::Transport => ProductionSlot::Transport,
            Self::RegionalPopulation => ProductionSlot::RegionalPopulation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
enum ExpansionTarget {
    Production(ProductionSlot),
    RegionalPopulation,
}

#[allow(dead_code)]
impl ExpansionTarget {
    pub const fn slot(self) -> ProductionSlot {
        match self {
            Self::Production(slot) => slot,
            Self::RegionalPopulation => ProductionSlot::RegionalPopulation,
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
    const fn input_band(self) -> SkillBand {
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
pub enum CityOrderId {
    Item(ResourceKind),
    CivilianRecruit(CivilianUnitKind),
    MilitaryRecruit(MilitaryRecruitmentCategory),
    Ship(ShipOrderSlot),
    Training(TrainingLevel),
    Expansion(ProductionSlot),
    FoodProcessing,
    PowerPlant,
    TransportCapacity,
    PopulationGrowth,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CityOrderView {
    pub quantity: i16,
    pub requested_quantity: i16,
    pub maximum: i16,
    pub limiting_constraint: ProductionConstraint,
}

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
    pub production_slot: ProductionSlot,
}

pub const fn transport_capacity_order_spec() -> MaterialOrderSpec {
    MaterialOrderSpec {
        primary: ResourceKind::Lumber,
        secondary: ResourceKind::Steel,
        production_slot: ProductionSlot::Transport,
    }
}

pub const fn expansion_order_spec(target: ProductionSlot) -> Option<MaterialOrderSpec> {
    match target {
        ProductionSlot::TextileMill
        | ProductionSlot::ClothingFactory
        | ProductionSlot::SteelMill
        | ProductionSlot::Metalworks
        | ProductionSlot::LumberMill
        | ProductionSlot::FurnitureFactory
        | ProductionSlot::OilRefinery => Some(MaterialOrderSpec {
            primary: ResourceKind::Lumber,
            secondary: ResourceKind::Steel,
            production_slot: ProductionSlot::Transport,
        }),
        _ => None,
    }
}

pub const fn item_order_spec(output: ResourceKind) -> Option<ItemOrderSpec> {
    let (inputs, production_slot) = match output {
        ResourceKind::Fabric => (
            ItemInputs::Either(ResourceKind::Wool, ResourceKind::Cotton),
            ProductionSlot::TextileMill,
        ),
        ResourceKind::Lumber => (
            ItemInputs::Double(ResourceKind::Timber),
            ProductionSlot::LumberMill,
        ),
        ResourceKind::Paper => (
            ItemInputs::Double(ResourceKind::Timber),
            ProductionSlot::LumberMill,
        ),
        ResourceKind::Steel => (
            ItemInputs::Both(ResourceKind::Iron, ResourceKind::Coal),
            ProductionSlot::SteelMill,
        ),
        ResourceKind::Fuel => (
            ItemInputs::Double(ResourceKind::Oil),
            ProductionSlot::OilRefinery,
        ),
        ResourceKind::Clothing => (
            ItemInputs::Double(ResourceKind::Fabric),
            ProductionSlot::ClothingFactory,
        ),
        ResourceKind::Furniture => (
            ItemInputs::Double(ResourceKind::Lumber),
            ProductionSlot::FurnitureFactory,
        ),
        ResourceKind::Hardware | ResourceKind::Arms => (
            ItemInputs::Double(ResourceKind::Steel),
            ProductionSlot::Metalworks,
        ),
        _ => return None,
    };
    Some(ItemOrderSpec {
        output,
        inputs,
        production_slot,
    })
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

fn military_order(unit_kind: MilitaryUnitKind) -> MilitaryRecruitOrderState {
    MilitaryRecruitOrderState {
        unit_kind,
        progress: ProductionProgress::default(),
    }
}

impl Default for CityOrders {
    fn default() -> Self {
        let mut items = ResourceTable::default();
        for output in [
            ResourceKind::Fabric,
            ResourceKind::Lumber,
            ResourceKind::Paper,
            ResourceKind::Steel,
            ResourceKind::Fuel,
            ResourceKind::Clothing,
            ResourceKind::Furniture,
            ResourceKind::Hardware,
            ResourceKind::Arms,
        ] {
            items[output] = Some(RequestedCityOrderState::default());
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
        for slot in [
            ProductionSlot::TextileMill,
            ProductionSlot::ClothingFactory,
            ProductionSlot::SteelMill,
            ProductionSlot::Metalworks,
            ProductionSlot::LumberMill,
            ProductionSlot::FurnitureFactory,
            ProductionSlot::OilRefinery,
        ] {
            expansions[slot] = Some(RequestedCityOrderState::default());
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

fn population_growth_max_order(progress: &mut ProductionProgress, city: &CityState) -> i16 {
    let mut limit = city.stockpile[ResourceKind::Furniture] + progress.quantity;
    limit = limit.min(city.stockpile[ResourceKind::Clothing] + progress.quantity);
    limit = limit.min(city.stockpile[ResourceKind::Food] + progress.quantity);
    let capacity_limit =
        city.production_accum[ProductionSlot::RegionalPopulation] + progress.quantity;

    progress.limiting_constraint = ProductionConstraint::Resources;
    if capacity_limit < limit {
        progress.limiting_constraint = ProductionConstraint::Capacity;
        limit = capacity_limit;
    }
    limit
}

fn set_population_growth_quantity(
    progress: &mut ProductionProgress,
    city: &mut CityState,
    quantity: i16,
) -> bool {
    let delta = quantity - progress.quantity;
    if quantity > population_growth_max_order(progress, city) || quantity < 0 {
        return false;
    }
    progress.quantity = quantity;
    city.adjust_stock(ResourceKind::Furniture, -delta);
    city.adjust_stock(ResourceKind::Clothing, -delta);
    city.adjust_stock(ResourceKind::Food, -delta);
    city.production_accum[ProductionSlot::RegionalPopulation] -= delta;
    true
}

fn produce_population_growth(
    progress: &mut ProductionProgress,
    city: &mut CityState,
    owner: &GreatPowerState,
    owned_region_count: i32,
) {
    city.population.baseline_labor.low += progress.quantity;
    city.population.production_labor.low += progress.quantity;
    city.population.count += progress.quantity;

    city.production_accum[ProductionSlot::RegionalPopulation] =
        retail_region_capacity(owner, owned_region_count);
    progress.quantity = 0;
}

fn food_processing_max_order(progress: &ProductionProgress, city: &CityState) -> i16 {
    let mut limit = city.stockpile[ResourceKind::Grain] / 2;
    let animal_food = city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock];
    let workforce_limit = city.population.strength / 2;
    limit = limit.min(city.stockpile[ResourceKind::Fruit]);
    limit = limit.min(animal_food);
    limit = limit.min(workforce_limit);
    progress.quantity + limit * 2
}

fn set_food_processing_quantity(
    progress: &mut ProductionProgress,
    city: &mut CityState,
    mut quantity: i16,
) -> bool {
    if quantity & 1 != 0 {
        quantity += 1;
    }
    let previous_quantity = progress.quantity;
    if quantity > food_processing_max_order(progress, city) || quantity < 0 {
        return false;
    }
    progress.quantity = quantity;

    let half_delta = (quantity - previous_quantity) / 2;
    city.adjust_stock(ResourceKind::Grain, half_delta * -2);
    city.adjust_stock(ResourceKind::Fruit, -half_delta);
    city.population.strength -= half_delta * 2;

    let livestock_index = ResourceKind::Livestock;
    let livestock = city.stockpile[livestock_index];
    if livestock < half_delta {
        city.stockpile.set_nonnegative(livestock_index, 0);
        let fish_change = half_delta - livestock;
        city.adjust_stock(ResourceKind::Fish, -fish_change);
    } else {
        city.adjust_stock(ResourceKind::Livestock, -half_delta);
    }
    true
}

fn produce_food_processing(progress: &mut ProductionProgress, city: &mut CityState) {
    city.adjust_stock(ResourceKind::Food, progress.quantity);
    progress.quantity = 0;
    progress.reserved_workforce = 0;
}

fn capacity_max_order(
    state: &mut RequestedCityOrderState,
    city: &CityState,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
    production_slot: ProductionSlot,
) -> i16 {
    let workforce_limit = city.population.strength / 2 + state.progress.quantity;
    let production_limit = city.production_accum[production_slot] + state.progress.quantity;
    let resource_limit =
        (state.progress.tracking_by_resource[primary_input] + city.stockpile[primary_input]).min(
            state.progress.tracking_by_resource[secondary_input] + city.stockpile[secondary_input],
        );

    state.progress.limiting_constraint = ProductionConstraint::Capacity;
    let mut limit = production_limit;
    if workforce_limit < limit {
        state.progress.limiting_constraint = ProductionConstraint::Workforce;
        limit = workforce_limit;
    }
    if resource_limit < limit {
        state.progress.limiting_constraint = ProductionConstraint::Resources;
        limit = resource_limit;
    }
    limit
}

fn set_capacity_quantity(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
    production_slot: ProductionSlot,
    quantity: i16,
) -> bool {
    let delta = quantity - state.progress.quantity;
    if quantity > capacity_max_order(state, city, primary_input, secondary_input, production_slot)
        || quantity < 0
    {
        return false;
    }

    state.progress.quantity = quantity;
    state.requested_quantity = quantity;
    reserve_primary_and_secondary(
        city,
        &mut state.progress.tracking_by_resource,
        primary_input,
        Some(secondary_input),
        delta,
    );
    let workforce_change = delta * 2;
    city.population.strength -= workforce_change;
    state.progress.reserved_workforce += workforce_change;
    let production = &mut city.production_accum[production_slot];
    *production -= delta;
    true
}

fn produce_capacity(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    owner: &mut GreatPowerState,
    target: CapacityTarget,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
    owned_region_count: i32,
) {
    if state.progress.quantity == 0 {
        return;
    }

    match target {
        CapacityTarget::Transport => {
            owner.capacities.transport += state.progress.quantity;
        }
        CapacityTarget::Production(slot) => {
            let base = city.production_orders[slot];
            apply_production_increase(state, city, slot, base);
        }
        CapacityTarget::RegionalPopulation => {
            let base = retail_region_capacity(owner, owned_region_count);
            apply_production_increase(state, city, target.slot(), base);
        }
    }

    state.requested_quantity = 0;
    state.progress.quantity = 0;
    state.progress.tracking_by_resource[primary_input] = 0;
    state.progress.tracking_by_resource[secondary_input] = 0;
    state.progress.reserved_workforce = 0;
}

#[allow(dead_code)]
fn restock_capacity(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
    production_slot: ProductionSlot,
) -> bool {
    let max_order =
        capacity_max_order(state, city, primary_input, secondary_input, production_slot);
    let saved_requested_quantity = state.requested_quantity;
    state.progress.quantity = 0;
    if max_order < saved_requested_quantity
        && state.progress.limiting_constraint == ProductionConstraint::Resources
    {
        let accepted = set_capacity_quantity(
            state,
            city,
            primary_input,
            secondary_input,
            production_slot,
            max_order,
        );
        state.requested_quantity = saved_requested_quantity;
        accepted
    } else {
        set_capacity_quantity(
            state,
            city,
            primary_input,
            secondary_input,
            production_slot,
            saved_requested_quantity,
        )
    }
}

#[allow(dead_code)]
fn apply_production_increase(
    state: &RequestedCityOrderState,
    city: &mut CityState,
    slot: ProductionSlot,
    base: i16,
) {
    let new_value = base + state.progress.quantity;
    let delta = new_value - city.production_orders[slot];
    city.production_accum[slot] += delta;
    city.production_orders[slot] = new_value;
}

fn expansion_max_order(
    state: &RequestedCityOrderState,
    city: &CityState,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
) -> i16 {
    (state.progress.tracking_by_resource[primary_input] + city.stockpile[primary_input])
        .min(state.progress.tracking_by_resource[secondary_input] + city.stockpile[secondary_input])
}

fn set_expansion_quantity(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
    quantity: i16,
) -> bool {
    let delta = quantity - state.progress.quantity;
    if quantity > expansion_max_order(state, city, primary_input, secondary_input) || quantity < 0 {
        return false;
    }

    state.progress.quantity = quantity;
    state.requested_quantity = quantity;
    reserve_primary_and_secondary(
        city,
        &mut state.progress.tracking_by_resource,
        primary_input,
        Some(secondary_input),
        delta,
    );
    true
}

fn produce_expansion(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    owner: &GreatPowerState,
    target: ExpansionTarget,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
    owned_region_count: i32,
) {
    if state.progress.quantity == 0 {
        return;
    }

    let (slot, base) = match target {
        ExpansionTarget::Production(slot) => (slot, city.production_orders[slot]),
        ExpansionTarget::RegionalPopulation => (
            target.slot(),
            retail_region_capacity(owner, owned_region_count),
        ),
    };
    let new_value = base + state.progress.quantity;
    let delta = new_value - city.production_orders[slot];
    city.production_accum[slot] += delta;
    city.production_orders[slot] = new_value;

    state.requested_quantity = 0;
    state.progress.quantity = 0;
    state.progress.tracking_by_resource[primary_input] = 0;
    state.progress.tracking_by_resource[secondary_input] = 0;
}

#[allow(dead_code)]
fn restock_expansion(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    primary_input: ResourceKind,
    secondary_input: ResourceKind,
) -> bool {
    let max_order = expansion_max_order(state, city, primary_input, secondary_input);
    let saved_requested_quantity = state.requested_quantity;
    state.progress.quantity = 0;
    if max_order < saved_requested_quantity
        && state.progress.limiting_constraint == ProductionConstraint::Resources
    {
        let accepted =
            set_expansion_quantity(state, city, primary_input, secondary_input, max_order);
        state.requested_quantity = saved_requested_quantity;
        accepted
    } else {
        set_expansion_quantity(
            state,
            city,
            primary_input,
            secondary_input,
            saved_requested_quantity,
        )
    }
}

fn power_plant_max_order(state: &PowerPlantOrderState, city: &CityState) -> i16 {
    state.progress.quantity + city.stockpile[ResourceKind::Fuel] * 6
}

fn set_power_plant_quantity(
    state: &mut PowerPlantOrderState,
    city: &mut CityState,
    quantity: i16,
) -> bool {
    let delta = quantity - state.progress.quantity;
    if quantity > power_plant_max_order(state, city) || quantity < 0 {
        return false;
    }
    state.progress.quantity = quantity;

    if i32::from(city.population.strength) < -i32::from(delta) {
        state.progress.quantity -= delta;
        return false;
    }

    state.desired_quantity = quantity;
    city.adjust_stock(ResourceKind::Fuel, -(delta / 6));
    let previous_power = city.population.extra;
    city.power_available = quantity;
    city.population.extra = quantity;
    let power_change = quantity - previous_power;
    city.population.strength += power_change;
    true
}

const fn produce_power_plant(_state: &PowerPlantOrderState) {}

fn restock_power_plant(state: &mut PowerPlantOrderState, city: &mut CityState) -> bool {
    let max_order = power_plant_max_order(state, city);
    let saved_desired_quantity = state.desired_quantity;
    state.progress.quantity = 0;
    if max_order < saved_desired_quantity {
        let accepted = set_power_plant_quantity(state, city, max_order);
        state.desired_quantity = saved_desired_quantity;
        accepted
    } else {
        set_power_plant_quantity(state, city, saved_desired_quantity)
    }
}

fn training_max_order(
    level: TrainingLevel,
    progress: &mut ProductionProgress,
    city: &CityState,
    owner: &GreatPowerState,
    treasury: i32,
) -> i16 {
    let production = &city.population.production_labor;
    let (paper_per_unit, cash_per_unit, workforce_limit) = match level {
        TrainingLevel::Medium => (1_i16, 100_i32, production.low.min(city.population.strength)),
        TrainingLevel::High => (
            2_i16,
            1_000_i32,
            production.medium.min(city.population.strength / 2),
        ),
    };

    let cash_limit = if !owner.controller.is_human() {
        workforce_limit
    } else {
        let affordable = (treasury + owner.diplomacy_budget_base / 100).max(0) / cash_per_unit;
        if affordable < i32::from(workforce_limit) {
            affordable as i16
        } else {
            workforce_limit
        }
    };
    let paper_limit = city.stockpile[ResourceKind::Paper] / paper_per_unit;

    progress.limiting_constraint = ProductionConstraint::Workforce;
    let mut limit = workforce_limit;
    if cash_limit < limit {
        progress.limiting_constraint = ProductionConstraint::Treasury;
        limit = cash_limit;
    }
    if paper_limit < limit {
        progress.limiting_constraint = ProductionConstraint::Resources;
        limit = paper_limit;
    }
    if i32::from(progress.quantity) + i32::from(limit) > 99 {
        limit = 99 - progress.quantity;
    }
    progress.quantity + limit
}

fn set_training_quantity(
    level: TrainingLevel,
    progress: &mut ProductionProgress,
    city: &mut CityState,
    owner: &GreatPowerState,
    treasury: &mut i32,
    quantity: i16,
) -> bool {
    let delta = quantity - progress.quantity;
    if quantity > training_max_order(level, progress, city, owner, *treasury) || quantity < 0 {
        return false;
    }
    progress.quantity = quantity;

    let (paper_change, cash_change) = match level {
        TrainingLevel::Medium => (delta, i32::from(delta) * 100),
        TrainingLevel::High => (delta * 2, i32::from(delta) * 1_000),
    };
    city.adjust_stock(ResourceKind::Paper, -paper_change);
    *treasury -= cash_change;
    city.population.make_unavailable(level.input_band(), delta);
    true
}

fn produce_training(
    level: TrainingLevel,
    progress: &mut ProductionProgress,
    city: &mut CityState,
    owner: &mut GreatPowerState,
) {
    if progress.quantity == 0 {
        return;
    }
    let baseline = &mut city.population.baseline_labor;

    match level {
        TrainingLevel::Medium => {
            baseline.low -= progress.quantity;
            baseline.medium += progress.quantity;
        }
        TrainingLevel::High => {
            let new_level = i32::from(baseline.high) + i32::from(progress.quantity);
            if new_level >= 10 {
                let payload = if owner.pending_actions[PendingActionKind::UniversityExpansion]
                    .status()
                    < crate::PendingActionStatus::Queued
                {
                    Some(2)
                } else if new_level >= 30
                    && owner.pending_actions[PendingActionKind::UniversityExpansion].status()
                        <= crate::PendingActionStatus::Level3
                {
                    Some(3)
                } else {
                    None
                };
                if let Some(payload) = payload {
                    set_pending_action(owner, PendingActionKind::UniversityExpansion, payload);
                }
            }
            baseline.medium -= progress.quantity;
            baseline.high += progress.quantity;
        }
    }
    progress.quantity = 0;
}

#[allow(clippy::too_many_arguments)]
fn max_recruit_order(
    progress: &mut ProductionProgress,
    primary: ResourceCost,
    secondary: Option<ResourceCost>,
    cash_per_unit: i16,
    workforce: SkillBand,
    city: &CityState,
    owner: &GreatPowerState,
    treasury: i32,
) -> i16 {
    let production = &city.population.production_labor;
    let (available, divisor) = match workforce {
        SkillBand::Low => (production.low, 1),
        SkillBand::Medium => (production.medium, 2),
        SkillBand::High => (production.high, 4),
    };
    let workforce_limit = available.min(city.population.strength / divisor);

    let primary_limit = city.stockpile[primary.resource] / primary.per_unit();
    let secondary_limit = if let Some(secondary) = secondary {
        city.stockpile[secondary.resource] / secondary.per_unit()
    } else {
        primary_limit
    };
    progress.limiting_constraint = ProductionConstraint::Workforce;
    let mut limit = workforce_limit;
    if primary_limit < limit {
        progress.limiting_constraint = ProductionConstraint::Resources;
        limit = primary_limit;
    }
    if secondary_limit < limit {
        progress.limiting_constraint = ProductionConstraint::Resources;
        limit = secondary_limit;
    }
    if cash_per_unit != 0 && owner.controller.is_human() {
        let affordable =
            (owner.available_diplomacy_budget(treasury) / i32::from(cash_per_unit)).max(0);
        if affordable < i32::from(limit) {
            progress.limiting_constraint = ProductionConstraint::Treasury;
            limit = affordable as i16;
        }
    }
    progress.quantity + limit
}

#[allow(clippy::too_many_arguments)]
fn set_recruit_quantity(
    progress: &mut ProductionProgress,
    primary: ResourceCost,
    secondary: Option<ResourceCost>,
    cash_per_unit: i16,
    workforce: SkillBand,
    city: &mut CityState,
    owner: &GreatPowerState,
    treasury: &mut i32,
    quantity: i16,
) -> bool {
    let delta = quantity - progress.quantity;
    if quantity
        > max_recruit_order(
            progress,
            primary,
            secondary,
            cash_per_unit,
            workforce,
            city,
            owner,
            *treasury,
        )
        || quantity < 0
    {
        return false;
    }
    progress.quantity = quantity;

    apply_resource_cost(city, primary, delta);
    if let Some(secondary) = secondary {
        apply_resource_cost(city, secondary, delta);
    }
    city.population.remove_population(workforce, delta);
    let cash_change = i32::from(cash_per_unit) * i32::from(delta);
    *treasury -= cash_change;
    true
}

fn item_max_order(
    state: &mut RequestedCityOrderState,
    city: &CityState,
    spec: ItemOrderSpec,
) -> i16 {
    let workforce_limit = city.population.strength / 2 + state.progress.quantity;
    let production_limit = city.production_accum[spec.production_slot] + state.progress.quantity;
    let resource_limit = match spec.inputs {
        ItemInputs::Double(primary) => {
            let index = primary;
            (state.progress.tracking_by_resource[index] + city.stockpile[index]) / 2
        }
        ItemInputs::Both(primary, secondary) => {
            let primary_index = primary;
            let secondary_index = secondary;
            let primary_limit =
                state.progress.tracking_by_resource[primary_index] + city.stockpile[primary_index];
            let secondary_limit = state.progress.tracking_by_resource[secondary_index]
                + city.stockpile[secondary_index];
            primary_limit.min(secondary_limit)
        }
        ItemInputs::Either(primary, secondary) => {
            let primary_index = primary;
            let secondary_index = secondary;
            (state.progress.tracking_by_resource[secondary_index]
                + state.progress.tracking_by_resource[primary_index]
                + city.stockpile[secondary_index]
                + city.stockpile[primary_index])
                / 2
        }
    };

    state.progress.limiting_constraint = ProductionConstraint::Capacity;
    let mut limit = production_limit;
    if workforce_limit < limit {
        state.progress.limiting_constraint = ProductionConstraint::Workforce;
        limit = workforce_limit;
    }
    if resource_limit < limit {
        state.progress.limiting_constraint = ProductionConstraint::Resources;
        limit = resource_limit;
    }
    limit
}

fn set_item_quantity(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    spec: ItemOrderSpec,
    quantity: i16,
) -> bool {
    let delta = quantity - state.progress.quantity;
    if quantity > item_max_order(state, city, spec) || quantity < 0 {
        return false;
    }

    state.progress.quantity = quantity;
    state.requested_quantity = quantity;
    match spec.inputs {
        ItemInputs::Double(primary) => {
            reserve_primary_and_secondary(
                city,
                &mut state.progress.tracking_by_resource,
                primary,
                None,
                delta * 2,
            );
        }
        ItemInputs::Both(primary, secondary) => {
            reserve_primary_and_secondary(
                city,
                &mut state.progress.tracking_by_resource,
                primary,
                Some(secondary),
                delta,
            );
        }
        ItemInputs::Either(primary, secondary) => {
            let (mut primary_change, mut secondary_change) = if delta > 0 {
                (delta, delta)
            } else {
                let release = -delta;
                (release, release)
            };
            let primary_available = if delta > 0 {
                city.stockpile[primary]
            } else {
                state.progress.tracking_by_resource[primary]
            };
            let secondary_available = if delta > 0 {
                city.stockpile[secondary]
            } else {
                state.progress.tracking_by_resource[secondary]
            };

            if primary_available < primary_change {
                let shortfall = primary_change - primary_available;
                primary_change -= shortfall;
                secondary_change += shortfall;
            } else if secondary_available < secondary_change {
                let shortfall = secondary_change - secondary_available;
                secondary_change -= shortfall;
                primary_change += shortfall;
            }
            if delta < 0 {
                primary_change = -primary_change;
                secondary_change = -secondary_change;
            }
            apply_tracked_input_change(
                city,
                &mut state.progress.tracking_by_resource,
                primary,
                primary_change,
            );
            apply_tracked_input_change(
                city,
                &mut state.progress.tracking_by_resource,
                secondary,
                secondary_change,
            );
        }
    }

    let workforce_change = delta * 2;
    city.population.strength -= workforce_change;
    state.progress.reserved_workforce += workforce_change;
    let production = &mut city.production_accum[spec.production_slot];
    *production -= delta;
    true
}

fn produce_item(state: &mut RequestedCityOrderState, city: &mut CityState, spec: ItemOrderSpec) {
    let production = &mut city.production_accum[spec.production_slot];
    *production += state.progress.quantity;
    city.adjust_stock(spec.output, state.progress.quantity);
    city.rolling_item_production_score += i32::from(state.progress.quantity);
    match spec.inputs {
        ItemInputs::Double(primary) => {
            state.progress.tracking_by_resource[primary] = 0;
        }
        ItemInputs::Both(primary, secondary) | ItemInputs::Either(primary, secondary) => {
            state.progress.tracking_by_resource[primary] = 0;
            state.progress.tracking_by_resource[secondary] = 0;
        }
    }
    state.progress.reserved_workforce = 0;
    state.progress.accumulated_value += i32::from(state.progress.quantity);
}

fn restock_item(
    state: &mut RequestedCityOrderState,
    city: &mut CityState,
    spec: ItemOrderSpec,
) -> bool {
    let max_order = item_max_order(state, city, spec);
    let saved_requested_quantity = state.requested_quantity;
    state.progress.quantity = 0;
    if max_order < saved_requested_quantity
        && state.progress.limiting_constraint == ProductionConstraint::Resources
    {
        let accepted = set_item_quantity(state, city, spec, max_order);
        state.requested_quantity = saved_requested_quantity;
        accepted
    } else {
        set_item_quantity(state, city, spec, saved_requested_quantity)
    }
}

fn retail_region_capacity(owner: &GreatPowerState, owned_region_count: i32) -> i16 {
    let divisor = if owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion]
        .status()
        .has_reached(crate::PendingActionStatus::Level3)
    {
        3
    } else {
        4
    };
    let capacity = owned_region_count / divisor;
    if capacity > 1 { capacity as i16 } else { 1 }
}

fn apply_tracked_input_change(
    city: &mut CityState,
    tracking: &mut ResourceTable<i16>,
    resource: ResourceKind,
    change: i16,
) {
    city.adjust_stock(resource, -change);
    tracking[resource] += change;
}

fn reserve_primary_and_secondary(
    city: &mut CityState,
    tracking: &mut ResourceTable<i16>,
    primary: ResourceKind,
    secondary: Option<ResourceKind>,
    change: i16,
) {
    apply_tracked_input_change(city, tracking, primary, change);
    if let Some(secondary) = secondary {
        apply_tracked_input_change(city, tracking, secondary, change);
    }
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

fn ship_max_order(state: &ShipOrderState, city: &CityState) -> i16 {
    let costs = ship_order_costs(state.ship_type);
    let mut limit = 10_000_i16;
    for resource in [
        ResourceKind::Lumber,
        ResourceKind::Fabric,
        ResourceKind::Arms,
        ResourceKind::Steel,
        ResourceKind::Coal,
        ResourceKind::Fuel,
    ] {
        let cost = costs[resource];
        if cost != 0 {
            limit = limit.min(city.stockpile[resource] / cost);
        }
    }
    state.progress.quantity + limit
}

fn set_ship_quantity(state: &mut ShipOrderState, city: &mut CityState, quantity: i16) -> bool {
    let delta = quantity - state.progress.quantity;
    if quantity > ship_max_order(state, city) || quantity < 0 {
        return false;
    }
    state.progress.quantity = quantity;
    let costs = ship_order_costs(state.ship_type);
    for resource in [
        ResourceKind::Lumber,
        ResourceKind::Fabric,
        ResourceKind::Arms,
        ResourceKind::Steel,
        ResourceKind::Coal,
        ResourceKind::Fuel,
    ] {
        city.adjust_stock(resource, -(costs[resource] * delta));
    }
    true
}

fn city_order_quantity_accepted(
    orders: &mut CityOrders,
    city: &mut CityState,
    owner: &GreatPowerState,
    treasury: &mut i32,
    order: CityOrderId,
    quantity: i16,
) -> bool {
    match order {
        CityOrderId::Item(output) => {
            let spec = item_order_spec(output).expect("item order has a retail recipe");
            let state = orders.items[output]
                .as_mut()
                .expect("item order exists for every retail item recipe");
            set_item_quantity(state, city, spec, quantity)
        }
        CityOrderId::CivilianRecruit(kind) => {
            let spec = civilian_recruitment_spec(kind);
            set_recruit_quantity(
                &mut orders.civilian_recruitment[kind],
                spec.primary,
                spec.secondary,
                spec.cash_per_unit,
                spec.workforce,
                city,
                owner,
                treasury,
                quantity,
            )
        }
        CityOrderId::MilitaryRecruit(category) => {
            let state = &mut orders.military_recruitment[category];
            let spec = military_recruitment_spec(state.unit_kind)
                .expect("military order has a recruitable retail unit recipe");
            set_recruit_quantity(
                &mut state.progress,
                spec.primary,
                spec.secondary,
                spec.cash_per_unit,
                spec.workforce,
                city,
                owner,
                treasury,
                quantity,
            )
        }
        CityOrderId::Ship(track) => set_ship_quantity(&mut orders.ships[track], city, quantity),
        CityOrderId::Training(level) => set_training_quantity(
            level,
            &mut orders.training[level],
            city,
            owner,
            treasury,
            quantity,
        ),
        CityOrderId::Expansion(slot) => {
            let spec =
                expansion_order_spec(slot).expect("expansion order has a retail material recipe");
            let state = orders.expansions[slot]
                .as_mut()
                .expect("expansion order exists for every expandable production slot");
            set_expansion_quantity(state, city, spec.primary, spec.secondary, quantity)
        }
        CityOrderId::FoodProcessing => {
            set_food_processing_quantity(&mut orders.food_processing, city, quantity)
        }
        CityOrderId::PowerPlant => {
            set_power_plant_quantity(&mut orders.power_plant, city, quantity)
        }
        CityOrderId::TransportCapacity => {
            let spec = transport_capacity_order_spec();
            set_capacity_quantity(
                &mut orders.transport_capacity,
                city,
                spec.primary,
                spec.secondary,
                spec.production_slot,
                quantity,
            )
        }
        CityOrderId::PopulationGrowth => {
            set_population_growth_quantity(&mut orders.population_growth, city, quantity)
        }
    }
}

impl GameState {
    fn with_city_orders<R>(
        &mut self,
        nation: MajorNationId,
        operation: impl FnOnce(&mut CityOrders, &mut CityState, &GreatPowerState, &mut i32) -> R,
    ) -> R {
        let major = self.nations.major_mut(nation);
        let mut orders = std::mem::take(&mut major.city.orders);
        let result = operation(
            &mut orders,
            &mut major.city,
            &major.economy,
            &mut major.common.treasury,
        );
        major.city.orders = orders;
        result
    }

    /// Recomputes the retail maximum and remembered limiting constraint for a
    /// city order, then returns the projection used by city dialogs.
    pub fn refresh_city_order(
        &mut self,
        nation: MajorNationId,
        order: CityOrderId,
    ) -> CityOrderView {
        self.with_city_orders(nation, |orders, city, owner, treasury| {
            let (progress, requested_quantity, maximum) = match order {
                CityOrderId::Item(output) => {
                    let spec = item_order_spec(output).expect("item order has a retail recipe");
                    let state = orders.items[output]
                        .as_mut()
                        .expect("item order exists for every retail item recipe");
                    let maximum = item_max_order(state, city, spec);
                    (&state.progress, state.requested_quantity, maximum)
                }
                CityOrderId::CivilianRecruit(kind) => {
                    let spec = civilian_recruitment_spec(kind);
                    let progress = &mut orders.civilian_recruitment[kind];
                    let maximum = max_recruit_order(
                        progress,
                        spec.primary,
                        spec.secondary,
                        spec.cash_per_unit,
                        spec.workforce,
                        city,
                        owner,
                        *treasury,
                    );
                    (&*progress, progress.quantity, maximum)
                }
                CityOrderId::MilitaryRecruit(category) => {
                    let state = &mut orders.military_recruitment[category];
                    let spec = military_recruitment_spec(state.unit_kind)
                        .expect("military order has a recruitable retail unit recipe");
                    let maximum = max_recruit_order(
                        &mut state.progress,
                        spec.primary,
                        spec.secondary,
                        spec.cash_per_unit,
                        spec.workforce,
                        city,
                        owner,
                        *treasury,
                    );
                    (&state.progress, state.progress.quantity, maximum)
                }
                CityOrderId::Ship(track) => {
                    let state = &orders.ships[track];
                    let maximum = ship_max_order(state, city);
                    (&state.progress, state.progress.quantity, maximum)
                }
                CityOrderId::Training(level) => {
                    let progress = &mut orders.training[level];
                    let maximum = training_max_order(level, progress, city, owner, *treasury);
                    (&*progress, progress.quantity, maximum)
                }
                CityOrderId::Expansion(slot) => {
                    let spec = expansion_order_spec(slot)
                        .expect("expansion order has a retail material recipe");
                    let state = orders.expansions[slot]
                        .as_mut()
                        .expect("expansion order exists for every expandable production slot");
                    let maximum = expansion_max_order(state, city, spec.primary, spec.secondary);
                    (&state.progress, state.requested_quantity, maximum)
                }
                CityOrderId::FoodProcessing => {
                    let progress = &orders.food_processing;
                    let maximum = food_processing_max_order(progress, city);
                    (progress, progress.quantity, maximum)
                }
                CityOrderId::PowerPlant => {
                    let state = &orders.power_plant;
                    let maximum = power_plant_max_order(state, city);
                    (&state.progress, state.desired_quantity, maximum)
                }
                CityOrderId::TransportCapacity => {
                    let spec = transport_capacity_order_spec();
                    let state = &mut orders.transport_capacity;
                    let maximum = capacity_max_order(
                        state,
                        city,
                        spec.primary,
                        spec.secondary,
                        spec.production_slot,
                    );
                    (&state.progress, state.requested_quantity, maximum)
                }
                CityOrderId::PopulationGrowth => {
                    let progress = &mut orders.population_growth;
                    let maximum = population_growth_max_order(progress, city);
                    (&*progress, progress.quantity, maximum)
                }
            };
            CityOrderView {
                quantity: progress.quantity,
                requested_quantity,
                maximum,
                limiting_constraint: progress.limiting_constraint,
            }
        })
    }

    /// Returns whether `quantity` would be accepted without mutating authoritative state.
    ///
    /// City UI uses this to enable Accept; do not probe by calling
    /// [`Self::set_city_order_quantity`] and rolling the quantity back.
    pub fn can_set_city_order_quantity(
        &self,
        nation: MajorNationId,
        order: CityOrderId,
        quantity: i16,
    ) -> bool {
        let major = self.nations.major(nation);
        let mut orders = (*major.city().orders).clone();
        let mut city = major.city().clone();
        let economy = major.economy().clone();
        let mut treasury = major.common().treasury;
        city_order_quantity_accepted(
            &mut orders,
            &mut city,
            &economy,
            &mut treasury,
            order,
            quantity,
        )
    }

    /// Applies an absolute retail city-order quantity. Legal rejection is the
    /// observed boolean return, while the remembered limiting constraint may
    /// still be refreshed by the rejected call.
    pub fn set_city_order_quantity(
        &mut self,
        nation: MajorNationId,
        order: CityOrderId,
        quantity: i16,
    ) -> bool {
        self.with_city_orders(nation, |orders, city, owner, treasury| {
            city_order_quantity_accepted(orders, city, owner, treasury, order, quantity)
        })
    }

    /// Applies a signed quantity step through the same absolute retail setter.
    pub fn adjust_city_order(
        &mut self,
        nation: MajorNationId,
        order: CityOrderId,
        delta: i16,
    ) -> bool {
        let quantity = {
            let city = self.nations.city(nation);
            match order {
                CityOrderId::Item(output) => {
                    city.orders.items[output]
                        .as_ref()
                        .expect("item order has a retail recipe")
                        .progress
                        .quantity
                }
                CityOrderId::CivilianRecruit(kind) => {
                    city.orders.civilian_recruitment[kind].quantity
                }
                CityOrderId::MilitaryRecruit(category) => {
                    city.orders.military_recruitment[category].progress.quantity
                }
                CityOrderId::Ship(track) => city.orders.ships[track].progress.quantity,
                CityOrderId::Training(level) => city.orders.training[level].quantity,
                CityOrderId::Expansion(slot) => {
                    city.orders.expansions[slot]
                        .as_ref()
                        .expect("expansion order exists for every expandable production slot")
                        .progress
                        .quantity
                }
                CityOrderId::FoodProcessing => city.orders.food_processing.quantity,
                CityOrderId::PowerPlant => city.orders.power_plant.progress.quantity,
                CityOrderId::TransportCapacity => city.orders.transport_capacity.progress.quantity,
                CityOrderId::PopulationGrowth => city.orders.population_growth.quantity,
            }
        };
        self.set_city_order_quantity(nation, order, quantity + delta)
    }

    /// Resolves the city's retained production orders and starts its next
    /// production cycle. This is retail `TCity::EndCityPhase`; unit objects are
    /// committed after the city borrow is released.
    pub(crate) fn end_city_phase(&mut self, nation: MajorNationId) {
        const ITEM_OUTPUTS: [ResourceKind; 9] = [
            ResourceKind::Fabric,
            ResourceKind::Lumber,
            ResourceKind::Paper,
            ResourceKind::Steel,
            ResourceKind::Fuel,
            ResourceKind::Clothing,
            ResourceKind::Furniture,
            ResourceKind::Hardware,
            ResourceKind::Arms,
        ];
        const CIVILIAN_KINDS: [CivilianUnitKind; 9] = [
            CivilianUnitKind::Miner,
            CivilianUnitKind::Prospector,
            CivilianUnitKind::Farmer,
            CivilianUnitKind::Forester,
            CivilianUnitKind::Engineer,
            CivilianUnitKind::Rancher,
            CivilianUnitKind::Fisherman,
            CivilianUnitKind::Developer,
            CivilianUnitKind::Driller,
        ];
        const EXPANSION_SLOTS: [ProductionSlot; 7] = [
            ProductionSlot::TextileMill,
            ProductionSlot::ClothingFactory,
            ProductionSlot::SteelMill,
            ProductionSlot::Metalworks,
            ProductionSlot::LumberMill,
            ProductionSlot::FurnitureFactory,
            ProductionSlot::OilRefinery,
        ];

        let owned_region_count =
            self.nations
                .owned_region_count(nation.nation())
                .expect("city production requires a present major nation") as i32;
        let mut produced_civilians = CivilianUnitTable::default();
        {
            let MajorNation { economy, city, .. } = &mut self.nations.majors[nation];
            let mut orders = std::mem::take(&mut city.orders);

            city.phase_counter += 1;
            if matches!(economy.controller, MajorNationController::Computer) {
                for resource in all_resources() {
                    city.adjust_stock(resource, city.reserved_by_type[resource]);
                }
            }
            for resource in all_resources() {
                city.adjust_stock(resource, city.consumed_production_input_by_type[resource]);
                city.consumed_production_input_by_type[resource] = 0;
            }

            let previous_production_score = city.rolling_item_production_score;
            city.rolling_item_production_score = 0;
            produce_food_processing(&mut orders.food_processing, city);
            for output in ITEM_OUTPUTS {
                let state = orders.items[output]
                    .as_mut()
                    .expect("item order exists for every retail recipe");
                produce_item(
                    state,
                    city,
                    item_order_spec(output).expect("item order has a retail recipe"),
                );
            }
            produce_training(
                TrainingLevel::Medium,
                &mut orders.training[TrainingLevel::Medium],
                city,
                economy,
            );
            produce_training(
                TrainingLevel::High,
                &mut orders.training[TrainingLevel::High],
                city,
                economy,
            );
            city.rolling_item_production_score =
                previous_production_score * 9 / 10 + city.rolling_item_production_score * 10;

            for kind in CIVILIAN_KINDS {
                let progress = &mut orders.civilian_recruitment[kind];
                produced_civilians[kind] = progress.quantity;
                progress.quantity = 0;
            }

            let transport_spec = transport_capacity_order_spec();
            produce_capacity(
                &mut orders.transport_capacity,
                city,
                economy,
                CapacityTarget::Transport,
                transport_spec.primary,
                transport_spec.secondary,
                owned_region_count,
            );
            produce_power_plant(&orders.power_plant);
            for slot in EXPANSION_SLOTS {
                let spec = expansion_order_spec(slot)
                    .expect("expansion order has a retail material recipe");
                produce_expansion(
                    orders.expansions[slot]
                        .as_mut()
                        .expect("expansion order exists for every expandable slot"),
                    city,
                    economy,
                    ExpansionTarget::Production(slot),
                    spec.primary,
                    spec.secondary,
                    owned_region_count,
                );
            }
            produce_population_growth(
                &mut orders.population_growth,
                city,
                economy,
                owned_region_count,
            );

            if city.power_plant_upgrade_queued {
                city.power_plant_upgrade_queued = false;
                city.production_accum[ProductionSlot::PowerPlant] +=
                    999 - city.production_orders[ProductionSlot::PowerPlant];
                city.production_orders[ProductionSlot::PowerPlant] = 999;
            }
            for resource in all_resources() {
                if city.stockpile[resource] > 9_999 {
                    city.stockpile.set_nonnegative(resource, 9_999);
                }
            }

            city.power_available = 0;
            city.start_production_phase();
            restock_power_plant(&mut orders.power_plant, city);
            for output in ITEM_OUTPUTS {
                let state = orders.items[output]
                    .as_mut()
                    .expect("item order exists for every retail recipe");
                restock_item(
                    state,
                    city,
                    item_order_spec(output).expect("item order has a retail recipe"),
                );
            }
            city.production_accum[ProductionSlot::RegionalPopulation] =
                retail_region_capacity(economy, owned_region_count);
            city.production_accum[ProductionSlot::Transport] =
                city.production_orders[ProductionSlot::Transport];
            city.orders = orders;
        }

        for (kind, quantity) in produced_civilians {
            self.produce_civilian_recruits(nation, kind, quantity);
        }
    }

    /// Resolves the Armory and Shipyard orders after potential calculation.
    pub(crate) fn produce_city_units(&mut self, nation: MajorNationId) {
        const MILITARY_CATEGORIES: [MilitaryRecruitmentCategory; 8] = [
            MilitaryRecruitmentCategory::LightInfantry,
            MilitaryRecruitmentCategory::RegularInfantry,
            MilitaryRecruitmentCategory::HeavyInfantry,
            MilitaryRecruitmentCategory::LightCavalry,
            MilitaryRecruitmentCategory::HeavyCavalry,
            MilitaryRecruitmentCategory::LightArtillery,
            MilitaryRecruitmentCategory::HeavyArtillery,
            MilitaryRecruitmentCategory::Demolitionist,
        ];
        const CIVILIAN_KINDS: [CivilianUnitKind; 9] = [
            CivilianUnitKind::Miner,
            CivilianUnitKind::Prospector,
            CivilianUnitKind::Farmer,
            CivilianUnitKind::Forester,
            CivilianUnitKind::Engineer,
            CivilianUnitKind::Rancher,
            CivilianUnitKind::Fisherman,
            CivilianUnitKind::Developer,
            CivilianUnitKind::Driller,
        ];
        const SHIP_SLOTS: [ShipOrderSlot; 8] = [
            ShipOrderSlot::MerchantEarlyPrimary,
            ShipOrderSlot::MerchantEarlySecondary,
            ShipOrderSlot::MerchantAdvancedPrimary,
            ShipOrderSlot::MerchantAdvancedSecondary,
            ShipOrderSlot::WarshipEarlyPrimary,
            ShipOrderSlot::WarshipEarlySecondary,
            ShipOrderSlot::WarshipAdvancedPrimary,
            ShipOrderSlot::WarshipAdvancedSecondary,
        ];

        let mut military = Vec::new();
        let mut civilians = Vec::new();
        {
            let city = self.nations.city_mut(nation);
            for category in MILITARY_CATEGORIES {
                let order = &mut city.orders.military_recruitment[category];
                military.push((order.unit_kind, order.progress.quantity));
                order.progress.quantity = 0;
            }
            for kind in CIVILIAN_KINDS {
                let order = &mut city.orders.civilian_recruitment[kind];
                civilians.push((kind, order.quantity));
                order.quantity = 0;
            }
            for slot in SHIP_SLOTS {
                let order = &mut city.orders.ships[slot];
                let quantity = order.progress.quantity;
                if order.ship_type != ShipType::NoShip && quantity != 0 {
                    city.ship_order_count_by_type[order.ship_type] += quantity;
                    order.progress.quantity = 0;
                    order.progress.tracking_by_resource = ResourceTable::default();
                }
            }
        }

        for (unit_kind, quantity) in military {
            self.produce_military_recruits(nation, unit_kind, quantity);
        }
        for (unit_kind, quantity) in civilians {
            self.produce_civilian_recruits(nation, unit_kind, quantity);
        }
    }
}

fn apply_resource_cost(city: &mut CityState, cost: ResourceCost, quantity: i16) {
    let change = cost.per_unit() * quantity;
    city.adjust_stock(cost.resource, -change);
}

#[allow(dead_code)]
fn set_pending_action(owner: &mut GreatPowerState, action: PendingActionKind, payload: i16) {
    owner.pending_actions[action].queue(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(value: u8) -> ProductionSlot {
        ProductionSlot::from_index(value).unwrap()
    }

    fn city() -> CityState {
        CityState {
            orders: Box::default(),
            power_plant_upgrade_queued: false,
            food_substitution_count: 0,
            starvation_population_loss: 0,
            serialized_state: 0,
            phase_counter: 0,
            military_recruit_count_by_kind: crate::MilitaryUnitTable::default(),
            civilian_recruit_count_by_kind: crate::CivilianUnitTable::default(),
            ship_order_count_by_type: crate::ShipTypeTable::default(),
            rolling_item_production_score: 0,
            low_production: false,
            low_stock: false,
            reserved_by_type: crate::ResourceTable::default(),
            home_town: Some(crate::TownState::for_frog_city(crate::TileId::new(1))),
            power_available: 0,
            stockpile: crate::Stockpile::default(),
            production_orders: crate::ProductionTable::default(),
            production_accum: crate::ProductionTable::default(),
            production_flags: crate::ProductionTable::default(),
            production_current: crate::ProductionTable::default(),
            production_progress: crate::ProductionTable::default(),
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: crate::ResourceTable::default(),
            consumed_production_input_by_type: crate::ResourceTable::default(),
            population: PopulationState {
                count: 7,
                accumulator: crate::PopulationAccumulator::from_bits(7.0_f32.to_bits()),
                strength: 10,
                extra: 0,
                strike_phase: crate::StrikePhase::default(),
                baseline_labor: LaborPool::new(4, 2, 1),
                production_labor: LaborPool::new(4, 2, 1),
                pending_labor_delta: LaborPool::default(),
                predicted_need_by_resource: crate::ResourceTable::default(),
            },
        }
    }

    fn nation() -> GreatPowerState {
        crate::test_support::great_power_state()
    }

    fn item_state() -> RequestedCityOrderState {
        RequestedCityOrderState::default()
    }

    #[test]
    fn max_order_records_capacity_workforce_and_resource_constraints() {
        let mut state = city();
        let mut production = item_state();
        let lumber = item_order_spec(ResourceKind::Lumber).unwrap();
        state.production_accum[ProductionSlot::LumberMill] = 4;
        state.stockpile[ResourceKind::Timber] = 20;
        assert_eq!(item_max_order(&mut production, &state, lumber), 4);
        assert_eq!(
            production.progress.limiting_constraint,
            ProductionConstraint::Capacity
        );

        state.production_accum[ProductionSlot::LumberMill] = 20;
        assert_eq!(item_max_order(&mut production, &state, lumber), 5);
        assert_eq!(
            production.progress.limiting_constraint,
            ProductionConstraint::Workforce
        );

        state.population.strength = 30;
        state.stockpile[ResourceKind::Timber] = 8;
        assert_eq!(item_max_order(&mut production, &state, lumber), 4);
        assert_eq!(
            production.progress.limiting_constraint,
            ProductionConstraint::Resources
        );

        let mut two_input = item_state();
        let steel = item_order_spec(ResourceKind::Steel).unwrap();
        state.production_accum[ProductionSlot::SteelMill] = 20;
        state.stockpile[ResourceKind::Iron] = 9;
        state.stockpile[ResourceKind::Coal] = 3;
        assert_eq!(item_max_order(&mut two_input, &state, steel), 3);
        assert_eq!(
            two_input.progress.limiting_constraint,
            ProductionConstraint::Resources
        );
    }

    #[test]
    fn game_state_adjusts_the_authoritative_steel_order_and_releases_it() {
        let mut game = crate::test_support::game_state();
        let nation = MajorNationId::new(6);
        {
            let city = &mut game.nations.major_mut(nation).city;
            city.production_accum[ProductionSlot::SteelMill] = 1;
            city.stockpile[ResourceKind::Iron] = 1;
            city.stockpile[ResourceKind::Coal] = 1;
        }

        assert!(game.adjust_city_order(nation, CityOrderId::Item(ResourceKind::Steel), 1));
        let city = game.nations.city(nation);
        let steel = city.orders.items[ResourceKind::Steel].as_ref().unwrap();
        assert_eq!(steel.progress.quantity, 1);
        assert_eq!(steel.requested_quantity, 1);
        assert_eq!(steel.progress.tracking_by_resource[ResourceKind::Iron], 1);
        assert_eq!(steel.progress.tracking_by_resource[ResourceKind::Coal], 1);
        assert_eq!(steel.progress.reserved_workforce, 2);
        assert_eq!(city.stockpile[ResourceKind::Iron], 0);
        assert_eq!(city.stockpile[ResourceKind::Coal], 0);
        assert_eq!(city.population.strength, 10);
        assert_eq!(city.production_accum[ProductionSlot::SteelMill], 0);

        assert!(game.adjust_city_order(nation, CityOrderId::Item(ResourceKind::Steel), -1));
        let city = game.nations.city(nation);
        let steel = city.orders.items[ResourceKind::Steel].as_ref().unwrap();
        assert_eq!(steel.progress.quantity, 0);
        assert_eq!(steel.requested_quantity, 0);
        assert_eq!(steel.progress.tracking_by_resource[ResourceKind::Iron], 0);
        assert_eq!(steel.progress.tracking_by_resource[ResourceKind::Coal], 0);
        assert_eq!(steel.progress.reserved_workforce, 0);
        assert_eq!(city.stockpile[ResourceKind::Iron], 1);
        assert_eq!(city.stockpile[ResourceKind::Coal], 1);
        assert_eq!(city.population.strength, 12);
        assert_eq!(city.production_accum[ProductionSlot::SteelMill], 1);
    }

    #[test]
    fn rejected_quantity_keeps_reservations_unchanged() {
        let mut state = city();
        let mut production = item_state();
        let lumber = item_order_spec(ResourceKind::Lumber).unwrap();
        state.production_accum[ProductionSlot::LumberMill] = 1;
        state.stockpile[ResourceKind::Timber] = 20;
        assert!(!set_item_quantity(&mut production, &mut state, lumber, 2));
        assert_eq!(production.progress.quantity, 0);
        assert_eq!(state.stockpile[ResourceKind::Timber], 20);
        assert_eq!(state.population.strength, 10);
        assert_eq!(state.production_accum[ProductionSlot::LumberMill], 1);
        assert_eq!(
            production.progress.limiting_constraint,
            ProductionConstraint::Capacity
        );
    }

    #[test]
    fn produce_restores_capacity_creates_output_and_clears_reservations() {
        let mut state = city();
        let mut production = item_state();
        let steel = item_order_spec(ResourceKind::Steel).unwrap();
        state.production_accum[ProductionSlot::SteelMill] = 10;
        state.stockpile[ResourceKind::Iron] = 5;
        state.stockpile[ResourceKind::Coal] = 4;
        set_item_quantity(&mut production, &mut state, steel, 1);

        produce_item(&mut production, &mut state, steel);
        assert_eq!(state.production_accum[ProductionSlot::SteelMill], 10);
        assert_eq!(state.stockpile[ResourceKind::Steel], 1);
        assert_eq!(state.rolling_item_production_score, 1);
        assert_eq!(
            production.progress.tracking_by_resource[ResourceKind::Iron],
            0
        );
        assert_eq!(
            production.progress.tracking_by_resource[ResourceKind::Coal],
            0
        );
        assert_eq!(production.progress.reserved_workforce, 0);
        assert_eq!(production.progress.accumulated_value, 1);
    }

    #[test]
    fn resource_limited_restock_preserves_the_requested_quantity() {
        let mut state = city();
        let mut production = item_state();
        let lumber = item_order_spec(ResourceKind::Lumber).unwrap();
        production.progress.quantity = 5;
        production.requested_quantity = 5;
        state.population.strength = 20;
        state.production_accum[ProductionSlot::LumberMill] = 5;
        state.stockpile[ResourceKind::Timber] = 4;

        assert!(restock_item(&mut production, &mut state, lumber));
        assert_eq!(production.progress.quantity, 2);
        assert_eq!(production.requested_quantity, 5);
        assert_eq!(state.stockpile[ResourceKind::Timber], 0);
        assert_eq!(state.population.strength, 16);
        assert_eq!(state.production_accum[ProductionSlot::LumberMill], 3);
        assert_eq!(
            production.progress.limiting_constraint,
            ProductionConstraint::Resources
        );
    }

    #[test]
    fn either_inputs_shift_shortfalls_and_reverse_the_tracked_split() {
        let mut state = city();
        let mut production = item_state();
        let fabric = item_order_spec(ResourceKind::Fabric).unwrap();
        state.population.strength = 20;
        state.production_accum[ProductionSlot::TextileMill] = 10;
        state.stockpile[ResourceKind::Wool] = 1;
        state.stockpile[ResourceKind::Cotton] = 10;

        assert_eq!(item_max_order(&mut production, &state, fabric), 5);
        assert!(set_item_quantity(&mut production, &mut state, fabric, 3));
        assert_eq!(state.stockpile[ResourceKind::Wool], 0);
        assert_eq!(state.stockpile[ResourceKind::Cotton], 5);
        assert_eq!(
            production.progress.tracking_by_resource[ResourceKind::Wool],
            1
        );
        assert_eq!(
            production.progress.tracking_by_resource[ResourceKind::Cotton],
            5
        );

        assert!(set_item_quantity(&mut production, &mut state, fabric, 1));
        assert_eq!(state.stockpile[ResourceKind::Wool], 1);
        assert_eq!(state.stockpile[ResourceKind::Cotton], 8);
        assert_eq!(
            production.progress.tracking_by_resource[ResourceKind::Wool],
            0
        );
        assert_eq!(
            production.progress.tracking_by_resource[ResourceKind::Cotton],
            2
        );
        assert_eq!(state.population.strength, 18);
        assert_eq!(production.progress.reserved_workforce, 2);
        assert_eq!(state.production_accum[ProductionSlot::TextileMill], 9);

        produce_item(&mut production, &mut state, fabric);
        assert_eq!(
            production.progress.tracking_by_resource[ResourceKind::Cotton],
            0
        );
        assert_eq!(production.progress.reserved_workforce, 0);
    }

    #[test]
    fn either_inputs_shift_a_secondary_shortfall_to_the_primary_input() {
        let mut state = city();
        let mut production = item_state();
        let fabric = item_order_spec(ResourceKind::Fabric).unwrap();
        state.population.strength = 20;
        state.production_accum[ProductionSlot::TextileMill] = 10;
        state.stockpile[ResourceKind::Wool] = 10;
        state.stockpile[ResourceKind::Cotton] = 1;

        assert!(set_item_quantity(&mut production, &mut state, fabric, 3));
        assert_eq!(state.stockpile[ResourceKind::Wool], 5);
        assert_eq!(state.stockpile[ResourceKind::Cotton], 0);
        assert_eq!(
            production.progress.tracking_by_resource[ResourceKind::Wool],
            5
        );
        assert_eq!(
            production.progress.tracking_by_resource[ResourceKind::Cotton],
            1
        );
    }

    #[test]
    fn food_processing_limit_uses_grain_fruit_animals_and_workforce() {
        let mut state = city();
        let production = ProductionProgress::default();
        state.stockpile[ResourceKind::Grain] = 10;
        state.stockpile[ResourceKind::Fruit] = 4;
        state.stockpile[ResourceKind::Fish] = 1;
        state.stockpile[ResourceKind::Livestock] = 2;
        state.population.strength = 10;
        assert_eq!(food_processing_max_order(&production, &state), 6);
    }

    #[test]
    fn food_processing_rounds_even_and_consumes_livestock_before_fish() {
        let mut state = city();
        let mut production = ProductionProgress::default();
        state.stockpile[ResourceKind::Grain] = 10;
        state.stockpile[ResourceKind::Fruit] = 5;
        state.stockpile[ResourceKind::Fish] = 3;
        state.stockpile[ResourceKind::Livestock] = 1;
        state.population.strength = 10;

        assert!(set_food_processing_quantity(&mut production, &mut state, 3));
        assert_eq!(production.quantity, 4);
        assert_eq!(state.stockpile[ResourceKind::Grain], 6);
        assert_eq!(state.stockpile[ResourceKind::Fruit], 3);
        assert_eq!(state.stockpile[ResourceKind::Livestock], 0);
        assert_eq!(state.stockpile[ResourceKind::Fish], 2);
        assert_eq!(state.population.strength, 6);

        assert!(set_food_processing_quantity(&mut production, &mut state, 1));
        assert_eq!(production.quantity, 2);
        assert_eq!(state.stockpile[ResourceKind::Grain], 8);
        assert_eq!(state.stockpile[ResourceKind::Fruit], 4);
        assert_eq!(state.stockpile[ResourceKind::Livestock], 1);
        assert_eq!(state.stockpile[ResourceKind::Fish], 2);
        assert_eq!(state.population.strength, 8);
    }

    #[test]
    fn food_processing_accepts_minus_one_as_zero_after_retail_rounding() {
        let mut state = city();
        let mut production = ProductionProgress::default();
        assert!(set_food_processing_quantity(
            &mut production,
            &mut state,
            -1
        ));
        assert_eq!(production.quantity, 0);
        assert_eq!(state.population.strength, 10);
    }

    #[test]
    fn food_processing_produces_canned_food_and_clears_the_order() {
        let mut state = city();
        let mut production = ProductionProgress {
            quantity: 4,
            reserved_workforce: 7,
            ..ProductionProgress::default()
        };
        produce_food_processing(&mut production, &mut state);
        assert_eq!(state.stockpile[ResourceKind::Food], 4);
        assert_eq!(production.quantity, 0);
        assert_eq!(production.reserved_workforce, 0);
    }

    #[test]
    fn population_growth_selects_resource_then_capacity_limits() {
        let mut state = city();
        let mut production = ProductionProgress::default();
        state.stockpile[ResourceKind::Furniture] = 3;
        state.stockpile[ResourceKind::Clothing] = 2;
        state.stockpile[ResourceKind::Food] = 4;
        state.production_accum[slot(15)] = 10;
        assert_eq!(population_growth_max_order(&mut production, &state), 2);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Resources
        );

        state.production_accum[slot(15)] = 1;
        assert_eq!(population_growth_max_order(&mut production, &state), 1);
        assert_eq!(
            production.limiting_constraint,
            ProductionConstraint::Capacity
        );
    }

    #[test]
    fn population_growth_quantity_reserves_and_refunds_all_inputs() {
        let mut state = city();
        let mut production = ProductionProgress::default();
        state.stockpile[ResourceKind::Furniture] = 3;
        state.stockpile[ResourceKind::Clothing] = 3;
        state.stockpile[ResourceKind::Food] = 3;
        state.production_accum[slot(15)] = 3;

        assert!(set_population_growth_quantity(
            &mut production,
            &mut state,
            2
        ));
        assert_eq!(state.stockpile[ResourceKind::Furniture], 1);
        assert_eq!(state.stockpile[ResourceKind::Clothing], 1);
        assert_eq!(state.stockpile[ResourceKind::Food], 1);
        assert_eq!(state.production_accum[slot(15)], 1);

        assert!(set_population_growth_quantity(
            &mut production,
            &mut state,
            1
        ));
        assert_eq!(state.stockpile[ResourceKind::Furniture], 2);
        assert_eq!(state.stockpile[ResourceKind::Clothing], 2);
        assert_eq!(state.stockpile[ResourceKind::Food], 2);
        assert_eq!(state.production_accum[slot(15)], 2);
    }

    #[test]
    fn population_growth_produces_low_skill_population_and_refreshes_capacity() {
        let mut state = city();
        let mut owner = nation();
        let mut production = ProductionProgress {
            quantity: 2,
            limiting_constraint: ProductionConstraint::Resources,
            ..ProductionProgress::default()
        };
        owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
            crate::PendingActionState::new(crate::PendingActionStatus::Level3, None);
        let float_count = state.population.accumulator;

        produce_population_growth(&mut production, &mut state, &owner, 12);
        assert_eq!(state.population.baseline_labor.low, 6);
        assert_eq!(state.population.production_labor.low, 6);
        assert_eq!(state.population.count, 9);
        assert_eq!(state.population.accumulator, float_count);
        assert_eq!(state.production_accum[slot(15)], 4);
        assert_eq!(production.quantity, 0);
    }

    fn capacity_order() -> RequestedCityOrderState {
        RequestedCityOrderState::default()
    }

    fn expansion_order() -> RequestedCityOrderState {
        RequestedCityOrderState::default()
    }

    #[test]
    fn capacity_order_uses_item_reservations_then_expands_a_production_slot() {
        let mut state = city();
        let mut production = capacity_order();
        state.stockpile[ResourceKind::Lumber] = 5;
        state.stockpile[ResourceKind::Steel] = 4;
        state.production_accum[slot(14)] = 10;
        state.production_orders[slot(3)] = 6;

        assert!(set_capacity_quantity(
            &mut production,
            &mut state,
            ResourceKind::Lumber,
            ResourceKind::Steel,
            ProductionSlot::Transport,
            2,
        ));
        assert_eq!(state.population.strength, 6);
        assert_eq!(state.production_accum[slot(14)], 8);
        produce_capacity(
            &mut production,
            &mut state,
            &mut nation(),
            CapacityTarget::Production(ProductionSlot::Metalworks),
            ResourceKind::Lumber,
            ResourceKind::Steel,
            0,
        );

        assert_eq!(state.production_orders[slot(3)], 8);
        assert_eq!(state.production_accum[slot(3)], 2);
        assert_eq!(production.progress.quantity, 0);
        assert_eq!(production.requested_quantity, 0);
        assert_eq!(production.progress.reserved_workforce, 0);
        assert_eq!(
            production.progress.tracking_by_resource[ResourceKind::Lumber],
            0
        );
        assert_eq!(
            production.progress.tracking_by_resource[ResourceKind::Steel],
            0
        );
    }

    #[test]
    fn capacity_order_transport_target_increases_the_nation_capacity() {
        let mut state = city();
        let mut owner = nation();
        let mut production = capacity_order();
        production.progress.quantity = 3;
        production.requested_quantity = 3;
        production.progress.reserved_workforce = 6;
        production.progress.tracking_by_resource[ResourceKind::Lumber] = 3;
        production.progress.tracking_by_resource[ResourceKind::Steel] = 3;
        owner.capacities.transport = 4;

        produce_capacity(
            &mut production,
            &mut state,
            &mut owner,
            CapacityTarget::Transport,
            ResourceKind::Lumber,
            ResourceKind::Steel,
            0,
        );
        assert_eq!(owner.capacities.transport, 7);
        assert_eq!(state.production_orders, crate::ProductionTable::default());
        assert_eq!(production.progress.quantity, 0);
        assert_eq!(production.progress.reserved_workforce, 0);
    }

    #[test]
    fn capacity_order_region_target_rebases_before_adding_the_order() {
        let mut state = city();
        let mut owner = nation();
        let mut production = capacity_order();
        production.progress.quantity = 2;
        owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
            crate::PendingActionState::new(crate::PendingActionStatus::Level3, None);
        state.production_orders[slot(15)] = 1;
        state.production_accum[slot(15)] = 3;

        produce_capacity(
            &mut production,
            &mut state,
            &mut owner,
            CapacityTarget::RegionalPopulation,
            ResourceKind::Lumber,
            ResourceKind::Steel,
            12,
        );
        assert_eq!(state.production_orders[slot(15)], 6);
        assert_eq!(state.production_accum[slot(15)], 8);
    }

    #[test]
    fn expansion_order_reserves_only_its_two_material_inputs() {
        let mut state = city();
        let mut production = expansion_order();
        state.stockpile[ResourceKind::Lumber] = 3;
        state.stockpile[ResourceKind::Steel] = 2;
        state.production_accum[slot(14)] = 9;

        assert_eq!(
            expansion_max_order(
                &production,
                &state,
                ResourceKind::Lumber,
                ResourceKind::Steel,
            ),
            2
        );
        assert!(set_expansion_quantity(
            &mut production,
            &mut state,
            ResourceKind::Lumber,
            ResourceKind::Steel,
            2,
        ));
        assert_eq!(state.stockpile[ResourceKind::Lumber], 1);
        assert_eq!(state.stockpile[ResourceKind::Steel], 0);
        assert_eq!(state.population.strength, 10);
        assert_eq!(state.production_accum[slot(14)], 9);
        assert_eq!(production.progress.reserved_workforce, 0);

        assert!(set_expansion_quantity(
            &mut production,
            &mut state,
            ResourceKind::Lumber,
            ResourceKind::Steel,
            1,
        ));
        assert_eq!(state.stockpile[ResourceKind::Lumber], 2);
        assert_eq!(state.stockpile[ResourceKind::Steel], 1);
    }

    #[test]
    fn expansion_production_keeps_the_unused_inherited_workforce_field() {
        let mut state = city();
        let owner = nation();
        let mut production = expansion_order();
        state.production_orders[slot(2)] = 4;
        state.production_accum[slot(2)] = 7;
        production.progress.quantity = 2;
        production.requested_quantity = 2;
        production.progress.reserved_workforce = 9;
        production.progress.tracking_by_resource[ResourceKind::Lumber] = 2;
        production.progress.tracking_by_resource[ResourceKind::Steel] = 2;

        produce_expansion(
            &mut production,
            &mut state,
            &owner,
            ExpansionTarget::Production(ProductionSlot::SteelMill),
            ResourceKind::Lumber,
            ResourceKind::Steel,
            0,
        );
        assert_eq!(state.production_orders[slot(2)], 6);
        assert_eq!(state.production_accum[slot(2)], 9);
        assert_eq!(production.progress.quantity, 0);
        assert_eq!(production.requested_quantity, 0);
        assert_eq!(production.progress.reserved_workforce, 9);
        assert_eq!(
            production.progress.tracking_by_resource[ResourceKind::Lumber],
            0
        );
        assert_eq!(
            production.progress.tracking_by_resource[ResourceKind::Steel],
            0
        );
    }

    #[test]
    fn expansion_region_target_uses_the_retail_region_divisor() {
        let mut state = city();
        let mut owner = nation();
        let mut production = expansion_order();
        production.progress.quantity = 1;
        owner.pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion] =
            crate::PendingActionState::new(crate::PendingActionStatus::Queued, None);
        state.production_orders[slot(15)] = 8;
        state.production_accum[slot(15)] = 10;

        produce_expansion(
            &mut production,
            &mut state,
            &owner,
            ExpansionTarget::RegionalPopulation,
            ResourceKind::Lumber,
            ResourceKind::Steel,
            12,
        );
        assert_eq!(state.production_orders[slot(15)], 4);
        assert_eq!(state.production_accum[slot(15)], 6);
    }

    #[test]
    fn zero_capacity_and_expansion_orders_do_not_touch_any_state() {
        let mut state = city();
        let mut owner = nation();
        let mut capacity = capacity_order();
        let mut expansion = expansion_order();
        capacity.requested_quantity = 4;
        capacity.progress.reserved_workforce = 7;
        expansion.requested_quantity = 5;
        expansion.progress.reserved_workforce = 8;
        let expected_state = state.clone();
        let expected_owner = owner.clone();
        let expected_capacity = capacity.clone();
        let expected_expansion = expansion.clone();

        produce_capacity(
            &mut capacity,
            &mut state,
            &mut owner,
            CapacityTarget::RegionalPopulation,
            ResourceKind::Lumber,
            ResourceKind::Steel,
            20,
        );
        produce_expansion(
            &mut expansion,
            &mut state,
            &owner,
            ExpansionTarget::RegionalPopulation,
            ResourceKind::Lumber,
            ResourceKind::Steel,
            20,
        );
        assert_eq!(state, expected_state);
        assert_eq!(owner, expected_owner);
        assert_eq!(capacity, expected_capacity);
        assert_eq!(expansion, expected_expansion);
    }

    #[test]
    fn power_plant_limit_counts_each_fuel_unit_as_six_power() {
        let mut state = city();
        let production = PowerPlantOrderState {
            progress: ProductionProgress {
                quantity: 5,
                ..ProductionProgress::default()
            },
            desired_quantity: 0,
        };
        state.stockpile[ResourceKind::Fuel] = 3;
        assert_eq!(power_plant_max_order(&production, &state), 23);
    }

    #[test]
    fn power_plant_quantity_reserves_and_refunds_fuel_with_truncating_division() {
        let mut state = city();
        let mut production = PowerPlantOrderState::default();
        state.stockpile[ResourceKind::Fuel] = 3;

        assert!(set_power_plant_quantity(&mut production, &mut state, 13));
        assert_eq!(state.stockpile[ResourceKind::Fuel], 1);
        assert_eq!(production.desired_quantity, 13);
        assert_eq!(state.power_available, 13);
        assert_eq!(state.population.extra, 13);
        assert_eq!(state.population.strength, 23);

        assert!(set_power_plant_quantity(&mut production, &mut state, 6));
        assert_eq!(state.stockpile[ResourceKind::Fuel], 2);
        assert_eq!(production.desired_quantity, 6);
        assert_eq!(state.power_available, 6);
        assert_eq!(state.population.extra, 6);
        assert_eq!(state.population.strength, 16);
    }

    #[test]
    fn power_plant_rejects_a_reduction_that_exceeds_available_strength() {
        let mut state = city();
        let mut production = PowerPlantOrderState {
            progress: ProductionProgress {
                quantity: 6,
                ..ProductionProgress::default()
            },
            desired_quantity: 6,
        };
        state.stockpile[ResourceKind::Fuel] = 2;
        state.population.strength = 2;
        state.population.extra = 6;
        state.power_available = 6;
        let expected_state = state.clone();

        assert!(!set_power_plant_quantity(&mut production, &mut state, 0));
        assert_eq!(production.progress.quantity, 6);
        assert_eq!(production.desired_quantity, 6);
        assert_eq!(state, expected_state);
    }

    #[test]
    fn power_plant_restock_clamps_but_preserves_the_desired_quantity() {
        let mut state = city();
        let mut production = PowerPlantOrderState {
            progress: ProductionProgress::default(),
            desired_quantity: 15,
        };
        state.stockpile[ResourceKind::Fuel] = 2;

        assert!(restock_power_plant(&mut production, &mut state));
        assert_eq!(production.progress.quantity, 12);
        assert_eq!(production.desired_quantity, 15);
        assert_eq!(state.stockpile[ResourceKind::Fuel], 0);
        assert_eq!(state.power_available, 12);
        assert_eq!(state.population.extra, 12);
        assert_eq!(state.population.strength, 22);
    }

    #[test]
    fn power_plant_production_is_a_retail_no_op() {
        let production = PowerPlantOrderState {
            progress: ProductionProgress {
                quantity: 12,
                accumulated_value: 7,
                ..ProductionProgress::default()
            },
            desired_quantity: 18,
        };
        let expected = production.clone();
        produce_power_plant(&production);
        assert_eq!(production, expected);
    }

    #[test]
    fn training_limits_record_workforce_treasury_resources_and_the_global_cap() {
        let mut state = city();
        let mut owner = nation();
        let mut medium = ProductionProgress::default();
        state.stockpile[ResourceKind::Paper] = 10;
        assert_eq!(
            training_max_order(TrainingLevel::Medium, &mut medium, &state, &owner, 10_000),
            4
        );
        assert_eq!(medium.limiting_constraint, ProductionConstraint::Workforce);
        assert_eq!(
            training_max_order(TrainingLevel::Medium, &mut medium, &state, &owner, i32::MAX),
            4
        );

        assert_eq!(
            training_max_order(TrainingLevel::Medium, &mut medium, &state, &owner, 150),
            1
        );
        assert_eq!(medium.limiting_constraint, ProductionConstraint::Treasury);

        state.stockpile[ResourceKind::Paper] = 0;
        assert_eq!(
            training_max_order(TrainingLevel::Medium, &mut medium, &state, &owner, 10_000),
            0
        );
        assert_eq!(medium.limiting_constraint, ProductionConstraint::Resources);

        owner.controller = crate::MajorNationController::Computer;
        state.stockpile[ResourceKind::Paper] = 100;
        medium.quantity = 98;
        assert_eq!(
            training_max_order(TrainingLevel::Medium, &mut medium, &state, &owner, -50_000),
            99
        );

        let mut high = ProductionProgress::default();
        assert_eq!(
            training_max_order(TrainingLevel::High, &mut high, &state, &owner, 0),
            2
        );
        assert_eq!(high.limiting_constraint, ProductionConstraint::Workforce);
    }

    #[test]
    fn training_quantity_reserves_and_refunds_paper_cash_and_workers() {
        let mut state = city();
        let owner = nation();
        let mut treasury = 1_000;
        let mut production = ProductionProgress::default();
        state.stockpile[ResourceKind::Paper] = 10;

        assert!(set_training_quantity(
            TrainingLevel::Medium,
            &mut production,
            &mut state,
            &owner,
            &mut treasury,
            2,
        ));
        assert_eq!(state.stockpile[ResourceKind::Paper], 8);
        assert_eq!(treasury, 800);
        assert_eq!(state.population.production_labor.low, 2);
        assert_eq!(state.population.strength, 8);

        assert!(set_training_quantity(
            TrainingLevel::Medium,
            &mut production,
            &mut state,
            &owner,
            &mut treasury,
            1,
        ));
        assert_eq!(state.stockpile[ResourceKind::Paper], 9);
        assert_eq!(treasury, 900);
        assert_eq!(state.population.production_labor.low, 3);
        assert_eq!(state.population.strength, 9);
    }

    #[test]
    fn high_training_uses_two_paper_and_one_thousand_cash_per_worker() {
        let mut state = city();
        let owner = nation();
        let mut treasury = 3_000;
        let mut production = ProductionProgress::default();
        state.stockpile[ResourceKind::Paper] = 6;

        assert!(set_training_quantity(
            TrainingLevel::High,
            &mut production,
            &mut state,
            &owner,
            &mut treasury,
            2,
        ));
        assert_eq!(state.stockpile[ResourceKind::Paper], 2);
        assert_eq!(treasury, 1_000);
        assert_eq!(state.population.production_labor.medium, 0);
        assert_eq!(state.population.strength, 6);
    }

    #[test]
    fn training_production_promotes_the_requested_baseline_workers() {
        let mut state = city();
        let mut owner = nation();
        let mut medium = ProductionProgress {
            quantity: 2,
            ..ProductionProgress::default()
        };

        produce_training(TrainingLevel::Medium, &mut medium, &mut state, &mut owner);
        assert_eq!(state.population.baseline_labor.low, 2);
        assert_eq!(state.population.baseline_labor.medium, 4);
        assert_eq!(medium.quantity, 0);

        owner.pending_actions[PendingActionKind::UniversityExpansion] =
            crate::PendingActionState::new(crate::PendingActionStatus::Level3, None);
        state.population.baseline_labor.high = 29;
        let mut high = ProductionProgress {
            quantity: 1,
            ..ProductionProgress::default()
        };
        produce_training(TrainingLevel::High, &mut high, &mut state, &mut owner);
        assert_eq!(state.population.baseline_labor.medium, 3);
        assert_eq!(state.population.baseline_labor.high, 30);
        assert_eq!(
            owner.pending_actions[PendingActionKind::UniversityExpansion].status(),
            crate::PendingActionStatus::Queued
        );
        assert_eq!(
            owner.pending_actions[PendingActionKind::UniversityExpansion].payload(),
            Some(3)
        );
        assert_eq!(high.quantity, 0);
    }

    #[test]
    fn high_training_preserves_the_retail_pending_action_threshold_order() {
        let mut state = city();
        let mut owner = nation();
        state.population.baseline_labor.high = 29;
        let mut production = ProductionProgress {
            quantity: 1,
            ..ProductionProgress::default()
        };

        produce_training(TrainingLevel::High, &mut production, &mut state, &mut owner);
        assert_eq!(
            owner.pending_actions[PendingActionKind::UniversityExpansion].status(),
            crate::PendingActionStatus::Queued
        );
        assert_eq!(
            owner.pending_actions[PendingActionKind::UniversityExpansion].payload(),
            Some(2)
        );
    }

    #[test]
    fn zero_training_order_leaves_state_untouched() {
        let mut state = city();
        let mut owner = nation();
        let mut production = ProductionProgress::default();
        let expected_state = state.clone();
        let expected_owner = owner.clone();

        produce_training(TrainingLevel::High, &mut production, &mut state, &mut owner);
        assert_eq!(state, expected_state);
        assert_eq!(owner, expected_owner);
    }

    struct TestRecruitOrder {
        primary: ResourceCost,
        secondary: Option<ResourceCost>,
        cash_per_unit: i16,
        workforce: SkillBand,
        progress: ProductionProgress,
    }

    fn unit_order(workforce: SkillBand) -> TestRecruitOrder {
        TestRecruitOrder {
            primary: ResourceCost::new(ResourceKind::Paper, 2),
            secondary: Some(ResourceCost::new(ResourceKind::Steel, 1)),
            cash_per_unit: 100,
            workforce,
            progress: ProductionProgress::default(),
        }
    }

    #[test]
    fn unit_order_supports_each_retail_workforce_mode() {
        let mut state = city();
        let mut owner = nation();
        owner.controller = crate::MajorNationController::Computer;
        state.stockpile[ResourceKind::Paper] = 200;
        state.stockpile[ResourceKind::Steel] = 200;

        for (workforce, expected) in [
            (SkillBand::Low, 4),
            (SkillBand::Medium, 2),
            (SkillBand::High, 1),
        ] {
            let mut production = unit_order(workforce);
            assert_eq!(
                max_recruit_order(
                    &mut production.progress,
                    production.primary,
                    production.secondary,
                    production.cash_per_unit,
                    production.workforce,
                    &state,
                    &owner,
                    -1,
                ),
                expected
            );
            assert_eq!(
                production.progress.limiting_constraint,
                ProductionConstraint::Workforce
            );
        }
    }

    #[test]
    fn unit_order_records_primary_secondary_and_treasury_limits() {
        let mut state = city();
        let owner = nation();
        let mut production = unit_order(SkillBand::Low);
        state.population.production_labor.low = 100;
        state.population.strength = 100;
        state.stockpile[ResourceKind::Paper] = 4;
        state.stockpile[ResourceKind::Steel] = 10;
        assert_eq!(
            max_recruit_order(
                &mut production.progress,
                production.primary,
                production.secondary,
                production.cash_per_unit,
                production.workforce,
                &state,
                &owner,
                i32::MAX,
            ),
            2
        );
        assert_eq!(
            max_recruit_order(
                &mut production.progress,
                production.primary,
                production.secondary,
                production.cash_per_unit,
                production.workforce,
                &state,
                &owner,
                10_000,
            ),
            2
        );
        assert_eq!(
            production.progress.limiting_constraint,
            ProductionConstraint::Resources
        );

        state.stockpile[ResourceKind::Paper] = 20;
        state.stockpile[ResourceKind::Steel] = 3;
        assert_eq!(
            max_recruit_order(
                &mut production.progress,
                production.primary,
                production.secondary,
                production.cash_per_unit,
                production.workforce,
                &state,
                &owner,
                10_000,
            ),
            3
        );
        assert_eq!(
            production.progress.limiting_constraint,
            ProductionConstraint::Resources
        );

        state.stockpile[ResourceKind::Steel] = 20;
        assert_eq!(
            max_recruit_order(
                &mut production.progress,
                production.primary,
                production.secondary,
                production.cash_per_unit,
                production.workforce,
                &state,
                &owner,
                150,
            ),
            1
        );
        assert_eq!(
            production.progress.limiting_constraint,
            ProductionConstraint::Treasury
        );
    }

    #[test]
    fn unit_order_reserves_and_refunds_resources_population_and_cash() {
        let mut state = city();
        let owner = nation();
        let mut treasury = 1_000;
        let mut production = unit_order(SkillBand::Low);
        state.stockpile[ResourceKind::Paper] = 10;
        state.stockpile[ResourceKind::Steel] = 10;

        assert!(set_recruit_quantity(
            &mut production.progress,
            production.primary,
            production.secondary,
            production.cash_per_unit,
            production.workforce,
            &mut state,
            &owner,
            &mut treasury,
            2,
        ));
        assert_eq!(state.stockpile[ResourceKind::Paper], 6);
        assert_eq!(state.stockpile[ResourceKind::Steel], 8);
        assert_eq!(treasury, 800);
        assert_eq!(state.population.baseline_labor.low, 2);
        assert_eq!(state.population.production_labor.low, 2);
        assert_eq!(state.population.count, 5);
        assert_eq!(state.population.count_float(), 5.0);
        assert_eq!(state.population.strength, 8);

        assert!(set_recruit_quantity(
            &mut production.progress,
            production.primary,
            production.secondary,
            production.cash_per_unit,
            production.workforce,
            &mut state,
            &owner,
            &mut treasury,
            1,
        ));
        assert_eq!(state.stockpile[ResourceKind::Paper], 8);
        assert_eq!(state.stockpile[ResourceKind::Steel], 9);
        assert_eq!(treasury, 900);
        assert_eq!(state.population.baseline_labor.low, 3);
        assert_eq!(state.population.production_labor.low, 3);
        assert_eq!(state.population.count, 6);
        assert_eq!(state.population.count_float(), 6.0);
        assert_eq!(state.population.strength, 9);
    }

    #[test]
    fn unit_order_ignores_treasury_when_the_nation_is_not_eligible() {
        let mut state = city();
        let mut owner = nation();
        owner.controller = crate::MajorNationController::Computer;
        let mut production = unit_order(SkillBand::Low);
        state.population.production_labor.low = 100;
        state.population.strength = 100;
        state.stockpile[ResourceKind::Paper] = 12;
        state.stockpile[ResourceKind::Steel] = 12;

        assert_eq!(
            max_recruit_order(
                &mut production.progress,
                production.primary,
                production.secondary,
                production.cash_per_unit,
                production.workforce,
                &state,
                &owner,
                -10_000,
            ),
            6
        );
        assert_eq!(
            production.progress.limiting_constraint,
            ProductionConstraint::Resources
        );
    }
}
