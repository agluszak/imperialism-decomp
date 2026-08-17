//! City state, buildings, and production orders.

mod buildings;
mod production;
mod state;

pub use buildings::{
    CityFacilitySlot, CityWindowPosition, IndustryCapabilitySlot, IndustryCapabilityTable,
};
pub use production::{
    CIVILIAN_RESOURCE_SPECIALTIES, CityOrderId, CityOrderUpdate, CityOrders, ExpandableFacility,
    ExpansionOrderTable, ItemOrderTable, ManufacturedItem, MilitaryRecruitOrderState,
    MilitaryRecruitOrderTable, MilitaryRecruitmentCategory, OrderLimit, PowerPlantOrderState,
    ProductionConstraint, ProductionProgress, RecruitmentOrderSpec, RequestedCityOrderState,
    ResourceCost, ShipMaterials, ShipOrderSlot, ShipOrderState, ShipOrderTable, TrainingLevel,
    TrainingOrderTable, civilian_recruitment_spec, military_recruitment_spec,
    resource_development_yield, ship_display_stats, ship_order_costs,
};
pub(crate) use production::{
    EXPANSION_INPUTS, ItemInputs, UNIVERSITY_REQUIREMENT_LEVEL_BY_RETAIL_ID,
    ship_creates_navy_object, ship_stock_cap,
};
pub use state::{CityState, Stockpile, TownState};
