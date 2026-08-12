//! City state, buildings, and production orders.

mod buildings;
mod production;
mod state;

pub use buildings::{BuildingWindowState, CityFacilitySlot};
pub use production::{
    CIVILIAN_RESOURCE_SPECIALTIES, CityOrderId, CityOrderStatus, CityOrders, ExpandableFacility,
    ExpansionOrderTable, ItemOrderTable, ManufacturedItem, MilitaryRecruitOrderState,
    MilitaryRecruitOrderTable, MilitaryRecruitmentCategory, OrderLimit, PowerPlantOrderState,
    ProductionConstraint, ProductionProgress, RecruitmentOrderSpec, RequestedCityOrderState,
    ResourceCost, ShipOrderSlot, ShipOrderState, ShipOrderTable, TrainingLevel, TrainingOrderTable,
    civilian_recruitment_spec, military_recruitment_spec, resource_development_yield,
    ship_display_stats, ship_order_costs,
};
pub use state::{CityState, Stockpile, TownState};
