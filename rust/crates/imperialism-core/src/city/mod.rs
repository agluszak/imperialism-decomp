//! City state, buildings, and production orders.

mod buildings;
mod production;
mod state;

pub use buildings::{CityFacilitySlot, CityWindowPosition};
pub use production::{
    CIVILIAN_RESOURCE_SPECIALTIES, CityOrderId, CityOrders, ExpandableFacility,
    ExpansionOrderTable, ItemOrderTable, ManufacturedItem, MilitaryRecruitOrderState,
    MilitaryRecruitOrderTable, MilitaryRecruitmentCategory, OrderLimit, PowerPlantOrderState,
    ProductionConstraint, ProductionProgress, RecruitmentOrderSpec, RequestedCityOrderState,
    ResourceCost, ShipMaterials, ShipOrderSlot, ShipOrderState, ShipOrderTable, TrainingLevel,
    TrainingOrderTable, civilian_recruitment_spec, military_recruitment_spec,
    resource_development_yield, ship_display_stats, ship_order_costs,
};
pub(crate) use production::{EXPANSION_INPUTS, ItemInputs};
pub use state::{CityState, Stockpile, TownState};
