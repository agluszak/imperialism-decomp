mod interior;

use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AiTradeState {
    /// Temporary stock synthesized for resources food through fuel during AI bidding.
    pub temporary_processed_stock: ProcessedTradeCommodityTable<i32>,
}

/// Persistent inputs and pending work owned by retail's city interior minister.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct InteriorCivilianState {
    pub(crate) pending_recruitment: Option<CivilianUnitKind>,
    pub(crate) railhead_target: Option<TileId>,
    pub(crate) resource_order_metrics: ResourceTable<i32>,
    pub(crate) city_order_demand: AiCityOrderDemand,
    pub(crate) deferred_labor_shortfall: i32,
    pub(crate) production_deficit_by_slot: ProductionTable<i32>,
    pub(crate) temporarily_reserved_ship_arms: i32,
    pub(crate) railhead_priority_by_resource: ResourceTable<i32>,
    pub(crate) exterior_need_by_resource: ResourceTable<i32>,
    pub(crate) historical_need_by_resource: ResourceTable<i32>,
    pub(crate) civilian_order_demand_by_resource: ResourceTable<i32>,
    pub(crate) average_development_order_allocation: i32,
    pub(crate) pending_development_actions: Vec<PendingDevelopmentAction>,
}

/// Persistent production quantities requested by an automated interior minister.
///
/// These are planning inputs for the authoritative [`CityOrders`], not a second
/// set of city orders. Retail keeps them after an order has been partially
/// accepted so the next city pass can retry the remaining request.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AiCityOrderDemand {
    pub(crate) training: TrainingOrderTable<i32>,
    pub(crate) military_recruitment: MilitaryRecruitOrderTable<i32>,
    pub(crate) civilian_recruitment: CivilianUnitTable<i32>,
    pub(crate) ships: ShipOrderTable<i32>,
    pub(crate) transport_capacity: i32,
    pub(crate) expansions: ExpansionOrderTable<i32>,
    pub(crate) population_growth: i32,
}

impl AiCityOrderDemand {
    pub fn from_parts(
        training: TrainingOrderTable<i32>,
        military_recruitment: MilitaryRecruitOrderTable<i32>,
        civilian_recruitment: CivilianUnitTable<i32>,
        ships: ShipOrderTable<i32>,
        transport_capacity: i32,
        expansions: ExpansionOrderTable<i32>,
        population_growth: i32,
    ) -> Self {
        Self {
            training,
            military_recruitment,
            civilian_recruitment,
            ships,
            transport_capacity,
            expansions,
            population_growth,
        }
    }

    pub const fn training(&self) -> &TrainingOrderTable<i32> {
        &self.training
    }

    pub const fn military_recruitment(&self) -> &MilitaryRecruitOrderTable<i32> {
        &self.military_recruitment
    }

    pub const fn civilian_recruitment(&self) -> &CivilianUnitTable<i32> {
        &self.civilian_recruitment
    }

    pub const fn ships(&self) -> &ShipOrderTable<i32> {
        &self.ships
    }

    pub const fn transport_capacity(&self) -> i32 {
        self.transport_capacity
    }

    pub const fn expansions(&self) -> &ExpansionOrderTable<i32> {
        &self.expansions
    }

    pub const fn population_growth(&self) -> i32 {
        self.population_growth
    }
}

/// One ordered city-development request retained by an AI interior minister.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PendingDevelopmentAction {
    Industry { slot: CityFacilitySlot },
    LandUnit { unit_type: MilitaryUnitKind },
}

impl InteriorCivilianState {
    pub(crate) fn for_random_start(human: bool) -> Self {
        let mut state = Self::default();
        if !human {
            state.city_order_demand = initial_ai_city_order_demand();
        }
        state
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        pending_recruitment: Option<CivilianUnitKind>,
        railhead_target: Option<TileId>,
        resource_order_metrics: ResourceTable<i32>,
        city_order_demand: AiCityOrderDemand,
        deferred_labor_shortfall: i32,
        production_deficit_by_slot: ProductionTable<i32>,
        temporarily_reserved_ship_arms: i32,
        railhead_priority_by_resource: ResourceTable<i32>,
        exterior_need_by_resource: ResourceTable<i32>,
        historical_need_by_resource: ResourceTable<i32>,
        civilian_order_demand_by_resource: ResourceTable<i32>,
        average_development_order_allocation: i32,
        pending_development_actions: Vec<PendingDevelopmentAction>,
    ) -> Self {
        Self {
            pending_recruitment,
            railhead_target,
            resource_order_metrics,
            city_order_demand,
            deferred_labor_shortfall,
            production_deficit_by_slot,
            temporarily_reserved_ship_arms,
            railhead_priority_by_resource,
            exterior_need_by_resource,
            historical_need_by_resource,
            civilian_order_demand_by_resource,
            average_development_order_allocation,
            pending_development_actions,
        }
    }

    pub const fn pending_recruitment(&self) -> Option<CivilianUnitKind> {
        self.pending_recruitment
    }

    pub const fn railhead_target(&self) -> Option<TileId> {
        self.railhead_target
    }

    pub const fn resource_order_metrics(&self) -> &ResourceTable<i32> {
        &self.resource_order_metrics
    }

    pub const fn city_order_demand(&self) -> &AiCityOrderDemand {
        &self.city_order_demand
    }

    pub const fn deferred_labor_shortfall(&self) -> i32 {
        self.deferred_labor_shortfall
    }

    pub const fn production_deficit_by_slot(&self) -> &ProductionTable<i32> {
        &self.production_deficit_by_slot
    }

    pub const fn temporarily_reserved_ship_arms(&self) -> i32 {
        self.temporarily_reserved_ship_arms
    }

    pub const fn railhead_priority_by_resource(&self) -> &ResourceTable<i32> {
        &self.railhead_priority_by_resource
    }

    pub const fn exterior_need_by_resource(&self) -> &ResourceTable<i32> {
        &self.exterior_need_by_resource
    }

    pub const fn historical_need_by_resource(&self) -> &ResourceTable<i32> {
        &self.historical_need_by_resource
    }

    pub const fn civilian_order_demand_by_resource(&self) -> &ResourceTable<i32> {
        &self.civilian_order_demand_by_resource
    }

    pub fn pending_development_actions(&self) -> &[PendingDevelopmentAction] {
        &self.pending_development_actions
    }
}

/// Demand retained after `TCityInteriorMinister::MakeNewCity` binds an AI Frog City.
pub(crate) fn initial_ai_city_order_demand() -> AiCityOrderDemand {
    let mut demand = AiCityOrderDemand::default();
    demand.expansions[ExpandableFacility::TextileMill] = 2;
    demand.expansions[ExpandableFacility::ClothingFactory] = 1;
    demand.expansions[ExpandableFacility::SteelMill] = 2;
    demand.expansions[ExpandableFacility::LumberMill] = 2;
    demand
}

/// An AI major's current use of one province or live sea/port-zone target.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiTargetState {
    #[default]
    Unmarked,
    Candidate,
    MissionQueued,
}

/// The exact foreign-minister behavior selected for a major nation.
///
/// Retail constructs the base minister for human and proxy nations. AI nations
/// receive one of the six personality implementations selected by map setup.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForeignMinisterPersonality {
    Base,
    Arms,
    Trader,
    Textile,
    Diplomat,
    Bill,
    Ted,
}

impl ForeignMinisterPersonality {
    pub(crate) const fn initial_skill_index(self) -> i32 {
        match self {
            Self::Base | Self::Arms => 0,
            Self::Trader => 1,
            Self::Textile => 2,
            Self::Diplomat => 3,
            Self::Bill => 4,
            Self::Ted => 5,
        }
    }
}
