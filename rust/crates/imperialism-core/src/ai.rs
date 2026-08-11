use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AiTradeState {
    /// Temporary stock synthesized for resources food through fuel during AI bidding.
    pub temporary_processed_stock: ProcessedTradeCommodityTable<i16>,
}

/// Persistent inputs and pending work owned by retail's city interior minister.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct InteriorCivilianState {
    pub(crate) pending_recruitment: Option<CivilianUnitKind>,
    pub(crate) railhead_target: Option<TileId>,
    pub(crate) resource_order_metrics: ResourceTable<i16>,
    pub(crate) city_order_demand: AiCityOrderDemand,
    pub(crate) deferred_labor_shortfall: i16,
    pub(crate) production_deficit_by_slot: ProductionTable<i16>,
    pub(crate) temporarily_reserved_ship_arms: i16,
    pub(crate) railhead_priority_by_resource: ResourceTable<i16>,
    pub(crate) exterior_need_by_resource: ResourceTable<i16>,
    pub(crate) historical_need_by_resource: ResourceTable<i16>,
    pub(crate) civilian_order_demand_by_resource: ResourceTable<i16>,
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
    pub(crate) training: TrainingOrderTable<i16>,
    pub(crate) military_recruitment: MilitaryRecruitOrderTable<i16>,
    pub(crate) civilian_recruitment: CivilianUnitTable<i16>,
    pub(crate) ships: ShipOrderTable<i16>,
    pub(crate) transport_capacity: i16,
    pub(crate) expansions: ProductionTable<i16>,
    pub(crate) population_growth: i16,
}

impl AiCityOrderDemand {
    pub fn from_parts(
        training: TrainingOrderTable<i16>,
        military_recruitment: MilitaryRecruitOrderTable<i16>,
        civilian_recruitment: CivilianUnitTable<i16>,
        ships: ShipOrderTable<i16>,
        transport_capacity: i16,
        expansions: ProductionTable<i16>,
        population_growth: i16,
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
        resource_order_metrics: ResourceTable<i16>,
        city_order_demand: AiCityOrderDemand,
        deferred_labor_shortfall: i16,
        production_deficit_by_slot: ProductionTable<i16>,
        temporarily_reserved_ship_arms: i16,
        railhead_priority_by_resource: ResourceTable<i16>,
        exterior_need_by_resource: ResourceTable<i16>,
        historical_need_by_resource: ResourceTable<i16>,
        civilian_order_demand_by_resource: ResourceTable<i16>,
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
}

/// Demand retained after `TCityInteriorMinister::MakeNewCity` binds an AI Frog City.
pub(crate) fn initial_ai_city_order_demand() -> AiCityOrderDemand {
    let mut demand = AiCityOrderDemand::default();
    demand.expansions[CityFacilitySlot::TextileMill] = 2;
    demand.expansions[CityFacilitySlot::ClothingFactory] = 1;
    demand.expansions[CityFacilitySlot::SteelMill] = 2;
    demand.expansions[CityFacilitySlot::LumberMill] = 2;
    demand
}

/// Runtime-derived inputs used by an AI major when selecting a fort province.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AiDevelopmentPressureState {
    pub(crate) expansion_pressure_per_compatible_region_bits: u32,
    pub(crate) average_unit_divergence_per_owned_region_bits: u32,
    pub(crate) active_mission_pressure_average_bits: u32,
}

impl AiDevelopmentPressureState {
    pub(crate) fn expansion_pressure_per_compatible_region(self) -> f32 {
        f32::from_bits(self.expansion_pressure_per_compatible_region_bits)
    }

    pub(crate) fn average_unit_divergence_per_owned_region(self) -> f32 {
        f32::from_bits(self.average_unit_divergence_per_owned_region_bits)
    }

    pub(crate) fn active_mission_pressure_average(self) -> f32 {
        f32::from_bits(self.active_mission_pressure_average_bits)
    }
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
    pub(crate) const fn initial_skill_index(self) -> i16 {
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
