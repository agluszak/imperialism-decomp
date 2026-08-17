use crate::*;
use serde::{Deserialize, Serialize};

/// One retail `TTown` marker from its owning great power's ordered town list.
///
/// A great power has one [`CityState`] and any number of towns. The first town
/// is the city's home marker after save load; the city does not own a duplicate
/// copy of that marker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TownState {
    pub name: String,
    pub created_turn: i16,
    pub owner_nation: NationId,
    pub resource_yield_by_type: ResourceTable<i16>,
    pub transport_linked: bool,
    /// Retail's verbatim one-byte `enabledFlag`.
    pub enabled: u8,
    /// Persisted verbatim because older states may contain a noncanonical true byte.
    pub has_adjacent_city: u8,
    pub active: bool,
}

impl TownState {
    pub(crate) fn constructed(
        _tile: TileId,
        owner_nation: NationId,
        enabled: u8,
        created_turn: i16,
    ) -> Self {
        Self {
            name: String::new(),
            created_turn,
            owner_nation,
            resource_yield_by_type: ResourceTable::default(),
            transport_linked: false,
            enabled,
            has_adjacent_city: 0,
            active: enabled == 0,
        }
    }

    pub(crate) fn for_frog_city(_tile: TileId, owner_nation: NationId) -> Self {
        Self {
            name: "FrogCity".to_owned(),
            created_turn: 0,
            owner_nation,
            resource_yield_by_type: ResourceTable::default(),
            transport_linked: false,
            enabled: 1,
            has_adjacent_city: 0,
            active: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CityState {
    pub orders: CityOrders,
    pub power_plant_upgrade_queued: bool,
    pub food_substitution_count: i16,
    pub starvation_population_loss: i16,
    pub serialized_state: i16,
    pub phase_counter: i16,
    /// Cumulative military recruit deltas by [`MilitaryUnitKind`].
    #[serde(
        serialize_with = "crate::units::serialize_military_unit_table",
        deserialize_with = "crate::units::deserialize_military_unit_table"
    )]
    pub military_recruit_count_by_kind: MilitaryUnitTable<i16>,
    /// Cumulative civilian recruit deltas by [`CivilianUnitKind`].
    #[serde(
        serialize_with = "crate::units::serialize_civilian_unit_table",
        deserialize_with = "crate::units::deserialize_civilian_unit_table"
    )]
    pub civilian_recruit_count_by_kind: CivilianUnitTable<i16>,
    pub ship_order_count_by_type: ShipTypeTable<i16>,
    pub rolling_item_production_score: i32,
    pub low_production: bool,
    pub low_stock: bool,
    pub reserved_by_type: ResourceTable<i16>,
    pub power_available: i16,
    pub stockpile: Stockpile,
    pub production_orders: ProductionTable<i16>,
    pub production_accum: ProductionTable<i16>,
    pub building_windows: ProductionTable<Option<CityWindowPosition>>,
    pub population_growth_penalty_ticks: i16,
    pub unmet_resource_retries: ResourceTable<i16>,
    pub consumed_production_input_by_type: ResourceTable<i16>,
    pub population: PopulationState,
}

impl CityState {
    /// Builds the scenario start city. `stockpile` and `production` come from
    /// the difficulty presets, `labor` is the `SetPopulation` triple, and only
    /// the human capital gets the Frog City marker at tile 0.
    pub(crate) fn for_random_start(
        stockpile: ResourceTable<i16>,
        production: ProductionTable<i16>,
        labor: LaborPool,
        _human: bool,
    ) -> Self {
        Self {
            orders: CityOrders::default(),
            power_plant_upgrade_queued: false,
            food_substitution_count: 0,
            starvation_population_loss: 0,
            serialized_state: 0,
            phase_counter: 0,
            military_recruit_count_by_kind: MilitaryUnitTable::default(),
            civilian_recruit_count_by_kind: CivilianUnitTable::default(),
            ship_order_count_by_type: ShipTypeTable::default(),
            rolling_item_production_score: 0,
            low_production: false,
            low_stock: false,
            reserved_by_type: ResourceTable::default(),
            power_available: 0,
            stockpile: Stockpile::from_table(stockpile),
            production_orders: production,
            production_accum: production,
            building_windows: ProductionTable::default(),
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: ResourceTable::default(),
            consumed_production_input_by_type: ResourceTable::default(),
            population: PopulationState::from_labor(labor),
        }
    }
}

/// City stock counters. Retail stores these as `short` and uses 16-bit wrap;
/// [`Self::verify_stocks`] is the explicit clamp from `TCity::VerifyStocks`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Stockpile(ResourceTable<i16>);

impl Stockpile {
    pub fn from_table(amounts: ResourceTable<i16>) -> Self {
        Self(amounts)
    }

    /// Retail `TCity::VerifyStocks`: clamp each negative stock to 0.
    pub fn verify_stocks(&mut self) {
        for amount in self.0.values_mut() {
            if *amount < 0 {
                *amount = 0;
            }
        }
    }

    pub(crate) fn wrapping_add(&mut self, resource: crate::ResourceKind, amount: i16) {
        self.0[resource] = self.0[resource].wrapping_add(amount);
    }

    /// Wrap, then clamp every negative stock. Retail `AddToCityStockCounterAndRefresh`
    /// and each `SetQuantity` / `Produce` stock mutation.
    pub(crate) fn wrapping_add_and_verify(&mut self, resource: crate::ResourceKind, amount: i16) {
        self.wrapping_add(resource, amount);
        self.verify_stocks();
    }
}

impl std::ops::Index<crate::ResourceKind> for Stockpile {
    type Output = i16;
    fn index(&self, resource: crate::ResourceKind) -> &Self::Output {
        &self.0[resource]
    }
}

impl std::ops::IndexMut<crate::ResourceKind> for Stockpile {
    fn index_mut(&mut self, resource: crate::ResourceKind) -> &mut Self::Output {
        &mut self.0[resource]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stockpile_wraps_and_verify_stocks_clamps_negatives() {
        let mut stockpile = Stockpile::from_table(ResourceTable::from_array([-1; 23]));
        assert_eq!(stockpile[ResourceKind::Paper], -1);

        stockpile.wrapping_add(ResourceKind::Paper, 1);
        assert_eq!(stockpile[ResourceKind::Paper], 0);
        stockpile.wrapping_add(ResourceKind::Paper, -1);
        assert_eq!(stockpile[ResourceKind::Paper], -1);
        stockpile[ResourceKind::Paper] = i16::MAX;
        stockpile.wrapping_add(ResourceKind::Paper, 1);
        assert_eq!(stockpile[ResourceKind::Paper], i16::MIN);

        stockpile.verify_stocks();
        assert_eq!(stockpile[ResourceKind::Paper], 0);
        assert!(crate::all_resources().all(|resource| stockpile[resource] >= 0));
    }
}
