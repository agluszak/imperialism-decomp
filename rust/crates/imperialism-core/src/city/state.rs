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
    pub tile: TileId,
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
    pub(crate) fn for_frog_city(tile: TileId, owner_nation: NationId) -> Self {
        Self {
            name: "FrogCity".to_owned(),
            tile,
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
    /// Boxed to keep the dense fixed order tables out of already-large
    /// full-state stack frames.
    pub orders: Box<CityOrders>,
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
    pub production_flags: ProductionTable<u8>,
    pub production_current: ProductionTable<i16>,
    pub production_progress: ProductionTable<i16>,
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
            orders: Box::default(),
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
            production_orders: production.clone(),
            production_accum: production,
            production_flags: ProductionTable::default(),
            production_current: ProductionTable::default(),
            production_progress: ProductionTable::default(),
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: ResourceTable::default(),
            consumed_production_input_by_type: ResourceTable::default(),
            population: PopulationState::from_labor(labor),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Stockpile(ResourceTable<i16>);

impl<'de> Deserialize<'de> for Stockpile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self::from_table(ResourceTable::deserialize(deserializer)?))
    }
}

impl Stockpile {
    pub fn from_table(mut amounts: ResourceTable<i16>) -> Self {
        amounts
            .values_mut()
            .for_each(|amount| *amount = (*amount).max(0));
        Self(amounts)
    }
    pub(crate) fn credit(&mut self, resource: crate::ResourceKind, amount: i16) {
        self.0[resource] = self.0[resource].saturating_add(amount).max(0);
    }
    pub(crate) fn debit_clamped(&mut self, resource: crate::ResourceKind, amount: i16) {
        self.0[resource] = self.0[resource].saturating_sub(amount).max(0);
    }
    pub(crate) fn set_nonnegative(&mut self, resource: crate::ResourceKind, amount: i16) {
        self.0[resource] = amount.max(0);
    }
}

impl std::ops::Index<crate::ResourceKind> for Stockpile {
    type Output = i16;
    fn index(&self, resource: crate::ResourceKind) -> &Self::Output {
        &self.0[resource]
    }
}

#[cfg(test)]
impl std::ops::IndexMut<crate::ResourceKind> for Stockpile {
    fn index_mut(&mut self, resource: crate::ResourceKind) -> &mut Self::Output {
        &mut self.0[resource]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stockpile_deserialization_normalizes_each_resource_once() {
        let serialized = serde_json::to_string(&ResourceTable::from_array([-1; 23])).unwrap();
        let stockpile: Stockpile = serde_json::from_str(&serialized).unwrap();

        assert_eq!(stockpile[ResourceKind::Paper], 0);
        assert!(crate::all_resources().all(|resource| stockpile[resource] >= 0));
    }
}
