use crate::market::all_trade_commodities;
use crate::*;

/// One player order on a Board of Trade commodity row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlayerTradeOrder {
    None,
    Buy,
    Sell(i16),
}

impl PlayerTradeOrder {
    fn from_potential(value: i16) -> Self {
        if value < 0 {
            Self::Buy
        } else if value > 0 {
            Self::Sell(value)
        } else {
            Self::None
        }
    }
}

/// One row in retail's transport-allocation ledger.
///
/// Cotton and wool share a row, as do fish and livestock. The remaining
/// visible rows each address one resource directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportAllocation {
    primary: ResourceKind,
    secondary: Option<ResourceKind>,
}

/// The authoritative values displayed by one retail transport-ledger row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportRowStatus {
    pub allocated: i16,
    pub available: i16,
    pub limit: Option<i16>,
    pub adjustable: bool,
    pub can_decrease: bool,
    pub can_increase: bool,
}

impl TransportAllocation {
    pub const COTTON_AND_WOOL: Self = Self::pair(ResourceKind::Cotton, ResourceKind::Wool);
    pub const TIMBER: Self = Self::single(ResourceKind::Timber);
    pub const COAL: Self = Self::single(ResourceKind::Coal);
    pub const IRON: Self = Self::single(ResourceKind::Iron);
    pub const HORSES: Self = Self::single(ResourceKind::Horses);
    pub const OIL: Self = Self::single(ResourceKind::Oil);
    pub const FABRIC: Self = Self::single(ResourceKind::Fabric);
    pub const LUMBER: Self = Self::single(ResourceKind::Lumber);
    pub const STEEL: Self = Self::single(ResourceKind::Steel);
    pub const FUEL: Self = Self::single(ResourceKind::Fuel);
    pub const CLOTHING: Self = Self::single(ResourceKind::Clothing);
    pub const FURNITURE: Self = Self::single(ResourceKind::Furniture);
    pub const HARDWARE: Self = Self::single(ResourceKind::Hardware);
    pub const GRAIN: Self = Self::single(ResourceKind::Grain);
    pub const FRUIT: Self = Self::single(ResourceKind::Fruit);
    pub const FISH_AND_LIVESTOCK: Self = Self::pair(ResourceKind::Fish, ResourceKind::Livestock);
    pub const GEMS: Self = Self::single(ResourceKind::Gems);
    pub const GOLD: Self = Self::single(ResourceKind::Gold);

    const fn single(resource: ResourceKind) -> Self {
        Self {
            primary: resource,
            secondary: None,
        }
    }

    const fn pair(primary: ResourceKind, secondary: ResourceKind) -> Self {
        Self {
            primary,
            secondary: Some(secondary),
        }
    }

    pub const fn resources(self) -> (ResourceKind, Option<ResourceKind>) {
        (self.primary, self.secondary)
    }
}

impl GameState {
    /// Recalculates the world's seventeen market commodity prices in retail order.
    pub fn recalculate_trade_prices(&mut self) {
        self.market.recalculate_prices();
    }

    pub fn player_trade_order(
        &self,
        nation: MajorNationId,
        commodity: TradeCommodity,
    ) -> PlayerTradeOrder {
        PlayerTradeOrder::from_potential(
            self.nations.majors[nation].economy.item_potentials[commodity.resource()],
        )
    }

    /// Applies one retail Board of Trade order without settling any trade.
    pub fn set_player_trade_order(
        &mut self,
        nation: MajorNationId,
        commodity: TradeCommodity,
        order: PlayerTradeOrder,
    ) -> PlayerTradeOrder {
        assert!(
            self.nations.majors[nation].economy.diplomacy_eligible,
            "player trade order requires a diplomacy-eligible major nation"
        );

        let resource = commodity.resource();
        let current = self.player_trade_order(nation, commodity);
        let value = match order {
            PlayerTradeOrder::None => 0,
            PlayerTradeOrder::Buy => {
                let bid_count = all_trade_commodities()
                    .filter(|&row| self.player_trade_order(nation, row) == PlayerTradeOrder::Buy)
                    .count();
                if current != PlayerTradeOrder::Buy && bid_count >= 4 {
                    return current;
                }
                -1
            }
            PlayerTradeOrder::Sell(requested) => {
                let major = &self.nations.majors[nation];
                let maximum =
                    major.city.stockpile[resource].min(major.economy.capacities.trade_offer);
                if maximum <= 0 {
                    return current;
                }
                requested.clamp(1, maximum)
            }
        };

        let major = &mut self.nations.majors[nation].economy;
        major.set_item_potential(resource, value);
        PlayerTradeOrder::from_potential(major.item_potentials[resource])
    }

    /// Steps one selected Board of Trade offer without re-clamping a recalled order.
    pub fn step_player_trade_offer(
        &mut self,
        nation: MajorNationId,
        commodity: TradeCommodity,
        delta: i16,
    ) -> PlayerTradeOrder {
        assert!(matches!(delta, -1 | 1), "trade offer step must be -1 or 1");
        assert!(
            self.nations.majors[nation].economy.diplomacy_eligible,
            "player trade order requires a diplomacy-eligible major nation"
        );

        let PlayerTradeOrder::Sell(quantity) = self.player_trade_order(nation, commodity) else {
            return self.player_trade_order(nation, commodity);
        };
        let resource = commodity.resource();
        let major = &self.nations.majors[nation];
        let maximum = major.city.stockpile[resource].min(major.economy.capacities.trade_offer);
        let next = if delta < 0 && quantity > 1 {
            quantity - 1
        } else if delta > 0 && quantity < maximum {
            quantity + 1
        } else {
            quantity
        };
        self.nations.majors[nation].economy.item_potentials[resource] = next;
        PlayerTradeOrder::Sell(next)
    }

    pub fn purchase_item(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
        amount: i16,
        price: i16,
    ) {
        let MajorNation {
            common, economy, ..
        } = &mut self.nations.majors[nation];
        settle_purchase(common, economy, resource, amount, price);
    }

    pub fn remember_trade_bids(&mut self, nation: MajorNationId) {
        self.nations.majors[nation].economy.remember_trade_bids();
    }

    pub fn commit_purchased_items(&mut self, nation: MajorNationId) {
        let MajorNation { economy, city, .. } = &mut self.nations.majors[nation];
        economy.settle_purchased_items(city);
    }

    /// Settles the nation's transported-item ledger into city stock.
    pub fn settle_transported_items(&mut self, nation: MajorNationId) {
        let MajorNation { economy, city, .. } = &mut self.nations.majors[nation];
        economy.settle_transported_items(city);
    }

    /// Mirrors `TGreatPower::AddCreatedItems` at the city-and-transport phase
    /// boundary. Commodity targets remain available for the rest of the phase;
    /// only the city's settled stock changes here.
    pub fn add_created_items(&mut self, nation: MajorNationId) {
        let MajorNation {
            common,
            economy: major,
            city,
            ..
        } = &mut self.nations.majors[nation];

        common.treasury += i32::from(major.need_target_by_type[ResourceKind::Gems]) * 500;
        city.stockpile[ResourceKind::Gems] = 0;
        city.stockpile.verify_stocks();

        common.treasury += i32::from(major.need_target_by_type[ResourceKind::Gold]) * 200;
        city.stockpile[ResourceKind::Gold] = 0;
        city.stockpile.verify_stocks();

        for resource in all_resources() {
            city.stockpile
                .wrapping_add_and_verify(resource, major.need_target_by_type[resource]);
        }
    }

    /// Queues or cancels the city's power-plant upgrade and applies its
    /// corresponding treasury charge or refund.
    pub fn set_power_plant_upgrade(&mut self, nation: MajorNationId, enabled: bool) {
        let MajorNation { common, city, .. } = &mut self.nations.majors[nation];
        city.set_power_plant_upgrade(&mut common.treasury, enabled);
    }

    /// Moves one resource into city stock, limited by both the resource need
    /// and unused transport capacity.
    pub fn direct_transport(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
        requested: i16,
    ) -> i16 {
        let MajorNation {
            economy: major,
            city,
            ..
        } = &mut self.nations.majors[nation];
        city.direct_transport(major, resource, requested)
    }

    /// Steps one retail transport-ledger row down or up by one unit.
    ///
    /// This changes the allocation that will be delivered during city and
    /// transport resolution. It deliberately does not credit city stock now.
    pub fn step_transport_allocation(
        &mut self,
        nation: MajorNationId,
        allocation: TransportAllocation,
        delta: i16,
    ) -> bool {
        assert!(
            delta == -1 || delta == 1,
            "transport ledger steps are one unit"
        );

        let cotton_first = self.market.rows[TradeCommodity::Cotton].price
            > self.market.rows[TradeCommodity::Wool].price;
        let major = &mut self.nations.majors[nation].economy;
        let current = transport_allocation_total(&major.need_current_by_type, allocation);
        let target = transport_allocation_total(&major.need_target_by_type, allocation);
        if current == 0
            || (delta > 0
                && (target >= current
                    || major.capacities.reserved_transport == major.capacities.transport))
            || (delta < 0 && target <= 0)
        {
            return false;
        }

        let new_target = target + delta;
        if allocation == TransportAllocation::COTTON_AND_WOOL {
            let (primary, secondary) = if cotton_first {
                (ResourceKind::Cotton, ResourceKind::Wool)
            } else {
                (ResourceKind::Wool, ResourceKind::Cotton)
            };
            split_transport_allocation(major, primary, secondary, new_target);
        } else if allocation == TransportAllocation::FISH_AND_LIVESTOCK {
            split_transport_allocation(
                major,
                ResourceKind::Fish,
                ResourceKind::Livestock,
                new_target,
            );
        } else {
            major.update_need_target(allocation.primary, new_target);
        }
        true
    }

    pub fn transport_row_status(
        &self,
        nation: MajorNationId,
        allocation: TransportAllocation,
    ) -> TransportRowStatus {
        let major = &self.nations.majors[nation];
        let economy = &major.economy;
        let available = transport_allocation_total(&economy.need_current_by_type, allocation);
        let allocated = transport_allocation_total(&economy.need_target_by_type, allocation);
        let adjustable = available != 0;
        TransportRowStatus {
            allocated,
            available,
            limit: transport_row_limit(major, allocation),
            adjustable,
            can_decrease: adjustable && allocated > 0,
            can_increase: adjustable
                && allocated < available
                && economy.capacities.reserved_transport != economy.capacities.transport,
        }
    }

    /// Spends one lumber and one steel to add one transport-capacity unit.
    ///
    pub fn increase_rolling_stock(&mut self, nation: MajorNationId) -> bool {
        let MajorNation {
            economy: major,
            city,
            ..
        } = &mut self.nations.majors[nation];
        city.increase_rolling_stock(major)
    }

    /// Spends three lumber and one fabric to add one merchant-capacity unit.
    ///
    pub fn increase_merchant_marine(&mut self, nation: MajorNationId) -> bool {
        let MajorNation {
            economy: major,
            city,
            ..
        } = &mut self.nations.majors[nation];
        city.increase_merchant_marine(major)
    }

    /// Allocates the next transport capacity across the retail city-policy
    /// priority list.
    pub fn allocate_transport_needs(&mut self, nation: MajorNationId) {
        self.nations.majors[nation]
            .economy
            .allocate_transport_needs();
    }

    /// Replaces a major nation's merchant capacity with its city's current
    /// industry allocation score.
    pub fn refresh_merchant_capacity(&mut self, nation: MajorNationId) {
        let capacity = self.nations.majors[nation].city.merchant_capacity();
        let major = &mut self.nations.majors[nation].economy;
        major.capacities.trade_offer = capacity;
        major.capacities.available_merchant = capacity;
    }

    /// Restores the remembered trade bids, constrained by current city stock,
    /// and clears the preceding aid allocations.
    pub fn recall_trade_bids(&mut self, nation: MajorNationId) {
        let MajorNation {
            economy: major,
            city,
            ..
        } = &mut self.nations.majors[nation];
        let stockpile = city.stockpile;

        for resource in all_resources() {
            let bid = major.remembered_trade_offers_by_resource[resource];
            if bid == -1 {
                major.unfilled_trade_offer_count += 1;
            }
            major.item_potentials[resource] = bid.min(stockpile[resource]);
        }
        major.aid_allocation_by_minor_nation = Default::default();
    }

    /// Restores the player's Board of Trade ledger and applies its no-merchant branch.
    pub fn recall_player_trade_orders(&mut self, nation: MajorNationId) {
        assert!(
            self.nations.majors[nation].economy.diplomacy_eligible,
            "player trade orders require a diplomacy-eligible major nation"
        );
        self.recall_trade_bids(nation);
        let major = &mut self.nations.majors[nation].economy;
        if major.capacities.trade_offer == 0 {
            for commodity in all_trade_commodities() {
                let resource = commodity.resource();
                if major.item_potentials[resource] > 0 {
                    major.item_potentials[resource] = 0;
                }
            }
        }
    }

    /// Resets the retail player trade phase.
    ///
    /// Nations outside this mode use a different retail virtual implementation.
    /// Calling the player implementation for one is an internal phase-dispatch bug.
    pub fn reset_player_trade_phase(&mut self, nation: MajorNationId) {
        assert!(
            self.nations.majors[nation].economy.diplomacy_eligible,
            "player trade phase requires a diplomacy-eligible major nation"
        );

        self.refresh_merchant_capacity(nation);
        let major = &mut self.nations.majors[nation].economy;
        major.unfilled_trade_offer_count = 0;
        major.budget_pool_base = 0;
        major.budget_pool_delta = 0;
        self.recall_trade_bids(nation);
    }

    /// Retail `TGreatPower::ResetDiplomacyNeedScoresAndClearAidAllocationMatrix`
    /// and the `TAutoGreatPower` override.
    pub(crate) fn reset_diplomacy_need_scores_and_clear_aid_allocation_matrix(
        &mut self,
        nation: MajorNationId,
    ) {
        self.refresh_merchant_capacity(nation);
        let is_auto = self.is_auto(nation);
        let major = &mut self.nations.majors[nation].economy;
        major.unfilled_trade_offer_count = 0;
        major.budget_pool_delta = 0;
        major.budget_pool_base = 0;
        if is_auto {
            major.item_potentials = ResourceTable::default();
            major.aid_allocation_by_minor_nation = Default::default();
            return;
        }
        self.recall_trade_bids(nation);
    }

    /// Retail `TGreatPower::ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches`.
    /// The AutoGreatPower override (`SetTradeBids` / subsidy) is not ported.
    pub(crate) fn reset_diplomacy_need_slots_7012_if_mode_gate_matches(
        &mut self,
        nation: MajorNationId,
    ) {
        if self.is_auto(nation) || self.turn.difficulty != Difficulty::Introductory {
            return;
        }
        for resource in [
            ResourceKind::Food,
            ResourceKind::Cotton,
            ResourceKind::Wool,
            ResourceKind::Timber,
        ] {
            self.nations.majors[nation]
                .economy
                .set_item_potential(resource, -1);
        }
        self.remember_trade_bids(nation);
    }

    /// Credits a minor nation's resource-specific aid allocation.
    pub fn add_aid_allocation(
        &mut self,
        nation: MajorNationId,
        minor_nation: MinorNationId,
        resource: ResourceKind,
        amount: i32,
    ) {
        let MajorNation {
            common,
            economy: major,
            ..
        } = &mut self.nations.majors[nation];
        common.treasury += amount;
        major.aid_allocation_by_minor_nation[minor_nation][resource] += amount;
        major.aid_allocation_total += amount;
    }

    /// Sets one current diplomatic grant, refunding the replaced amount before
    /// charging the replacement.
    pub fn set_diplomacy_grant(
        &mut self,
        nation: MajorNationId,
        target: NationId,
        grant: Option<DiplomacyGrant>,
    ) -> bool {
        let MajorNation {
            common,
            economy: major,
            ..
        } = &mut self.nations.majors[nation];
        let current = major.diplomacy_grants_by_nation[target];
        if current == grant {
            return true;
        }
        let current_amount = current.map_or(0, |grant| grant.amount);
        let proposed_amount = grant.map_or(0, |grant| grant.amount);
        if grant.is_some()
            && current_amount - proposed_amount + major.available_diplomacy_budget(common.treasury)
                < 0
        {
            return false;
        }

        major.grant_total_cost += proposed_amount - current_amount;
        common.treasury += current_amount - proposed_amount;
        major.diplomacy_grants_by_nation[target] = grant;
        true
    }

    /// Clears current diplomacy policies and one-time grants, then posts each
    /// recurring grant through the ordinary treasury path.
    pub fn reset_diplomacy_commitments(&mut self, nation: MajorNationId) {
        for target in NationId::all() {
            let recurring_grant = {
                let major = &mut self.nations.majors[nation].economy;
                major.diplomacy_policy_by_nation[target] = None;
                let grant = major.diplomacy_grants_by_nation[target];
                major.diplomacy_grants_by_nation[target] = None;
                grant.filter(|grant| grant.recurring)
            };

            if let Some(grant) = recurring_grant {
                let _ = self.set_diplomacy_grant(nation, target, Some(grant));
            }
        }
    }

    /// Applies one recovered decrement to a bilateral trade-policy score.
    pub fn decrement_trade_policy_score(&mut self, nation: MajorNationId, target: NationId) {
        let common = &mut self.nations.majors[nation].common;
        let next = common.trade_policy_by_nation[target].decrement_step(common.treasury);
        common.trade_policy_by_nation[target] = next;
    }

    /// Sets one bilateral trade policy and clears its grant for a boycott.
    pub fn set_trade_policy(
        &mut self,
        nation: MajorNationId,
        target: NationId,
        policy: TradePolicyScore,
    ) {
        let common = &mut self.nations.majors[nation].common;
        if target != nation.nation() {
            common.trade_policy_by_nation[target] = policy;
        }

        if policy == TradePolicyScore::BOYCOTT {
            self.set_diplomacy_grant(nation, target, None);
        }
    }
}

fn transport_allocation_total(
    amounts: &ResourceTable<i16>,
    allocation: TransportAllocation,
) -> i16 {
    let (primary, secondary) = allocation.resources();
    amounts[primary] + secondary.map_or(0, |resource| amounts[resource])
}

fn transport_row_limit(major: &MajorNation, allocation: TransportAllocation) -> Option<i16> {
    let city = &major.city;
    let building =
        |slot| city.building_type(slot, &major.economy, major.common.owned_region_count());
    let deficit = if allocation == TransportAllocation::COTTON_AND_WOOL {
        building(CityFacilitySlot::TextileMill) * 2
            - city.stockpile[ResourceKind::Cotton]
            - city.stockpile[ResourceKind::Wool]
    } else if allocation == TransportAllocation::TIMBER {
        building(CityFacilitySlot::LumberMill) * 2 - city.stockpile[ResourceKind::Timber]
    } else if allocation == TransportAllocation::COAL {
        building(CityFacilitySlot::SteelMill) - city.stockpile[ResourceKind::Coal]
    } else if allocation == TransportAllocation::IRON {
        building(CityFacilitySlot::SteelMill) - city.stockpile[ResourceKind::Iron]
    } else if allocation == TransportAllocation::OIL {
        building(CityFacilitySlot::OilRefinery) * 2 - city.stockpile[ResourceKind::Oil]
    } else if allocation == TransportAllocation::FABRIC {
        building(CityFacilitySlot::ClothingFactory) * 2 - city.stockpile[ResourceKind::Fabric]
    } else if allocation == TransportAllocation::LUMBER {
        building(CityFacilitySlot::FurnitureFactory) * 2 - city.stockpile[ResourceKind::Lumber]
    } else if allocation == TransportAllocation::STEEL {
        building(CityFacilitySlot::Metalworks) * 2 - city.stockpile[ResourceKind::Steel]
    } else if allocation == TransportAllocation::FUEL {
        building(CityFacilitySlot::PowerPlant) * 2 - city.stockpile[ResourceKind::Fuel]
    } else if allocation == TransportAllocation::GRAIN {
        city.population.predicted_need(ResourceKind::Grain) - city.stockpile[ResourceKind::Grain]
    } else if allocation == TransportAllocation::FRUIT {
        city.population.predicted_need(ResourceKind::Fruit) - city.stockpile[ResourceKind::Fruit]
    } else if allocation == TransportAllocation::FISH_AND_LIVESTOCK {
        city.population.predicted_need(ResourceKind::Livestock)
            - city.stockpile[ResourceKind::Fish]
            - city.stockpile[ResourceKind::Livestock]
    } else {
        return None;
    };
    Some(deficit.max(0))
}

fn split_transport_allocation(
    major: &mut GreatPowerState,
    primary: ResourceKind,
    secondary: ResourceKind,
    total: i16,
) {
    let primary_target = major.need_current_by_type[primary].min(total);
    major.update_need_target(primary, primary_target);
    major.update_need_target(secondary, total - primary_target);
}

fn settle_purchase(
    common: &mut NationCommonState,
    major: &mut GreatPowerState,
    resource: ResourceKind,
    amount: i16,
    price: i16,
) {
    major.purchased_items_by_resource[resource] += amount;
    let cost = i32::from(price) * i32::from(amount);
    common.treasury -= cost;

    if amount > 0 {
        major.capacities.available_merchant -= amount;
        major.budget_pool_delta -= cost;
    } else {
        major.budget_pool_base -= cost;
        if is_special_nation_interaction_resource(resource) {
            major.special_resource_trade_balance -= i32::from(amount);
        }
    }
}

const fn is_special_nation_interaction_resource(resource: ResourceKind) -> bool {
    matches!(
        resource,
        ResourceKind::Clothing
            | ResourceKind::Furniture
            | ResourceKind::Hardware
            | ResourceKind::Arms
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn major() -> GreatPowerState {
        let mut major = crate::test_support::great_power_state();
        major.capacities = crate::NationCapacities::from_array([10, 4, 0, 0]);
        major.budget_pool_base = 200;
        major.budget_pool_delta = 100;
        major.special_resource_trade_balance = 30;
        major
    }

    fn state() -> GameState {
        let majors = crate::MajorNationTable::from_fn(|nation| MajorNation {
            auto: None,
            common: NationCommonState::from_parts(
                String::new(),
                crate::CountryStatus::Independent,
                Vec::new(),
                1_000,
                Some(crate::TileId::new(0)),
                crate::NationTable::default(),
            ),
            economy: major(),
            city: city(),
            towns: vec![crate::TownState::for_frog_city(
                crate::TileId::new(0),
                nation.nation(),
            )],
        });
        let mut diplomacy_rng = RetailCrtRng::from_state(1);
        GameState {
            turn: TurnState {
                scenario_map: None,
                economic_turn: 1,
                diplomacy_year_term_raw: 1914,
                phase: crate::PhaseCode::STRATEGIC_MAP,
                turn_flow_status_flags: 0,
                quarter_gate_by_decade: [0, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                difficulty: Difficulty::Easy,
                active_nation: NationId::new(6),
                selected_nation: NationId::new(6),
                last_turn_alert_tick: 0,
                turn_alert_mask: 0,
                turn_cooldown_defer_counter: 0,
            },
            unit_ids: crate::UnitIdAllocator::default(),
            map: MapMgr::new(
                crate::MapTopology::Bounded,
                vec![crate::TileState::default(); crate::STRATEGIC_TILE_COUNT],
            ),
            map_view_origin: TileId::new(1),
            ocean: Ocean::default(),
            rng: RngState {
                crt_rand: RetailCrtRng::from_state(1),
                map_generation: RetailLcg::from_state(1),
                zone_status: RetailLcg::from_state(1),
            },
            market: crate::TradeMarketState::default(),
            technology: crate::TechnologyState::default(),
            diplomacy: crate::DiplomacyState::for_random_start(
                crate::MajorNationId::new(6),
                Difficulty::Normal,
                &mut diplomacy_rng,
            ),
            nations: Nations::new(majors, MinorNationTable::default()),
            military_units: Default::default(),
            civilian_units: Default::default(),
            object_ids: crate::ObjectIdAllocator::default(),
            ships: Default::default(),
            admirals: Default::default(),
            task_forces: Default::default(),
            missions: Default::default(),
            news: crate::NewsState::default(),
            pending: crate::PendingWorkState::default(),
            battle_reports: Vec::new(),
            continuation: crate::turn_flow::TurnContinuation::None,
        }
    }

    fn city() -> CityState {
        CityState {
            population: PopulationState {
                count: 0,
                accumulator: crate::PopulationAccumulator::from_bits(0),
                strength: 0,
                extra: 0,
                strike_phase: crate::StrikePhase::default(),
                baseline_labor: LaborPool::default(),
                production_labor: LaborPool::default(),
                pending_labor_delta: LaborPool::default(),
                predicted_need_by_resource: crate::ResourceTable::default(),
            },
            ..crate::test_support::city()
        }
    }

    #[test]
    fn transport_ledger_steps_grouped_rows_without_settling_city_stock() {
        let nation = MajorNationId::new(6);
        let mut game = state();
        let city_before = game.nations.majors[nation].city.stockpile;
        let major = &mut game.nations.majors[nation].economy;
        major.capacities.transport = 10;
        major.need_current_by_type[ResourceKind::Cotton] = 2;
        major.need_current_by_type[ResourceKind::Wool] = 2;
        major.need_current_by_type[ResourceKind::Fish] = 1;
        major.need_current_by_type[ResourceKind::Livestock] = 2;

        let status = game.transport_row_status(nation, TransportAllocation::COTTON_AND_WOOL);
        assert_eq!(status.allocated, 0);
        assert_eq!(status.available, 4);
        assert!(status.adjustable);
        assert!(!status.can_decrease);
        assert!(status.can_increase);

        // Equal prices prioritize wool in the recovered ledger.
        assert!(game.step_transport_allocation(nation, TransportAllocation::COTTON_AND_WOOL, 1));
        let major = &game.nations.majors[nation].economy;
        assert_eq!(major.need_target_by_type[ResourceKind::Cotton], 0);
        assert_eq!(major.need_target_by_type[ResourceKind::Wool], 1);

        game.market.rows[TradeCommodity::Cotton].price += 1;
        assert!(game.step_transport_allocation(nation, TransportAllocation::COTTON_AND_WOOL, 1));
        let major = &game.nations.majors[nation].economy;
        assert_eq!(major.need_target_by_type[ResourceKind::Cotton], 2);
        assert_eq!(major.need_target_by_type[ResourceKind::Wool], 0);
        let status = game.transport_row_status(nation, TransportAllocation::COTTON_AND_WOOL);
        assert_eq!(status.allocated, 2);
        assert!(status.can_decrease);

        assert!(game.step_transport_allocation(nation, TransportAllocation::FISH_AND_LIVESTOCK, 1));
        assert!(game.step_transport_allocation(nation, TransportAllocation::FISH_AND_LIVESTOCK, 1));
        assert!(game.step_transport_allocation(
            nation,
            TransportAllocation::FISH_AND_LIVESTOCK,
            -1
        ));
        let major = &game.nations.majors[nation].economy;
        assert_eq!(major.need_target_by_type[ResourceKind::Fish], 1);
        assert_eq!(major.need_target_by_type[ResourceKind::Livestock], 0);
        assert_eq!(major.capacities.reserved_transport, 3);
        assert_eq!(game.nations.majors[nation].city.stockpile, city_before);

        let major = &mut game.nations.majors[nation].economy;
        major.need_current_by_type[ResourceKind::Hardware] = 2;
        major.capacities.transport = 3;
        major.capacities.reserved_transport = 3;
        assert!(!game.step_transport_allocation(nation, TransportAllocation::HARDWARE, 1));
        game.nations.majors[nation]
            .economy
            .capacities
            .reserved_transport = 4;
        assert!(game.step_transport_allocation(nation, TransportAllocation::HARDWARE, 1));
        let major = &game.nations.majors[nation].economy;
        assert_eq!(major.need_target_by_type[ResourceKind::Hardware], 1);
        assert_eq!(major.capacities.reserved_transport, 5);
    }

    #[test]
    fn player_trade_orders_preserve_retail_modes_and_limits() {
        let nation = MajorNationId::new(6);
        let mut game = state();
        game.nations.city_mut(nation).stockpile[ResourceKind::Fabric] = 3;
        game.nations.majors[nation].economy.capacities.trade_offer = 0;
        assert_eq!(
            game.set_player_trade_order(nation, TradeCommodity::Cotton, PlayerTradeOrder::Buy),
            PlayerTradeOrder::Buy
        );
        game.set_player_trade_order(nation, TradeCommodity::Cotton, PlayerTradeOrder::None);
        game.nations.majors[nation].economy.capacities.trade_offer = 4;
        assert_eq!(
            game.set_player_trade_order(nation, TradeCommodity::Fabric, PlayerTradeOrder::Sell(9)),
            PlayerTradeOrder::Sell(3)
        );
        assert_eq!(
            game.set_player_trade_order(nation, TradeCommodity::Fabric, PlayerTradeOrder::Sell(0)),
            PlayerTradeOrder::Sell(1)
        );

        game.nations.city_mut(nation).stockpile[ResourceKind::Fabric] = 10;
        game.nations.majors[nation]
            .economy
            .remembered_trade_offers_by_resource[ResourceKind::Fabric] = 10;
        game.recall_player_trade_orders(nation);
        assert_eq!(
            game.step_player_trade_offer(nation, TradeCommodity::Fabric, -1),
            PlayerTradeOrder::Sell(9)
        );
        assert_eq!(
            game.step_player_trade_offer(nation, TradeCommodity::Fabric, 1),
            PlayerTradeOrder::Sell(9)
        );
        game.nations.majors[nation].economy.capacities.trade_offer = 0;
        game.recall_player_trade_orders(nation);
        assert_eq!(
            game.player_trade_order(nation, TradeCommodity::Fabric),
            PlayerTradeOrder::None
        );
        game.nations.majors[nation].economy.capacities.trade_offer = 4;

        for commodity in [
            TradeCommodity::Cotton,
            TradeCommodity::Wool,
            TradeCommodity::Timber,
            TradeCommodity::Coal,
        ] {
            assert_eq!(
                game.set_player_trade_order(nation, commodity, PlayerTradeOrder::Buy),
                PlayerTradeOrder::Buy
            );
        }
        assert_eq!(
            game.set_player_trade_order(nation, TradeCommodity::Iron, PlayerTradeOrder::Buy),
            PlayerTradeOrder::None
        );
        game.set_player_trade_order(nation, TradeCommodity::Cotton, PlayerTradeOrder::None);
        assert_eq!(
            game.set_player_trade_order(nation, TradeCommodity::Iron, PlayerTradeOrder::Buy),
            PlayerTradeOrder::Buy
        );
    }

    #[test]
    fn created_items_credit_precious_metals_and_settle_targets_into_city_stock() {
        let nation = MajorNationId::new(6);
        let mut game = state();
        let major = &mut game.nations.majors[nation].economy;
        major.need_target_by_type[ResourceKind::Cotton] = 2;
        major.need_target_by_type[ResourceKind::Food] = 7;
        major.need_target_by_type[ResourceKind::Fabric] = 1;
        major.need_target_by_type[ResourceKind::Gems] = 3;
        major.need_target_by_type[ResourceKind::Gold] = 4;

        let city = game.nations.city_mut(MajorNationId::new(6));
        city.stockpile[ResourceKind::Cotton] = -5;
        city.stockpile[ResourceKind::Food] = 3;
        city.stockpile[ResourceKind::Fabric] = 5;
        city.stockpile[ResourceKind::Steel] = -1;
        city.stockpile[ResourceKind::Gems] = 99;
        city.stockpile[ResourceKind::Gold] = 99;

        game.add_created_items(nation);

        let state = &game.nations.majors[nation];
        let major = &state.economy;
        let city = &game.nations.majors[MajorNationId::new(6)].city;
        assert_eq!(state.common.treasury, 3_300);
        assert_eq!(city.stockpile[ResourceKind::Cotton], 2);
        assert_eq!(city.stockpile[ResourceKind::Food], 10);
        assert_eq!(city.stockpile[ResourceKind::Fabric], 6);
        assert_eq!(city.stockpile[ResourceKind::Steel], 0);
        assert_eq!(city.stockpile[ResourceKind::Gems], 3);
        assert_eq!(city.stockpile[ResourceKind::Gold], 4);
        assert_eq!(major.need_target_by_type[ResourceKind::Gems], 3);
        assert_eq!(major.need_target_by_type[ResourceKind::Gold], 4);
    }

    #[test]
    fn diplomacy_grant_settlement_replaces_or_rejects_grants() {
        let nation = MajorNationId::new(6);
        let target = NationId::new(8);
        let mut game = state();
        let state = &mut game.nations.majors[nation];
        state.common.treasury = 10_000;
        let major = &mut state.economy;
        major.diplomacy_budget_base = 50_000;
        let recurring_ten_thousand = DiplomacyGrant {
            amount: 10_000,
            recurring: true,
        };
        assert!(game.set_diplomacy_grant(nation, target, Some(recurring_ten_thousand)));

        let state = &game.nations.majors[nation];
        let major = &state.economy;
        assert_eq!(state.common.treasury, 0);
        assert_eq!(major.grant_total_cost, 10_000);
        assert_eq!(
            major.diplomacy_grants_by_nation[target],
            Some(recurring_ten_thousand)
        );

        let before_rejected = game.clone();
        assert!(!game.set_diplomacy_grant(
            nation,
            NationId::new(9),
            Some(DiplomacyGrant {
                amount: 1_000,
                recurring: false,
            }),
        ));
        assert_eq!(game, before_rejected);

        assert!(game.set_diplomacy_grant(
            nation,
            target,
            Some(DiplomacyGrant {
                amount: 3_000,
                recurring: true,
            }),
        ));
        assert!(game.set_diplomacy_grant(nation, target, None));
        let state = &game.nations.majors[nation];
        let major = &state.economy;
        assert_eq!(state.common.treasury, 10_000);
        assert_eq!(major.grant_total_cost, 0);
        assert_eq!(major.diplomacy_grants_by_nation[target], None);
    }

    #[test]
    fn decrements_trade_policy_score_through_the_retail_steps() {
        let nation = MajorNationId::new(6);
        let target = NationId::new(0);
        let mut game = state();

        for (score, treasury, expected) in [
            (100, 0, 95),
            (95, 0, 90),
            (90, 0, 75),
            (75, 10_000, 75),
            (75, 10_001, 50),
            (300, 50_000, 300),
        ] {
            let common = &mut game.nations.majors[nation].common;
            common.trade_policy_by_nation[target] = TradePolicyScore::new(score);
            common.treasury = treasury;

            game.decrement_trade_policy_score(nation, target);

            assert_eq!(
                game.nations.majors[nation].common.trade_policy_by_nation[target],
                TradePolicyScore::new(expected)
            );
        }
    }
}
