use crate::{
    DiplomacyGrant, GameState, GreatPowerState, MajorNation, MajorNationId, MinorNationId,
    NationCommonState, NationId, ResourceKind, TradePolicyScore, all_resources,
};

impl GameState {
    /// Recalculates the world's seventeen market commodity prices in retail order.
    pub fn recalculate_trade_prices(&mut self) {
        self.market.recalculate_prices();
    }

    pub fn place_trade_bid(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
        amount: i16,
    ) -> i16 {
        let major = &mut self.nations.majors[nation].economy;
        major.set_item_potential(resource, amount);
        major.item_potentials[resource]
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
        } = &mut self.nations.majors[nation];

        common.treasury += i32::from(major.need_target_by_type[ResourceKind::Gems]) * 500;
        city.stockpile.set_nonnegative(ResourceKind::Gems, 0);

        common.treasury += i32::from(major.need_target_by_type[ResourceKind::Gold]) * 200;
        city.stockpile.set_nonnegative(ResourceKind::Gold, 0);

        for resource in all_resources() {
            city.adjust_stock(resource, major.need_target_by_type[resource]);
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

    /// Resets the retail player trade phase.
    ///
    /// Nations outside this mode use a different retail virtual implementation.
    /// Calling the player implementation for one is an internal phase-dispatch bug.
    pub fn reset_player_trade_phase(&mut self, nation: MajorNationId) {
        assert!(
            self.nations.majors[nation].economy.controller.is_human(),
            "player trade phase requires a human-controlled major nation"
        );

        self.refresh_merchant_capacity(nation);
        let major = &mut self.nations.majors[nation].economy;
        major.unfilled_trade_offer_count = 0;
        major.budget_pool_base = 0;
        major.budget_pool_delta = 0;
        self.recall_trade_bids(nation);
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
    use crate::{
        CityState, Difficulty, DiplomacyPolicy, LaborPool, MajorNation, MinorNationId,
        MinorNationTable, Nations, PopulationState, RetailCrtRng, RetailLcg, RngState, ShipType,
        StrategicMap, TradePolicyScore, TurnState,
    };

    fn major() -> GreatPowerState {
        GreatPowerState {
            controller: crate::MajorNationController::Human,
            foreign_minister_personality: crate::ForeignMinisterPersonality::Base,
            foreign_minister_skill_index: 0,
            development_grant_by_nation: crate::NationTable::default(),
            defense_minister_skill_index: 0,
            capacities: crate::NationCapacities::from_array([10, 4, 0, 0]),
            grant_total_cost: 0,
            unfilled_trade_offer_count: 0,
            diplomacy_policy_by_nation: crate::NationTable::default(),
            diplomacy_grants_by_nation: crate::NationTable::default(),
            need_current_by_type: crate::ResourceTable::default(),
            need_target_by_type: crate::ResourceTable::default(),
            relation_delta_current: crate::ResourceTable::default(),
            purchased_items_by_resource: crate::ResourceTable::default(),
            item_potentials: crate::ResourceTable::default(),
            unfilled_trade_turns_by_resource: crate::ResourceTable::default(),
            transported_items_by_resource: crate::ResourceTable::default(),
            remembered_trade_offers_by_resource: crate::ResourceTable::default(),
            aid_allocation_by_minor_nation: crate::MinorNationTable::default(),
            budget_pool_base: 200,
            budget_pool_delta: 100,
            special_resource_trade_balance: 30,
            candidate_nation_flags: crate::NationTable::default(),
            scenario_initialized: false,
            turn_finished: false,
            pending_actions: crate::PendingActionTable::default(),
            diplomacy_budget_base: 0,
            escalation_counter: 0,
            pending_commitment_cost: 0,
            pressure_counter: 0,
            aid_allocation_total: 0,
            colony_boycott_flags: crate::NationTable::default(),
            military_expenses: 0,
        }
    }

    fn state() -> GameState {
        let majors = crate::MajorNationTable::from_fn(|_nation| MajorNation {
            common: NationCommonState {
                status: crate::CountryStatus::Independent,
                owned_regions: Vec::new(),
                treasury: 1_000,
                home_tile: Some(crate::TileId::new(0)),
                trade_policy_by_nation: crate::NationTable::default(),
            },
            economy: major(),
            city: city(),
        });
        let mut diplomacy_rng = RetailCrtRng::from_state(1);
        GameState {
            turn: TurnState {
                scenario_map: None,
                economic_turn: 1,
                diplomacy_year_term_raw: 1914,
                phase: crate::PhaseCode::STRATEGIC_MAP,
                difficulty: Difficulty::Easy,
                active_nation: NationId::new(6),
                selected_nation: NationId::new(6),
            },
            unit_ids: crate::UnitIdAllocator::default(),
            world: StrategicMap::new(
                crate::MapTopology::Bounded,
                vec![crate::TileState::default(); crate::STRATEGIC_TILE_COUNT],
            )
            .unwrap(),
            provinces: crate::ProvinceTable::default(),
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
            nations: Nations {
                majors,
                minors: MinorNationTable::default(),
            },
            military_units: vec![],
            civilian_units: vec![],
            ships: vec![],
            task_forces: vec![],
            missions: vec![],
            pending: crate::PendingWorkState::default(),
        }
    }

    fn city() -> CityState {
        CityState {
            home_town_tile: Some(crate::TileId::new(0)),
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
    #[should_panic(expected = "player trade phase requires a human-controlled major nation")]
    fn player_trade_phase_requires_a_human_controller() {
        let nation = MajorNationId::new(6);
        let mut game = state();
        game.nations.majors[nation].economy.controller = crate::MajorNationController::Computer;

        game.reset_player_trade_phase(nation);
    }

    #[test]
    fn buyer_uses_merchant_capacity_and_delta_budget() {
        let nation = MajorNationId::new(6);
        let mut game = state();
        game.purchase_item(nation, ResourceKind::Fabric, 3, 7);
        let state = &game.nations.majors[MajorNationId::new(6)];
        let major = &state.economy;
        assert_eq!(state.common.treasury, 979);
        assert_eq!(major.purchased_items_by_resource[ResourceKind::Fabric], 3);
        assert_eq!(major.capacities.available_merchant, 7);
        assert_eq!(major.budget_pool_delta, 79);
        assert_eq!(major.budget_pool_base, 200);
        assert_eq!(major.special_resource_trade_balance, 30);
    }

    #[test]
    fn trade_bid_clamps_to_merchant_capacity_and_reports_the_applied_amount() {
        let nation = MajorNationId::new(6);
        let mut game = state();
        let applied = game.place_trade_bid(nation, ResourceKind::Fabric, 9);
        assert_eq!(
            game.nations.majors[MajorNationId::new(6)]
                .economy
                .item_potentials[ResourceKind::Fabric],
            4
        );
        assert_eq!(applied, 4);
    }

    #[test]
    fn remembered_bids_and_purchased_items_commit_as_one_trade_phase() {
        let major_nation = MajorNationId::new(6);
        let mut game = state();
        game.place_trade_bid(major_nation, ResourceKind::Fabric, -1);
        game.place_trade_bid(major_nation, ResourceKind::Clothing, -1);
        game.remember_trade_bids(major_nation);
        game.purchase_item(major_nation, ResourceKind::Fabric, 3, 7);
        game.purchase_item(major_nation, ResourceKind::Food, -30, 1);
        game.nations.city_mut(MajorNationId::new(6)).stockpile[ResourceKind::Food] = 20;

        game.commit_purchased_items(major_nation);
        let major = &game.nations.majors[MajorNationId::new(6)].economy;
        assert!(
            major
                .purchased_items_by_resource
                .iter()
                .all(|(_, amount)| *amount == 0)
        );
        assert_eq!(
            major.unfilled_trade_turns_by_resource[ResourceKind::Fabric],
            0
        );
        assert_eq!(
            major.unfilled_trade_turns_by_resource[ResourceKind::Clothing],
            1
        );
        let city = &game.nations.majors[MajorNationId::new(6)].city;
        assert_eq!(city.stockpile[ResourceKind::Fabric], 3);
        assert_eq!(city.stockpile[ResourceKind::Food], 0);
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
        city.stockpile.set_nonnegative(ResourceKind::Cotton, -5);
        city.stockpile[ResourceKind::Food] = 3;
        city.stockpile[ResourceKind::Fabric] = 5;
        city.stockpile.set_nonnegative(ResourceKind::Steel, -1);
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
    fn reset_diplomacy_commitments_reposts_only_recurring_grants() {
        let nation = MajorNationId::new(6);
        let policy_target = NationId::new(0);
        let one_time_target = NationId::new(1);
        let recurring_target = NationId::new(2);
        let recurring_grant = DiplomacyGrant {
            amount: 3_000,
            recurring: true,
        };
        let mut game = state();
        let state = &mut game.nations.majors[nation];
        state.common.treasury = 10_000;
        state.economy.diplomacy_policy_by_nation[policy_target] =
            Some(DiplomacyPolicy::BuildConsulate);
        game.set_diplomacy_grant(
            nation,
            one_time_target,
            Some(DiplomacyGrant {
                amount: 1_000,
                recurring: false,
            }),
        );
        game.set_diplomacy_grant(nation, recurring_target, Some(recurring_grant));

        game.reset_diplomacy_commitments(nation);

        let state = &game.nations.majors[nation];
        let major = &state.economy;
        assert_eq!(major.diplomacy_policy_by_nation[policy_target], None);
        assert_eq!(major.diplomacy_grants_by_nation[one_time_target], None);
        assert_eq!(
            major.diplomacy_grants_by_nation[recurring_target],
            Some(recurring_grant)
        );
        assert_eq!(state.common.treasury, 3_000);
        assert_eq!(major.grant_total_cost, 7_000);
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

    #[test]
    fn refreshes_merchant_capacity_from_city_industry_weights() {
        let nation = MajorNationId::new(6);
        let mut game = state();
        let city = game.nations.city_mut(nation);
        city.ship_order_count_by_type[ShipType::Trader] = 2;
        city.ship_order_count_by_type[ShipType::Paddlewheeler] = 1;
        city.ship_order_count_by_type[ShipType::Freighter] = 1;

        game.refresh_merchant_capacity(nation);

        let major = &game.nations.majors[nation].economy;
        assert_eq!(major.capacities.trade_offer, 28);
        assert_eq!(major.capacities.available_merchant, 28);
    }

    #[test]
    fn recalls_bids_clamps_them_to_stock_and_clears_aid() {
        let nation = MajorNationId::new(6);
        let mut game = state();
        let city = game.nations.city_mut(nation);
        city.stockpile[ResourceKind::Cotton] = 3;
        city.stockpile[ResourceKind::Timber] = 5;

        let major = &mut game.nations.majors[nation].economy;
        major.unfilled_trade_offer_count = 4;
        major.item_potentials[ResourceKind::Cotton] = 99;
        major.remembered_trade_offers_by_resource[ResourceKind::Cotton] = 7;
        major.remembered_trade_offers_by_resource[ResourceKind::Wool] = -1;
        major.remembered_trade_offers_by_resource[ResourceKind::Timber] = 2;
        major.aid_allocation_by_minor_nation[MinorNationId::new(7)][ResourceKind::Cotton] = 8;
        major.aid_allocation_by_minor_nation[MinorNationId::new(14)][ResourceKind::Steel] = 8;
        major.aid_allocation_by_minor_nation[MinorNationId::new(22)][ResourceKind::Gold] = 8;

        game.recall_trade_bids(nation);

        let major = &game.nations.majors[nation].economy;
        assert_eq!(major.unfilled_trade_offer_count, 5);
        assert_eq!(major.item_potentials[ResourceKind::Cotton], 3);
        assert_eq!(major.item_potentials[ResourceKind::Wool], -1);
        assert_eq!(major.item_potentials[ResourceKind::Timber], 2);
        assert_eq!(
            major.aid_allocation_by_minor_nation,
            MinorNationTable::default()
        );
    }

    #[test]
    fn special_resource_seller_uses_base_budget_and_balance() {
        let nation = MajorNationId::new(6);
        let mut game = state();
        game.purchase_item(nation, ResourceKind::Clothing, -2, 5);
        let state = &game.nations.majors[MajorNationId::new(6)];
        let major = &state.economy;
        assert_eq!(state.common.treasury, 1_010);
        assert_eq!(
            major.purchased_items_by_resource[ResourceKind::Clothing],
            -2
        );
        assert_eq!(major.capacities.available_merchant, 10);
        assert_eq!(major.budget_pool_base, 210);
        assert_eq!(major.budget_pool_delta, 100);
        assert_eq!(major.special_resource_trade_balance, 32);
    }

    #[test]
    fn ordinary_resource_seller_does_not_change_special_balance() {
        let nation = MajorNationId::new(6);
        let mut game = state();
        game.purchase_item(nation, ResourceKind::Fabric, -2, 5);
        assert_eq!(
            game.nations.majors[MajorNationId::new(6)]
                .economy
                .special_resource_trade_balance,
            30
        );
    }
}
