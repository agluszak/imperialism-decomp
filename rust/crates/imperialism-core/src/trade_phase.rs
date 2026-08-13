use crate::*;
use enum_map::Enum;

const TRADE_DEAL_ORDER: [TradeCommodity; 17] = [
    TradeCommodity::Clothing,
    TradeCommodity::Furniture,
    TradeCommodity::Hardware,
    TradeCommodity::Arms,
    TradeCommodity::Food,
    TradeCommodity::Fabric,
    TradeCommodity::Lumber,
    TradeCommodity::Paper,
    TradeCommodity::Steel,
    TradeCommodity::Fuel,
    TradeCommodity::Cotton,
    TradeCommodity::Wool,
    TradeCommodity::Timber,
    TradeCommodity::Coal,
    TradeCommodity::Iron,
    TradeCommodity::Horses,
    TradeCommodity::Oil,
];

const BASIC_SUBSIDY_RESOURCES: [TradeCommodity; 5] = [
    TradeCommodity::Cotton,
    TradeCommodity::Wool,
    TradeCommodity::Timber,
    TradeCommodity::Coal,
    TradeCommodity::Iron,
];

const MANUFACTURED_RESOURCES: [TradeCommodity; 4] = [
    TradeCommodity::Clothing,
    TradeCommodity::Furniture,
    TradeCommodity::Hardware,
    TradeCommodity::Arms,
];

#[derive(Clone, Copy, Debug)]
struct TradeDeal {
    buyer: NationId,
    seller: NationId,
    seller_offer: i16,
    standing: i16,
    unit_price: i32,
    commodity: TradeCommodity,
}

#[derive(Clone, Copy, Debug)]
struct MinisterTradeRuntime {
    partner_enabled: [bool; MajorNationId::COUNT as usize],
    capability: i16,
}

impl Default for MinisterTradeRuntime {
    fn default() -> Self {
        Self {
            partner_enabled: [true; MajorNationId::COUNT as usize],
            capability: 0,
        }
    }
}

#[derive(Default)]
struct TradeScratch {
    current: TradeCommodityTable<NationTable<i16>>,
    accumulated: TradeCommodityTable<NationTable<i16>>,
    ranks: TradeCommodityTable<Vec<TradeDeal>>,
    ministers: MajorNationTable<MinisterTradeRuntime>,
}

impl GameState {
    /// Whether phase seven is inside the recovered first-turn, no-player-offer slice.
    pub(crate) fn supports_first_turn_trade_phase(&self) -> bool {
        let Some(active) = MajorNationId::from_nation(self.turn.active_nation) else {
            return false;
        };
        if self.turn.economic_turn != 1
            || self.turn.difficulty != Difficulty::Easy
            || self.turn.phase != PhaseCode::TRADE
            || self.turn.scenario_map.is_some()
            || self.turn.selected_nation != self.turn.active_nation
            || self
                .diplomacy
                .special_relation_sources
                .iter()
                .any(Option::is_some)
            || self
                .diplomacy
                .special_relation_targets
                .iter()
                .any(Option::is_some)
            || self
                .map
                .tiles
                .iter()
                .any(|tile| tile.secondary_owner_nation.is_some())
            || self.nations.minors.iter().any(Option::is_none)
            || [TradeCommodity::Coal, TradeCommodity::Iron]
                .into_iter()
                .any(|commodity| {
                    (MinorNationId::FIRST..NationId::COUNT).any(|slot| {
                        self.market.rows[commodity].maximum_offer_by_nation
                            [MinorNationId::new(slot).nation()]
                            != 0
                    })
                })
        {
            return false;
        }

        for source in NationId::all() {
            let Some(common) = self.nations.common(source) else {
                return false;
            };
            if common.status() != CountryStatus::Independent
                || NationId::all().any(|target| {
                    common.trade_policy_by_nation[target] != TradePolicyScore::NEUTRAL
                        || self.diplomacy.relationships[source][target]
                            != DiplomaticRelationship::Peace
                })
            {
                return false;
            }
        }

        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            let economy = &self.nations.majors[nation].economy;
            if economy.controller.is_human() != (nation == active)
                || self.technology.city_capabilities_by_nation[nation].oil_drilling
                || economy.foreign_trade.interior_bid.is_some()
                || (!economy.controller.is_human() && economy.ai_trade.is_none())
                || all_trade_commodities()
                    .any(|commodity| economy.foreign_trade.purchase_priority[commodity] != 0)
                || (economy.controller.is_human()
                    && all_trade_commodities().any(|commodity| {
                        economy.remembered_trade_offers_by_resource[resource(commodity)] < 0
                    }))
            {
                return false;
            }

            if !economy.controller.is_human()
                && !matches!(
                    economy.foreign_minister_personality,
                    ForeignMinisterPersonality::Trader
                        | ForeignMinisterPersonality::Textile
                        | ForeignMinisterPersonality::Diplomat
                        | ForeignMinisterPersonality::Bill
                        | ForeignMinisterPersonality::Ted
                )
            {
                return false;
            }
        }

        true
    }

    /// Runs retail phase seven through its exhausted no-player-offer traversal.
    ///
    /// Phase advancement and the unconditional blank offer-sheet presentation
    /// remain the turn driver's responsibility.
    pub(crate) fn run_trade_phase(&mut self) {
        assert!(
            self.supports_first_turn_trade_phase(),
            "first-turn trade phase contains an unrecovered branch"
        );

        self.select_priority_nations_for_minor_capabilities();
        self.clear_trade_deal_books();

        let mut scratch = TradeScratch::default();
        self.reset_trade_market(&mut scratch);
        self.run_trade_nation_update_passes(&mut scratch);
        self.set_and_tally_minor_trade_bids(&mut scratch);
        self.tally_major_trade_bids(&mut scratch);
        self.recalculate_trade_prices();
        self.calculate_trade_deal_order(&mut scratch);
        self.settle_trade_deals(&mut scratch);
        self.finish_trade_phase(&scratch);
    }

    fn select_priority_nations_for_minor_capabilities(&mut self) {
        for pending in self.pending.nations.iter_mut() {
            pending.proposals.clear();
        }

        for slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = MinorNationId::new(slot);
            let mut best_offer_score = 0x8b_i16;
            let mut best_offer_nation = None;
            let mut best_relation_score = 9_000_i32;
            let mut best_relation_nation = None;
            let mut offer_seed = 0_u32;
            let mut relation_seed = 0_u32;

            for major_slot in 0..MajorNationId::COUNT {
                let major = MajorNationId::new(major_slot);
                let standing = self.diplomacy.standings[minor.nation()][major.nation()];
                let side_effect =
                    self.diplomacy.mission_levels[major.nation()][minor.nation()].retail();

                if side_effect != 0 {
                    if best_offer_score < standing {
                        best_offer_score = standing;
                        best_offer_nation = Some(major);
                    } else if best_offer_score == standing
                        && (self.minor_is_colony_of(minor, major)
                            || select_local_tie(
                                standing,
                                self.turn.economic_turn,
                                major,
                                &mut offer_seed,
                            ))
                    {
                        best_offer_nation = Some(major);
                    }
                }

                let score = if side_effect >= 1 {
                    i32::from(200 - side_effect) * i32::from(standing)
                } else {
                    0
                };
                if best_relation_score < score {
                    best_relation_score = score;
                    best_relation_nation = Some(major);
                } else if best_relation_score == score
                    && (self.minor_is_colony_of(minor, major)
                        || select_local_tie(
                            standing,
                            self.turn.economic_turn,
                            major,
                            &mut relation_seed,
                        ))
                {
                    best_relation_nation = Some(major);
                }
            }

            self.diplomacy.special_relation_sources[minor] = best_offer_nation;
            self.diplomacy.special_relation_targets[minor] = best_relation_nation;
        }
    }

    fn clear_trade_deal_books(&mut self) {
        for slot in (0..MajorNationId::COUNT).rev() {
            self.nations.majors[MajorNationId::new(slot)]
                .economy
                .deal_book = TradeCommodityTable::default();
        }
    }

    fn reset_trade_market(&mut self, scratch: &mut TradeScratch) {
        *scratch = TradeScratch::default();
        for commodity in all_trade_commodities() {
            let row = &mut self.market.rows[commodity];
            row.request_count = 0;
            row.offer_count = 0;
            row.amount_offered = 0;
            row.adjusted_offer_count = 0.0;
            row.current_offer_by_nation = NationTable::default();
        }
    }

    fn run_trade_nation_update_passes(&mut self, _scratch: &mut TradeScratch) {
        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            if self.nations.majors[nation].economy.controller.is_human() {
                self.reset_player_trade_phase(nation);
            } else {
                self.refresh_merchant_capacity(nation);
                let economy = &mut self.nations.majors[nation].economy;
                economy.unfilled_trade_offer_count = 0;
                economy.budget_pool_base = 0;
                economy.budget_pool_delta = 0;
                economy.item_potentials = ResourceTable::default();
                economy.aid_allocation_by_minor_nation = MinorNationTable::default();
            }
        }

        for slot in MinorNationId::FIRST..NationId::COUNT {
            self.initialize_minor_trade_status(MinorNationId::new(slot));
        }

        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            if !self.nations.majors[nation].economy.controller.is_human() {
                self.set_ai_trade_bids(nation);
                self.apply_usual_subsidy_rule(nation);
            }
        }
    }

    fn initialize_minor_trade_status(&mut self, nation: MinorNationId) {
        let mut supply = ResourceTable::default();
        let mut independent = ResourceTable::default();
        supply[ResourceKind::Food] = 2;

        for tile in &self.map.tiles {
            if tile.owner_nation.and_then(TileOwnerTag::nation) != Some(nation.nation())
                || tile.gate == 0xf
            {
                continue;
            }
            for resource in tile.edge_resources.into_iter().flatten() {
                supply[resource] += 1;
                independent[resource] += 1;
            }
        }

        let trade = &mut self.nations.minors[nation]
            .as_mut()
            .expect("supported trade phase has every minor nation")
            .trade;
        trade.current_supply = supply;
        trade.offers = ResourceTable::default();
        trade.grant_deltas = ResourceTable::default();
        trade.secondary_manufactured_request = None;
        trade.primary_request_fulfilled = 0;
        trade.secondary_request_fulfilled = 0;
        trade.independent_resource_counts = independent;
    }

    fn set_ai_trade_bids(&mut self, nation: MajorNationId) {
        let capacity = self.nations.majors[nation].economy.capacities.trade_offer;
        let needs_money = [
            ResourceKind::Clothing,
            ResourceKind::Furniture,
            ResourceKind::Hardware,
        ]
        .into_iter()
        .any(|resource| self.major_stock(nation, resource) >= capacity);
        let foreign = &self.nations.majors[nation].economy.foreign_trade;
        let request_ship = foreign.phase_counter >= foreign.refresh_interval || needs_money;
        if request_ship {
            let requested = foreign.requested_ship;
            let economy = &mut self.nations.majors[nation].economy;
            if economy.pending_ship.is_none() {
                economy.pending_ship = Some(requested);
            }
            economy.foreign_trade.phase_counter = 0;
        }

        let personality = self.nations.majors[nation]
            .economy
            .foreign_minister_personality;
        let preferences = match personality {
            ForeignMinisterPersonality::Trader => {
                let mut entries = Vec::new();
                for commodity in [
                    TradeCommodity::Cotton,
                    TradeCommodity::Wool,
                    TradeCommodity::Timber,
                    TradeCommodity::Coal,
                    TradeCommodity::Iron,
                ] {
                    let mut priority = self.market.rows[commodity].price as i16;
                    if matches!(commodity, TradeCommodity::Coal | TradeCommodity::Iron) {
                        priority -= 15;
                    }
                    insert_lowest_first(&mut entries, commodity, priority);
                }
                [
                    Some(entries[0].0),
                    Some(entries[1].0),
                    Some(entries[2].0),
                    Some(entries[3].0),
                ]
            }
            ForeignMinisterPersonality::Textile => {
                let mut entries = Vec::new();
                for commodity in [
                    TradeCommodity::Coal,
                    TradeCommodity::Iron,
                    TradeCommodity::Timber,
                ] {
                    insert_lowest_first(
                        &mut entries,
                        commodity,
                        self.major_stock(nation, resource(commodity)),
                    );
                }
                [
                    Some(TradeCommodity::Cotton),
                    Some(TradeCommodity::Wool),
                    Some(entries[0].0),
                    Some(entries[1].0),
                ]
            }
            ForeignMinisterPersonality::Diplomat => {
                let fourth = if self.rng.next_crt_rand() < 0x3ffe {
                    TradeCommodity::Coal
                } else {
                    TradeCommodity::Iron
                };
                [
                    Some(TradeCommodity::Timber),
                    Some(TradeCommodity::Cotton),
                    Some(TradeCommodity::Wool),
                    Some(fourth),
                ]
            }
            ForeignMinisterPersonality::Bill => {
                let (first, third) = if self.major_stock(nation, ResourceKind::Iron)
                    < self.major_stock(nation, ResourceKind::Coal)
                {
                    (TradeCommodity::Iron, TradeCommodity::Coal)
                } else {
                    (TradeCommodity::Coal, TradeCommodity::Iron)
                };
                [Some(first), Some(TradeCommodity::Timber), Some(third), None]
            }
            ForeignMinisterPersonality::Ted => {
                let (first, third) = if self.major_stock(nation, ResourceKind::Iron)
                    < self.major_stock(nation, ResourceKind::Coal)
                {
                    (TradeCommodity::Iron, TradeCommodity::Coal)
                } else {
                    (TradeCommodity::Coal, TradeCommodity::Iron)
                };
                let fourth = if self.rng.next_crt_rand() < 0x3ffe {
                    TradeCommodity::Cotton
                } else {
                    TradeCommodity::Wool
                };
                [
                    Some(first),
                    Some(TradeCommodity::Timber),
                    Some(third),
                    Some(fourth),
                ]
            }
            ForeignMinisterPersonality::Base | ForeignMinisterPersonality::Arms => {
                unreachable!("unsupported foreign-minister personality passed the phase guard")
            }
        };

        self.nations.majors[nation]
            .economy
            .foreign_trade
            .preferred_resources = preferences;
        for commodity in preferences.into_iter().flatten() {
            self.set_major_trade_potential(nation, commodity, -1);
        }

        match personality {
            ForeignMinisterPersonality::Trader => {
                let divisor = if self.nations.majors[nation].common.treasury < 0 {
                    1
                } else {
                    4
                };
                let budget = capacity / divisor;
                let prices = self.sorted_manufactured_offer_prices();
                let mut allocated = 0;
                for selected in (0..3).rev() {
                    if allocated >= budget {
                        break;
                    }
                    let commodity = prices[selected];
                    let amount = self.major_stock(nation, resource(commodity));
                    self.set_major_trade_potential(nation, commodity, amount);
                    allocated += amount;
                }
                self.set_fixed_arms_offer(nation, 1_200);
            }
            ForeignMinisterPersonality::Textile => {
                let clothing = self.major_stock(nation, ResourceKind::Clothing);
                if self.nations.majors[nation].common.treasury < 0
                    || clothing >= capacity
                    || (clothing > 4 && self.market.rows[TradeCommodity::Clothing].price > 1_000)
                {
                    self.set_major_trade_potential(
                        nation,
                        TradeCommodity::Clothing,
                        clothing.min(capacity),
                    );
                }
                if self.nations.majors[nation].common.treasury < 0
                    || self.nations.majors[nation].economy.item_potentials[ResourceKind::Clothing]
                        == 0
                {
                    let budget = capacity / 2;
                    let (first, second) = if self.market.rows[TradeCommodity::Hardware].price
                        > self.market.rows[TradeCommodity::Furniture].price
                    {
                        (TradeCommodity::Hardware, TradeCommodity::Furniture)
                    } else {
                        (TradeCommodity::Furniture, TradeCommodity::Hardware)
                    };
                    let first_amount = self.major_stock(nation, resource(first)).min(budget);
                    self.set_major_trade_potential(nation, first, first_amount);
                    let second_amount = self
                        .major_stock(nation, resource(second))
                        .min(budget - first_amount);
                    self.set_major_trade_potential(nation, second, second_amount);
                }
                self.set_scaled_arms_offer(nation, 1_500);
            }
            ForeignMinisterPersonality::Diplomat | ForeignMinisterPersonality::Bill => {
                self.set_rotating_manufactured_offers(nation);
                if personality == ForeignMinisterPersonality::Diplomat {
                    self.set_fixed_arms_offer(nation, 1_200);
                } else {
                    self.set_scaled_arms_offer(nation, 1_500);
                }
            }
            ForeignMinisterPersonality::Ted => {
                let hardware = self.major_stock(nation, ResourceKind::Hardware);
                if self.nations.majors[nation].common.treasury >= 0
                    && capacity > hardware
                    && hardware < 10
                {
                    self.set_major_trade_potential(
                        nation,
                        TradeCommodity::Clothing,
                        self.major_stock(nation, ResourceKind::Clothing),
                    );
                    self.set_major_trade_potential(
                        nation,
                        TradeCommodity::Furniture,
                        self.major_stock(nation, ResourceKind::Furniture),
                    );
                } else {
                    let amount = capacity.min(hardware);
                    self.set_major_trade_potential(nation, TradeCommodity::Hardware, amount);
                    if capacity > amount * 2 {
                        self.set_major_trade_potential(
                            nation,
                            TradeCommodity::Clothing,
                            self.major_stock(nation, ResourceKind::Clothing),
                        );
                        self.set_major_trade_potential(
                            nation,
                            TradeCommodity::Furniture,
                            self.major_stock(nation, ResourceKind::Furniture),
                        );
                    }
                }
                self.set_scaled_arms_offer(nation, 1_500);
            }
            ForeignMinisterPersonality::Base | ForeignMinisterPersonality::Arms => unreachable!(),
        }
    }

    fn apply_usual_subsidy_rule(&mut self, nation: MajorNationId) {
        for commodity in BASIC_SUBSIDY_RESOURCES {
            let roll = self.rng.next_crt_rand();
            if roll % 100 + 200 < self.market.rows[commodity].price {
                self.set_subsidy_offer(nation, commodity);
            }
        }

        let roll = self.rng.next_crt_rand();
        if roll % 100 + 200 < self.market.rows[TradeCommodity::Horses].price {
            self.set_subsidy_offer(nation, TradeCommodity::Horses);
        }
    }

    fn set_subsidy_offer(&mut self, nation: MajorNationId, commodity: TradeCommodity) {
        let stock = self.major_stock(nation, resource(commodity));
        let amount = if stock == 0 { 0 } else { (stock / 2).min(5) };
        self.set_major_trade_potential(nation, commodity, amount);
    }

    fn set_rotating_manufactured_offers(&mut self, nation: MajorNationId) {
        let target = if self.nations.majors[nation].common.treasury < 0 {
            self.nations.majors[nation].economy.capacities.trade_offer
        } else {
            self.nations.majors[nation].economy.capacities.trade_offer / 2
        };
        let prices = self.sorted_manufactured_offer_prices();
        let mut amounts = TradeCommodityTable::<i16>::default();
        let mut selected = 2_usize;
        let mut iteration = 0;
        while target > 0 && iteration < i32::from(target) * 3 {
            let commodity = prices[selected];
            if amounts[commodity] < self.major_stock(nation, resource(commodity)) {
                amounts[commodity] += 1;
                self.set_major_trade_potential(nation, commodity, amounts[commodity]);
            }
            if MANUFACTURED_RESOURCES[..3]
                .iter()
                .map(|commodity| amounts[*commodity])
                .sum::<i16>()
                >= target
            {
                break;
            }
            selected = if selected == 0 { 2 } else { selected - 1 };
            iteration += 1;
        }
    }

    fn sorted_manufactured_offer_prices(&self) -> [TradeCommodity; 3] {
        let mut entries = Vec::new();
        for commodity in [
            TradeCommodity::Clothing,
            TradeCommodity::Furniture,
            TradeCommodity::Hardware,
        ] {
            insert_lowest_first(
                &mut entries,
                commodity,
                self.market.rows[commodity].price as i16,
            );
        }
        [entries[0].0, entries[1].0, entries[2].0]
    }

    fn set_fixed_arms_offer(&mut self, nation: MajorNationId, threshold: i32) {
        if self.market.rows[TradeCommodity::Arms].price > threshold
            && self.major_stock(nation, ResourceKind::Arms) > 6
        {
            self.set_major_trade_potential(nation, TradeCommodity::Arms, 2);
        }
    }

    fn set_scaled_arms_offer(&mut self, nation: MajorNationId, threshold: i32) {
        if self.market.rows[TradeCommodity::Arms].price <= threshold {
            return;
        }
        let stock = self.major_stock(nation, ResourceKind::Arms);
        let amount = stock / 10;
        if amount > 2 {
            self.set_major_trade_potential(nation, TradeCommodity::Arms, amount);
        } else if stock > 6 {
            self.set_major_trade_potential(nation, TradeCommodity::Arms, 2);
        }
    }

    fn major_stock(&self, nation: MajorNationId, resource: ResourceKind) -> i16 {
        self.nations.majors[nation].city.stockpile[resource]
    }

    fn set_major_trade_potential(
        &mut self,
        nation: MajorNationId,
        commodity: TradeCommodity,
        amount: i16,
    ) {
        self.nations.majors[nation]
            .economy
            .set_item_potential(resource(commodity), amount);
    }

    fn minor_is_colony_of(&self, minor: MinorNationId, major: MajorNationId) -> bool {
        matches!(
            self.nations.minors[minor]
                .as_ref()
                .expect("supported trade phase has every minor nation")
                .common
                .status(),
            CountryStatus::ColonyOf(master) if master == major.nation()
        )
    }

    fn set_and_tally_minor_trade_bids(&mut self, scratch: &mut TradeScratch) {
        for slot in MinorNationId::FIRST..NationId::COUNT {
            let nation = MinorNationId::new(slot);
            self.set_minor_trade_bids(nation);
        }

        let base = minor_offer_weight_base(self.turn.economic_turn);
        for commodity in [
            TradeCommodity::Cotton,
            TradeCommodity::Wool,
            TradeCommodity::Timber,
            TradeCommodity::Coal,
            TradeCommodity::Iron,
            TradeCommodity::Horses,
            TradeCommodity::Oil,
        ] {
            let resource = resource(commodity);
            for slot in MinorNationId::FIRST..NationId::COUNT {
                let nation = MinorNationId::new(slot);
                let trade = &self.nations.minors[nation]
                    .as_ref()
                    .expect("supported trade phase has every minor nation")
                    .trade;
                let metric = trade.offers[resource];
                scratch.current[commodity][nation.nation()] = metric;
                if metric > 0 {
                    let value = metric.min(trade.current_supply[resource]);
                    let row = &mut self.market.rows[commodity];
                    row.offer_count += 1;
                    row.amount_offered += i32::from(value);
                    let factor = if row.price < i32::from(trade.thresholds.random_offer_price) {
                        0.0
                    } else {
                        offer_weight(base, value, false)
                    };
                    row.adjusted_offer_count += factor;
                }
            }
        }

        for slot in MinorNationId::FIRST..NationId::COUNT {
            let nation = MinorNationId::new(slot);
            let trade = &self.nations.minors[nation]
                .as_ref()
                .expect("supported trade phase has every minor nation")
                .trade;
            let metric = trade.offers[ResourceKind::Food];
            scratch.current[TradeCommodity::Food][nation.nation()] = metric;
            if metric > 0 {
                let row = &mut self.market.rows[TradeCommodity::Food];
                row.offer_count += 1;
                row.amount_offered += i32::from(metric);
                row.adjusted_offer_count += offer_weight(base, metric, false);
            }
        }

        for commodity in MANUFACTURED_RESOURCES {
            for slot in MinorNationId::FIRST..NationId::COUNT {
                let nation = MinorNationId::new(slot);
                let metric = self.nations.minors[nation]
                    .as_ref()
                    .expect("supported trade phase has every minor nation")
                    .trade
                    .offers[resource(commodity)];
                scratch.current[commodity][nation.nation()] = metric;
                if metric < 0 {
                    self.market.rows[commodity].request_count += 1;
                }
            }
        }
    }

    fn tally_major_trade_bids(&mut self, scratch: &mut TradeScratch) {
        let base = major_offer_weight_base(self.turn.economic_turn);
        for commodity in all_trade_commodities() {
            for slot in 0..MajorNationId::COUNT {
                let nation = MajorNationId::new(slot);
                let metric =
                    self.nations.majors[nation].economy.item_potentials[resource(commodity)];
                scratch.current[commodity][nation.nation()] = metric;
                let row = &mut self.market.rows[commodity];
                if metric < 0 {
                    row.request_count += 1;
                } else if metric > 0 {
                    row.offer_count += 1;
                    row.amount_offered += i32::from(metric);
                    row.adjusted_offer_count += offer_weight(base, metric, true);
                }
            }
        }
    }

    fn set_minor_trade_bids(&mut self, nation: MinorNationId) {
        let random_bucket = self.rng.next_crt_rand() % 100;
        let random_commodity = match random_bucket {
            0..=24 => TradeCommodity::Cotton,
            25..=49 => TradeCommodity::Wool,
            50..=74 => TradeCommodity::Timber,
            _ => TradeCommodity::Food,
        };
        let prices = TradeCommodityTable::from_fn(|commodity| self.market.rows[commodity].price);
        let (thresholds, previous) = {
            let trade = &self.nations.minors[nation]
                .as_ref()
                .expect("supported trade phase has every minor nation")
                .trade;
            (trade.thresholds, trade.primary_manufactured_request)
        };
        let primary = loop {
            let roll = self.rng.next_crt_rand() % 100;
            let candidate = match roll {
                0..=29 => TradeCommodity::Clothing,
                30..=59 => TradeCommodity::Furniture,
                60..=89 => TradeCommodity::Hardware,
                _ => TradeCommodity::Arms,
            };
            if Some(candidate) != previous {
                break candidate;
            }
        };

        let trade = &mut self.nations.minors[nation]
            .as_mut()
            .expect("supported trade phase has every minor nation")
            .trade;
        let random_resource = resource(random_commodity);
        if i32::from(thresholds.random_offer_price) < prices[random_commodity] {
            trade.offers[random_resource] = trade.current_supply[random_resource];
        }

        for commodity in [
            TradeCommodity::Cotton,
            TradeCommodity::Wool,
            TradeCommodity::Timber,
            TradeCommodity::Coal,
            TradeCommodity::Iron,
            TradeCommodity::Horses,
            TradeCommodity::Oil,
            TradeCommodity::Food,
        ] {
            if i32::from(thresholds.general_offer_price) < prices[commodity] {
                let resource = resource(commodity);
                trade.offers[resource] = trade.current_supply[resource];
            }
        }
        for (commodity, threshold) in [
            (TradeCommodity::Coal, thresholds.coal_offer_price),
            (TradeCommodity::Iron, thresholds.iron_offer_price),
            (TradeCommodity::Oil, thresholds.oil_offer_price),
        ] {
            if i32::from(threshold) < prices[commodity] {
                let resource = resource(commodity);
                trade.offers[resource] = trade.current_supply[resource];
            }
        }

        trade.primary_manufactured_request = (i32::from(thresholds.primary_manufactured_price)
            >= prices[primary])
            .then_some(primary);
        trade.secondary_manufactured_request =
            MANUFACTURED_RESOURCES.into_iter().find(|commodity| {
                prices[*commodity] < i32::from(thresholds.secondary_manufactured_price)
                    && Some(*commodity) != trade.primary_manufactured_request
            });
        if let Some(commodity) = trade.primary_manufactured_request {
            trade.offers[resource(commodity)] = -1;
        }
        if let Some(commodity) = trade.secondary_manufactured_request {
            trade.offers[resource(commodity)] = -1;
        }
    }

    fn calculate_trade_deal_order(&mut self, scratch: &mut TradeScratch) {
        for commodity in [
            TradeCommodity::Cotton,
            TradeCommodity::Wool,
            TradeCommodity::Timber,
            TradeCommodity::Coal,
            TradeCommodity::Iron,
            TradeCommodity::Horses,
            TradeCommodity::Oil,
        ] {
            for seller_slot in 0..MajorNationId::COUNT {
                self.rank_deals_for_seller(
                    scratch,
                    commodity,
                    MajorNationId::new(seller_slot).nation(),
                    (0..MajorNationId::COUNT).map(|slot| MajorNationId::new(slot).nation()),
                );
            }
            for seller_slot in MinorNationId::FIRST..NationId::COUNT {
                self.rank_deals_for_seller(
                    scratch,
                    commodity,
                    NationId::new(seller_slot),
                    (0..MajorNationId::COUNT).map(|slot| MajorNationId::new(slot).nation()),
                );
            }
        }

        for commodity in [
            TradeCommodity::Food,
            TradeCommodity::Fabric,
            TradeCommodity::Lumber,
            TradeCommodity::Paper,
            TradeCommodity::Steel,
            TradeCommodity::Fuel,
        ] {
            for seller_slot in 0..MajorNationId::COUNT {
                self.rank_deals_for_seller(
                    scratch,
                    commodity,
                    MajorNationId::new(seller_slot).nation(),
                    (0..MajorNationId::COUNT).map(|slot| MajorNationId::new(slot).nation()),
                );
            }
            if commodity == TradeCommodity::Food {
                for seller_slot in MinorNationId::FIRST..NationId::COUNT {
                    self.rank_deals_for_seller(
                        scratch,
                        commodity,
                        NationId::new(seller_slot),
                        (0..MajorNationId::COUNT).map(|slot| MajorNationId::new(slot).nation()),
                    );
                }
            }
        }

        for commodity in MANUFACTURED_RESOURCES {
            for seller_slot in 0..MajorNationId::COUNT {
                let seller = MajorNationId::new(seller_slot).nation();
                self.rank_deals_for_seller(
                    scratch,
                    commodity,
                    seller,
                    (0..MajorNationId::COUNT)
                        .map(|slot| MajorNationId::new(slot).nation())
                        .chain((MinorNationId::FIRST..NationId::COUNT).map(NationId::new)),
                );
            }
        }
    }

    fn rank_deals_for_seller(
        &self,
        scratch: &mut TradeScratch,
        commodity: TradeCommodity,
        seller: NationId,
        buyers: impl Iterator<Item = NationId>,
    ) {
        let seller_offer = scratch.current[commodity][seller];
        if seller_offer <= 0 {
            return;
        }
        scratch.accumulated[commodity][seller] += seller_offer;

        for buyer in buyers {
            if scratch.current[commodity][buyer] >= 0 {
                continue;
            }
            let Some(unit_price) = self.trade_deal_price(buyer, seller, commodity) else {
                continue;
            };
            let deal = TradeDeal {
                buyer,
                seller,
                seller_offer,
                standing: self.diplomacy.standings[buyer][seller],
                unit_price,
                commodity,
            };
            insert_ranked_deal(&mut scratch.ranks[commodity], deal);
        }
    }

    fn trade_deal_price(
        &self,
        buyer: NationId,
        seller: NationId,
        commodity: TradeCommodity,
    ) -> Option<i32> {
        if self.diplomacy.relationships[buyer][seller] == DiplomaticRelationship::War {
            return None;
        }

        let price = self.market.rows[commodity].price;
        let base_price = self.market.rows[commodity].base_price;
        if preferred_trade_nation(self.nations.common(seller)?, seller) == buyer {
            return Some(price.min(base_price));
        }
        if preferred_trade_nation(self.nations.common(buyer)?, buyer) == seller {
            return Some(price.max(base_price));
        }

        if let Some(seller) = MajorNationId::from_nation(seller) {
            let policy = self.nations.majors[seller].common.trade_policy_by_nation[buyer].retail();
            match policy {
                100 => Some(price),
                300 => None,
                _ => Some((f64::from(price * policy) * 0.01) as i32),
            }
        } else {
            let buyer = MajorNationId::from_nation(buyer)
                .expect("retail trade deal rows never pair two minor nations");
            let policy = self.nations.majors[buyer].common.trade_policy_by_nation[seller].retail();
            match policy {
                100 => Some(price),
                300 => None,
                _ => Some((f64::from(price) * f64::from(200 - policy) * 0.01) as i32),
            }
        }
    }

    fn settle_trade_deals(&mut self, scratch: &mut TradeScratch) {
        for commodity in TRADE_DEAL_ORDER {
            let deals = scratch.ranks[commodity].clone();
            for deal in deals {
                let mut available = self.trade_amount_unsold(deal.seller, commodity);
                if MajorNationId::from_nation(deal.seller).is_some()
                    && MajorNationId::from_nation(deal.buyer).is_none()
                {
                    let seller = MajorNationId::from_nation(deal.seller).unwrap();
                    available = available.min(
                        self.nations.majors[seller]
                            .economy
                            .capacities
                            .available_merchant,
                    );
                }
                if available < 1 {
                    continue;
                }

                if let Some(buyer) = MajorNationId::from_nation(deal.buyer) {
                    if !self.nations.majors[buyer]
                        .economy
                        .is_still_buying(resource(commodity))
                    {
                        self.add_trade_deal_book_entry(
                            buyer,
                            commodity,
                            TradeDealBookEntry {
                                kind: DealBookEntryKind::Offer,
                                nation: deal.seller,
                                amount: 0,
                                unit_price: 0,
                            },
                        );
                        continue;
                    }
                    let Some((amount, shortfall)) = self.ai_trade_reply(
                        buyer,
                        deal.seller,
                        available,
                        commodity,
                        &mut scratch.ministers[buyer],
                    ) else {
                        continue;
                    };
                    self.apply_trade_deal_results(
                        deal.buyer,
                        deal.seller,
                        amount,
                        deal.unit_price,
                        commodity,
                        shortfall,
                    );
                } else if self
                    .minor_is_still_buying(MinorNationId::new(deal.buyer.get()), commodity)
                {
                    self.apply_trade_deal_results(
                        deal.buyer,
                        deal.seller,
                        available,
                        deal.unit_price,
                        commodity,
                        true,
                    );
                }
            }
        }
    }

    fn trade_amount_unsold(&self, nation: NationId, commodity: TradeCommodity) -> i16 {
        if let Some(nation) = MajorNationId::from_nation(nation) {
            self.nations.majors[nation]
                .economy
                .amount_unsold(resource(commodity))
        } else {
            let trade = &self.nations.minors[MinorNationId::new(nation.get())]
                .as_ref()
                .expect("supported trade phase has every minor nation")
                .trade;
            (trade.current_supply[resource(commodity)] + trade.grant_deltas[resource(commodity)])
                .max(0)
        }
    }

    fn minor_is_still_buying(&self, nation: MinorNationId, commodity: TradeCommodity) -> bool {
        let trade = &self.nations.minors[nation]
            .as_ref()
            .expect("supported trade phase has every minor nation")
            .trade;
        if trade.primary_manufactured_request == Some(commodity) {
            return trade.primary_request_fulfilled == 0;
        }
        if trade.secondary_manufactured_request == Some(commodity) {
            return trade.secondary_request_fulfilled == 0;
        }
        true
    }

    fn ai_trade_reply(
        &self,
        nation: MajorNationId,
        _seller: NationId,
        requested: i16,
        commodity: TradeCommodity,
        runtime: &mut MinisterTradeRuntime,
    ) -> Option<(i16, bool)> {
        let economy = &self.nations.majors[nation].economy;
        debug_assert_eq!(economy.foreign_trade.purchase_priority[commodity], 0);
        let available = economy.capacities.available_merchant;
        let total_capacity = economy.capacities.trade_offer;

        match economy.foreign_minister_personality {
            ForeignMinisterPersonality::Trader => {
                Some((available.min(requested), available < requested))
            }
            ForeignMinisterPersonality::Textile => Some((available.min(requested), false)),
            ForeignMinisterPersonality::Diplomat => {
                let quota = if total_capacity < 12 {
                    1
                } else if total_capacity >= 25 {
                    3
                } else {
                    2
                };
                Some((quota.min(available).min(requested), false))
            }
            ForeignMinisterPersonality::Ted => match commodity {
                TradeCommodity::Coal => {
                    if runtime.partner_enabled[TradeCommodity::Coal.into_usize()] {
                        runtime.capability = available / 2;
                        runtime.partner_enabled[TradeCommodity::Coal.into_usize()] = false;
                    }
                    if runtime.capability >= requested {
                        runtime.capability -= requested;
                        Some((requested, false))
                    } else {
                        let amount = runtime.capability;
                        runtime.capability = 0;
                        Some((amount, true))
                    }
                }
                TradeCommodity::Timber | TradeCommodity::Iron | TradeCommodity::Oil => {
                    Some((available.min(requested), false))
                }
                TradeCommodity::Cotton | TradeCommodity::Wool => {
                    let quota = if total_capacity < 15 {
                        1
                    } else if total_capacity >= 30 {
                        3
                    } else {
                        2
                    };
                    Some((quota.min(requested).min(available), false))
                }
                _ => None,
            },
            ForeignMinisterPersonality::Bill => match commodity {
                TradeCommodity::Timber => {
                    if self.market.rows[TradeCommodity::Coal].price >= 105
                        && self.market.rows[TradeCommodity::Iron].price >= 105
                    {
                        if runtime.partner_enabled[TradeCommodity::Timber.into_usize()] {
                            runtime.capability = (available / 3).max(2);
                            runtime.partner_enabled[TradeCommodity::Timber.into_usize()] = false;
                        }
                        let amount = runtime.capability.min(available);
                        if amount >= requested {
                            runtime.capability = (runtime.capability - requested).max(0);
                            Some((requested, false))
                        } else {
                            runtime.capability = 0;
                            Some((amount, true))
                        }
                    } else {
                        Some((available.min(requested), false))
                    }
                }
                TradeCommodity::Coal => {
                    if runtime.partner_enabled[TradeCommodity::Coal.into_usize()] {
                        runtime.capability = available / 2;
                        runtime.partner_enabled[TradeCommodity::Coal.into_usize()] = false;
                    }
                    let wanted = if self.market.rows[TradeCommodity::Iron].price < 105 {
                        requested
                    } else {
                        runtime.capability.min(requested)
                    };
                    if available >= wanted {
                        runtime.capability -= wanted;
                        Some((wanted, false))
                    } else {
                        runtime.capability = 0;
                        Some((available, false))
                    }
                }
                TradeCommodity::Iron | TradeCommodity::Oil => {
                    Some((available.min(requested), false))
                }
                _ => None,
            },
            ForeignMinisterPersonality::Base | ForeignMinisterPersonality::Arms => None,
        }
    }

    fn apply_trade_deal_results(
        &mut self,
        buyer: NationId,
        seller: NationId,
        amount: i16,
        unit_price: i32,
        commodity: TradeCommodity,
        shortfall: bool,
    ) {
        if shortfall && let Some(buyer) = MajorNationId::from_nation(buyer) {
            self.nations.majors[buyer]
                .economy
                .clear_trade_offer(resource(commodity));
        }

        if amount > 0 {
            self.apply_nation_trade_purchase(buyer, commodity, amount, unit_price as i16);
            self.apply_nation_trade_purchase(seller, commodity, -amount, unit_price as i16);
            if let Some(seller) = MajorNationId::from_nation(seller)
                && MajorNationId::from_nation(buyer).is_none()
            {
                self.nations.majors[seller].economy.deliver_item(amount);
            }

            if self.diplomacy.mission_levels[buyer][seller].retail() >= 1 {
                let standing = self.diplomacy.standings[buyer][seller]
                    .wrapping_add(1)
                    .clamp(50, 255);
                self.diplomacy.standings[buyer][seller] = standing;
                self.diplomacy.standings[seller][buyer] = standing;
            }
            if let Some(seller) = MajorNationId::from_nation(seller) {
                self.add_trade_deal_book_entry(
                    seller,
                    commodity,
                    TradeDealBookEntry {
                        kind: DealBookEntryKind::Accept,
                        nation: buyer,
                        amount,
                        unit_price,
                    },
                );
            }
            if let Some(buyer) = MajorNationId::from_nation(buyer) {
                self.add_trade_deal_book_entry(
                    buyer,
                    commodity,
                    TradeDealBookEntry {
                        kind: DealBookEntryKind::Offer,
                        nation: seller,
                        amount,
                        unit_price,
                    },
                );
            }
        } else if let Some(buyer) = MajorNationId::from_nation(buyer) {
            self.add_trade_deal_book_entry(
                buyer,
                commodity,
                TradeDealBookEntry {
                    kind: DealBookEntryKind::Offer,
                    nation: seller,
                    amount,
                    unit_price,
                },
            );
        }
    }

    fn apply_nation_trade_purchase(
        &mut self,
        nation: NationId,
        commodity: TradeCommodity,
        amount: i16,
        unit_price: i16,
    ) {
        if let Some(nation) = MajorNationId::from_nation(nation) {
            self.purchase_item(nation, resource(commodity), amount, unit_price);
            return;
        }

        let trade = &mut self.nations.minors[MinorNationId::new(nation.get())]
            .as_mut()
            .expect("supported trade phase has every minor nation")
            .trade;
        if amount >= 1 && MANUFACTURED_RESOURCES.contains(&commodity) {
            if trade.primary_manufactured_request == Some(commodity) {
                trade.primary_request_fulfilled = amount;
            } else if trade.secondary_manufactured_request == Some(commodity) {
                trade.secondary_request_fulfilled = amount;
            }
        } else if commodity.into_usize() <= TradeCommodity::Oil.into_usize()
            || commodity == TradeCommodity::Food
        {
            trade.grant_deltas[resource(commodity)] += amount;
        }
    }

    fn add_trade_deal_book_entry(
        &mut self,
        nation: MajorNationId,
        commodity: TradeCommodity,
        entry: TradeDealBookEntry,
    ) {
        let entries = &mut self.nations.majors[nation].economy.deal_book[commodity];
        let index = entries
            .iter()
            .position(|current| entry.nation < current.nation)
            .unwrap_or(entries.len());
        entries.insert(index, entry);
    }

    fn finish_trade_phase(&mut self, scratch: &TradeScratch) {
        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            if !self.nations.majors[nation].economy.controller.is_human() {
                self.finish_ai_trade_phase(nation);
            }
            self.nations.majors[nation].economy.item_potentials = ResourceTable::default();
        }

        for commodity in all_trade_commodities() {
            for nation in NationId::all() {
                self.market.rows[commodity].current_offer_by_nation[nation] =
                    scratch.current[commodity][nation];
                self.market.rows[commodity].maximum_offer_by_nation[nation] =
                    self.market.rows[commodity].maximum_offer_by_nation[nation]
                        .max(scratch.accumulated[commodity][nation]);
            }
        }
    }

    fn finish_ai_trade_phase(&mut self, nation: MajorNationId) {
        for (commodity, resource) in [
            (ProcessedTradeCommodity::Food, ResourceKind::Food),
            (ProcessedTradeCommodity::Fabric, ResourceKind::Fabric),
            (ProcessedTradeCommodity::Lumber, ResourceKind::Lumber),
            (ProcessedTradeCommodity::Paper, ResourceKind::Paper),
            (ProcessedTradeCommodity::Steel, ResourceKind::Steel),
            (ProcessedTradeCommodity::Fuel, ResourceKind::Fuel),
        ] {
            let pending = self.nations.majors[nation]
                .economy
                .ai_trade
                .as_ref()
                .expect("supported automated nation has AI trade state")
                .temporary_processed_stock[commodity];
            if pending > 0 {
                self.nations.majors[nation]
                    .city
                    .adjust_stock(resource, -pending);
            }
            self.nations.majors[nation]
                .economy
                .ai_trade
                .as_mut()
                .expect("supported automated nation has AI trade state")
                .temporary_processed_stock[commodity] = 0;
        }

        let economy = &mut self.nations.majors[nation].economy;
        economy.foreign_trade.interior_bid = None;
        if economy.capacities.available_merchant == 0 {
            economy.foreign_trade.phase_counter += 1;
        }
        economy.foreign_trade.purchase_priority = TradeCommodityTable::default();
    }
}

fn all_trade_commodities() -> impl ExactSizeIterator<Item = TradeCommodity> {
    (0..TradeCommodity::LENGTH).map(TradeCommodity::from_usize)
}

fn resource(commodity: TradeCommodity) -> ResourceKind {
    ResourceKind::from_usize(commodity.into_usize())
}

fn preferred_trade_nation(common: &NationCommonState, own_nation: NationId) -> NationId {
    match common.status() {
        CountryStatus::Independent => own_nation,
        CountryStatus::ProtectorateOf(master) | CountryStatus::ColonyOf(master) => master,
    }
}

fn insert_ranked_deal(deals: &mut Vec<TradeDeal>, deal: TradeDeal) {
    let index = deals
        .iter()
        .position(|current| deal_sorts_before_or_equal(deal, *current))
        .unwrap_or(deals.len());
    deals.insert(index, deal);
}

fn deal_sorts_before_or_equal(first: TradeDeal, second: TradeDeal) -> bool {
    let manufactured = matches!(
        first.commodity,
        TradeCommodity::Clothing
            | TradeCommodity::Furniture
            | TradeCommodity::Hardware
            | TradeCommodity::Arms
    );
    let mut first_score = if manufactured {
        (255 - i32::from(first.standing)) * first.unit_price
    } else {
        -(first.unit_price * i32::from(first.standing))
    };
    let mut second_score = if manufactured {
        (255 - i32::from(second.standing)) * second.unit_price
    } else {
        -(second.unit_price * i32::from(second.standing))
    };
    if first_score == second_score {
        first_score = deal_tie_score(first);
        second_score = deal_tie_score(second);
    }
    first_score <= second_score
}

fn deal_tie_score(deal: TradeDeal) -> i32 {
    (i32::from(deal.seller_offer) * i32::from(deal.buyer.get())
        + deal.unit_price
        + i32::from(deal.seller.get()) * i32::from(deal.standing)
        + deal.commodity.into_usize() as i32)
        % 7
}

fn select_local_tie(
    standing: i16,
    economic_turn: i32,
    nation: MajorNationId,
    seed: &mut u32,
) -> bool {
    let mut value = u32::from_ne_bytes(i32::from(standing).to_ne_bytes())
        .wrapping_add(0x31)
        .wrapping_add(u32::from_ne_bytes(economic_turn.to_ne_bytes()))
        .wrapping_add(u32::from(nation.get()));
    if value == 0 {
        value = *seed;
    }
    *seed = value.wrapping_mul(0x015a_4e35).wrapping_add(1);
    (*seed >> 12) & 1 != 0
}

fn insert_lowest_first(
    entries: &mut Vec<(TradeCommodity, i16)>,
    commodity: TradeCommodity,
    key: i16,
) {
    let index = entries
        .iter()
        .position(|(_, current)| key <= *current)
        .unwrap_or(entries.len());
    entries.insert(index, (commodity, key));
}

fn minor_offer_weight_base(economic_turn: i32) -> f64 {
    match economic_turn.div_euclid(4) {
        ..=10 => 1.10,
        11..=20 => 1.09,
        21..=30 => 1.08,
        31..=40 => 1.07,
        41..=50 => 1.06,
        51..=60 => 1.05,
        61..=70 => 1.04,
        71..=80 => 1.03,
        81..=90 => 1.02,
        _ => 1.01,
    }
}

fn major_offer_weight_base(economic_turn: i32) -> f64 {
    match economic_turn.div_euclid(4) {
        ..=10 => 1.10,
        11..=20 => 1.08,
        21..=30 => 1.06,
        31..=40 => 1.04,
        41..=50 => 1.03,
        51..=60 => 1.02,
        _ => 1.01,
    }
}

fn offer_weight(base: f64, amount: i16, cap_at_two: bool) -> f64 {
    if amount == 1 {
        return 1.0;
    }
    let mut value = 1.0;
    for _ in 0..(amount - 1).min(23) {
        value *= base;
    }
    if cap_at_two { value.min(2.0) } else { value }
}
