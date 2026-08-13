//! Retail `TSimMgr::DoTrade` as one domain operation.

use crate::create_random_game::resource_capability_level;
use crate::market::all_trade_commodities;
use crate::*;

const DEAL_CATEGORY_ORDER: [u8; TradeCommodity::LENGTH] =
    [13, 14, 15, 16, 7, 8, 9, 10, 11, 12, 0, 1, 2, 3, 4, 5, 6];
const NO_RESOURCE: i16 = -10;
const GRANT_DELTA_SCALE: f32 = -1.0 / 255.0;
const RELATION_SCALE: f64 = 1.0 / 255.0;
const RELATION_RAND_SCALE: f64 = 32767.0;

struct RankedDeal {
    buyer: NationId,
    seller: NationId,
    offer_amount: i16,
    standing: i16,
    price: i32,
    category: TradeCommodity,
}

struct TradePhase {
    recurring_grant: MinorNationTable<ResourceTable<i16>>,
    status_by_major: MinorNationTable<ResourceTable<[i16; MAJOR_NATION_COUNT]>>,
    deals: TradeCommodityTable<Vec<RankedDeal>>,
    arms_basic_split: i16,
    arms_advanced_split: i16,
}

impl TradePhase {
    fn new() -> Self {
        Self {
            recurring_grant: MinorNationTable::default(),
            status_by_major: MinorNationTable::default(),
            deals: TradeCommodityTable::default(),
            arms_basic_split: 0,
            arms_advanced_split: 0,
        }
    }
}

impl GameState {
    /// Resolves one complete retail trade phase (`TSimMgr::DoTrade`).
    ///
    /// Human Board of Trade orders are consumed from remembered bids. Offer-sheet
    /// UI is treated as Accept at the posed amount. The following civilian phase
    /// is not started.
    pub fn do_trade(&mut self) {
        let mut phase = TradePhase::new();
        self.initialize_deal_books();
        self.reset_market_rows();
        self.run_nation_update_passes(&mut phase);
        self.set_minors_trade_bids(&mut phase);
        self.tally_major_trade_bids();
        self.market.recalculate_prices();
        self.calculate_deal_order(&mut phase);
        self.resolve_deals(&mut phase);
        self.end_trade_offers();
    }

    fn initialize_deal_books(&mut self) {
        for slot in (0..MajorNationId::COUNT).rev() {
            let nation = MajorNationId::new(slot);
            self.nations.majors[nation].economy.deal_book = TradeCommodityTable::default();
        }
    }

    fn reset_market_rows(&mut self) {
        for commodity in all_trade_commodities() {
            let row = &mut self.market.rows[commodity];
            row.request_count = 0;
            row.offer_count = 0;
            row.amount_offered = 0;
            row.adjusted_offer_count = 0.0;
            row.current_offer_by_nation = NationTable::from_array([0; NATION_COUNT]);
            row.accumulated_offer_by_nation = NationTable::from_array([0; NATION_COUNT]);
        }
    }

    fn run_nation_update_passes(&mut self, phase: &mut TradePhase) {
        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            if !self.major_is_trade_eligible(nation) {
                continue;
            }
            if self.nations.majors[nation].economy.controller.is_human() {
                self.reset_player_trade_phase(nation);
            } else {
                self.reset_ai_trade_phase(nation);
            }
        }

        for slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = MinorNationId::new(slot);
            if self.nations.minors[minor].is_some() {
                self.initialize_minor_trade_status(minor, phase);
            }
        }

        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            if !self.major_is_trade_eligible(nation) {
                continue;
            }
            if self.nations.majors[nation].economy.controller.is_human() {
                if self.turn.difficulty == Difficulty::Introductory
                    && self.turn.phase == PhaseCode::CAPITAL_SELECTION
                {
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
                    self.nations.majors[nation].economy.remember_trade_bids();
                }
            } else {
                self.set_ai_trade_bids(nation);
                self.do_usual_subsidy_rule(nation);
            }
        }
    }

    fn reset_ai_trade_phase(&mut self, nation: MajorNationId) {
        self.refresh_merchant_capacity(nation);
        let major = &mut self.nations.majors[nation].economy;
        major.unfilled_trade_offer_count = 0;
        major.budget_pool_delta = 0;
        major.budget_pool_base = 0;
        major.item_potentials = ResourceTable::default();
        major.aid_allocation_by_minor_nation = Default::default();
    }

    fn initialize_minor_trade_status(&mut self, minor: MinorNationId, phase: &mut TradePhase) {
        {
            let Some(state) = self.nations.minors[minor].as_mut() else {
                return;
            };
            state.trade.secondary_manufactured_request = None;
            state.trade.primary_request_fulfilled = 0;
            state.trade.secondary_request_fulfilled = 0;
            state.trade.offers = ResourceTable::default();
            state.trade.grant_deltas = ResourceTable::default();
            state.trade.independent_resource_counts = ResourceTable::default();
            state.trade.current_supply = ResourceTable::default();
            state.trade.current_supply[ResourceKind::Food] = 2;
        }
        phase.recurring_grant[minor] = ResourceTable::default();
        phase.status_by_major[minor] = ResourceTable::default();

        let owner = TileOwnerTag::from_nation(minor.nation());
        for index in 0..STRATEGIC_TILE_COUNT {
            let tile = &self.map[TileId::new(index as u16)];
            if tile.owner_nation != Some(owner) {
                continue;
            }
            if let Some(great_power) = tile.secondary_owner_nation {
                for resource in tile.edge_resources.into_iter().flatten() {
                    let yield_level = resource_capability_level(tile, resource);
                    phase.recurring_grant[minor][resource] += yield_level;
                    phase.status_by_major[minor][resource][usize::from(great_power.get())] +=
                        yield_level;
                    if let Some(state) = self.nations.minors[minor].as_mut() {
                        state.trade.current_supply[resource] += yield_level;
                    }
                }
            } else {
                for resource in tile.edge_resources.into_iter().flatten() {
                    if tile.gate == 0x0f {
                        continue;
                    }
                    if let Some(state) = self.nations.minors[minor].as_mut() {
                        state.trade.current_supply[resource] += 1;
                        state.trade.independent_resource_counts[resource] += 1;
                    }
                }
            }
        }

        let mut aid = Vec::new();
        for slot in 0..MajorNationId::COUNT {
            let major = MajorNationId::new(slot);
            let gold = phase.status_by_major[minor][ResourceKind::Gold][usize::from(slot)];
            if gold != 0 {
                let standing = self.diplomacy.standings[minor.nation()][major.nation()];
                aid.push((
                    major,
                    ResourceKind::Gold,
                    i32::from(standing) * i32::from(gold) * 200 / 255,
                ));
            }
            let gems = phase.status_by_major[minor][ResourceKind::Gems][usize::from(slot)];
            if gems != 0 {
                let standing = self.diplomacy.standings[minor.nation()][major.nation()];
                aid.push((
                    major,
                    ResourceKind::Gems,
                    i32::from(standing) * i32::from(gems) * 500 / 255,
                ));
            }
        }
        for (major, resource, amount) in aid {
            self.add_aid_allocation(major, minor, resource, amount);
        }
    }

    fn set_minors_trade_bids(&mut self, phase: &mut TradePhase) {
        for slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = MinorNationId::new(slot);
            if self.nations.minors[minor].is_some() {
                self.set_minor_trade_bids(minor, phase);
            }
        }
        self.tally_minors_trade_bids(phase);
    }

    fn set_minor_trade_bids(&mut self, minor: MinorNationId, phase: &TradePhase) {
        let offer_independent_resources = !matches!(
            self.nations.minors[minor]
                .as_ref()
                .map(|state| state.common.status()),
            Some(CountryStatus::ColonyOf(_))
        );
        let saved_primary = self.nations.minors[minor]
            .as_ref()
            .and_then(|state| state.trade.primary_manufactured_request);

        if offer_independent_resources {
            let roll = self.rng.next_crt_rand() % 100;
            let random_resource = if roll < 0x19 {
                ResourceKind::Cotton
            } else if roll < 0x32 {
                ResourceKind::Wool
            } else if roll <= 0x4a {
                ResourceKind::Timber
            } else {
                ResourceKind::Food
            };
            let Some(state) = self.nations.minors[minor].as_mut() else {
                return;
            };
            if i32::from(state.trade.thresholds.random_offer_price)
                < self.market.rows[trade_commodity(random_resource)].price
            {
                state.trade.offers[random_resource] = state.trade.current_supply[random_resource];
            }
            for resource in [
                ResourceKind::Cotton,
                ResourceKind::Wool,
                ResourceKind::Timber,
                ResourceKind::Coal,
                ResourceKind::Iron,
                ResourceKind::Horses,
                ResourceKind::Oil,
                ResourceKind::Food,
            ] {
                if i32::from(state.trade.thresholds.general_offer_price)
                    < self.market.rows[trade_commodity(resource)].price
                {
                    state.trade.offers[resource] = state.trade.current_supply[resource];
                }
            }
            offer_or_grant(
                state,
                &phase.recurring_grant[minor],
                ResourceKind::Coal,
                state.trade.thresholds.coal_offer_price,
                self.market.rows[TradeCommodity::Coal].price,
            );
            offer_or_grant(
                state,
                &phase.recurring_grant[minor],
                ResourceKind::Iron,
                state.trade.thresholds.iron_offer_price,
                self.market.rows[TradeCommodity::Iron].price,
            );
            offer_or_grant(
                state,
                &phase.recurring_grant[minor],
                ResourceKind::Oil,
                state.trade.thresholds.oil_offer_price,
                self.market.rows[TradeCommodity::Oil].price,
            );
            for resource in [
                ResourceKind::Cotton,
                ResourceKind::Wool,
                ResourceKind::Timber,
            ] {
                if state.trade.offers[resource] == 0 {
                    state.trade.offers[resource] = phase.recurring_grant[minor][resource];
                }
            }
        }

        let Some(state) = self.nations.minors[minor].as_mut() else {
            return;
        };
        if saved_primary == state.trade.primary_manufactured_request {
            let current = resource_code(state.trade.primary_manufactured_request);
            let mut rolled;
            loop {
                let roll = self.rng.next_crt_rand() % 100;
                rolled = if roll < 0x1e {
                    0x0d
                } else if roll < 0x3c {
                    0x0e
                } else if roll > 0x59 {
                    0x10
                } else {
                    0x0f
                };
                if rolled != current {
                    break;
                }
            }
            let price =
                self.market.rows[TradeCommodity::from_retail(rolled).expect("manufactured")].price;
            if i32::from(state.trade.thresholds.primary_manufactured_price) < price {
                state.trade.primary_manufactured_request = None;
            } else {
                state.trade.primary_manufactured_request = TradeCommodity::from_retail(rolled);
            }
        }

        state.trade.secondary_manufactured_request = None;
        for commodity in [
            TradeCommodity::Clothing,
            TradeCommodity::Furniture,
            TradeCommodity::Hardware,
            TradeCommodity::Arms,
        ] {
            if self.market.rows[commodity].price
                < i32::from(state.trade.thresholds.secondary_manufactured_price)
                && Some(commodity) != state.trade.primary_manufactured_request
            {
                state.trade.secondary_manufactured_request = Some(commodity);
                break;
            }
        }

        if let Some(commodity) = state.trade.primary_manufactured_request {
            state.trade.offers[commodity.resource()] = -1;
        }
        if let Some(commodity) = state.trade.secondary_manufactured_request {
            state.trade.offers[commodity.resource()] = -1;
        }
    }

    fn tally_minors_trade_bids(&mut self, phase: &TradePhase) {
        let base = minor_offer_base(self.turn.economic_turn);
        for commodity in [
            TradeCommodity::Cotton,
            TradeCommodity::Wool,
            TradeCommodity::Timber,
            TradeCommodity::Coal,
            TradeCommodity::Iron,
            TradeCommodity::Horses,
            TradeCommodity::Oil,
        ] {
            for slot in MinorNationId::FIRST..NationId::COUNT {
                let minor = MinorNationId::new(slot);
                let Some(state) = self.nations.minors[minor].as_ref() else {
                    continue;
                };
                let metric = state.trade.offers[commodity.resource()];
                self.market.rows[commodity].current_offer_by_nation[minor.nation()] = metric;
                if metric <= 0 {
                    continue;
                }
                let stock = state.trade.current_supply[commodity.resource()];
                let value = if stock < metric { stock } else { metric };
                let row = &mut self.market.rows[commodity];
                row.offer_count += 1;
                row.amount_offered += i32::from(value);
                let factor = if row.price < i32::from(state.trade.thresholds.random_offer_price) {
                    0.0
                } else if value == 1 {
                    1.0
                } else {
                    let exponent = if value < 0x19 { value - 1 } else { 0x17 };
                    trade_power(base, exponent)
                };
                row.adjusted_offer_count += factor;
            }
        }

        for slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = MinorNationId::new(slot);
            let Some(state) = self.nations.minors[minor].as_ref() else {
                continue;
            };
            let metric = state.trade.offers[ResourceKind::Food];
            self.market.rows[TradeCommodity::Food].current_offer_by_nation[minor.nation()] = metric;
            if metric <= 0 {
                continue;
            }
            let row = &mut self.market.rows[TradeCommodity::Food];
            row.offer_count += 1;
            row.amount_offered += i32::from(metric);
            let factor = if metric == 1 {
                1.0
            } else if metric > 0x18 {
                trade_power(base, 0x17)
            } else {
                trade_power(base, metric - 1)
            };
            row.adjusted_offer_count += factor;
        }

        for commodity in [
            TradeCommodity::Clothing,
            TradeCommodity::Furniture,
            TradeCommodity::Hardware,
            TradeCommodity::Arms,
        ] {
            for slot in MinorNationId::FIRST..NationId::COUNT {
                let minor = MinorNationId::new(slot);
                let Some(state) = self.nations.minors[minor].as_ref() else {
                    continue;
                };
                let metric = state.trade.offers[commodity.resource()];
                self.market.rows[commodity].current_offer_by_nation[minor.nation()] = metric;
                if metric < 0 {
                    self.market.rows[commodity].request_count += 1;
                }
            }
        }
        let _ = phase;
    }

    fn tally_major_trade_bids(&mut self) {
        let base = major_offer_base(self.turn.economic_turn);
        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            if self.major_is_trade_eligible(nation) {
                self.assign_fallback_trade_offers(nation);
            }
        }

        for commodity in all_trade_commodities() {
            for slot in 0..MajorNationId::COUNT {
                let nation = MajorNationId::new(slot);
                if !self.major_is_trade_eligible(nation) {
                    continue;
                }
                let metric =
                    self.nations.majors[nation].economy.item_potentials[commodity.resource()];
                self.market.rows[commodity].current_offer_by_nation[nation.nation()] = metric;
                let row = &mut self.market.rows[commodity];
                if metric < 0 {
                    row.request_count += 1;
                } else if metric > 0 {
                    row.offer_count += 1;
                    row.amount_offered += i32::from(metric);
                    let factor = if metric == 1 {
                        1.0
                    } else {
                        let exponent = if metric < 0x19 { metric - 1 } else { 0x17 };
                        trade_power(base, exponent).min(2.0)
                    };
                    row.adjusted_offer_count += factor;
                }
            }
        }
    }

    fn assign_fallback_trade_offers(&mut self, nation: MajorNationId) {
        if !self.nations.majors[nation].economy.controller.is_human() {
            self.arrange_materials_offers(nation);
            return;
        }

        let buying_processed = [
            ResourceKind::Food,
            ResourceKind::Fabric,
            ResourceKind::Lumber,
            ResourceKind::Paper,
            ResourceKind::Steel,
        ]
        .into_iter()
        .any(|resource| self.nations.majors[nation].economy.item_potentials[resource] < 0);

        if buying_processed {
            let ranked = self.build_independent_major_relationship_list(nation);
            let mut selected = None;
            for resource in [
                ResourceKind::Food,
                ResourceKind::Fabric,
                ResourceKind::Lumber,
                ResourceKind::Paper,
                ResourceKind::Steel,
            ] {
                if self.nations.majors[nation].economy.item_potentials[resource] >= 0 {
                    continue;
                }
                if selected.is_none() {
                    for &candidate in ranked.iter().rev() {
                        if !self.nations.majors[candidate].economy.controller.is_human() {
                            selected = Some(candidate);
                            break;
                        }
                    }
                }
                if let Some(selected) = selected {
                    self.set_trade_offers_for(selected, resource, nation);
                }
            }
        }

        if self.nations.majors[nation].economy.item_potentials[ResourceKind::Horses] == -1 {
            loop {
                let candidate = MajorNationId::new((self.rng.next_crt_rand() % 7) as u8);
                if self.major_is_trade_eligible(candidate)
                    && !self.nations_at_war(candidate.nation(), nation.nation())
                    && candidate != nation
                {
                    self.set_trade_offers_for(candidate, ResourceKind::Horses, nation);
                    break;
                }
            }
        }
    }

    fn arrange_materials_offers(&mut self, nation: MajorNationId) {
        if let Some(bid) = self.nations.majors[nation]
            .economy
            .foreign_trade
            .interior_bid
            && let Some(&selected) = self
                .build_independent_major_relationship_list(nation)
                .last()
        {
            self.set_trade_offers_for(selected, bid.commodity.resource(), nation);
        }

        if self.nations.majors[nation]
            .economy
            .foreign_trade
            .purchase_priority[TradeCommodity::Horses]
            > 0
        {
            let mut found = false;
            let mut trial = 1;
            let mut fallback = MajorNationId::new(0);
            loop {
                if found {
                    break;
                }
                fallback = MajorNationId::new((self.rng.next_crt_rand() % 7) as u8);
                if self.major_is_trade_eligible(fallback)
                    && !self.nations_at_war(fallback.nation(), nation.nation())
                    && fallback != nation
                {
                    found = true;
                }
                if trial >= 0x14 {
                    break;
                }
                trial += 1;
            }
            if found {
                self.set_trade_offers_for(fallback, ResourceKind::Horses, nation);
            }
        }
    }

    fn set_trade_offers_for(
        &mut self,
        seller: MajorNationId,
        resource: ResourceKind,
        requester: MajorNationId,
    ) {
        if self.nations.majors[seller].economy.controller.is_human() {
            self.add_shortage_event(seller, requester, resource);
            return;
        }

        if self.nations.majors[requester].economy.controller.is_human() {
            if resource != ResourceKind::Horses {
                let standing = self.diplomacy.standings[seller.nation()][requester.nation()];
                let scaled = f64::from(standing) * RELATION_SCALE;
                let roll = f64::from(self.rng.next_crt_rand());
                if roll > scaled * RELATION_RAND_SCALE {
                    self.raise_need_planning_metrics(seller, resource);
                }
                return;
            }
        } else if resource != ResourceKind::Horses {
            let stock = self.nations.majors[seller].city.stockpile[resource];
            let mut cap = 10_i16.min(stock);
            cap = cap.min(self.nations.majors[seller].economy.capacities.trade_offer);
            if self.nations.majors[seller].economy.item_potentials[resource] == -1 {
                return;
            }
            self.nations.majors[seller]
                .economy
                .set_item_potential(resource, cap);
            return;
        }

        let horses = self.nations.majors[seller].city.stockpile[ResourceKind::Horses];
        if horses != 0
            && self.nations.majors[seller].economy.item_potentials[ResourceKind::Horses] != -1
        {
            let mut amount = i16::from(horses != 1) + 1;
            amount = amount.min(self.nations.majors[seller].economy.capacities.trade_offer);
            self.nations.majors[seller]
                .economy
                .set_item_potential(ResourceKind::Horses, amount);
        }
    }

    fn raise_need_planning_metrics(&mut self, nation: MajorNationId, resource: ResourceKind) {
        if let Some(processed) = ProcessedTradeCommodity::from_resource(resource)
            && let Some(ai_trade) = self.nations.majors[nation].economy.ai_trade.as_mut()
        {
            ai_trade.temporary_processed_stock[processed] += 4;
        }
        self.nations.city_mut(nation).adjust_stock(resource, 4);
        let potential = self.nations.majors[nation].economy.item_potentials[resource];
        self.nations.majors[nation]
            .economy
            .set_item_potential(resource, potential + 4);
    }

    fn add_shortage_event(
        &mut self,
        subject: MajorNationId,
        affected: MajorNationId,
        resource: ResourceKind,
    ) {
        for event in &mut self.pending.newspaper_events {
            if let PendingNewspaperEvent::Shortage {
                subject: existing_subject,
                affected_nations,
                resource: existing_resource,
            } = event
                && *existing_subject == subject
                && *existing_resource == resource
            {
                affected_nations[affected.nation()] = true;
                return;
            }
        }
        let mut affected_nations = NationTable::default();
        affected_nations[affected.nation()] = true;
        self.pending
            .newspaper_events
            .push(PendingNewspaperEvent::Shortage {
                subject,
                affected_nations,
                resource,
            });
    }

    fn calculate_deal_order(&mut self, phase: &mut TradePhase) {
        for row in 0..7 {
            let commodity = TradeCommodity::from_retail(row).expect("raw commodity");
            self.pair_deals(phase, commodity, 0..7, 0..7);
            self.pair_deals(phase, commodity, 7..NATION_COUNT as u8, 0..7);
        }
        for row in 7..0x0d {
            let commodity = TradeCommodity::from_retail(row).expect("processed commodity");
            self.pair_deals(phase, commodity, 0..7, 0..7);
            if row == 7 {
                self.pair_deals(phase, commodity, 7..NATION_COUNT as u8, 0..7);
            }
        }
        for row in 0x0d..0x11 {
            let commodity = TradeCommodity::from_retail(row).expect("manufactured commodity");
            self.pair_deals(phase, commodity, 0..7, 0..7);
            self.pair_deals(phase, commodity, 0..7, 7..NATION_COUNT as u8);
        }
    }

    fn pair_deals(
        &mut self,
        phase: &mut TradePhase,
        commodity: TradeCommodity,
        sellers: std::ops::Range<u8>,
        buyers: std::ops::Range<u8>,
    ) {
        for seller_slot in sellers {
            let seller = NationId::new(seller_slot);
            if !self.nation_present(seller) {
                continue;
            }
            let cell = self.market.rows[commodity].current_offer_by_nation[seller];
            if cell <= 0 {
                continue;
            }
            self.market.rows[commodity].accumulated_offer_by_nation[seller] += cell;
            for buyer_slot in buyers.clone() {
                let buyer = NationId::new(buyer_slot);
                if !self.nation_present(buyer) {
                    continue;
                }
                if self.market.rows[commodity].current_offer_by_nation[buyer] >= 0 {
                    continue;
                }
                if self.has_boycott(buyer, seller) || self.nations_at_war(buyer, seller) {
                    continue;
                }
                let deal = RankedDeal {
                    buyer,
                    seller,
                    offer_amount: cell,
                    standing: self.diplomacy.standings[buyer][seller],
                    price: self.deal_price(buyer, seller, commodity),
                    category: commodity,
                };
                insert_sorted(&mut phase.deals[commodity], deal, compare_deals);
            }
        }
    }

    fn deal_price(&self, buyer: NationId, seller: NationId, commodity: TradeCommodity) -> i32 {
        if self.nations_at_war(buyer, seller) {
            return -1;
        }
        let price = self.market.rows[commodity].price;
        let base = self.market.rows[commodity].base_price;
        if preferred_nation(self.nation_status(seller), seller) == buyer {
            return price.min(base);
        }
        if preferred_nation(self.nation_status(buyer), buyer) == seller {
            return price.max(base);
        }

        if let Some(target) = MajorNationId::from_nation(seller) {
            let relation =
                self.nations.majors[target].common.trade_policy_by_nation[buyer].retail();
            if relation == 100 {
                return price;
            }
            if relation == 300 {
                return -1;
            }
            return (f64::from(price * relation) * 0.01) as i32;
        }
        let Some(source) = MajorNationId::from_nation(buyer) else {
            return price;
        };
        let relation = self.nations.majors[source].common.trade_policy_by_nation[seller].retail();
        if relation == 100 {
            return price;
        }
        if relation == 300 {
            return -1;
        }
        let inverse = 200 - relation;
        (f64::from(price) * f64::from(inverse) * 0.01) as i32
    }

    fn resolve_deals(&mut self, phase: &mut TradePhase) {
        for &row in &DEAL_CATEGORY_ORDER {
            let commodity = TradeCommodity::from_retail(i16::from(row)).expect("deal commodity");
            for index in 0..phase.deals[commodity].len() {
                let deal = &phase.deals[commodity][index];
                let buyer = deal.buyer;
                let seller = deal.seller;
                let price = deal.price as i16;
                let mut transfer = self.amount_unsold(seller, commodity.resource());
                if MajorNationId::from_nation(seller).is_some()
                    && MajorNationId::from_nation(buyer).is_none()
                {
                    let capacity = self.nations.majors
                        [MajorNationId::from_nation(seller).expect("great-power seller")]
                    .economy
                    .capacities
                    .available_merchant;
                    if capacity < transfer {
                        transfer = capacity;
                    }
                }
                if transfer > 0 {
                    self.reply_to_trade_offer(buyer, seller, transfer, price, commodity, phase);
                }
            }
        }
    }

    fn amount_unsold(&self, nation: NationId, resource: ResourceKind) -> i16 {
        if let Some(major) = MajorNationId::from_nation(nation) {
            self.nations.majors[major].economy.amount_unsold(resource)
        } else {
            let minor = MinorNationId::new(nation.get());
            self.nations.minors[minor]
                .as_ref()
                .map(|state| {
                    (state.trade.current_supply[resource] + state.trade.grant_deltas[resource])
                        .max(0)
                })
                .unwrap_or(0)
        }
    }

    fn reply_to_trade_offer(
        &mut self,
        buyer: NationId,
        seller: NationId,
        amount: i16,
        price: i16,
        commodity: TradeCommodity,
        phase: &mut TradePhase,
    ) {
        if let Some(major) = MajorNationId::from_nation(buyer) {
            if self.nations.majors[major]
                .economy
                .is_still_buying(commodity.resource())
            {
                if self.nations.majors[major].economy.controller.is_human() {
                    self.set_deal_results(buyer, seller, amount, price, commodity, false, phase);
                } else {
                    self.ai_reply_to_trade_offer(major, seller, amount, price, commodity, phase);
                }
            } else {
                self.add_to_deal_book(major, DealBookEntryKind::Offer, seller, 0, commodity, 0);
            }
            return;
        }

        let minor = MinorNationId::new(buyer.get());
        if self.minor_still_buying(minor, commodity.resource()) {
            self.set_deal_results(buyer, seller, amount, price, commodity, true, phase);
        }
    }

    fn minor_still_buying(&self, minor: MinorNationId, resource: ResourceKind) -> bool {
        let Some(state) = self.nations.minors[minor].as_ref() else {
            return false;
        };
        let Some(commodity) = TradeCommodity::from_retail(resource as i16) else {
            return true;
        };
        if !matches!(
            commodity,
            TradeCommodity::Clothing
                | TradeCommodity::Furniture
                | TradeCommodity::Hardware
                | TradeCommodity::Arms
        ) {
            return true;
        }
        if state.trade.primary_manufactured_request == Some(commodity) {
            return state.trade.primary_request_fulfilled == 0;
        }
        if state.trade.secondary_manufactured_request == Some(commodity) {
            return state.trade.secondary_request_fulfilled == 0;
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn set_deal_results(
        &mut self,
        buyer: NationId,
        seller: NationId,
        amount: i16,
        price: i16,
        commodity: TradeCommodity,
        shortfall: bool,
        phase: &mut TradePhase,
    ) {
        if shortfall && let Some(major) = MajorNationId::from_nation(buyer) {
            self.nations.majors[major]
                .economy
                .clear_trade_offer(commodity.resource());
        }
        if amount > 0 {
            self.purchase_for_nation(buyer, commodity.resource(), amount, price, phase);
            self.purchase_for_nation(seller, commodity.resource(), -amount, price, phase);
            if let Some(seller_major) = MajorNationId::from_nation(seller)
                && MajorNationId::from_nation(buyer).is_none()
            {
                self.nations.majors[seller_major]
                    .economy
                    .deliver_item(amount);
            }
            if self.diplomacy.mission_levels[buyer][seller] != DiplomaticMissionLevel::None {
                let standing = self.diplomacy.standings[buyer][seller];
                self.set_relationship(buyer, seller, standing + 1);
            }
            if let Some(seller_major) = MajorNationId::from_nation(seller) {
                self.add_to_deal_book(
                    seller_major,
                    DealBookEntryKind::Accept,
                    buyer,
                    amount,
                    commodity,
                    i32::from(price),
                );
            }
            if let Some(buyer_major) = MajorNationId::from_nation(buyer) {
                self.add_to_deal_book(
                    buyer_major,
                    DealBookEntryKind::Offer,
                    seller,
                    amount,
                    commodity,
                    i32::from(price),
                );
            }
        } else if let Some(buyer_major) = MajorNationId::from_nation(buyer) {
            self.add_to_deal_book(
                buyer_major,
                DealBookEntryKind::Offer,
                seller,
                amount,
                commodity,
                i32::from(price),
            );
        }
    }

    fn purchase_for_nation(
        &mut self,
        nation: NationId,
        resource: ResourceKind,
        amount: i16,
        price: i16,
        phase: &TradePhase,
    ) {
        if let Some(major) = MajorNationId::from_nation(nation) {
            if amount < 0
                && let Some(processed) = ProcessedTradeCommodity::from_resource(resource)
                && let Some(ai_trade) = self.nations.majors[major].economy.ai_trade.as_mut()
            {
                ai_trade.temporary_processed_stock[processed] += amount;
            }
            self.purchase_item(major, resource, amount, price);
            return;
        }

        let minor = MinorNationId::new(nation.get());
        self.purchase_minor_item(minor, resource, amount, price, phase);
    }

    fn purchase_minor_item(
        &mut self,
        minor: MinorNationId,
        resource: ResourceKind,
        amount: i16,
        price: i16,
        phase: &TradePhase,
    ) {
        let Some(state) = self.nations.minors[minor].as_mut() else {
            return;
        };
        if amount >= 1
            && let Some(commodity) = TradeCommodity::from_retail(resource as i16)
            && matches!(
                commodity,
                TradeCommodity::Clothing
                    | TradeCommodity::Furniture
                    | TradeCommodity::Hardware
                    | TradeCommodity::Arms
            )
        {
            if state.trade.primary_manufactured_request == Some(commodity) {
                state.trade.primary_request_fulfilled = amount;
            } else if state.trade.secondary_manufactured_request == Some(commodity) {
                state.trade.secondary_request_fulfilled = amount;
            }
            return;
        }

        if resource == ResourceKind::Food {
            state.trade.grant_deltas[ResourceKind::Food] += amount;
            return;
        }
        if !matches!(
            resource,
            ResourceKind::Cotton
                | ResourceKind::Wool
                | ResourceKind::Timber
                | ResourceKind::Coal
                | ResourceKind::Iron
                | ResourceKind::Horses
                | ResourceKind::Oil
        ) {
            return;
        }

        state.trade.grant_deltas[resource] += amount;
        if phase.recurring_grant[minor][resource] == 0 {
            return;
        }

        let need_current = state.trade.current_supply[resource];
        let mut grants = Vec::new();
        for slot in 0..MajorNationId::COUNT {
            let link = phase.status_by_major[minor][resource][usize::from(slot)];
            if link == 0 {
                continue;
            }
            let major = MajorNationId::new(slot);
            let standing = self.diplomacy.standings[minor.nation()][major.nation()];
            let neg_delta = -i32::from(amount);
            let int_factor = if i32::from(link) < neg_delta {
                i32::from(link)
            } else {
                neg_delta
            };
            let mut float_amount = f32::from(link) / f32::from(need_current);
            float_amount *= f32::from(standing);
            float_amount *= f32::from(price);
            float_amount *= f32::from(amount);
            float_amount *= GRANT_DELTA_SCALE;
            let integer_amount = (int_factor * i32::from(standing) * i32::from(price) / 255) as f32;
            let mut grant_amount = float_amount as i32;
            let integer_grant = integer_amount as i32;
            if integer_grant > grant_amount {
                grant_amount = integer_grant;
            }
            grants.push((major, grant_amount));
        }
        for (major, grant_amount) in grants {
            self.add_aid_allocation(major, minor, resource, grant_amount);
        }
    }

    fn add_to_deal_book(
        &mut self,
        owner: MajorNationId,
        kind: DealBookEntryKind,
        counterparty: NationId,
        amount: i16,
        commodity: TradeCommodity,
        price: i32,
    ) {
        let entry = TradeDealBookEntry {
            kind,
            nation: counterparty,
            amount,
            unit_price: price,
        };
        let rng = &mut self.rng;
        insert_sorted(
            &mut self.nations.majors[owner].economy.deal_book[commodity],
            entry,
            |a, b| compare_by_nation(a, b, rng),
        );
    }

    fn set_relationship(&mut self, source: NationId, target: NationId, standing: i16) {
        if standing == self.diplomacy.standings[source][target] {
            return;
        }
        let mut clamped = i32::from(standing);
        if standing < 0 {
            clamped = 0;
        }
        if standing > 0xff && source != target {
            clamped = 0xff;
        }
        if standing <= 0x31 {
            clamped = if self.nations_at_war(source, target) {
                i32::from(standing)
            } else {
                0x32
            };
            if (clamped as i16) < 0 {
                clamped = 0;
            }
        }
        let clamped = clamped as i16;
        self.diplomacy.standings[source][target] = clamped;
        self.diplomacy.standings[target][source] = clamped;
        if MajorNationId::from_nation(source).is_some() {
            self.match_colony_relationships(source);
        }
        if MajorNationId::from_nation(target).is_some() {
            self.match_colony_relationships(target);
        }
    }

    fn match_colony_relationships(&mut self, overlord: NationId) {
        for slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = MinorNationId::new(slot);
            let is_colony = self.nations.minors[minor]
                .as_ref()
                .is_some_and(|state| state.common.status() == CountryStatus::ColonyOf(overlord));
            if !is_colony {
                continue;
            }
            let colony = minor.nation();
            for other in NationId::all() {
                self.diplomacy.standings[colony][other] = self.diplomacy.standings[overlord][other];
                self.diplomacy.standings[other][colony] = self.diplomacy.standings[other][overlord];
            }
        }
    }

    fn end_trade_offers(&mut self) {
        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            self.clear_trade_offers(nation);
        }
        for commodity in all_trade_commodities() {
            for nation in NationId::all() {
                let accumulated = self.market.rows[commodity].accumulated_offer_by_nation[nation];
                let maximum = &mut self.market.rows[commodity].maximum_offer_by_nation[nation];
                if accumulated > *maximum {
                    *maximum = accumulated;
                }
            }
        }
    }

    fn clear_trade_offers(&mut self, nation: MajorNationId) {
        if !self.nations.majors[nation].economy.controller.is_human() {
            self.end_ai_trade_phase(nation);
            if let Some(ai_trade) = self.nations.majors[nation].economy.ai_trade.as_mut() {
                let pending = ai_trade.temporary_processed_stock;
                for processed in [
                    ProcessedTradeCommodity::Food,
                    ProcessedTradeCommodity::Fabric,
                    ProcessedTradeCommodity::Lumber,
                    ProcessedTradeCommodity::Paper,
                    ProcessedTradeCommodity::Steel,
                    ProcessedTradeCommodity::Fuel,
                ] {
                    let amount = pending[processed];
                    if amount > 0 {
                        let resource = match processed {
                            ProcessedTradeCommodity::Food => ResourceKind::Food,
                            ProcessedTradeCommodity::Fabric => ResourceKind::Fabric,
                            ProcessedTradeCommodity::Lumber => ResourceKind::Lumber,
                            ProcessedTradeCommodity::Paper => ResourceKind::Paper,
                            ProcessedTradeCommodity::Steel => ResourceKind::Steel,
                            ProcessedTradeCommodity::Fuel => ResourceKind::Fuel,
                        };
                        let current = self.nations.majors[nation].city.stockpile[resource];
                        let next = if current >= amount {
                            current - amount
                        } else {
                            0
                        };
                        self.nations
                            .city_mut(nation)
                            .adjust_stock(resource, next - current);
                    }
                }
                if let Some(ai_trade) = self.nations.majors[nation].economy.ai_trade.as_mut() {
                    ai_trade.temporary_processed_stock = ProcessedTradeCommodityTable::default();
                }
            }
        }
        self.nations.majors[nation].economy.item_potentials = ResourceTable::default();
    }

    fn end_ai_trade_phase(&mut self, nation: MajorNationId) {
        let trade = &mut self.nations.majors[nation].economy.foreign_trade;
        if let Some(bid) = trade.interior_bid.as_mut() {
            bid.amount = 0;
        }
        trade.capability_flag_14 = 0;
        trade.interior_bid = None;
        if self.nations.majors[nation]
            .economy
            .capacities
            .available_merchant
            == 0
        {
            self.nations.majors[nation]
                .economy
                .foreign_trade
                .phase_counter += 1;
        }
        self.nations.majors[nation]
            .economy
            .foreign_trade
            .purchase_priority = TradeCommodityTable::default();
    }

    fn set_ai_trade_bids(&mut self, nation: MajorNationId) {
        self.prepare_personality_trade_bids(nation);
        let personality = self.nations.majors[nation]
            .economy
            .foreign_minister_personality;
        if personality != ForeignMinisterPersonality::Base {
            let preferred = self.nations.majors[nation]
                .economy
                .foreign_trade
                .preferred_resources;
            for resource in preferred.into_iter().flatten() {
                self.nations.majors[nation]
                    .economy
                    .set_item_potential(resource.resource(), -1);
            }
        }
        match personality {
            ForeignMinisterPersonality::Ted => self.ted_set_trade_bids(nation),
            ForeignMinisterPersonality::Bill => self.bill_set_trade_bids(nation),
            ForeignMinisterPersonality::Diplomat => self.diplomat_set_trade_bids(nation),
            ForeignMinisterPersonality::Textile => self.textile_set_trade_bids(nation),
            ForeignMinisterPersonality::Trader => self.trader_set_trade_bids(nation),
            ForeignMinisterPersonality::Arms => self.arms_set_trade_bids(nation),
            ForeignMinisterPersonality::Base => {}
        }
    }

    fn prepare_personality_trade_bids(&mut self, nation: MajorNationId) {
        let treasury = self.nations.majors[nation].common.treasury;
        {
            let trade = &mut self.nations.majors[nation].economy.foreign_trade;
            trade.trade_partner_enabled = [1; 7];
            trade.capability_flag_16 = 0;
            if treasury < 0 {
                trade.capability_flag_14 = 1;
            }
        }
        let trade = &self.nations.majors[nation].economy.foreign_trade;
        if trade.phase_counter >= trade.refresh_interval || self.we_need_money(nation) {
            if self.nations.majors[nation].economy.pending_ship.is_none() {
                self.nations.majors[nation].economy.pending_ship = Some(
                    self.nations.majors[nation]
                        .economy
                        .foreign_trade
                        .requested_ship,
                );
            }
            self.nations.majors[nation]
                .economy
                .foreign_trade
                .phase_counter = 0;
        }
        self.set_buy_priorities(nation);
        if let Some(bid) = self.nations.majors[nation]
            .economy
            .foreign_trade
            .interior_bid
        {
            self.nations.majors[nation]
                .economy
                .set_item_potential(bid.commodity.resource(), -1);
            self.nations.majors[nation]
                .economy
                .foreign_trade
                .purchase_priority[bid.commodity] = bid.amount;
        }
    }

    fn we_need_money(&self, nation: MajorNationId) -> bool {
        let cap = self.nations.majors[nation].economy.capacities.trade_offer;
        let stock = |resource| self.nations.majors[nation].city.stockpile[resource];
        if stock(ResourceKind::Clothing) < cap
            && stock(ResourceKind::Furniture) < cap
            && stock(ResourceKind::Hardware) < cap
        {
            return false;
        }
        true
    }

    fn set_buy_priorities(&mut self, nation: MajorNationId) {
        match self.nations.majors[nation]
            .economy
            .foreign_minister_personality
        {
            ForeignMinisterPersonality::Ted => self.ted_set_buy_priorities(nation),
            ForeignMinisterPersonality::Bill => self.bill_set_buy_priorities(nation),
            ForeignMinisterPersonality::Diplomat => self.diplomat_set_buy_priorities(nation),
            ForeignMinisterPersonality::Textile => self.textile_set_buy_priorities(nation),
            ForeignMinisterPersonality::Trader => self.trader_set_buy_priorities(nation),
            ForeignMinisterPersonality::Arms => self.arms_set_buy_priorities(nation),
            ForeignMinisterPersonality::Base => self.base_set_buy_priorities(nation),
        }
    }

    fn base_set_buy_priorities(&mut self, nation: MajorNationId) {
        let mut priorities = Vec::new();
        for commodity in all_trade_commodities() {
            let priority = self.nations.majors[nation]
                .economy
                .foreign_trade
                .purchase_priority[commodity];
            if priority != 0 {
                insert_sorted(
                    &mut priorities,
                    (resource_code(Some(commodity)), priority + 1),
                    compare_index_and_rank,
                );
            }
        }
        let preferred = self.nations.majors[nation]
            .economy
            .foreign_trade
            .preferred_resources;
        for resource in preferred {
            let code = resource_code(resource);
            if !priorities.iter().any(|&(existing, _)| existing == code) {
                insert_sorted(&mut priorities, (code, 1), compare_index_and_rank);
            }
        }
        for index in 0..4 {
            let code = priorities
                .get(index)
                .map(|(code, _)| *code)
                .unwrap_or(NO_RESOURCE);
            self.nations.majors[nation]
                .economy
                .foreign_trade
                .preferred_resources[index] = TradeCommodity::from_retail(code);
        }
    }

    fn do_usual_subsidy_rule(&mut self, nation: MajorNationId) {
        let loop_count = i32::from(self.has_oil(nation)) + 5;
        for resource in [
            ResourceKind::Cotton,
            ResourceKind::Wool,
            ResourceKind::Timber,
            ResourceKind::Coal,
            ResourceKind::Iron,
            ResourceKind::Horses,
            ResourceKind::Oil,
        ]
        .into_iter()
        .take(loop_count as usize)
        {
            let roll = self.rng.next_crt_rand();
            let price = self.market.rows[trade_commodity(resource)].price;
            if roll % 100 + 200 < price {
                let stock = self.nations.majors[nation].city.stockpile[resource];
                if stock == 0 {
                    self.nations.majors[nation]
                        .economy
                        .set_item_potential(resource, 0);
                } else {
                    let mut amount = i32::from(stock) / 2;
                    if amount > 4 {
                        amount = 5;
                    }
                    self.nations.majors[nation]
                        .economy
                        .set_item_potential(resource, amount as i16);
                }
            }
        }

        let roll = self.rng.next_crt_rand();
        let price = self.market.rows[TradeCommodity::Horses].price;
        if roll % 100 + 200 < price {
            let stock = self.nations.majors[nation].city.stockpile[ResourceKind::Horses];
            if stock != 0 {
                let mut amount = i32::from(stock) / 2;
                if amount > 4 {
                    amount = 5;
                }
                self.nations.majors[nation]
                    .economy
                    .set_item_potential(ResourceKind::Horses, amount as i16);
            } else {
                self.nations.majors[nation]
                    .economy
                    .set_item_potential(ResourceKind::Horses, 0);
            }
        }
    }

    fn ted_set_buy_priorities(&mut self, nation: MajorNationId) {
        let stock = |resource| self.nations.majors[nation].city.stockpile[resource];
        if !self.has_oil(nation) {
            let iron_first = stock(ResourceKind::Iron) < stock(ResourceKind::Coal);
            let fourth = self.cotton_or_wool_roll();
            if iron_first {
                self.set_preferred(nation, [4, 2, 3, fourth]);
            } else {
                self.set_preferred(nation, [3, 2, 4, fourth]);
            }
            self.base_set_buy_priorities(nation);
            return;
        }
        let mut preferred = [0_i16; 4];
        if stock(ResourceKind::Iron) < stock(ResourceKind::Coal) {
            preferred[0] = 4;
            if stock(ResourceKind::Oil) < stock(ResourceKind::Coal) {
                preferred[1] = 6;
                preferred[2] = if stock(ResourceKind::Timber) < stock(ResourceKind::Coal) {
                    2
                } else {
                    3
                };
            } else {
                preferred[1] = 3;
                preferred[2] = if stock(ResourceKind::Oil) > stock(ResourceKind::Timber) {
                    2
                } else {
                    6
                };
            }
        } else {
            preferred[0] = 3;
            if stock(ResourceKind::Oil) < stock(ResourceKind::Iron) {
                preferred[1] = 6;
                preferred[2] = if stock(ResourceKind::Iron) > stock(ResourceKind::Timber) {
                    2
                } else {
                    4
                };
            } else {
                preferred[1] = 4;
                preferred[2] = if stock(ResourceKind::Oil) > stock(ResourceKind::Timber) {
                    2
                } else {
                    6
                };
            }
        }
        preferred[3] = self.cotton_or_wool_roll();
        self.set_preferred(nation, preferred);
        self.base_set_buy_priorities(nation);
    }

    fn ted_set_trade_bids(&mut self, nation: MajorNationId) {
        let cap = self.nations.majors[nation].economy.capacities.trade_offer;
        let hardware = self.nations.majors[nation].city.stockpile[ResourceKind::Hardware];
        if self.nations.majors[nation].common.treasury >= 0 && cap > hardware && hardware < 10 {
            self.offer_all_stock(nation, ResourceKind::Clothing);
            self.offer_all_stock(nation, ResourceKind::Furniture);
        } else {
            let amount = cap.min(hardware);
            self.nations.majors[nation]
                .economy
                .set_item_potential(ResourceKind::Hardware, amount);
            if cap > amount * 2 {
                self.offer_all_stock(nation, ResourceKind::Clothing);
                self.offer_all_stock(nation, ResourceKind::Furniture);
            }
        }
        self.ted_style_arms_bid(nation, 1500);
    }

    fn bill_set_buy_priorities(&mut self, nation: MajorNationId) {
        let stock = |resource| self.nations.majors[nation].city.stockpile[resource];
        if self.has_oil(nation) {
            if stock(ResourceKind::Iron) < stock(ResourceKind::Coal) {
                self.set_preferred(nation, [4, 2, 6, 3]);
            } else {
                self.set_preferred(nation, [3, 2, 6, 4]);
            }
        } else if stock(ResourceKind::Iron) < stock(ResourceKind::Coal) {
            self.set_preferred(nation, [4, 2, 3, NO_RESOURCE]);
        } else {
            self.set_preferred(nation, [3, 2, 4, NO_RESOURCE]);
        }
        self.base_set_buy_priorities(nation);
    }

    fn bill_set_trade_bids(&mut self, nation: MajorNationId) {
        self.sell_processed_round_robin(nation, true);
        self.ted_style_arms_bid(nation, 1500);
    }

    fn diplomat_set_buy_priorities(&mut self, nation: MajorNationId) {
        let iron = self.nations.majors[nation].city.stockpile[ResourceKind::Iron];
        let coal = self.nations.majors[nation].city.stockpile[ResourceKind::Coal];
        let oil = self.nations.majors[nation].city.stockpile[ResourceKind::Oil];
        let cotton = self.nations.majors[nation].city.stockpile[ResourceKind::Cotton];
        let wool = self.nations.majors[nation].city.stockpile[ResourceKind::Wool];
        if self.has_oil(nation) {
            let fourth = if self.rng.next_crt_rand() % 2 == 0 {
                1
            } else {
                0
            };
            if iron < coal {
                self.set_preferred(nation, [2, 4, if oil < coal { 6 } else { 3 }, fourth]);
            } else {
                self.set_preferred(nation, [2, 3, if oil < iron { 6 } else { 4 }, fourth]);
            }
            self.base_set_buy_priorities(nation);
            return;
        }

        let has_trade_candidate = (MinorNationId::FIRST..NationId::COUNT).any(|slot| {
            let nation_id = NationId::new(slot);
            self.nation_present(nation_id)
                && (self.market.rows[TradeCommodity::Coal].maximum_offer_by_nation[nation_id] != 0
                    || self.market.rows[TradeCommodity::Iron].maximum_offer_by_nation[nation_id]
                        != 0)
        });
        if !has_trade_candidate {
            let fourth = if self.rng.next_crt_rand() < 0x3ffe {
                3
            } else {
                4
            };
            self.set_preferred(nation, [2, 0, 1, fourth]);
        } else if (self.turn.economic_turn / 4) & 1 != 0 {
            let (second, third) = if iron < coal { (4, 3) } else { (3, 4) };
            let fourth = if self.market.rows[TradeCommodity::Cotton].price
                > self.market.rows[TradeCommodity::Wool].price
            {
                0
            } else {
                1
            };
            self.set_preferred(nation, [2, second, third, fourth]);
        } else {
            let (second, third) = if cotton < wool { (0, 1) } else { (1, 0) };
            let fourth = if iron < coal { 4 } else { 3 };
            self.set_preferred(nation, [2, second, third, fourth]);
        }
        self.base_set_buy_priorities(nation);
    }

    fn diplomat_set_trade_bids(&mut self, nation: MajorNationId) {
        self.sell_processed_round_robin(nation, true);
        if self.market.rows[TradeCommodity::Arms].price > 1200
            && self.nations.majors[nation].city.stockpile[ResourceKind::Arms] > 6
            && !self.has_any_war(nation.nation())
        {
            self.nations.majors[nation]
                .economy
                .set_item_potential(ResourceKind::Arms, 2);
        }
    }

    fn textile_set_buy_priorities(&mut self, nation: MajorNationId) {
        let mut prices = Vec::new();
        for resource in [ResourceKind::Coal, ResourceKind::Iron, ResourceKind::Timber] {
            insert_sorted(
                &mut prices,
                (
                    resource as i16,
                    self.nations.majors[nation].city.stockpile[resource],
                ),
                compare_by_price,
            );
        }
        if self.has_oil(nation) {
            insert_sorted(
                &mut prices,
                (
                    ResourceKind::Oil as i16,
                    self.nations.majors[nation].city.stockpile[ResourceKind::Oil],
                ),
                compare_by_price,
            );
        }
        let third = prices.first().map(|(code, _)| *code).unwrap_or(NO_RESOURCE);
        let fourth = prices.get(1).map(|(code, _)| *code).unwrap_or(NO_RESOURCE);
        self.set_preferred(nation, [0, 1, third, fourth]);
        self.base_set_buy_priorities(nation);
    }

    fn textile_set_trade_bids(&mut self, nation: MajorNationId) {
        let cap = self.nations.majors[nation].economy.capacities.trade_offer;
        let clothing = self.nations.majors[nation].city.stockpile[ResourceKind::Clothing];
        if self.nations.majors[nation].common.treasury < 0
            || clothing >= cap
            || (clothing > 4 && self.market.rows[TradeCommodity::Clothing].price > 1000)
        {
            self.nations.majors[nation]
                .economy
                .set_item_potential(ResourceKind::Clothing, clothing.min(cap));
        }
        if self.nations.majors[nation].common.treasury < 0
            || self.nations.majors[nation].economy.item_potentials[ResourceKind::Clothing] == 0
        {
            let budget = cap / 2;
            let (first, second) = if self.market.rows[TradeCommodity::Hardware].price
                > self.market.rows[TradeCommodity::Furniture].price
            {
                (ResourceKind::Hardware, ResourceKind::Furniture)
            } else {
                (ResourceKind::Furniture, ResourceKind::Hardware)
            };
            let first_stock = self.nations.majors[nation].city.stockpile[first];
            let first_amount = first_stock.min(budget);
            self.nations.majors[nation]
                .economy
                .set_item_potential(first, first_amount);
            let remaining = budget - first_amount;
            let second_stock = self.nations.majors[nation].city.stockpile[second];
            self.nations.majors[nation]
                .economy
                .set_item_potential(second, second_stock.min(remaining));
        }
        self.ted_style_arms_bid(nation, 1500);
    }

    fn trader_set_buy_priorities(&mut self, nation: MajorNationId) {
        let mut prices = Vec::new();
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
            insert_sorted(
                &mut prices,
                (resource_code(Some(commodity)), priority),
                compare_by_price,
            );
        }
        if self.has_oil(nation) {
            insert_sorted(
                &mut prices,
                (
                    ResourceKind::Oil as i16,
                    self.market.rows[TradeCommodity::Oil].price as i16 - 15,
                ),
                compare_by_price,
            );
        }
        let mut preferred = [NO_RESOURCE; 4];
        for (index, &(code, _)) in prices.iter().take(4).enumerate() {
            preferred[index] = code;
        }
        self.set_preferred(nation, preferred);
        self.base_set_buy_priorities(nation);
    }

    fn trader_set_trade_bids(&mut self, nation: MajorNationId) {
        let mut prices = self.sorted_processed_prices();
        let divisor = if self.nations.majors[nation].common.treasury < 0 {
            1
        } else {
            4
        };
        let budget = self.nations.majors[nation].economy.capacities.trade_offer / divisor;
        let mut selected = 3_i16;
        let mut allocated = 0_i16;
        while budget > allocated && selected >= 1 {
            let resource = prices[(selected as usize) - 1];
            let stock = self.nations.majors[nation].city.stockpile[resource];
            self.nations.majors[nation]
                .economy
                .set_item_potential(resource, stock);
            allocated += stock;
            selected -= 1;
        }
        let _ = &mut prices;
        if self.market.rows[TradeCommodity::Arms].price > 1200
            && self.nations.majors[nation].city.stockpile[ResourceKind::Arms] > 6
            && !self.has_any_war(nation.nation())
        {
            self.nations.majors[nation]
                .economy
                .set_item_potential(ResourceKind::Arms, 2);
        }
    }

    fn arms_set_buy_priorities(&mut self, nation: MajorNationId) {
        if self.has_oil(nation) {
            self.set_preferred(nation, [6, 2, 3, 4]);
        } else {
            let fourth = if self.rng.next_crt_rand() % 2 != 0 {
                0
            } else {
                1
            };
            self.set_preferred(nation, [2, 3, 4, fourth]);
        }
        self.base_set_buy_priorities(nation);
    }

    fn arms_set_trade_bids(&mut self, nation: MajorNationId) {
        let mut prices = self.sorted_processed_prices();
        let budget = self.nations.majors[nation].economy.capacities.trade_offer / 2;
        let mut selected = 3_i16;
        let mut allocated = 0_i16;
        while allocated < budget && selected >= 1 {
            let resource = prices[(selected as usize) - 1];
            let stock = self.nations.majors[nation].city.stockpile[resource];
            let amount = stock.min(budget - allocated);
            self.nations.majors[nation]
                .economy
                .set_item_potential(resource, amount);
            allocated += amount;
            selected -= 1;
        }
        let _ = &mut prices;
        if self.nations.majors[nation].common.treasury < 0 && !self.has_any_war(nation.nation()) {
            let available = self.nations.majors[nation].city.stockpile[ResourceKind::Arms];
            let mut amount = available / 10;
            if amount > 10 {
                amount = 10;
            }
            if amount > 2 {
                self.nations.majors[nation]
                    .economy
                    .set_item_potential(ResourceKind::Arms, amount);
            } else if available > 6 {
                self.nations.majors[nation]
                    .economy
                    .set_item_potential(ResourceKind::Arms, 2);
            }
        }
    }

    fn ai_reply_to_trade_offer(
        &mut self,
        buyer: MajorNationId,
        seller: NationId,
        amount: i16,
        price: i16,
        commodity: TradeCommodity,
        phase: &mut TradePhase,
    ) {
        let resource = commodity.resource();
        if self.nations.majors[buyer]
            .economy
            .foreign_trade
            .purchase_priority[commodity]
            != 0
        {
            self.base_reply_to_trade_offer(buyer, seller, amount, price, commodity, phase);
            return;
        }
        match self.nations.majors[buyer]
            .economy
            .foreign_minister_personality
        {
            ForeignMinisterPersonality::Ted => {
                self.ted_reply(buyer, seller, amount, price, commodity, phase);
            }
            ForeignMinisterPersonality::Bill => {
                self.bill_reply(buyer, seller, amount, price, commodity, phase);
            }
            ForeignMinisterPersonality::Diplomat => {
                let mut take = if self.nations.majors[buyer].economy.capacities.trade_offer < 12 {
                    1
                } else if self.nations.majors[buyer].economy.capacities.trade_offer >= 25 {
                    3
                } else {
                    2
                };
                take = take.min(self.merchant_capacity_for_proposal(buyer, resource));
                take = take.min(amount);
                self.set_deal_results(buyer.nation(), seller, take, price, commodity, false, phase);
            }
            ForeignMinisterPersonality::Textile => {
                let available = self.merchant_capacity_for_proposal(buyer, resource);
                let take = if available >= amount {
                    amount
                } else {
                    available
                };
                self.set_deal_results(buyer.nation(), seller, take, price, commodity, false, phase);
            }
            ForeignMinisterPersonality::Trader => {
                let available = self.merchant_capacity_for_proposal(buyer, resource);
                if available >= amount {
                    self.set_deal_results(
                        buyer.nation(),
                        seller,
                        amount,
                        price,
                        commodity,
                        false,
                        phase,
                    );
                } else {
                    self.set_deal_results(
                        buyer.nation(),
                        seller,
                        available,
                        price,
                        commodity,
                        true,
                        phase,
                    );
                }
            }
            ForeignMinisterPersonality::Arms => {
                self.arms_reply(buyer, seller, amount, price, commodity, phase);
            }
            ForeignMinisterPersonality::Base => {
                self.base_reply_to_trade_offer(buyer, seller, amount, price, commodity, phase);
            }
        }
    }

    fn base_reply_to_trade_offer(
        &mut self,
        buyer: MajorNationId,
        seller: NationId,
        amount: i16,
        price: i16,
        commodity: TradeCommodity,
        phase: &mut TradePhase,
    ) {
        let resource = commodity.resource();
        let mut dispatch = amount;
        if self.nations.majors[buyer]
            .economy
            .foreign_trade
            .interior_bid
            .is_some_and(|bid| bid.commodity == commodity)
        {
            let interior_amount = self.nations.majors[buyer]
                .economy
                .foreign_trade
                .interior_bid
                .expect("interior bid")
                .amount;
            if interior_amount < dispatch {
                dispatch = interior_amount;
            }
            let available = self.merchant_capacity_for_proposal(buyer, resource);
            if available < dispatch {
                self.set_deal_results(
                    buyer.nation(),
                    seller,
                    available,
                    price,
                    commodity,
                    false,
                    phase,
                );
                return;
            }
        } else {
            let ledger = self.nations.majors[buyer]
                .economy
                .foreign_trade
                .purchase_priority[commodity];
            if ledger < 1 {
                dispatch = 0;
            } else if ledger < dispatch {
                dispatch = ledger;
            }
            let available = self.merchant_capacity_for_proposal(buyer, resource);
            if available < dispatch {
                dispatch = available;
            }
            self.nations.majors[buyer]
                .economy
                .foreign_trade
                .purchase_priority[commodity] -= dispatch;
        }
        self.set_deal_results(
            buyer.nation(),
            seller,
            dispatch,
            price,
            commodity,
            false,
            phase,
        );
    }

    fn ted_reply(
        &mut self,
        buyer: MajorNationId,
        seller: NationId,
        amount: i16,
        price: i16,
        commodity: TradeCommodity,
        phase: &mut TradePhase,
    ) {
        match commodity {
            TradeCommodity::Coal => {
                if self.nations.majors[buyer]
                    .economy
                    .foreign_trade
                    .trade_partner_enabled[3]
                    != 0
                {
                    self.nations.majors[buyer]
                        .economy
                        .foreign_trade
                        .capability_flag_16 =
                        self.merchant_capacity_for_proposal(buyer, ResourceKind::Coal) / 2;
                    self.nations.majors[buyer]
                        .economy
                        .foreign_trade
                        .trade_partner_enabled[3] = 0;
                }
                let available = self.nations.majors[buyer]
                    .economy
                    .foreign_trade
                    .capability_flag_16;
                if available >= amount {
                    self.set_deal_results(
                        buyer.nation(),
                        seller,
                        amount,
                        price,
                        commodity,
                        false,
                        phase,
                    );
                    self.nations.majors[buyer]
                        .economy
                        .foreign_trade
                        .capability_flag_16 -= amount;
                } else {
                    self.set_deal_results(
                        buyer.nation(),
                        seller,
                        available,
                        price,
                        commodity,
                        true,
                        phase,
                    );
                    self.nations.majors[buyer]
                        .economy
                        .foreign_trade
                        .capability_flag_16 = 0;
                }
            }
            TradeCommodity::Timber | TradeCommodity::Iron | TradeCommodity::Oil => {
                let available = self.merchant_capacity_for_proposal(buyer, commodity.resource());
                let take = if available >= amount {
                    amount
                } else {
                    available
                };
                self.set_deal_results(buyer.nation(), seller, take, price, commodity, false, phase);
            }
            TradeCommodity::Cotton | TradeCommodity::Wool => {
                let cap = self.nations.majors[buyer].economy.capacities.trade_offer;
                let mut take = if cap < 15 {
                    1
                } else if cap >= 30 {
                    3
                } else {
                    2
                };
                take = take.min(amount);
                let available = self.merchant_capacity_for_proposal(buyer, commodity.resource());
                if available < take {
                    take = available;
                }
                self.set_deal_results(buyer.nation(), seller, take, price, commodity, false, phase);
            }
            _ => {}
        }
    }

    fn bill_reply(
        &mut self,
        buyer: MajorNationId,
        seller: NationId,
        amount: i16,
        price: i16,
        commodity: TradeCommodity,
        phase: &mut TradePhase,
    ) {
        match commodity {
            TradeCommodity::Timber => {
                if self.market.rows[TradeCommodity::Coal].price >= 105
                    && self.market.rows[TradeCommodity::Iron].price >= 105
                {
                    if self.nations.majors[buyer]
                        .economy
                        .foreign_trade
                        .trade_partner_enabled[2]
                        != 0
                    {
                        let mut split = self.nations.majors[buyer]
                            .economy
                            .capacities
                            .available_merchant
                            / 3;
                        if split < 2 {
                            split = 2;
                        }
                        self.nations.majors[buyer]
                            .economy
                            .foreign_trade
                            .capability_flag_16 = split;
                        self.nations.majors[buyer]
                            .economy
                            .foreign_trade
                            .trade_partner_enabled[2] = 0;
                    }
                    let available = self.nations.majors[buyer]
                        .economy
                        .capacities
                        .available_merchant;
                    let take = self.nations.majors[buyer]
                        .economy
                        .foreign_trade
                        .capability_flag_16
                        .min(available);
                    if take >= amount {
                        self.set_deal_results(
                            buyer.nation(),
                            seller,
                            amount,
                            price,
                            commodity,
                            false,
                            phase,
                        );
                        self.nations.majors[buyer]
                            .economy
                            .foreign_trade
                            .capability_flag_16 -= amount;
                        if self.nations.majors[buyer]
                            .economy
                            .foreign_trade
                            .capability_flag_16
                            < 0
                        {
                            self.nations.majors[buyer]
                                .economy
                                .foreign_trade
                                .capability_flag_16 = 0;
                        }
                    } else {
                        self.set_deal_results(
                            buyer.nation(),
                            seller,
                            take,
                            price,
                            commodity,
                            true,
                            phase,
                        );
                        self.nations.majors[buyer]
                            .economy
                            .foreign_trade
                            .capability_flag_16 = 0;
                    }
                } else {
                    let available = self.nations.majors[buyer]
                        .economy
                        .capacities
                        .available_merchant;
                    let take = if available >= amount {
                        amount
                    } else {
                        available
                    };
                    self.set_deal_results(
                        buyer.nation(),
                        seller,
                        take,
                        price,
                        commodity,
                        false,
                        phase,
                    );
                }
            }
            TradeCommodity::Coal => {
                if self.nations.majors[buyer]
                    .economy
                    .foreign_trade
                    .trade_partner_enabled[3]
                    != 0
                {
                    self.nations.majors[buyer]
                        .economy
                        .foreign_trade
                        .capability_flag_16 = self.nations.majors[buyer]
                        .economy
                        .capacities
                        .available_merchant
                        / 2;
                    self.nations.majors[buyer]
                        .economy
                        .foreign_trade
                        .trade_partner_enabled[3] = 0;
                }
                let mut take = if self.market.rows[TradeCommodity::Iron].price < 105 {
                    amount
                } else {
                    self.nations.majors[buyer]
                        .economy
                        .foreign_trade
                        .capability_flag_16
                };
                take = take.min(amount);
                let available = self.nations.majors[buyer]
                    .economy
                    .capacities
                    .available_merchant;
                if available >= take {
                    self.set_deal_results(
                        buyer.nation(),
                        seller,
                        take,
                        price,
                        commodity,
                        false,
                        phase,
                    );
                    self.nations.majors[buyer]
                        .economy
                        .foreign_trade
                        .capability_flag_16 -= take;
                } else {
                    self.set_deal_results(
                        buyer.nation(),
                        seller,
                        available,
                        price,
                        commodity,
                        false,
                        phase,
                    );
                    self.nations.majors[buyer]
                        .economy
                        .foreign_trade
                        .capability_flag_16 = 0;
                }
            }
            TradeCommodity::Iron | TradeCommodity::Oil => {
                let available = self.nations.majors[buyer]
                    .economy
                    .capacities
                    .available_merchant;
                if available >= amount {
                    self.set_deal_results(
                        buyer.nation(),
                        seller,
                        amount,
                        price,
                        commodity,
                        false,
                        phase,
                    );
                    if commodity == TradeCommodity::Iron {
                        self.nations.majors[buyer]
                            .economy
                            .foreign_trade
                            .capability_flag_16 -= amount;
                    }
                } else {
                    self.set_deal_results(
                        buyer.nation(),
                        seller,
                        available,
                        price,
                        commodity,
                        commodity == TradeCommodity::Iron,
                        phase,
                    );
                    if commodity == TradeCommodity::Iron {
                        self.nations.majors[buyer]
                            .economy
                            .foreign_trade
                            .capability_flag_16 = 0;
                    }
                }
            }
            _ => {}
        }
    }

    fn arms_reply(
        &mut self,
        buyer: MajorNationId,
        seller: NationId,
        amount: i16,
        price: i16,
        commodity: TradeCommodity,
        phase: &mut TradePhase,
    ) {
        let resource = commodity.resource() as usize;
        let cap = self.nations.majors[buyer]
            .economy
            .capacities
            .available_merchant;
        if self.has_oil(buyer) {
            if !matches!(
                commodity,
                TradeCommodity::Timber | TradeCommodity::Coal | TradeCommodity::Iron
            ) {
                self.nations.majors[buyer]
                    .economy
                    .foreign_trade
                    .capability_flag_16 = cap;
            } else if resource < 7
                && self.nations.majors[buyer]
                    .economy
                    .foreign_trade
                    .trade_partner_enabled[resource]
                    != 0
            {
                self.nations.majors[buyer]
                    .economy
                    .foreign_trade
                    .capability_flag_16 = if phase.arms_advanced_split == 0 {
                    cap / 3
                } else {
                    cap / 2
                };
                phase.arms_advanced_split += 1;
            }
        } else if !matches!(
            commodity,
            TradeCommodity::Cotton
                | TradeCommodity::Wool
                | TradeCommodity::Timber
                | TradeCommodity::Coal
        ) {
            self.nations.majors[buyer]
                .economy
                .foreign_trade
                .capability_flag_16 = cap;
        } else if resource < 7
            && self.nations.majors[buyer]
                .economy
                .foreign_trade
                .trade_partner_enabled[resource]
                != 0
        {
            if phase.arms_basic_split == 0 {
                self.nations.majors[buyer]
                    .economy
                    .foreign_trade
                    .capability_flag_16 = cap / 3;
            } else {
                self.nations.majors[buyer]
                    .economy
                    .foreign_trade
                    .capability_flag_16 = cap / 2;
            }
            phase.arms_basic_split += 1;
        }
        if resource < 7 {
            self.nations.majors[buyer]
                .economy
                .foreign_trade
                .trade_partner_enabled[resource] = 0;
        }
        let available = self.nations.majors[buyer]
            .economy
            .foreign_trade
            .capability_flag_16;
        if available >= amount {
            self.set_deal_results(
                buyer.nation(),
                seller,
                amount,
                price,
                commodity,
                false,
                phase,
            );
            self.nations.majors[buyer]
                .economy
                .foreign_trade
                .capability_flag_16 -= amount;
        } else {
            self.set_deal_results(
                buyer.nation(),
                seller,
                available,
                price,
                commodity,
                true,
                phase,
            );
            self.nations.majors[buyer]
                .economy
                .foreign_trade
                .capability_flag_16 = 0;
        }
    }

    fn merchant_capacity_for_proposal(&self, nation: MajorNationId, resource: ResourceKind) -> i16 {
        let available = self.nations.majors[nation]
            .economy
            .capacities
            .available_merchant;
        let priority = |commodity| {
            self.nations.majors[nation]
                .economy
                .foreign_trade
                .purchase_priority[commodity]
        };
        let offered = |commodity| self.market.rows[commodity].amount_offered;
        let proposal = resource as i16;
        if priority(TradeCommodity::Iron) != 0 && offered(TradeCommodity::Iron) != 0 {
            if proposal == 4 {
                return available;
            }
            if trades_first(proposal, 4) == proposal {
                return (i32::from(available) - 2).max(0) as i16;
            }
            return available;
        }
        if priority(TradeCommodity::Horses) != 0 && offered(TradeCommodity::Horses) != 0 {
            if proposal == 5 {
                return available;
            }
            if trades_first(proposal, 5) == proposal {
                return (i32::from(available) - 2).max(0) as i16;
            }
            return available;
        }
        if priority(TradeCommodity::Coal) != 0 && offered(TradeCommodity::Coal) != 0 {
            if proposal != 3 {
                if trades_first(proposal, 3) == proposal {
                    return (i32::from(available) - 2).max(0) as i16;
                }
                return available;
            }
            if priority(TradeCommodity::Iron) != 0 {
                return (i32::from(available) - 1).max(0) as i16;
            }
        }
        available
    }

    fn sell_processed_round_robin(&mut self, nation: MajorNationId, half_capacity: bool) {
        let cap = self.nations.majors[nation].economy.capacities.trade_offer;
        let target = if self.nations.majors[nation].common.treasury < 0 || !half_capacity {
            cap
        } else {
            cap / 2
        };
        let prices = self.sorted_processed_prices();
        let mut amounts = [0_i16; 17];
        let mut selected = 3_i16;
        let mut iteration = 0_i32;
        while target > 0 && iteration < i32::from(target) * 3 {
            let resource = prices[(selected as usize) - 1];
            let index = resource as usize;
            if amounts[index] < self.nations.majors[nation].city.stockpile[resource] {
                amounts[index] += 1;
                self.nations.majors[nation]
                    .economy
                    .set_item_potential(resource, amounts[index]);
            }
            if amounts[0x0d] + amounts[0x0e] + amounts[0x0f] >= target {
                break;
            }
            selected -= 1;
            if selected == 0 {
                selected = 3;
            }
            iteration += 1;
        }
    }

    fn sorted_processed_prices(&self) -> [ResourceKind; 3] {
        let mut prices = Vec::new();
        for resource in [
            ResourceKind::Clothing,
            ResourceKind::Furniture,
            ResourceKind::Hardware,
        ] {
            insert_sorted(
                &mut prices,
                (
                    resource,
                    self.market.rows[trade_commodity(resource)].price as i16,
                ),
                |a, b| compare_by_price(&(a.0 as i16, a.1), &(b.0 as i16, b.1)),
            );
        }
        [prices[0].0, prices[1].0, prices[2].0]
    }

    fn ted_style_arms_bid(&mut self, nation: MajorNationId, threshold: i32) {
        if self.market.rows[TradeCommodity::Arms].price > threshold
            && !self.has_any_war(nation.nation())
        {
            let available = self.nations.majors[nation].city.stockpile[ResourceKind::Arms];
            let amount = available / 10;
            if amount > 2 {
                self.nations.majors[nation]
                    .economy
                    .set_item_potential(ResourceKind::Arms, amount);
            } else if available > 6 {
                self.nations.majors[nation]
                    .economy
                    .set_item_potential(ResourceKind::Arms, 2);
            }
        }
    }

    fn offer_all_stock(&mut self, nation: MajorNationId, resource: ResourceKind) {
        let stock = self.nations.majors[nation].city.stockpile[resource];
        self.nations.majors[nation]
            .economy
            .set_item_potential(resource, stock);
    }

    fn cotton_or_wool_roll(&mut self) -> i16 {
        if self.rng.next_crt_rand() < 0x3ffe {
            0
        } else {
            1
        }
    }

    fn set_preferred(&mut self, nation: MajorNationId, codes: [i16; 4]) {
        self.nations.majors[nation]
            .economy
            .foreign_trade
            .preferred_resources = codes.map(TradeCommodity::from_retail);
    }

    fn build_independent_major_relationship_list(
        &mut self,
        source: MajorNationId,
    ) -> Vec<MajorNationId> {
        let mut list = Vec::new();
        for slot in 0..MajorNationId::COUNT {
            let candidate = MajorNationId::new(slot);
            if !self.nation_present(candidate.nation()) || candidate == source {
                continue;
            }
            if self.nations.majors[candidate].common.status() != CountryStatus::Independent {
                continue;
            }
            let standing = self.diplomacy.standings[source.nation()][candidate.nation()];
            let rng = &mut self.rng;
            insert_sorted(&mut list, (candidate, standing), |a, b| {
                compare_relationship(a.1, b.1, rng)
            });
        }
        list.into_iter().map(|(nation, _)| nation).collect()
    }

    fn major_is_trade_eligible(&self, nation: MajorNationId) -> bool {
        !matches!(
            self.nations.majors[nation].common.status(),
            CountryStatus::ColonyOf(_)
        )
    }

    fn nation_present(&self, nation: NationId) -> bool {
        self.nations.common(nation).is_some()
    }

    fn nation_status(&self, nation: NationId) -> CountryStatus {
        self.nations
            .common(nation)
            .map(NationCommonState::status)
            .unwrap_or(CountryStatus::Independent)
    }

    fn nations_at_war(&self, source: NationId, target: NationId) -> bool {
        self.nation_present(source)
            && self.nation_present(target)
            && self.diplomacy.relationships[source][target] == DiplomaticRelationship::War
    }

    fn has_boycott(&self, source: NationId, target: NationId) -> bool {
        let source_policy = self
            .nations
            .common(source)
            .map(|common| common.trade_policy_by_nation[target])
            .unwrap_or_default();
        let target_policy = self
            .nations
            .common(target)
            .map(|common| common.trade_policy_by_nation[source])
            .unwrap_or_default();
        source_policy == TradePolicyScore::BOYCOTT || target_policy == TradePolicyScore::BOYCOTT
    }

    fn has_any_war(&self, nation: NationId) -> bool {
        NationId::all().any(|target| self.nations_at_war(nation, target))
    }

    fn has_oil(&self, nation: MajorNationId) -> bool {
        self.technology.city_capabilities_by_nation[nation].oil_drilling
    }
}

fn offer_or_grant(
    state: &mut MinorNation,
    recurring: &ResourceTable<i16>,
    resource: ResourceKind,
    threshold: i16,
    price: i32,
) {
    if i32::from(threshold) < price {
        state.trade.offers[resource] = state.trade.current_supply[resource];
    } else if recurring[resource] != 0 {
        state.trade.offers[resource] = recurring[resource];
    }
}

fn trade_commodity(resource: ResourceKind) -> TradeCommodity {
    TradeCommodity::from_retail(resource as i16).expect("market commodity")
}

fn resource_code(commodity: Option<TradeCommodity>) -> i16 {
    commodity.map_or(NO_RESOURCE, |commodity| commodity as i16)
}

fn preferred_nation(status: CountryStatus, own: NationId) -> NationId {
    match status {
        CountryStatus::ColonyOf(nation) | CountryStatus::ProtectorateOf(nation) => nation,
        CountryStatus::Independent => own,
    }
}

fn major_offer_base(turn: i32) -> f64 {
    let bucket = (turn + (turn >> 31 & 3)) >> 2;
    if bucket < 0x0b {
        1.1
    } else if bucket < 0x15 {
        1.08
    } else if bucket < 0x1f {
        1.06
    } else if bucket < 0x29 {
        1.04
    } else if bucket < 0x33 {
        1.03
    } else if bucket < 0x3d {
        1.02
    } else {
        1.01
    }
}

fn minor_offer_base(turn: i32) -> f64 {
    let band = (turn + (turn >> 31 & 3)) >> 2;
    if band < 0x0b {
        1.1
    } else if band < 0x15 {
        1.09
    } else if band < 0x1f {
        1.08
    } else if band < 0x29 {
        1.07
    } else if band < 0x33 {
        1.06
    } else if band < 0x3d {
        1.05
    } else if band < 0x47 {
        1.04
    } else if band < 0x51 {
        1.03
    } else if band < 0x5b {
        1.02
    } else {
        1.01
    }
}

fn trade_power(base: f64, exponent: i16) -> f64 {
    let mut result = 1.0;
    for _ in 0..exponent.max(0) {
        result *= base;
    }
    result
}

fn trades_first(proposal: i16, category: i16) -> i16 {
    for &slot in &DEAL_CATEGORY_ORDER {
        let slot = i16::from(slot);
        if slot == proposal {
            return proposal;
        }
        if slot == category {
            return category;
        }
    }
    proposal
}

fn insert_sorted<T>(list: &mut Vec<T>, item: T, mut cmp: impl FnMut(&T, &T) -> i16) {
    if let Some(index) = list.iter().position(|existing| cmp(&item, existing) != 1) {
        list.insert(index, item);
    } else {
        list.push(item);
    }
}

fn compare_deals(a: &RankedDeal, b: &RankedDeal) -> i16 {
    let invert = matches!(
        a.category,
        TradeCommodity::Clothing
            | TradeCommodity::Furniture
            | TradeCommodity::Hardware
            | TradeCommodity::Arms
    );
    let mut score_a = if invert {
        (0xff - i32::from(a.standing)) * a.price
    } else {
        -(a.price * i32::from(a.standing))
    };
    let mut score_b = if invert {
        (0xff - i32::from(b.standing)) * b.price
    } else {
        -(b.price * i32::from(b.standing))
    };
    if score_a == score_b {
        score_a = (i32::from(a.offer_amount) * i32::from(a.buyer.get())
            + a.price
            + i32::from(a.seller.get()) * i32::from(a.standing)
            + i32::from(a.category as u8))
            % 7;
        score_b = (i32::from(b.category as u8)
            + i32::from(b.offer_amount) * i32::from(b.buyer.get())
            + b.price
            + i32::from(b.seller.get()) * i32::from(b.standing))
            % 7;
    }
    if score_a <= score_b { -1 } else { 1 }
}

fn compare_by_nation(a: &TradeDealBookEntry, b: &TradeDealBookEntry, rng: &mut RngState) -> i16 {
    compare_relationship(i16::from(a.nation.get()), i16::from(b.nation.get()), rng)
}

fn compare_relationship(a_key: i16, b_key: i16, rng: &mut RngState) -> i16 {
    if b_key < a_key {
        1
    } else if a_key < b_key {
        -1
    } else if rng.next_crt_rand() % 2 != 0 {
        1
    } else {
        -1
    }
}

fn compare_index_and_rank(a: &(i16, i16), b: &(i16, i16)) -> i16 {
    if a.1 <= b.1 { 1 } else { -1 }
}

fn compare_by_price(a: &(i16, i16), b: &(i16, i16)) -> i16 {
    if a.1 <= b.1 { -1 } else { 1 }
}
