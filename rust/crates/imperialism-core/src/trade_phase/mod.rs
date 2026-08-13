//! Retail `TSimMgr::DoTrade` as one domain operation.

mod ai_bids;
mod ai_replies;
mod bids;
mod deals;
mod prepare;

use crate::market::all_trade_commodities;
use crate::*;

pub(super) const DEAL_CATEGORY_ORDER: [u8; TradeCommodity::LENGTH] =
    [13, 14, 15, 16, 7, 8, 9, 10, 11, 12, 0, 1, 2, 3, 4, 5, 6];
pub(super) const NO_RESOURCE: i16 = -10;
pub(super) const GRANT_DELTA_SCALE: f32 = -1.0 / 255.0;
pub(super) const RELATION_SCALE: f64 = 1.0 / 255.0;
pub(super) const RELATION_RAND_SCALE: f64 = 32767.0;

pub(super) const RAW_COMMODITIES: [TradeCommodity; 7] = [
    TradeCommodity::Cotton,
    TradeCommodity::Wool,
    TradeCommodity::Timber,
    TradeCommodity::Coal,
    TradeCommodity::Iron,
    TradeCommodity::Horses,
    TradeCommodity::Oil,
];
pub(super) const MANUFACTURED_COMMODITIES: [TradeCommodity; 4] = [
    TradeCommodity::Clothing,
    TradeCommodity::Furniture,
    TradeCommodity::Hardware,
    TradeCommodity::Arms,
];
pub(super) const PROCESSED_NEED: [ResourceKind; 5] = [
    ResourceKind::Food,
    ResourceKind::Fabric,
    ResourceKind::Lumber,
    ResourceKind::Paper,
    ResourceKind::Steel,
];

pub(super) struct RankedDeal {
    pub(super) buyer: NationId,
    pub(super) seller: NationId,
    pub(super) offer_amount: i16,
    pub(super) standing: i16,
    pub(super) price: i32,
    pub(super) category: TradeCommodity,
}

pub(super) struct TradePhase {
    pub(super) recurring_grant: MinorNationTable<ResourceTable<i16>>,
    pub(super) status_by_major: MinorNationTable<ResourceTable<[i16; MAJOR_NATION_COUNT]>>,
    pub(super) deals: TradeCommodityTable<Vec<RankedDeal>>,
    pub(super) arms_basic_split: i16,
    pub(super) arms_advanced_split: i16,
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

    fn is_human(&self, nation: MajorNationId) -> bool {
        self.nations.majors[nation].economy.controller.is_human()
    }

    fn city_stock(&self, nation: MajorNationId, resource: ResourceKind) -> i16 {
        self.nations.majors[nation].city.stockpile[resource]
    }

    fn trade_offer_cap(&self, nation: MajorNationId) -> i16 {
        self.nations.majors[nation].economy.capacities.trade_offer
    }

    fn available_merchant(&self, nation: MajorNationId) -> i16 {
        self.nations.majors[nation]
            .economy
            .capacities
            .available_merchant
    }

    fn foreign_trade(&self, nation: MajorNationId) -> &ForeignTradeState {
        &self.nations.majors[nation].economy.foreign_trade
    }

    fn foreign_trade_mut(&mut self, nation: MajorNationId) -> &mut ForeignTradeState {
        &mut self.nations.majors[nation].economy.foreign_trade
    }

    fn set_trade_potential(&mut self, nation: MajorNationId, resource: ResourceKind, value: i16) {
        self.nations.majors[nation]
            .economy
            .set_item_potential(resource, value);
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

    fn random_eligible_peer(&mut self, nation: MajorNationId) -> Option<MajorNationId> {
        let candidate = MajorNationId::new((self.rng.next_crt_rand() % 7) as u8);
        (self.major_is_trade_eligible(candidate)
            && !self.nations_at_war(candidate.nation(), nation.nation())
            && candidate != nation)
            .then_some(candidate)
    }

    #[allow(clippy::too_many_arguments)]
    fn accept_offer(
        &mut self,
        buyer: MajorNationId,
        seller: NationId,
        amount: i16,
        available: i16,
        price: i16,
        commodity: TradeCommodity,
        shortfall_if_short: bool,
        phase: &mut TradePhase,
    ) -> i16 {
        let take = amount.min(available);
        self.set_deal_results(
            buyer.nation(),
            seller,
            take,
            price,
            commodity,
            shortfall_if_short && take < amount,
            phase,
        );
        take
    }

    fn enable_partner_split(&mut self, buyer: MajorNationId, resource_index: usize, split: i16) {
        if self.foreign_trade(buyer).trade_partner_enabled[resource_index] != 0 {
            let trade = self.foreign_trade_mut(buyer);
            trade.capability_flag_16 = split;
            trade.trade_partner_enabled[resource_index] = 0;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn accept_from_capability_flag(
        &mut self,
        buyer: MajorNationId,
        seller: NationId,
        amount: i16,
        price: i16,
        commodity: TradeCommodity,
        shortfall_if_short: bool,
        phase: &mut TradePhase,
    ) {
        let available = self.foreign_trade(buyer).capability_flag_16;
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
            self.foreign_trade_mut(buyer).capability_flag_16 -= amount;
        } else {
            self.set_deal_results(
                buyer.nation(),
                seller,
                available,
                price,
                commodity,
                shortfall_if_short,
                phase,
            );
            self.foreign_trade_mut(buyer).capability_flag_16 = 0;
        }
    }
}

pub(super) fn offer_or_grant(
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

pub(super) fn trade_commodity(resource: ResourceKind) -> TradeCommodity {
    TradeCommodity::from_retail(resource as i16).expect("market commodity")
}

pub(super) fn resource_code(commodity: Option<TradeCommodity>) -> i16 {
    commodity.map_or(NO_RESOURCE, |commodity| commodity as i16)
}

pub(super) fn preferred_nation(status: CountryStatus, own: NationId) -> NationId {
    match status {
        CountryStatus::ColonyOf(nation) | CountryStatus::ProtectorateOf(nation) => nation,
        CountryStatus::Independent => own,
    }
}

pub(super) fn offer_base(turn: i32, steps: &[(i32, f64)]) -> f64 {
    let bucket = (turn + (turn >> 31 & 3)) >> 2;
    for &(threshold, value) in steps {
        if bucket < threshold {
            return value;
        }
    }
    1.01
}

pub(super) fn major_offer_base(turn: i32) -> f64 {
    offer_base(
        turn,
        &[
            (0x0b, 1.1),
            (0x15, 1.08),
            (0x1f, 1.06),
            (0x29, 1.04),
            (0x33, 1.03),
            (0x3d, 1.02),
        ],
    )
}

pub(super) fn minor_offer_base(turn: i32) -> f64 {
    offer_base(
        turn,
        &[
            (0x0b, 1.1),
            (0x15, 1.09),
            (0x1f, 1.08),
            (0x29, 1.07),
            (0x33, 1.06),
            (0x3d, 1.05),
            (0x47, 1.04),
            (0x51, 1.03),
            (0x5b, 1.02),
        ],
    )
}

pub(super) fn trade_power(base: f64, exponent: i16) -> f64 {
    let mut result = 1.0;
    for _ in 0..exponent.max(0) {
        result *= base;
    }
    result
}

pub(super) fn offer_factor(base: f64, amount: i16) -> f64 {
    if amount == 1 {
        1.0
    } else {
        let exponent = if amount < 0x19 { amount - 1 } else { 0x17 };
        trade_power(base, exponent)
    }
}

pub(super) fn subsidy_from_stock(stock: i16) -> i16 {
    if stock == 0 {
        0
    } else {
        (i32::from(stock) / 2).min(5) as i16
    }
}

pub(super) fn trades_first(proposal: i16, category: i16) -> i16 {
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

pub(super) fn insert_sorted<T>(list: &mut Vec<T>, item: T, mut cmp: impl FnMut(&T, &T) -> i16) {
    if let Some(index) = list.iter().position(|existing| cmp(&item, existing) != 1) {
        list.insert(index, item);
    } else {
        list.push(item);
    }
}

pub(super) fn compare_deals(a: &RankedDeal, b: &RankedDeal) -> i16 {
    let invert = MANUFACTURED_COMMODITIES.contains(&a.category);
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

pub(super) fn compare_by_nation(
    a: &TradeDealBookEntry,
    b: &TradeDealBookEntry,
    rng: &mut RngState,
) -> i16 {
    compare_relationship(i16::from(a.nation.get()), i16::from(b.nation.get()), rng)
}

pub(super) fn compare_relationship(a_key: i16, b_key: i16, rng: &mut RngState) -> i16 {
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

pub(super) fn compare_index_and_rank(a: &(i16, i16), b: &(i16, i16)) -> i16 {
    if a.1 <= b.1 { 1 } else { -1 }
}

pub(super) fn compare_by_price(a: &(i16, i16), b: &(i16, i16)) -> i16 {
    if a.1 <= b.1 { -1 } else { 1 }
}
