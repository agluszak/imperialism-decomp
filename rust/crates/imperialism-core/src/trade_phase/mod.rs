//! Retail `TSimMgr::DoTrade` as a resumable trade-phase continuation.

mod ai_bids;
mod ai_replies;
mod bids;
mod deals;
mod prepare;

use crate::market::all_trade_commodities;
use crate::*;
use serde::{Deserialize, Serialize};

pub(super) const DEAL_CATEGORY_ORDER: [TradeCommodity; TradeCommodity::LENGTH] = [
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

/// One Offer Sheet interruption from `TGreatPower::ReplyToTradeOffer`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingTradeOffer {
    pub buyer: NationId,
    pub seller: NationId,
    pub amount: i16,
    pub price: i16,
    pub commodity: TradeCommodity,
}

/// Progress of `TTradeMgr::StartDeals` / `NextTradeDeal`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TradeProgress {
    Offer(PendingTradeOffer),
    Complete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct RankedDeal {
    pub(super) buyer: NationId,
    pub(super) seller: NationId,
    pub(super) offer_amount: i16,
    pub(super) standing: i16,
    pub(super) price: i32,
    pub(super) category: TradeCommodity,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TradeSession {
    phase: TradePhase,
    category: Option<TradeCommodity>,
    entry_ordinal: usize,
    pending: Option<PendingTradeOffer>,
}

impl TradeSession {
    fn skip_empty_categories(&mut self) {
        while let Some(category) = self.category {
            if !self.phase.deals[category].is_empty() {
                break;
            }
            self.category = next_deal_commodity(category);
        }
    }

    fn advance_deal_cursor(&mut self) {
        let category = self.category.expect("active deal cursor has a commodity");
        let size = self.phase.deals[category].len();
        self.entry_ordinal += 1;
        if self.entry_ordinal > size {
            self.category = next_deal_commodity(category);
            self.skip_empty_categories();
            self.entry_ordinal = 1;
        }
    }
}

fn next_deal_commodity(current: TradeCommodity) -> Option<TradeCommodity> {
    DEAL_CATEGORY_ORDER
        .iter()
        .skip_while(|&&commodity| commodity != current)
        .nth(1)
        .copied()
}

impl GameState {
    /// Starts retail `TSimMgr::DoTrade` through `TTradeMgr::StartDeals`.
    ///
    /// Human buyers still in the market return [`TradeProgress::Offer`] instead of
    /// settling. The following civilian phase is not started.
    pub fn begin_trade_phase(&mut self) -> TradeProgress {
        let mut phase = TradePhase::new();
        self.initialize_deal_books();
        self.reset_market_rows();
        self.run_nation_update_passes(&mut phase);
        self.set_minors_trade_bids(&mut phase);
        self.tally_major_trade_bids();
        self.market.recalculate_prices();
        self.calculate_deal_order(&mut phase);
        let mut session = TradeSession {
            phase,
            category: DEAL_CATEGORY_ORDER.first().copied(),
            entry_ordinal: 1,
            pending: None,
        };
        session.skip_empty_categories();
        let progress = self.continue_trade_deals(&mut session);
        if matches!(progress, TradeProgress::Offer(_)) {
            self.continuation = crate::turn_flow::TurnContinuation::Trade(session);
        }
        progress
    }

    /// Applies the player's Offer Sheet answer and resumes `TTradeMgr::NextTradeDeal`.
    ///
    /// `amount` is the purchased quantity (`0` rejects). `stop_buying` is the `nomo`
    /// checkbox and becomes `SetDealResults` shortfall.
    pub fn reply_to_trade_offer(&mut self, amount: i16, stop_buying: bool) -> TradeProgress {
        let mut session = match std::mem::take(&mut self.continuation) {
            crate::turn_flow::TurnContinuation::Trade(session) => session,
            other => {
                self.continuation = other;
                panic!("Offer Sheet reply requires an active trade session");
            }
        };
        let pending = session
            .pending
            .take()
            .expect("Offer Sheet reply requires a pending trade offer");
        self.set_deal_results(
            pending.buyer,
            pending.seller,
            amount,
            pending.price,
            pending.commodity,
            stop_buying,
            &mut session.phase,
        );
        let progress = self.continue_trade_deals(&mut session);
        if matches!(progress, TradeProgress::Offer(_)) {
            self.continuation = crate::turn_flow::TurnContinuation::Trade(session);
        }
        progress
    }

    pub fn pending_trade_offer(&self) -> Option<PendingTradeOffer> {
        match &self.continuation {
            crate::turn_flow::TurnContinuation::Trade(session) => session.pending,
            _ => None,
        }
    }

    fn continue_trade_deals(&mut self, session: &mut TradeSession) -> TradeProgress {
        let mut blocked = false;
        while let Some(commodity) = session.category {
            let deal = session.phase.deals[commodity][session.entry_ordinal - 1];
            let mut transfer = self.amount_unsold(deal.seller, commodity.resource());
            if let Some(seller_major) = MajorNationId::from_nation(deal.seller)
                && MajorNationId::from_nation(deal.buyer).is_none()
            {
                transfer = transfer.min(self.available_merchant(seller_major));
            }
            if transfer > 0 {
                blocked = self
                    .settle_or_block_trade_offer(
                        &mut session.phase,
                        deal.buyer,
                        deal.seller,
                        transfer,
                        deal.price as i16,
                        commodity,
                    )
                    .inspect(|offer| session.pending = Some(*offer))
                    .is_some();
            }
            session.advance_deal_cursor();
            if blocked {
                break;
            }
        }
        if blocked {
            TradeProgress::Offer(
                session
                    .pending
                    .expect("a blocked trade deal leaves a pending offer"),
            )
        } else {
            self.end_trade_offers();
            TradeProgress::Complete
        }
    }

    fn initialize_deal_books(&mut self) {
        for nation in MajorNationId::all().rev() {
            self.nations.majors[&nation].economy.deal_book = TradeCommodityTable::default();
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
        self.nations.majors[&nation].economy.diplomacy_eligible
    }

    fn city_stock(&self, nation: MajorNationId, resource: ResourceKind) -> i16 {
        self.nations.majors[&nation].city.stockpile[resource]
    }

    fn trade_offer_cap(&self, nation: MajorNationId) -> i16 {
        self.nations.majors[&nation].economy.capacities.trade_offer
    }

    fn available_merchant(&self, nation: MajorNationId) -> i16 {
        self.nations.majors[&nation]
            .economy
            .capacities
            .available_merchant
    }

    fn foreign_trade(&self, nation: MajorNationId) -> &ForeignTradeState {
        &self.nations.majors[&nation].economy.foreign_trade
    }

    fn foreign_trade_mut(&mut self, nation: MajorNationId) -> &mut ForeignTradeState {
        &mut self.nations.majors[&nation].economy.foreign_trade
    }

    fn set_trade_potential(&mut self, nation: MajorNationId, resource: ResourceKind, value: i16) {
        self.nations.majors[&nation]
            .economy
            .set_item_potential(resource, value);
    }

    fn major_is_trade_eligible(&self, nation: MajorNationId) -> bool {
        !matches!(
            self.nations.majors[&nation].common.status(),
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
        if self.foreign_trade(buyer).trade_partner_enabled[resource_index] {
            let trade = self.foreign_trade_mut(buyer);
            trade.capability_flag_16 = split;
            trade.trade_partner_enabled[resource_index] = false;
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
    TradeCommodity::from_resource(resource).expect("market commodity")
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

pub(super) fn trades_first(proposal: TradeCommodity, category: TradeCommodity) -> TradeCommodity {
    for &commodity in &DEAL_CATEGORY_ORDER {
        if commodity == proposal {
            return proposal;
        }
        if commodity == category {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    fn seed_merchant_capacity(city: &mut CityState) {
        city.ship_order_count_by_type[ShipType::Trader] = 2;
        city.ship_order_count_by_type[ShipType::Paddlewheeler] = 1;
        city.ship_order_count_by_type[ShipType::Freighter] = 1;
    }

    fn human_clothing_offer_state() -> GameState {
        let mut state = game_state();
        let buyer = MajorNationId::new(0);
        let seller = MajorNationId::new(1);
        for nation in MajorNationId::all() {
            seed_merchant_capacity(&mut state.nations.majors[&nation].city);
            state.nations.majors[&nation].city.stockpile[ResourceKind::Clothing] = 10;
            state.nations.majors[&nation].city.stockpile[ResourceKind::Timber] = 12;
            state.nations.majors[&nation].common.treasury = 20_000;
        }
        state.nations.majors[&buyer]
            .economy
            .remembered_trade_offers_by_resource[ResourceKind::Clothing] = -1;
        state.nations.majors[&buyer]
            .economy
            .remembered_trade_offers_by_resource[ResourceKind::Timber] = 5;
        state.nations.majors[&seller]
            .economy
            .remembered_trade_offers_by_resource[ResourceKind::Clothing] = 4;
        state
    }

    #[test]
    fn begin_trade_phase_interrupts_for_a_human_buyer() {
        let mut state = human_clothing_offer_state();
        let progress = state.begin_trade_phase();
        let TradeProgress::Offer(offer) = progress else {
            panic!("human buyer must be interrupted by the Offer Sheet, got {progress:?}");
        };
        assert_eq!(offer.buyer, NationId::new(0));
        assert_eq!(offer.seller, NationId::new(1));
        assert_eq!(offer.commodity, TradeCommodity::Clothing);
        assert!(offer.amount > 0);
        assert_eq!(state.pending_trade_offer(), Some(offer));
        assert_eq!(
            state.nations.majors[&MajorNationId::new(0)]
                .economy
                .purchased_items_by_resource[ResourceKind::Clothing],
            0
        );
    }

    #[test]
    fn rejecting_a_human_offer_resumes_and_can_complete() {
        let mut state = human_clothing_offer_state();
        let TradeProgress::Offer(_) = state.begin_trade_phase() else {
            panic!("expected a pending human offer");
        };
        assert_eq!(
            state.reply_to_trade_offer(0, false),
            TradeProgress::Complete
        );
        assert_eq!(state.pending_trade_offer(), None);
        assert!(!matches!(
            state.continuation,
            crate::turn_flow::TurnContinuation::Trade(_)
        ));
        assert_eq!(
            state.nations.majors[&MajorNationId::new(0)]
                .economy
                .purchased_items_by_resource[ResourceKind::Clothing],
            0
        );
    }

    #[test]
    fn accepting_the_posed_amount_settles_then_completes() {
        let mut state = human_clothing_offer_state();
        let TradeProgress::Offer(offer) = state.begin_trade_phase() else {
            panic!("expected a pending human offer");
        };
        assert_eq!(
            state.reply_to_trade_offer(offer.amount, false),
            TradeProgress::Complete
        );
        assert_eq!(state.pending_trade_offer(), None);
        assert_eq!(
            state.nations.majors[&MajorNationId::new(0)]
                .economy
                .purchased_items_by_resource[ResourceKind::Clothing],
            offer.amount
        );
    }
}
