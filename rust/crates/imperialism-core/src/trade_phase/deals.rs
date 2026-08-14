use super::*;
use crate::market::all_trade_commodities;
use crate::*;

impl GameState {
    pub(super) fn calculate_deal_order(&mut self, phase: &mut TradePhase) {
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
            self.pair_deals(phase, commodity, 0..7, 0..NATION_COUNT as u8);
        }
    }

    pub(super) fn pair_deals(
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

    pub(super) fn deal_price(
        &self,
        buyer: NationId,
        seller: NationId,
        commodity: TradeCommodity,
    ) -> i32 {
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

    pub(super) fn settle_or_block_trade_offer(
        &mut self,
        phase: &mut TradePhase,
        buyer: NationId,
        seller: NationId,
        amount: i16,
        price: i16,
        commodity: TradeCommodity,
    ) -> Option<PendingTradeOffer> {
        if let Some(major) = MajorNationId::from_nation(buyer) {
            if self.nations.majors[major]
                .economy
                .is_still_buying(commodity.resource())
            {
                if self.is_human(major) {
                    return Some(PendingTradeOffer {
                        buyer,
                        seller,
                        amount,
                        price,
                        commodity,
                    });
                }
                self.ai_reply_to_trade_offer(major, seller, amount, price, commodity, phase);
            } else {
                self.add_to_deal_book(major, DealBookEntryKind::Offer, seller, 0, commodity, 0);
            }
            return None;
        }

        let minor = MinorNationId::new(buyer.get());
        if self.minor_still_buying(minor, commodity.resource()) {
            self.set_deal_results(buyer, seller, amount, price, commodity, true, phase);
        }
        None
    }

    pub(super) fn amount_unsold(&self, nation: NationId, resource: ResourceKind) -> i16 {
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

    pub(super) fn minor_still_buying(&self, minor: MinorNationId, resource: ResourceKind) -> bool {
        let Some(state) = self.nations.minors[minor].as_ref() else {
            return false;
        };
        let Some(commodity) = TradeCommodity::from_retail(resource as i16) else {
            return true;
        };
        if !MANUFACTURED_COMMODITIES.contains(&commodity) {
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
    pub(super) fn set_deal_results(
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

    pub(super) fn purchase_for_nation(
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
                && let Some(auto) = self.nations.majors[major].auto.as_mut()
            {
                auto.trade.temporary_processed_stock[processed] += amount;
            }
            self.purchase_item(major, resource, amount, price);
            return;
        }

        let minor = MinorNationId::new(nation.get());
        self.purchase_minor_item(minor, resource, amount, price, phase);
    }

    pub(super) fn purchase_minor_item(
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
            && MANUFACTURED_COMMODITIES.contains(&commodity)
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
        if !RAW_COMMODITIES
            .iter()
            .any(|commodity| commodity.resource() == resource)
        {
            return;
        }

        state.trade.grant_deltas[resource] += amount;
        if phase.recurring_grant[minor][resource] == 0 {
            return;
        }

        let need_current = state.trade.current_supply[resource];
        let mut grants = Vec::new();
        for major in MajorNationId::all() {
            let link = phase.status_by_major[minor][resource][usize::from(major.get())];
            if link == 0 {
                continue;
            }
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

    pub(super) fn add_to_deal_book(
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

    pub(super) fn end_trade_offers(&mut self) {
        for nation in MajorNationId::all() {
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

    pub(super) fn clear_trade_offers(&mut self, nation: MajorNationId) {
        if !self.is_human(nation) {
            self.end_ai_trade_phase(nation);
            if let Some(auto) = self.nations.majors[nation].auto.as_mut() {
                let pending = auto.trade.temporary_processed_stock;
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
                        let resource = processed.resource();
                        let current = self.city_stock(nation, resource);
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
                if let Some(auto) = self.nations.majors[nation].auto.as_mut() {
                    auto.trade.temporary_processed_stock = ProcessedTradeCommodityTable::default();
                }
            }
        }
        self.nations.majors[nation].economy.item_potentials = ResourceTable::default();
    }

    pub(super) fn end_ai_trade_phase(&mut self, nation: MajorNationId) {
        {
            let trade = self.foreign_trade_mut(nation);
            if let Some(bid) = trade.interior_bid.as_mut() {
                bid.amount = 0;
            }
            trade.capability_flag_14 = 0;
            trade.interior_bid = None;
        }
        if self.available_merchant(nation) == 0 {
            self.foreign_trade_mut(nation).phase_counter += 1;
        }
        self.foreign_trade_mut(nation).purchase_priority = TradeCommodityTable::default();
    }
}
