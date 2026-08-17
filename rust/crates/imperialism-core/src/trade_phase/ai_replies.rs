use super::*;
use crate::*;

impl GameState {
    pub(super) fn ai_reply_to_trade_offer(
        &mut self,
        buyer: MajorNationId,
        seller: NationId,
        amount: i16,
        price: i16,
        commodity: TradeCommodity,
        phase: &mut TradePhase,
    ) {
        let resource = commodity.resource();
        if self.foreign_trade(buyer).purchase_priority[commodity] != 0 {
            self.base_reply_to_trade_offer(buyer, seller, amount, price, commodity, phase);
            return;
        }
        match self.nations.majors[&buyer]
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
                let cap = self.trade_offer_cap(buyer);
                let mut take = if cap < 12 {
                    1
                } else if cap >= 25 {
                    3
                } else {
                    2
                };
                take = take.min(self.merchant_capacity_for_proposal(buyer, resource));
                self.accept_offer(buyer, seller, amount, take, price, commodity, false, phase);
            }
            ForeignMinisterPersonality::Textile => {
                let available = self.merchant_capacity_for_proposal(buyer, resource);
                self.accept_offer(
                    buyer, seller, amount, available, price, commodity, false, phase,
                );
            }
            ForeignMinisterPersonality::Trader => {
                let available = self.merchant_capacity_for_proposal(buyer, resource);
                self.accept_offer(
                    buyer, seller, amount, available, price, commodity, true, phase,
                );
            }
            ForeignMinisterPersonality::Arms => {
                self.arms_reply(buyer, seller, amount, price, commodity, phase);
            }
            ForeignMinisterPersonality::Base => {
                self.base_reply_to_trade_offer(buyer, seller, amount, price, commodity, phase);
            }
        }
    }

    pub(super) fn base_reply_to_trade_offer(
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
        if self
            .foreign_trade(buyer)
            .interior_bid
            .is_some_and(|bid| bid.commodity == commodity)
        {
            let interior_amount = self
                .foreign_trade(buyer)
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
            let ledger = self.foreign_trade(buyer).purchase_priority[commodity];
            if ledger < 1 {
                dispatch = 0;
            } else if ledger < dispatch {
                dispatch = ledger;
            }
            let available = self.merchant_capacity_for_proposal(buyer, resource);
            if available < dispatch {
                dispatch = available;
            }
            self.foreign_trade_mut(buyer).purchase_priority[commodity] -= dispatch;
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

    pub(super) fn ted_reply(
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
                self.enable_partner_split(
                    buyer,
                    3,
                    self.merchant_capacity_for_proposal(buyer, ResourceKind::Coal) / 2,
                );
                self.accept_from_capability_flag(
                    buyer, seller, amount, price, commodity, true, phase,
                );
            }
            TradeCommodity::Timber | TradeCommodity::Iron | TradeCommodity::Oil => {
                let available = self.merchant_capacity_for_proposal(buyer, commodity.resource());
                self.accept_offer(
                    buyer, seller, amount, available, price, commodity, false, phase,
                );
            }
            TradeCommodity::Cotton | TradeCommodity::Wool => {
                let cap = self.trade_offer_cap(buyer);
                let mut take = if cap < 15 {
                    1
                } else if cap >= 30 {
                    3
                } else {
                    2
                };
                take = take.min(amount);
                take = take.min(self.merchant_capacity_for_proposal(buyer, commodity.resource()));
                self.set_deal_results(buyer.nation(), seller, take, price, commodity, false, phase);
            }
            _ => {}
        }
    }

    pub(super) fn bill_reply(
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
                    self.enable_partner_split(
                        buyer,
                        2,
                        (self.available_merchant(buyer) / 3).max(2),
                    );
                    let take = self
                        .foreign_trade(buyer)
                        .capability_flag_16
                        .min(self.available_merchant(buyer));
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
                        let flag = &mut self.foreign_trade_mut(buyer).capability_flag_16;
                        *flag -= amount;
                        if *flag < 0 {
                            *flag = 0;
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
                        self.foreign_trade_mut(buyer).capability_flag_16 = 0;
                    }
                } else {
                    self.accept_offer(
                        buyer,
                        seller,
                        amount,
                        self.available_merchant(buyer),
                        price,
                        commodity,
                        false,
                        phase,
                    );
                }
            }
            TradeCommodity::Coal => {
                self.enable_partner_split(buyer, 3, self.available_merchant(buyer) / 2);
                let mut take = if self.market.rows[TradeCommodity::Iron].price < 105 {
                    amount
                } else {
                    self.foreign_trade(buyer).capability_flag_16
                };
                take = take.min(amount);
                let available = self.available_merchant(buyer);
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
                    self.foreign_trade_mut(buyer).capability_flag_16 -= take;
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
                    self.foreign_trade_mut(buyer).capability_flag_16 = 0;
                }
            }
            TradeCommodity::Iron | TradeCommodity::Oil => {
                let take = self.accept_offer(
                    buyer,
                    seller,
                    amount,
                    self.available_merchant(buyer),
                    price,
                    commodity,
                    commodity == TradeCommodity::Iron,
                    phase,
                );
                if commodity == TradeCommodity::Iron {
                    if take == amount {
                        self.foreign_trade_mut(buyer).capability_flag_16 -= amount;
                    } else {
                        self.foreign_trade_mut(buyer).capability_flag_16 = 0;
                    }
                }
            }
            _ => {}
        }
    }

    pub(super) fn arms_reply(
        &mut self,
        buyer: MajorNationId,
        seller: NationId,
        amount: i16,
        price: i16,
        commodity: TradeCommodity,
        phase: &mut TradePhase,
    ) {
        let resource = commodity.resource() as usize;
        let cap = self.available_merchant(buyer);
        if self.has_oil(buyer) {
            if !matches!(
                commodity,
                TradeCommodity::Timber | TradeCommodity::Coal | TradeCommodity::Iron
            ) {
                self.foreign_trade_mut(buyer).capability_flag_16 = cap;
            } else if resource < 7 && self.foreign_trade(buyer).trade_partner_enabled[resource] {
                self.foreign_trade_mut(buyer).capability_flag_16 = if phase.arms_advanced_split == 0
                {
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
            self.foreign_trade_mut(buyer).capability_flag_16 = cap;
        } else if resource < 7 && self.foreign_trade(buyer).trade_partner_enabled[resource] {
            self.foreign_trade_mut(buyer).capability_flag_16 = if phase.arms_basic_split == 0 {
                cap / 3
            } else {
                cap / 2
            };
            phase.arms_basic_split += 1;
        }
        if resource < 7 {
            self.foreign_trade_mut(buyer).trade_partner_enabled[resource] = false;
        }
        self.accept_from_capability_flag(buyer, seller, amount, price, commodity, true, phase);
    }

    pub(super) fn merchant_capacity_for_proposal(
        &self,
        nation: MajorNationId,
        resource: ResourceKind,
    ) -> i16 {
        let proposal = resource as i16;
        if let Some(capacity) =
            self.reserved_capacity_for_priority(nation, proposal, TradeCommodity::Iron)
        {
            return capacity;
        }
        if let Some(capacity) =
            self.reserved_capacity_for_priority(nation, proposal, TradeCommodity::Horses)
        {
            return capacity;
        }
        if let Some(capacity) =
            self.reserved_capacity_for_priority(nation, proposal, TradeCommodity::Coal)
        {
            if proposal == 3
                && self.foreign_trade(nation).purchase_priority[TradeCommodity::Iron] != 0
            {
                return (i32::from(self.available_merchant(nation)) - 1).max(0) as i16;
            }
            return capacity;
        }
        self.available_merchant(nation)
    }

    fn reserved_capacity_for_priority(
        &self,
        nation: MajorNationId,
        proposal: i16,
        commodity: TradeCommodity,
    ) -> Option<i16> {
        if self.foreign_trade(nation).purchase_priority[commodity] == 0
            || self.market.rows[commodity].amount_offered == 0
        {
            return None;
        }
        let available = self.available_merchant(nation);
        let code = commodity as i16;
        Some(if proposal == code {
            available
        } else if trades_first(proposal, code) == proposal {
            (i32::from(available) - 2).max(0) as i16
        } else {
            available
        })
    }
}
