use super::*;
use crate::market::all_trade_commodities;
use crate::*;

impl GameState {
    pub(super) fn set_ai_trade_bids(&mut self, nation: MajorNationId) {
        self.prepare_personality_trade_bids(nation);
        let personality = self.nations.majors[&nation]
            .economy
            .foreign_minister_personality;
        if personality != ForeignMinisterPersonality::Base {
            let preferred = self.foreign_trade(nation).preferred_resources;
            for resource in preferred.into_iter().flatten() {
                self.set_trade_potential(nation, resource.resource(), -1);
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

    pub(super) fn prepare_personality_trade_bids(&mut self, nation: MajorNationId) {
        let treasury = self.nations.majors[&nation].common.treasury;
        {
            let trade = self.foreign_trade_mut(nation);
            trade.trade_partner_enabled = TradePartnerCommodityTable::from_array([true; 7]);
            trade.capability_flag_16 = 0;
            if treasury < 0 {
                trade.capability_flag_14 = 1;
            }
        }
        let needs_refresh = {
            let trade = self.foreign_trade(nation);
            trade.phase_counter >= trade.refresh_interval || self.we_need_money(nation)
        };
        if needs_refresh {
            if self.nations.majors[&nation].economy.pending_ship.is_none() {
                self.nations.majors[&nation].economy.pending_ship =
                    Some(self.foreign_trade(nation).requested_ship);
            }
            self.foreign_trade_mut(nation).phase_counter = 0;
        }
        self.set_buy_priorities(nation);
        if let Some(bid) = self.foreign_trade(nation).interior_bid {
            self.set_trade_potential(nation, bid.commodity.resource(), -1);
            self.foreign_trade_mut(nation).purchase_priority[bid.commodity] = bid.amount;
        }
    }

    pub(super) fn we_need_money(&self, nation: MajorNationId) -> bool {
        let cap = self.trade_offer_cap(nation);
        [
            ResourceKind::Clothing,
            ResourceKind::Furniture,
            ResourceKind::Hardware,
        ]
        .into_iter()
        .any(|resource| self.city_stock(nation, resource) >= cap)
    }

    pub(super) fn set_buy_priorities(&mut self, nation: MajorNationId) {
        match self.nations.majors[&nation]
            .economy
            .foreign_minister_personality
        {
            ForeignMinisterPersonality::Ted => self.ted_set_buy_priorities(nation),
            ForeignMinisterPersonality::Bill => self.bill_set_buy_priorities(nation),
            ForeignMinisterPersonality::Diplomat => self.diplomat_set_buy_priorities(nation),
            ForeignMinisterPersonality::Textile => self.textile_set_buy_priorities(nation),
            ForeignMinisterPersonality::Trader => self.trader_set_buy_priorities(nation),
            ForeignMinisterPersonality::Arms => self.arms_set_buy_priorities(nation),
            ForeignMinisterPersonality::Base => {}
        }
        self.base_set_buy_priorities(nation);
    }

    pub(super) fn base_set_buy_priorities(&mut self, nation: MajorNationId) {
        let mut priorities = Vec::new();
        for commodity in all_trade_commodities() {
            let priority = self.foreign_trade(nation).purchase_priority[commodity];
            if priority != 0 {
                insert_sorted(
                    &mut priorities,
                    (commodity, priority + 1),
                    compare_commodity_rank,
                );
            }
        }
        let preferred = self.foreign_trade(nation).preferred_resources;
        for resource in preferred {
            if let Some(commodity) = resource
                && !priorities
                    .iter()
                    .any(|&(existing, _)| existing == commodity)
            {
                insert_sorted(&mut priorities, (commodity, 1), compare_commodity_rank);
            }
        }
        for index in 0..4 {
            let commodity = priorities.get(index).map(|(commodity, _)| *commodity);
            self.foreign_trade_mut(nation).preferred_resources[index] = commodity;
        }
    }

    pub(super) fn do_usual_subsidy_rule(&mut self, nation: MajorNationId) {
        let loop_count = i32::from(self.has_oil(nation)) + 5;
        for resource in RAW_COMMODITIES
            .into_iter()
            .map(TradeCommodity::resource)
            .take(loop_count as usize)
        {
            let roll = self.rng.next_crt_rand();
            let price = self.market.rows[trade_commodity(resource)].price;
            if roll % 100 + 200 < price {
                self.set_trade_potential(
                    nation,
                    resource,
                    subsidy_from_stock(self.city_stock(nation, resource)),
                );
            }
        }

        let roll = self.rng.next_crt_rand();
        let price = self.market.rows[TradeCommodity::Horses].price;
        if roll % 100 + 200 < price {
            self.set_trade_potential(
                nation,
                ResourceKind::Horses,
                subsidy_from_stock(self.city_stock(nation, ResourceKind::Horses)),
            );
        }
    }

    pub(super) fn ted_set_buy_priorities(&mut self, nation: MajorNationId) {
        let stock = |resource| self.city_stock(nation, resource);
        if !self.has_oil(nation) {
            let iron_first = stock(ResourceKind::Iron) < stock(ResourceKind::Coal);
            let fourth = self.cotton_or_wool_roll();
            if iron_first {
                self.set_preferred(
                    nation,
                    [
                        Some(TradeCommodity::Iron),
                        Some(TradeCommodity::Timber),
                        Some(TradeCommodity::Coal),
                        Some(fourth),
                    ],
                );
            } else {
                self.set_preferred(
                    nation,
                    [
                        Some(TradeCommodity::Coal),
                        Some(TradeCommodity::Timber),
                        Some(TradeCommodity::Iron),
                        Some(fourth),
                    ],
                );
            }
            return;
        }
        let mut preferred = [None; 4];
        if stock(ResourceKind::Iron) < stock(ResourceKind::Coal) {
            preferred[0] = Some(TradeCommodity::Iron);
            if stock(ResourceKind::Oil) < stock(ResourceKind::Coal) {
                preferred[1] = Some(TradeCommodity::Oil);
                preferred[2] = Some(if stock(ResourceKind::Timber) < stock(ResourceKind::Coal) {
                    TradeCommodity::Timber
                } else {
                    TradeCommodity::Coal
                });
            } else {
                preferred[1] = Some(TradeCommodity::Coal);
                preferred[2] = Some(if stock(ResourceKind::Oil) > stock(ResourceKind::Timber) {
                    TradeCommodity::Timber
                } else {
                    TradeCommodity::Oil
                });
            }
        } else {
            preferred[0] = Some(TradeCommodity::Coal);
            if stock(ResourceKind::Oil) < stock(ResourceKind::Iron) {
                preferred[1] = Some(TradeCommodity::Oil);
                preferred[2] = Some(if stock(ResourceKind::Iron) > stock(ResourceKind::Timber) {
                    TradeCommodity::Timber
                } else {
                    TradeCommodity::Iron
                });
            } else {
                preferred[1] = Some(TradeCommodity::Iron);
                preferred[2] = Some(if stock(ResourceKind::Oil) > stock(ResourceKind::Timber) {
                    TradeCommodity::Timber
                } else {
                    TradeCommodity::Oil
                });
            }
        }
        preferred[3] = Some(self.cotton_or_wool_roll());
        self.set_preferred(nation, preferred);
    }

    pub(super) fn ted_set_trade_bids(&mut self, nation: MajorNationId) {
        let cap = self.trade_offer_cap(nation);
        let hardware = self.city_stock(nation, ResourceKind::Hardware);
        if self.nations.majors[&nation].common.treasury >= 0 && cap > hardware && hardware < 10 {
            self.offer_all_stock(nation, ResourceKind::Clothing);
            self.offer_all_stock(nation, ResourceKind::Furniture);
        } else {
            let amount = cap.min(hardware);
            self.set_trade_potential(nation, ResourceKind::Hardware, amount);
            if cap > amount * 2 {
                self.offer_all_stock(nation, ResourceKind::Clothing);
                self.offer_all_stock(nation, ResourceKind::Furniture);
            }
        }
        self.ted_style_arms_bid(nation, 1500);
    }

    pub(super) fn bill_set_buy_priorities(&mut self, nation: MajorNationId) {
        let stock = |resource| self.city_stock(nation, resource);
        if self.has_oil(nation) {
            if stock(ResourceKind::Iron) < stock(ResourceKind::Coal) {
                self.set_preferred(
                    nation,
                    [
                        Some(TradeCommodity::Iron),
                        Some(TradeCommodity::Timber),
                        Some(TradeCommodity::Oil),
                        Some(TradeCommodity::Coal),
                    ],
                );
            } else {
                self.set_preferred(
                    nation,
                    [
                        Some(TradeCommodity::Coal),
                        Some(TradeCommodity::Timber),
                        Some(TradeCommodity::Oil),
                        Some(TradeCommodity::Iron),
                    ],
                );
            }
        } else if stock(ResourceKind::Iron) < stock(ResourceKind::Coal) {
            self.set_preferred(
                nation,
                [
                    Some(TradeCommodity::Iron),
                    Some(TradeCommodity::Timber),
                    Some(TradeCommodity::Coal),
                    None,
                ],
            );
        } else {
            self.set_preferred(
                nation,
                [
                    Some(TradeCommodity::Coal),
                    Some(TradeCommodity::Timber),
                    Some(TradeCommodity::Iron),
                    None,
                ],
            );
        }
    }

    pub(super) fn bill_set_trade_bids(&mut self, nation: MajorNationId) {
        self.sell_processed_round_robin(nation, true);
        self.ted_style_arms_bid(nation, 1500);
    }

    pub(super) fn diplomat_set_buy_priorities(&mut self, nation: MajorNationId) {
        let iron = self.city_stock(nation, ResourceKind::Iron);
        let coal = self.city_stock(nation, ResourceKind::Coal);
        let oil = self.city_stock(nation, ResourceKind::Oil);
        let cotton = self.city_stock(nation, ResourceKind::Cotton);
        let wool = self.city_stock(nation, ResourceKind::Wool);
        if self.has_oil(nation) {
            let fourth = if self.rng.next_crt_rand() % 2 == 0 {
                TradeCommodity::Wool
            } else {
                TradeCommodity::Cotton
            };
            if iron < coal {
                self.set_preferred(
                    nation,
                    [
                        Some(TradeCommodity::Timber),
                        Some(TradeCommodity::Iron),
                        Some(if oil < coal {
                            TradeCommodity::Oil
                        } else {
                            TradeCommodity::Coal
                        }),
                        Some(fourth),
                    ],
                );
            } else {
                self.set_preferred(
                    nation,
                    [
                        Some(TradeCommodity::Timber),
                        Some(TradeCommodity::Coal),
                        Some(if oil < iron {
                            TradeCommodity::Oil
                        } else {
                            TradeCommodity::Iron
                        }),
                        Some(fourth),
                    ],
                );
            }
            return;
        }

        let has_trade_candidate = MinorNationId::all().any(|minor| {
            let nation_id = minor.nation();
            self.nation_present(nation_id)
                && (self.market.rows[TradeCommodity::Coal].maximum_offer_by_nation[nation_id] != 0
                    || self.market.rows[TradeCommodity::Iron].maximum_offer_by_nation[nation_id]
                        != 0)
        });
        if !has_trade_candidate {
            let fourth = if self.rng.next_crt_rand() < 0x3ffe {
                TradeCommodity::Coal
            } else {
                TradeCommodity::Iron
            };
            self.set_preferred(
                nation,
                [
                    Some(TradeCommodity::Timber),
                    Some(TradeCommodity::Cotton),
                    Some(TradeCommodity::Wool),
                    Some(fourth),
                ],
            );
        } else if (self.turn.economic_turn / 4) & 1 != 0 {
            let (second, third) = if iron < coal {
                (TradeCommodity::Iron, TradeCommodity::Coal)
            } else {
                (TradeCommodity::Coal, TradeCommodity::Iron)
            };
            let fourth = if self.market.rows[TradeCommodity::Cotton].price
                > self.market.rows[TradeCommodity::Wool].price
            {
                TradeCommodity::Cotton
            } else {
                TradeCommodity::Wool
            };
            self.set_preferred(
                nation,
                [
                    Some(TradeCommodity::Timber),
                    Some(second),
                    Some(third),
                    Some(fourth),
                ],
            );
        } else {
            let (second, third) = if cotton < wool {
                (TradeCommodity::Cotton, TradeCommodity::Wool)
            } else {
                (TradeCommodity::Wool, TradeCommodity::Cotton)
            };
            let fourth = if iron < coal {
                TradeCommodity::Iron
            } else {
                TradeCommodity::Coal
            };
            self.set_preferred(
                nation,
                [
                    Some(TradeCommodity::Timber),
                    Some(second),
                    Some(third),
                    Some(fourth),
                ],
            );
        }
    }

    pub(super) fn diplomat_set_trade_bids(&mut self, nation: MajorNationId) {
        self.sell_processed_round_robin(nation, true);
        self.offer_surplus_arms(nation);
    }

    pub(super) fn textile_set_buy_priorities(&mut self, nation: MajorNationId) {
        let mut prices = Vec::new();
        for resource in [ResourceKind::Coal, ResourceKind::Iron, ResourceKind::Timber] {
            insert_sorted(
                &mut prices,
                (
                    TradeCommodity::from_resource(resource).expect("textile input is tradable"),
                    self.city_stock(nation, resource),
                ),
                compare_commodity_price,
            );
        }
        if self.has_oil(nation) {
            insert_sorted(
                &mut prices,
                (
                    TradeCommodity::Oil,
                    self.city_stock(nation, ResourceKind::Oil),
                ),
                compare_commodity_price,
            );
        }
        let third = prices.first().map(|(commodity, _)| *commodity);
        let fourth = prices.get(1).map(|(commodity, _)| *commodity);
        self.set_preferred(
            nation,
            [
                Some(TradeCommodity::Cotton),
                Some(TradeCommodity::Wool),
                third,
                fourth,
            ],
        );
    }

    pub(super) fn textile_set_trade_bids(&mut self, nation: MajorNationId) {
        let cap = self.trade_offer_cap(nation);
        let clothing = self.city_stock(nation, ResourceKind::Clothing);
        if self.nations.majors[&nation].common.treasury < 0
            || clothing >= cap
            || (clothing > 4 && self.market.rows[TradeCommodity::Clothing].price > 1000)
        {
            self.set_trade_potential(nation, ResourceKind::Clothing, clothing.min(cap));
        }
        if self.nations.majors[&nation].common.treasury < 0
            || self.nations.majors[&nation].economy.item_potentials[ResourceKind::Clothing] == 0
        {
            let budget = cap / 2;
            let (first, second) = if self.market.rows[TradeCommodity::Hardware].price
                > self.market.rows[TradeCommodity::Furniture].price
            {
                (ResourceKind::Hardware, ResourceKind::Furniture)
            } else {
                (ResourceKind::Furniture, ResourceKind::Hardware)
            };
            let first_stock = self.city_stock(nation, first);
            let first_amount = first_stock.min(budget);
            self.set_trade_potential(nation, first, first_amount);
            let remaining = budget - first_amount;
            let second_stock = self.city_stock(nation, second);
            self.set_trade_potential(nation, second, second_stock.min(remaining));
        }
        self.ted_style_arms_bid(nation, 1500);
    }

    pub(super) fn trader_set_buy_priorities(&mut self, nation: MajorNationId) {
        let mut prices = Vec::new();
        for commodity in [
            TradeCommodity::Cotton,
            TradeCommodity::Wool,
            TradeCommodity::Timber,
            TradeCommodity::Coal,
            TradeCommodity::Iron,
        ] {
            let mut priority = self.market.rows[commodity].price as i32;
            if matches!(commodity, TradeCommodity::Coal | TradeCommodity::Iron) {
                priority -= 15;
            }
            insert_sorted(&mut prices, (commodity, priority), compare_commodity_price);
        }
        if self.has_oil(nation) {
            insert_sorted(
                &mut prices,
                (
                    TradeCommodity::Oil,
                    self.market.rows[TradeCommodity::Oil].price as i32 - 15,
                ),
                compare_commodity_price,
            );
        }
        let mut preferred = [None; 4];
        for (index, &(commodity, _)) in prices.iter().take(4).enumerate() {
            preferred[index] = Some(commodity);
        }
        self.set_preferred(nation, preferred);
    }

    pub(super) fn trader_set_trade_bids(&mut self, nation: MajorNationId) {
        let prices = self.sorted_processed_prices();
        let divisor = if self.nations.majors[&nation].common.treasury < 0 {
            1
        } else {
            4
        };
        let budget = self.trade_offer_cap(nation) / divisor;
        let mut allocated = 0;
        for resource in prices.into_iter().rev() {
            if budget <= allocated {
                break;
            }
            let stock = self.city_stock(nation, resource);
            self.set_trade_potential(nation, resource, stock);
            allocated += stock;
        }
        self.offer_surplus_arms(nation);
    }

    pub(super) fn arms_set_buy_priorities(&mut self, nation: MajorNationId) {
        if self.has_oil(nation) {
            self.set_preferred(
                nation,
                [
                    Some(TradeCommodity::Oil),
                    Some(TradeCommodity::Timber),
                    Some(TradeCommodity::Coal),
                    Some(TradeCommodity::Iron),
                ],
            );
        } else {
            let fourth = if self.rng.next_crt_rand() % 2 != 0 {
                TradeCommodity::Cotton
            } else {
                TradeCommodity::Wool
            };
            self.set_preferred(
                nation,
                [
                    Some(TradeCommodity::Timber),
                    Some(TradeCommodity::Coal),
                    Some(TradeCommodity::Iron),
                    Some(fourth),
                ],
            );
        }
    }

    pub(super) fn arms_set_trade_bids(&mut self, nation: MajorNationId) {
        let prices = self.sorted_processed_prices();
        let budget = self.trade_offer_cap(nation) / 2;
        let mut allocated = 0;
        for resource in prices.into_iter().rev() {
            if allocated >= budget {
                break;
            }
            let stock = self.city_stock(nation, resource);
            let amount = stock.min(budget - allocated);
            self.set_trade_potential(nation, resource, amount);
            allocated += amount;
        }
        if self.nations.majors[&nation].common.treasury < 0 && !self.has_any_war(nation.nation()) {
            let available = self.city_stock(nation, ResourceKind::Arms);
            let mut amount = available / 10;
            if amount > 10 {
                amount = 10;
            }
            if amount > 2 {
                self.set_trade_potential(nation, ResourceKind::Arms, amount);
            } else if available > 6 {
                self.set_trade_potential(nation, ResourceKind::Arms, 2);
            }
        }
    }

    pub(super) fn offer_surplus_arms(&mut self, nation: MajorNationId) {
        if self.market.rows[TradeCommodity::Arms].price > 1200
            && self.city_stock(nation, ResourceKind::Arms) > 6
            && !self.has_any_war(nation.nation())
        {
            self.set_trade_potential(nation, ResourceKind::Arms, 2);
        }
    }

    pub(super) fn sell_processed_round_robin(
        &mut self,
        nation: MajorNationId,
        half_capacity: bool,
    ) {
        let cap = self.trade_offer_cap(nation);
        let target = if self.nations.majors[&nation].common.treasury < 0 || !half_capacity {
            cap
        } else {
            cap / 2
        };
        let prices = self.sorted_processed_prices();
        let mut amounts = ResourceTable::<i32>::default();
        let mut selected_prices = prices.into_iter().rev().cycle();
        let mut iteration = 0_i32;
        while target > 0 && iteration < i32::from(target) * 3 {
            let resource = selected_prices
                .next()
                .expect("cycled processed prices are never empty");
            if amounts[resource] < self.city_stock(nation, resource) {
                amounts[resource] += 1;
                self.set_trade_potential(nation, resource, amounts[resource]);
            }
            if amounts[ResourceKind::Clothing]
                + amounts[ResourceKind::Furniture]
                + amounts[ResourceKind::Hardware]
                >= target
            {
                break;
            }
            iteration += 1;
        }
    }

    pub(super) fn sorted_processed_prices(&self) -> [ResourceKind; 3] {
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
                    self.market.rows[trade_commodity(resource)].price as i32,
                ),
                compare_resource_price,
            );
        }
        [prices[0].0, prices[1].0, prices[2].0]
    }

    pub(super) fn ted_style_arms_bid(&mut self, nation: MajorNationId, threshold: i32) {
        if self.market.rows[TradeCommodity::Arms].price > threshold
            && !self.has_any_war(nation.nation())
        {
            let available = self.city_stock(nation, ResourceKind::Arms);
            let amount = available / 10;
            if amount > 2 {
                self.set_trade_potential(nation, ResourceKind::Arms, amount);
            } else if available > 6 {
                self.set_trade_potential(nation, ResourceKind::Arms, 2);
            }
        }
    }

    pub(super) fn offer_all_stock(&mut self, nation: MajorNationId, resource: ResourceKind) {
        let stock = self.city_stock(nation, resource);
        self.set_trade_potential(nation, resource, stock);
    }

    pub(super) fn cotton_or_wool_roll(&mut self) -> TradeCommodity {
        if self.rng.next_crt_rand() < 0x3ffe {
            TradeCommodity::Cotton
        } else {
            TradeCommodity::Wool
        }
    }

    pub(super) fn set_preferred(
        &mut self,
        nation: MajorNationId,
        resources: [Option<TradeCommodity>; 4],
    ) {
        self.foreign_trade_mut(nation).preferred_resources = resources;
    }
}

fn compare_commodity_rank(a: &(TradeCommodity, i32), b: &(TradeCommodity, i32)) -> i32 {
    if a.1 <= b.1 { 1 } else { -1 }
}

fn compare_commodity_price(a: &(TradeCommodity, i32), b: &(TradeCommodity, i32)) -> i32 {
    if a.1 <= b.1 { -1 } else { 1 }
}

fn compare_resource_price(a: &(ResourceKind, i32), b: &(ResourceKind, i32)) -> i32 {
    if a.1 <= b.1 { -1 } else { 1 }
}
