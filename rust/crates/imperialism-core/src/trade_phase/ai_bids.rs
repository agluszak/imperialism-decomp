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
            trade.trade_partner_enabled = [1; 7];
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
                    (resource_code(Some(commodity)), priority + 1),
                    compare_index_and_rank,
                );
            }
        }
        let preferred = self.foreign_trade(nation).preferred_resources;
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
            self.foreign_trade_mut(nation).preferred_resources[index] =
                TradeCommodity::from_retail(code);
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
                self.set_preferred(nation, [4, 2, 3, fourth]);
            } else {
                self.set_preferred(nation, [3, 2, 4, fourth]);
            }
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
                self.set_preferred(nation, [4, 2, 6, 3]);
            } else {
                self.set_preferred(nation, [3, 2, 6, 4]);
            }
        } else if stock(ResourceKind::Iron) < stock(ResourceKind::Coal) {
            self.set_preferred(nation, [4, 2, 3, NO_RESOURCE]);
        } else {
            self.set_preferred(nation, [3, 2, 4, NO_RESOURCE]);
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
                1
            } else {
                0
            };
            if iron < coal {
                self.set_preferred(nation, [2, 4, if oil < coal { 6 } else { 3 }, fourth]);
            } else {
                self.set_preferred(nation, [2, 3, if oil < iron { 6 } else { 4 }, fourth]);
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
                (resource as i16, self.city_stock(nation, resource)),
                compare_by_price,
            );
        }
        if self.has_oil(nation) {
            insert_sorted(
                &mut prices,
                (
                    ResourceKind::Oil as i16,
                    self.city_stock(nation, ResourceKind::Oil),
                ),
                compare_by_price,
            );
        }
        let third = prices.first().map(|(code, _)| *code).unwrap_or(NO_RESOURCE);
        let fourth = prices.get(1).map(|(code, _)| *code).unwrap_or(NO_RESOURCE);
        self.set_preferred(nation, [0, 1, third, fourth]);
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
    }

    pub(super) fn trader_set_trade_bids(&mut self, nation: MajorNationId) {
        let prices = self.sorted_processed_prices();
        let divisor = if self.nations.majors[&nation].common.treasury < 0 {
            1
        } else {
            4
        };
        let budget = self.trade_offer_cap(nation) / divisor;
        let mut selected = 3_i16;
        let mut allocated = 0_i16;
        while budget > allocated && selected >= 1 {
            let resource = prices[(selected as usize) - 1];
            let stock = self.city_stock(nation, resource);
            self.set_trade_potential(nation, resource, stock);
            allocated += stock;
            selected -= 1;
        }
        self.offer_surplus_arms(nation);
    }

    pub(super) fn arms_set_buy_priorities(&mut self, nation: MajorNationId) {
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
    }

    pub(super) fn arms_set_trade_bids(&mut self, nation: MajorNationId) {
        let prices = self.sorted_processed_prices();
        let budget = self.trade_offer_cap(nation) / 2;
        let mut selected = 3_i16;
        let mut allocated = 0_i16;
        while allocated < budget && selected >= 1 {
            let resource = prices[(selected as usize) - 1];
            let stock = self.city_stock(nation, resource);
            let amount = stock.min(budget - allocated);
            self.set_trade_potential(nation, resource, amount);
            allocated += amount;
            selected -= 1;
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
        let mut amounts = [0_i16; 17];
        let mut selected = 3_i16;
        let mut iteration = 0_i32;
        while target > 0 && iteration < i32::from(target) * 3 {
            let resource = prices[(selected as usize) - 1];
            let index = resource as usize;
            if amounts[index] < self.city_stock(nation, resource) {
                amounts[index] += 1;
                self.set_trade_potential(nation, resource, amounts[index]);
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
                    self.market.rows[trade_commodity(resource)].price as i16,
                ),
                |a, b| compare_by_price(&(a.0 as i16, a.1), &(b.0 as i16, b.1)),
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

    pub(super) fn cotton_or_wool_roll(&mut self) -> i16 {
        if self.rng.next_crt_rand() < 0x3ffe {
            0
        } else {
            1
        }
    }

    pub(super) fn set_preferred(&mut self, nation: MajorNationId, codes: [i16; 4]) {
        self.foreign_trade_mut(nation).preferred_resources = codes.map(TradeCommodity::from_retail);
    }
}
