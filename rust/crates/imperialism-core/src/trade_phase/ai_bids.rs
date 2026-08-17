use super::*;
use crate::market::all_trade_commodities;
use crate::*;

impl MajorNation {
    fn set_preferred_trade_resources(&mut self, codes: [i16; 4]) {
        self.economy.foreign_trade.preferred_resources = codes.map(TradeCommodity::from_retail);
    }
}

impl GameState {
    pub(super) fn set_ai_trade_bids(
        major: &mut MajorNation,
        has_oil: bool,
        has_trade_candidate: bool,
        economic_turn: i32,
        at_war: bool,
        rng: &mut RngState,
        market: &TradeMarketState,
    ) {
        let personality = major.economy.foreign_minister_personality;
        Self::prepare_personality_trade_bids(
            major,
            has_oil,
            has_trade_candidate,
            economic_turn,
            rng,
            market,
        );
        if personality != ForeignMinisterPersonality::Base {
            let preferred = major.economy.foreign_trade.preferred_resources;
            for resource in preferred.into_iter().flatten() {
                major.economy.set_item_potential(resource.resource(), -1);
            }
        }
        match personality {
            ForeignMinisterPersonality::Ted => Self::ted_set_trade_bids(major, market, at_war),
            ForeignMinisterPersonality::Bill => Self::bill_set_trade_bids(major, market, at_war),
            ForeignMinisterPersonality::Diplomat => {
                Self::diplomat_set_trade_bids(major, market, at_war)
            }
            ForeignMinisterPersonality::Textile => {
                Self::textile_set_trade_bids(major, market, at_war)
            }
            ForeignMinisterPersonality::Trader => {
                Self::trader_set_trade_bids(major, market, at_war)
            }
            ForeignMinisterPersonality::Arms => Self::arms_set_trade_bids(major, market, at_war),
            ForeignMinisterPersonality::Base => {}
        }
    }

    fn prepare_personality_trade_bids(
        major: &mut MajorNation,
        has_oil: bool,
        has_trade_candidate: bool,
        economic_turn: i32,
        rng: &mut RngState,
        market: &TradeMarketState,
    ) {
        let treasury = major.common.treasury;
        let needs_money = Self::we_need_money(major);
        let trade = &mut major.economy.foreign_trade;
        trade.trade_partner_enabled = [1; 7];
        trade.capability_flag_16 = 0;
        if treasury < 0 {
            trade.capability_flag_14 = 1;
        }
        if trade.phase_counter >= trade.refresh_interval || needs_money {
            if major.economy.pending_ship.is_none() {
                major.economy.pending_ship = trade.requested_ship;
            }
            trade.phase_counter = 0;
        }
        Self::set_buy_priorities(
            major,
            has_oil,
            has_trade_candidate,
            economic_turn,
            rng,
            market,
        );
        if let Some(bid) = major.economy.foreign_trade.interior_bid {
            major
                .economy
                .set_item_potential(bid.commodity.resource(), -1);
            major.economy.foreign_trade.purchase_priority[bid.commodity] = bid.amount;
        }
    }

    fn we_need_money(major: &MajorNation) -> bool {
        let cap = major.economy.capacities.trade_offer;
        [
            ResourceKind::Clothing,
            ResourceKind::Furniture,
            ResourceKind::Hardware,
        ]
        .into_iter()
        .any(|resource| major.city.stockpile[resource] >= cap)
    }

    fn set_buy_priorities(
        major: &mut MajorNation,
        has_oil: bool,
        has_trade_candidate: bool,
        economic_turn: i32,
        rng: &mut RngState,
        market: &TradeMarketState,
    ) {
        let personality = major.economy.foreign_minister_personality;
        match personality {
            ForeignMinisterPersonality::Ted => Self::ted_set_buy_priorities(major, has_oil, rng),
            ForeignMinisterPersonality::Bill => Self::bill_set_buy_priorities(major, has_oil),
            ForeignMinisterPersonality::Diplomat => Self::diplomat_set_buy_priorities(
                major,
                has_oil,
                has_trade_candidate,
                economic_turn,
                rng,
                market,
            ),
            ForeignMinisterPersonality::Textile => Self::textile_set_buy_priorities(major, has_oil),
            ForeignMinisterPersonality::Trader => {
                Self::trader_set_buy_priorities(major, has_oil, market)
            }
            ForeignMinisterPersonality::Arms => Self::arms_set_buy_priorities(major, has_oil, rng),
            ForeignMinisterPersonality::Base => {}
        }
        Self::base_set_buy_priorities(major);
    }

    fn base_set_buy_priorities(major: &mut MajorNation) {
        let trade = &major.economy.foreign_trade;
        let mut priorities = Vec::new();
        for commodity in all_trade_commodities() {
            let priority = trade.purchase_priority[commodity];
            if priority != 0 {
                insert_sorted(
                    &mut priorities,
                    (resource_code(Some(commodity)), priority + 1),
                    compare_index_and_rank,
                );
            }
        }
        for resource in trade.preferred_resources {
            let code = resource_code(resource);
            if !priorities.iter().any(|&(existing, _)| existing == code) {
                insert_sorted(&mut priorities, (code, 1), compare_index_and_rank);
            }
        }
        let preferred = std::array::from_fn(|index| {
            let code = priorities
                .get(index)
                .map(|(code, _)| *code)
                .unwrap_or(NO_RESOURCE);
            TradeCommodity::from_retail(code)
        });
        major.economy.foreign_trade.preferred_resources = preferred;
    }

    pub(super) fn do_usual_subsidy_rule(
        major: &mut MajorNation,
        has_oil: bool,
        rng: &mut RngState,
        market: &TradeMarketState,
    ) {
        let loop_count = i32::from(has_oil) + 5;
        for resource in RAW_COMMODITIES
            .into_iter()
            .map(TradeCommodity::resource)
            .take(loop_count as usize)
        {
            let roll = rng.next_crt_rand();
            let price = market.rows[trade_commodity(resource)].price;
            if roll % 100 + 200 < price {
                major.economy.set_item_potential(
                    resource,
                    subsidy_from_stock(major.city.stockpile[resource]),
                );
            }
        }

        let roll = rng.next_crt_rand();
        let price = market.rows[TradeCommodity::Horses].price;
        if roll % 100 + 200 < price {
            major.economy.set_item_potential(
                ResourceKind::Horses,
                subsidy_from_stock(major.city.stockpile[ResourceKind::Horses]),
            );
        }
    }

    fn ted_set_buy_priorities(major: &mut MajorNation, has_oil: bool, rng: &mut RngState) {
        let stockpile = major.city.stockpile.clone();
        let stock = |resource| stockpile[resource];
        if !has_oil {
            let iron_first = stock(ResourceKind::Iron) < stock(ResourceKind::Coal);
            let fourth = Self::cotton_or_wool_roll(rng);
            if iron_first {
                major.set_preferred_trade_resources([4, 2, 3, fourth]);
            } else {
                major.set_preferred_trade_resources([3, 2, 4, fourth]);
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
        preferred[3] = Self::cotton_or_wool_roll(rng);
        major.set_preferred_trade_resources(preferred);
    }

    fn ted_set_trade_bids(major: &mut MajorNation, market: &TradeMarketState, at_war: bool) {
        let treasury = major.common.treasury;
        let cap = major.economy.capacities.trade_offer;
        let hardware = major.city.stockpile[ResourceKind::Hardware];
        if treasury >= 0 && cap > hardware && hardware < 10 {
            Self::offer_all_stock(major, ResourceKind::Clothing);
            Self::offer_all_stock(major, ResourceKind::Furniture);
        } else {
            let amount = cap.min(hardware);
            major
                .economy
                .set_item_potential(ResourceKind::Hardware, amount);
            if cap > amount * 2 {
                Self::offer_all_stock(major, ResourceKind::Clothing);
                Self::offer_all_stock(major, ResourceKind::Furniture);
            }
        }
        Self::ted_style_arms_bid(major, market, at_war, 1500);
    }

    fn bill_set_buy_priorities(major: &mut MajorNation, has_oil: bool) {
        let stockpile = major.city.stockpile.clone();
        let stock = |resource| stockpile[resource];
        if has_oil {
            if stock(ResourceKind::Iron) < stock(ResourceKind::Coal) {
                major.set_preferred_trade_resources([4, 2, 6, 3]);
            } else {
                major.set_preferred_trade_resources([3, 2, 6, 4]);
            }
        } else if stock(ResourceKind::Iron) < stock(ResourceKind::Coal) {
            major.set_preferred_trade_resources([4, 2, 3, NO_RESOURCE]);
        } else {
            major.set_preferred_trade_resources([3, 2, 4, NO_RESOURCE]);
        }
    }

    fn bill_set_trade_bids(major: &mut MajorNation, market: &TradeMarketState, at_war: bool) {
        Self::sell_processed_round_robin(major, market, true);
        Self::ted_style_arms_bid(major, market, at_war, 1500);
    }

    fn diplomat_set_buy_priorities(
        major: &mut MajorNation,
        has_oil: bool,
        has_trade_candidate: bool,
        economic_turn: i32,
        rng: &mut RngState,
        market: &TradeMarketState,
    ) {
        let stock = &major.city.stockpile;
        let iron = stock[ResourceKind::Iron];
        let coal = stock[ResourceKind::Coal];
        let oil = stock[ResourceKind::Oil];
        let cotton = stock[ResourceKind::Cotton];
        let wool = stock[ResourceKind::Wool];
        if has_oil {
            let fourth = if rng.next_crt_rand() % 2 == 0 { 1 } else { 0 };
            if iron < coal {
                major.set_preferred_trade_resources([2, 4, if oil < coal { 6 } else { 3 }, fourth]);
            } else {
                major.set_preferred_trade_resources([2, 3, if oil < iron { 6 } else { 4 }, fourth]);
            }
            return;
        }

        if !has_trade_candidate {
            let fourth = if rng.next_crt_rand() < 0x3ffe { 3 } else { 4 };
            major.set_preferred_trade_resources([2, 0, 1, fourth]);
        } else if (economic_turn / 4) & 1 != 0 {
            let (second, third) = if iron < coal { (4, 3) } else { (3, 4) };
            let fourth = if market.rows[TradeCommodity::Cotton].price
                > market.rows[TradeCommodity::Wool].price
            {
                0
            } else {
                1
            };
            major.set_preferred_trade_resources([2, second, third, fourth]);
        } else {
            let (second, third) = if cotton < wool { (0, 1) } else { (1, 0) };
            let fourth = if iron < coal { 4 } else { 3 };
            major.set_preferred_trade_resources([2, second, third, fourth]);
        }
    }

    fn diplomat_set_trade_bids(major: &mut MajorNation, market: &TradeMarketState, at_war: bool) {
        Self::sell_processed_round_robin(major, market, true);
        Self::offer_surplus_arms(major, market, at_war);
    }

    fn textile_set_buy_priorities(major: &mut MajorNation, has_oil: bool) {
        let mut prices = Vec::new();
        for resource in [ResourceKind::Coal, ResourceKind::Iron, ResourceKind::Timber] {
            insert_sorted(
                &mut prices,
                (resource as i16, major.city.stockpile[resource]),
                compare_by_price,
            );
        }
        if has_oil {
            insert_sorted(
                &mut prices,
                (
                    ResourceKind::Oil as i16,
                    major.city.stockpile[ResourceKind::Oil],
                ),
                compare_by_price,
            );
        }
        let third = prices.first().map(|(code, _)| *code).unwrap_or(NO_RESOURCE);
        let fourth = prices.get(1).map(|(code, _)| *code).unwrap_or(NO_RESOURCE);
        major.set_preferred_trade_resources([0, 1, third, fourth]);
    }

    fn textile_set_trade_bids(major: &mut MajorNation, market: &TradeMarketState, at_war: bool) {
        let treasury = major.common.treasury;
        let clothing_potential = major.economy.item_potentials[ResourceKind::Clothing];
        let cap = major.economy.capacities.trade_offer;
        let clothing = major.city.stockpile[ResourceKind::Clothing];
        if treasury < 0
            || clothing >= cap
            || (clothing > 4 && market.rows[TradeCommodity::Clothing].price > 1000)
        {
            major
                .economy
                .set_item_potential(ResourceKind::Clothing, clothing.min(cap));
        }
        if treasury < 0 || clothing_potential == 0 {
            let budget = cap / 2;
            let (first, second) = if market.rows[TradeCommodity::Hardware].price
                > market.rows[TradeCommodity::Furniture].price
            {
                (ResourceKind::Hardware, ResourceKind::Furniture)
            } else {
                (ResourceKind::Furniture, ResourceKind::Hardware)
            };
            let first_stock = major.city.stockpile[first];
            let first_amount = first_stock.min(budget);
            major.economy.set_item_potential(first, first_amount);
            let remaining = budget - first_amount;
            let second_stock = major.city.stockpile[second];
            major
                .economy
                .set_item_potential(second, second_stock.min(remaining));
        }
        Self::ted_style_arms_bid(major, market, at_war, 1500);
    }

    fn trader_set_buy_priorities(
        major: &mut MajorNation,
        has_oil: bool,
        market: &TradeMarketState,
    ) {
        let mut prices = Vec::new();
        for commodity in [
            TradeCommodity::Cotton,
            TradeCommodity::Wool,
            TradeCommodity::Timber,
            TradeCommodity::Coal,
            TradeCommodity::Iron,
        ] {
            let mut priority = market.rows[commodity].price as i16;
            if matches!(commodity, TradeCommodity::Coal | TradeCommodity::Iron) {
                priority -= 15;
            }
            insert_sorted(
                &mut prices,
                (resource_code(Some(commodity)), priority),
                compare_by_price,
            );
        }
        if has_oil {
            insert_sorted(
                &mut prices,
                (
                    ResourceKind::Oil as i16,
                    market.rows[TradeCommodity::Oil].price as i16 - 15,
                ),
                compare_by_price,
            );
        }
        let mut preferred = [NO_RESOURCE; 4];
        for (index, &(code, _)) in prices.iter().take(4).enumerate() {
            preferred[index] = code;
        }
        major.set_preferred_trade_resources(preferred);
    }

    fn trader_set_trade_bids(major: &mut MajorNation, market: &TradeMarketState, at_war: bool) {
        let prices = Self::sorted_processed_prices(market);
        let treasury = major.common.treasury;
        let divisor = if treasury < 0 { 1 } else { 4 };
        let budget = major.economy.capacities.trade_offer / divisor;
        let mut selected = 3_i16;
        let mut allocated = 0_i16;
        while budget > allocated && selected >= 1 {
            let resource = prices[(selected as usize) - 1];
            let stock = major.city.stockpile[resource];
            major.economy.set_item_potential(resource, stock);
            allocated += stock;
            selected -= 1;
        }
        Self::offer_surplus_arms(major, market, at_war);
    }

    fn arms_set_buy_priorities(major: &mut MajorNation, has_oil: bool, rng: &mut RngState) {
        if has_oil {
            major.set_preferred_trade_resources([6, 2, 3, 4]);
        } else {
            let fourth = if rng.next_crt_rand() % 2 != 0 { 0 } else { 1 };
            major.set_preferred_trade_resources([2, 3, 4, fourth]);
        }
    }

    fn arms_set_trade_bids(major: &mut MajorNation, market: &TradeMarketState, at_war: bool) {
        let prices = Self::sorted_processed_prices(market);
        let budget = major.economy.capacities.trade_offer / 2;
        let mut selected = 3_i16;
        let mut allocated = 0_i16;
        while allocated < budget && selected >= 1 {
            let resource = prices[(selected as usize) - 1];
            let stock = major.city.stockpile[resource];
            let amount = stock.min(budget - allocated);
            major.economy.set_item_potential(resource, amount);
            allocated += amount;
            selected -= 1;
        }
        if major.common.treasury < 0 && !at_war {
            let available = major.city.stockpile[ResourceKind::Arms];
            let mut amount = available / 10;
            if amount > 10 {
                amount = 10;
            }
            if amount > 2 {
                major.economy.set_item_potential(ResourceKind::Arms, amount);
            } else if available > 6 {
                major.economy.set_item_potential(ResourceKind::Arms, 2);
            }
        }
    }

    fn offer_surplus_arms(major: &mut MajorNation, market: &TradeMarketState, at_war: bool) {
        if market.rows[TradeCommodity::Arms].price > 1200
            && major.city.stockpile[ResourceKind::Arms] > 6
            && !at_war
        {
            major.economy.set_item_potential(ResourceKind::Arms, 2);
        }
    }

    fn sell_processed_round_robin(
        major: &mut MajorNation,
        market: &TradeMarketState,
        half_capacity: bool,
    ) {
        let cap = major.economy.capacities.trade_offer;
        let treasury = major.common.treasury;
        let target = if treasury < 0 || !half_capacity {
            cap
        } else {
            cap / 2
        };
        let prices = Self::sorted_processed_prices(market);
        let mut amounts = [0_i16; 17];
        let mut selected = 3_i16;
        let mut iteration = 0_i32;
        while target > 0 && iteration < i32::from(target) * 3 {
            let resource = prices[(selected as usize) - 1];
            let index = resource as usize;
            if amounts[index] < major.city.stockpile[resource] {
                amounts[index] += 1;
                major.economy.set_item_potential(resource, amounts[index]);
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

    fn sorted_processed_prices(market: &TradeMarketState) -> [ResourceKind; 3] {
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
                    market.rows[trade_commodity(resource)].price as i16,
                ),
                |a, b| compare_by_price(&(a.0 as i16, a.1), &(b.0 as i16, b.1)),
            );
        }
        [prices[0].0, prices[1].0, prices[2].0]
    }

    fn ted_style_arms_bid(
        major: &mut MajorNation,
        market: &TradeMarketState,
        at_war: bool,
        threshold: i32,
    ) {
        if market.rows[TradeCommodity::Arms].price > threshold && !at_war {
            let available = major.city.stockpile[ResourceKind::Arms];
            let amount = available / 10;
            if amount > 2 {
                major.economy.set_item_potential(ResourceKind::Arms, amount);
            } else if available > 6 {
                major.economy.set_item_potential(ResourceKind::Arms, 2);
            }
        }
    }

    fn offer_all_stock(major: &mut MajorNation, resource: ResourceKind) {
        major
            .economy
            .set_item_potential(resource, major.city.stockpile[resource]);
    }

    fn cotton_or_wool_roll(rng: &mut RngState) -> i16 {
        if rng.next_crt_rand() < 0x3ffe { 0 } else { 1 }
    }
}
