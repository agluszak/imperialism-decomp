use super::*;
use crate::market::all_trade_commodities;
use crate::*;

impl GameState {
    pub(super) fn set_minors_trade_bids(&mut self, phase: &mut TradePhase) {
        for minor in MinorNationId::all() {
            if self.nations.minors[minor].is_some() {
                self.set_minor_trade_bids(minor, phase);
            }
        }
        self.tally_minors_trade_bids();
    }

    pub(super) fn set_minor_trade_bids(&mut self, minor: MinorNationId, phase: &TradePhase) {
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
            for resource in RAW_COMMODITIES
                .into_iter()
                .map(TradeCommodity::resource)
                .chain([ResourceKind::Food])
            {
                if i32::from(state.trade.thresholds.general_offer_price)
                    < self.market.rows[trade_commodity(resource)].price
                {
                    state.trade.offers[resource] = state.trade.current_supply[resource];
                }
            }
            for (resource, threshold) in [
                (ResourceKind::Coal, state.trade.thresholds.coal_offer_price),
                (ResourceKind::Iron, state.trade.thresholds.iron_offer_price),
                (ResourceKind::Oil, state.trade.thresholds.oil_offer_price),
            ] {
                offer_or_grant(
                    state,
                    &phase.recurring_grant[minor],
                    resource,
                    threshold,
                    self.market.rows[trade_commodity(resource)].price,
                );
            }
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
        for commodity in MANUFACTURED_COMMODITIES {
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

    pub(super) fn tally_minors_trade_bids(&mut self) {
        let base = minor_offer_base(self.turn.economic_turn);
        for commodity in RAW_COMMODITIES {
            for minor in MinorNationId::all() {
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
                } else {
                    offer_factor(base, value)
                };
                row.adjusted_offer_count += factor;
            }
        }

        for minor in MinorNationId::all() {
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
            row.adjusted_offer_count += offer_factor(base, metric);
        }

        for commodity in MANUFACTURED_COMMODITIES {
            for minor in MinorNationId::all() {
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
    }

    pub(super) fn tally_major_trade_bids(&mut self) {
        let base = major_offer_base(self.turn.economic_turn);
        for nation in MajorNationId::all() {
            if self.major_is_trade_eligible(nation) {
                self.assign_fallback_trade_offers(nation);
            }
        }

        for commodity in all_trade_commodities() {
            for nation in MajorNationId::all() {
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
                    row.adjusted_offer_count += offer_factor(base, metric).min(2.0);
                }
            }
        }
    }

    pub(super) fn assign_fallback_trade_offers(&mut self, nation: MajorNationId) {
        if !self.is_human(nation) {
            self.arrange_materials_offers(nation);
            return;
        }

        let buying_processed = PROCESSED_NEED
            .into_iter()
            .any(|resource| self.nations.majors[nation].economy.item_potentials[resource] < 0);

        if buying_processed {
            let ranked = self.build_independent_major_relationship_list(nation);
            let mut selected = None;
            for resource in PROCESSED_NEED {
                if self.nations.majors[nation].economy.item_potentials[resource] >= 0 {
                    continue;
                }
                if selected.is_none() {
                    for &candidate in ranked.iter().rev() {
                        if !self.is_human(candidate) {
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
                if let Some(candidate) = self.random_eligible_peer(nation) {
                    self.set_trade_offers_for(candidate, ResourceKind::Horses, nation);
                    break;
                }
            }
        }
    }

    pub(super) fn arrange_materials_offers(&mut self, nation: MajorNationId) {
        if let Some(bid) = self.foreign_trade(nation).interior_bid
            && let Some(&selected) = self
                .build_independent_major_relationship_list(nation)
                .last()
        {
            self.set_trade_offers_for(selected, bid.commodity.resource(), nation);
        }

        if self.foreign_trade(nation).purchase_priority[TradeCommodity::Horses] > 0 {
            let mut fallback = None;
            for _ in 1..=0x14 {
                if let Some(candidate) = self.random_eligible_peer(nation) {
                    fallback = Some(candidate);
                    break;
                }
            }
            if let Some(fallback) = fallback {
                self.set_trade_offers_for(fallback, ResourceKind::Horses, nation);
            }
        }
    }

    pub(super) fn set_trade_offers_for(
        &mut self,
        seller: MajorNationId,
        resource: ResourceKind,
        requester: MajorNationId,
    ) {
        if self.is_human(seller) {
            self.add_shortage_event(seller, requester, resource);
            return;
        }

        if self.is_human(requester) {
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
            let stock = self.city_stock(seller, resource);
            let mut cap = 10_i16.min(stock);
            cap = cap.min(self.trade_offer_cap(seller));
            if self.nations.majors[seller].economy.item_potentials[resource] == -1 {
                return;
            }
            self.set_trade_potential(seller, resource, cap);
            return;
        }

        let horses = self.city_stock(seller, ResourceKind::Horses);
        if horses != 0
            && self.nations.majors[seller].economy.item_potentials[ResourceKind::Horses] != -1
        {
            let mut amount = i16::from(horses != 1) + 1;
            amount = amount.min(self.trade_offer_cap(seller));
            self.set_trade_potential(seller, ResourceKind::Horses, amount);
        }
    }

    pub(super) fn raise_need_planning_metrics(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
    ) {
        if let Some(processed) = ProcessedTradeCommodity::from_resource(resource)
            && let Some(ai_trade) = self.nations.majors[nation].economy.ai_trade.as_mut()
        {
            ai_trade.temporary_processed_stock[processed] += 4;
        }
        self.nations.city_mut(nation).adjust_stock(resource, 4);
        let potential = self.nations.majors[nation].economy.item_potentials[resource];
        self.set_trade_potential(nation, resource, potential + 4);
    }

    pub(super) fn add_shortage_event(
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

    pub(super) fn build_independent_major_relationship_list(
        &mut self,
        source: MajorNationId,
    ) -> Vec<MajorNationId> {
        let mut list = Vec::new();
        for candidate in MajorNationId::all() {
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
}
