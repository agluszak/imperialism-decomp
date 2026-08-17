use super::*;
use crate::create_random_game::resource_capability_level;
use crate::*;

impl GameState {
    pub(super) fn run_nation_update_passes(&mut self, phase: &mut TradePhase) {
        for (_, major) in self
            .nations
            .live_majors_mut()
            .filter(|(_, major)| Self::major_is_trade_eligible(major))
        {
            if major.is_auto() {
                Self::reset_ai_trade_phase(major);
            } else {
                major.reset_player_trade_phase();
            }
        }

        for minor in MinorNationId::all() {
            if self.nations.minors[minor].is_some() {
                self.initialize_minor_trade_status(minor, phase);
            }
        }

        if self.turn.difficulty == Difficulty::Introductory
            && self.turn.phase == PhaseCode::CAPITAL_SELECTION
        {
            for (_, major) in self
                .nations
                .live_majors_mut()
                .filter(|(_, major)| !major.is_auto() && Self::major_is_trade_eligible(major))
            {
                for resource in [
                    ResourceKind::Food,
                    ResourceKind::Cotton,
                    ResourceKind::Wool,
                    ResourceKind::Timber,
                ] {
                    major.economy.set_item_potential(resource, -1);
                }
                major.remember_trade_bids();
            }
        }

        let has_trade_candidate = MinorNationId::all().any(|minor| {
            let nation = minor.nation();
            self.nation_present(nation)
                && (self.market.rows[TradeCommodity::Coal].maximum_offer_by_nation[nation] != 0
                    || self.market.rows[TradeCommodity::Iron].maximum_offer_by_nation[nation] != 0)
        });
        let at_war = MajorNationTable::from_fn(|nation| self.has_any_war(nation.nation()));
        let economic_turn = self.turn.economic_turn;
        let (nations, rng, market, technology) = (
            &mut self.nations,
            &mut self.rng,
            &self.market,
            &self.technology,
        );
        for (nation, major) in nations
            .live_majors_mut()
            .filter(|(_, major)| major.is_auto() && Self::major_is_trade_eligible(major))
        {
            Self::set_ai_trade_bids(
                major,
                technology.city_capabilities_by_nation[nation].oil_drilling,
                has_trade_candidate,
                economic_turn,
                at_war[nation],
                rng,
                market,
            );
            Self::do_usual_subsidy_rule(
                major,
                technology.city_capabilities_by_nation[nation].oil_drilling,
                rng,
                market,
            );
        }
    }

    pub(super) fn reset_ai_trade_phase(major: &mut MajorNation) {
        major.refresh_merchant_capacity();
        let major = &mut major.economy;
        major.unfilled_trade_offer_count = 0;
        major.budget_pool_delta = 0;
        major.budget_pool_base = 0;
        major.item_potentials = ResourceTable::default();
        major.aid_allocation_by_minor_nation = Default::default();
    }

    pub(super) fn initialize_minor_trade_status(
        &mut self,
        minor: MinorNationId,
        phase: &mut TradePhase,
    ) {
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
        for major in self.nations.live_major_ids() {
            for (resource, scale) in [(ResourceKind::Gold, 200), (ResourceKind::Gems, 500)] {
                let yield_level = phase.status_by_major[minor][resource][usize::from(major.get())];
                if yield_level != 0 {
                    let standing = self.diplomacy.standings[minor.nation()][major.nation()];
                    aid.push((
                        major,
                        resource,
                        i32::from(standing) * i32::from(yield_level) * scale / 255,
                    ));
                }
            }
        }
        for (major, resource, amount) in aid {
            self.add_aid_allocation(major, minor, resource, amount);
        }
    }
}
