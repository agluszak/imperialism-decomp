use super::*;
use crate::create_random_game::resource_capability_level;
use crate::*;

impl GameState {
    pub(super) fn run_nation_update_passes(&mut self, phase: &mut TradePhase) {
        for nation in MajorNationId::all() {
            if !self.major_is_trade_eligible(nation) {
                continue;
            }
            if self.is_human(nation) {
                self.reset_player_trade_phase(nation);
            } else {
                self.reset_ai_trade_phase(nation);
            }
        }

        for minor in MinorNationId::all() {
            if self.nations.minors.contains_key(&minor) {
                self.initialize_minor_trade_status(minor, phase);
            }
        }

        for nation in MajorNationId::all() {
            if !self.major_is_trade_eligible(nation) {
                continue;
            }
            if self.is_human(nation) {
                if self.turn.difficulty == Difficulty::Introductory
                    && self.turn.phase == PhaseCode::CAPITAL_SELECTION
                {
                    for resource in [
                        ResourceKind::Food,
                        ResourceKind::Cotton,
                        ResourceKind::Wool,
                        ResourceKind::Timber,
                    ] {
                        self.set_trade_potential(nation, resource, -1);
                    }
                    self.nations.majors[&nation].economy.remember_trade_bids();
                }
            } else {
                self.set_ai_trade_bids(nation);
                self.do_usual_subsidy_rule(nation);
            }
        }
    }

    pub(super) fn reset_ai_trade_phase(&mut self, nation: MajorNationId) {
        self.refresh_merchant_capacity(nation);
        let major = &mut self.nations.majors[&nation].economy;
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
            let Some(state) = self.nations.minors.get_mut(&minor) else {
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
                    if let Some(state) = self.nations.minors.get_mut(&minor) {
                        state.trade.current_supply[resource] += yield_level;
                    }
                }
            } else {
                for resource in tile.edge_resources.into_iter().flatten() {
                    if tile.gate == 0x0f {
                        continue;
                    }
                    if let Some(state) = self.nations.minors.get_mut(&minor) {
                        state.trade.current_supply[resource] += 1;
                        state.trade.independent_resource_counts[resource] += 1;
                    }
                }
            }
        }

        let mut aid = Vec::new();
        for major in MajorNationId::all() {
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
