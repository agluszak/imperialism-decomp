//! Diplomacy resolution (`TDiplomacyMgr::ApplyDiplomacyInterNationStatesForTurn`
//! plus per-nation `ReplyToDiplomacyOffers` and one queued war transition).

mod change_master;
mod offers;
mod planner;
mod relationships;
mod scores;
#[cfg(test)]
mod tests;
mod war;

use crate::*;

pub(super) const PLANNING_QUARTER: MajorNationTable<u32> =
    MajorNationTable::from_array([0, 3, 1, 2, 1, 2, 0]);
pub(super) const WAR_FOREIGN: [f32; 8] = [0.7, 1.1, 1.2, 1.5, 1.0, 0.9, 0.7, 0.0];
pub(super) const WAR_DEFENSE: [f32; 6] = [1.0, 1.0, 1.3, 1.3, 1.3, 0.0];
pub(super) const SEEK_ALLIANCE_FOREIGN: [f32; 8] = [0.6, 0.7, 0.7, 0.7, 0.8, 0.6, 0.6, 0.0];
pub(super) const SEEK_ALLIANCE_DEFENSE: [f32; 6] = [0.7, 1.1, 1.3, 0.9, 1.0, 0.0];
pub(super) const ACCEPT_ALLIANCE_FOREIGN: [f32; 8] = [0.5, 0.6, 0.6, 0.6, 0.7, 0.5, 0.5, 0.0];
pub(super) const ACCEPT_ALLIANCE_DEFENSE: [f32; 6] = [1.0, 1.0, 1.2, 0.8, 0.9, 0.0];
pub(super) const SEEK_PEACE_FOREIGN: [f32; 8] = [0.4, 0.5, 0.5, 0.5, 0.6, 0.4, 0.4, 0.0];
pub(super) const SEEK_PEACE_DEFENSE: [f32; 6] = [1.1, 1.0, 1.3, 0.7, 1.1, 0.0];
pub(super) const ACCEPT_PEACE_FOREIGN: [f32; 8] = [0.4, 0.5, 0.5, 0.5, 0.6, 0.4, 0.4, 0.0];
pub(super) const ACCEPT_PEACE_DEFENSE: [f32; 6] = [0.9, 0.8, 1.1, 0.5, 0.9, 0.0];
pub(super) const ALLY_WEIGHT: f32 = -0.25;
pub(super) const PEER_WEIGHT: f32 = -0.5;
pub(super) const YEAR_BIAS: f32 = -90.0;
pub(super) const STRENGTH_OFFSET: f32 = -100.0;
pub(super) const MANUFACTURED: [ResourceKind; 4] = [
    ResourceKind::Clothing,
    ResourceKind::Furniture,
    ResourceKind::Hardware,
    ResourceKind::Arms,
];
pub(super) const RAW_TRADE: [TradeCommodity; 7] = [
    TradeCommodity::Cotton,
    TradeCommodity::Wool,
    TradeCommodity::Timber,
    TradeCommodity::Coal,
    TradeCommodity::Iron,
    TradeCommodity::Horses,
    TradeCommodity::Oil,
];

impl GameState {
    /// Applies posted diplomacy and replies to resulting offers.
    ///
    /// AI nations auto-reply. A human offer that retail would pose as a dialog
    /// returns [`DiplomacyPhaseResult::Offer`]; [`Self::resolve_diplomacy_offer`]
    /// continues the same pass. After replies complete, one queued war is
    /// processed and may return [`DiplomacyPhaseResult::WarJoin`].
    pub fn do_diplomacy(&mut self) -> DiplomacyPhaseResult {
        self.apply_diplomacy_inter_nation_states();
        let result = self.reply_to_diplomacy_offers_from(0, 0);
        self.record_diplomacy_result(result)
    }

    /// Accepts or rejects the offer stored in the current continuation, then
    /// continues the remaining replies.
    pub(crate) fn resolve_diplomacy_offer(&mut self, accept: bool) -> DiplomacyPhaseResult {
        let crate::turn_flow::TurnContinuation::DiplomacyOffer { nation, index } =
            self.continuation
        else {
            panic!("diplomacy offer reply requires an active offer continuation");
        };
        self.continuation = crate::turn_flow::TurnContinuation::None;
        self.apply_human_offer_decision(nation, usize::from(index), accept);
        let result = self.reply_to_diplomacy_offers_from(nation.get(), usize::from(index) + 1);
        self.record_diplomacy_result(result)
    }

    /// Accepts or rejects the war-join dialog stored in the current continuation,
    /// then finishes the remaining reactions for that one war.
    pub(crate) fn resolve_diplomacy_war_join(&mut self, accept: bool) -> DiplomacyPhaseResult {
        let crate::turn_flow::TurnContinuation::DiplomacyWarJoin(prompt) = self.continuation else {
            panic!("diplomacy war-join reply requires an active war-join continuation");
        };
        self.continuation = crate::turn_flow::TurnContinuation::None;
        self.apply_war_join_decision(prompt, accept);
        let result =
            self.continue_war_reactions(prompt.pair_first, prompt.pair_second, prompt.cursor);
        self.record_diplomacy_result(result)
    }

    fn record_diplomacy_result(&mut self, result: DiplomacyPhaseResult) -> DiplomacyPhaseResult {
        self.continuation = match result {
            DiplomacyPhaseResult::Resolved => crate::turn_flow::TurnContinuation::None,
            DiplomacyPhaseResult::Offer(prompt) => {
                crate::turn_flow::TurnContinuation::DiplomacyOffer {
                    nation: prompt.nation,
                    index: prompt.index,
                }
            }
            DiplomacyPhaseResult::WarJoin(prompt) => {
                crate::turn_flow::TurnContinuation::DiplomacyWarJoin(prompt)
            }
        };
        result
    }

    fn apply_diplomacy_inter_nation_states(&mut self) {
        for nation in MajorNationId::all().rev() {
            if !self.nation_is_present(nation.nation()) {
                continue;
            }
            if self.is_auto(nation) {
                self.set_ai_diplomacy_policies(nation);
            }
        }

        for source in majors() {
            if !self.nation_is_present(source.nation()) {
                continue;
            }
            for target in NationId::all() {
                if !self.nation_is_present(target) {
                    continue;
                }
                let grant = self.nations.majors[source]
                    .economy
                    .diplomacy_grants_by_nation[target];
                if let Some(grant) = grant {
                    if let Some(major) = MajorNationId::from_nation(target) {
                        self.add_diplomacy_notice(
                            major,
                            NationId::new(0),
                            grant_notice_code(grant),
                        );
                    }
                    self.give_grant_to(source, target);
                }
                let Some(policy) = self.nations.majors[source]
                    .economy
                    .diplomacy_policy_by_nation[target]
                else {
                    continue;
                };
                match policy {
                    DiplomacyPolicy::BuildConsulate => {
                        self.set_mission_level(
                            source.nation(),
                            target,
                            DiplomaticMissionLevel::TradeConsulate,
                        );
                        self.add_treaty_event(
                            InterNationNewsKind::TradeConsulateEstablished,
                            source.nation(),
                            target,
                        );
                    }
                    DiplomacyPolicy::BuildEmbassy => {
                        self.set_mission_level(
                            source.nation(),
                            target,
                            DiplomaticMissionLevel::Embassy,
                        );
                        self.add_treaty_event(
                            InterNationNewsKind::EmbassyEstablished,
                            source.nation(),
                            target,
                        );
                    }
                    DiplomacyPolicy::DeclareWar => {
                        if !self.at_war(source.nation(), target) {
                            self.queue_war(source.nation(), target, None);
                        }
                    }
                    _ => self.add_diplomacy_offer(target, source.nation(), policy),
                }
            }
        }
    }
}

impl GameState {
    pub(crate) fn has_alliance_guard(&self, nation: NationId, guarded: NationId) -> bool {
        if !majors().any(|index| self.at_war(nation, index.nation())) {
            return false;
        }
        majors().any(|index| {
            let other = index.nation();
            self.at_war(other, nation) && !self.at_war(guarded, other)
        })
    }

    pub(super) fn minor_would_accept_join_empire(&self, minor: NationId, source: NationId) -> bool {
        if !self.is_independent(minor) {
            return false;
        }
        let standing = self.diplomacy.standings[minor][source];
        if standing <= 0xf9 {
            return false;
        }
        majors().all(|index| {
            let peer = index.nation();
            !self.nation_is_present(peer)
                || peer == source
                || (self.diplomacy.standings[minor][peer] - standing).abs() >= 10
        })
    }

    pub(super) fn manufactured_offers_exhausted(&self, nation: MajorNationId) -> bool {
        !MANUFACTURED.into_iter().any(|resource| {
            let potential = self.nations.majors[nation].economy.item_potentials[resource];
            potential > 0
                && self.nations.majors[nation]
                    .economy
                    .purchased_items_by_resource[resource]
                    + potential
                    > 0
        })
    }

    pub(crate) fn can_afford_diplomacy(&self, nation: MajorNationId, cost: i32) -> bool {
        let major = &self.nations.majors[nation];
        major
            .economy
            .available_diplomacy_budget(major.common.treasury)
            - major.economy.grant_total_cost
            - cost
            >= 0
    }

    pub(crate) fn war_stamp_stale(&self, source: NationId, target: NationId) -> bool {
        self.at_war(source, target)
            && self.diplomacy.relationship_turns[source][target]
                != Some(self.turn.economic_turn as i16)
    }

    pub(super) fn owns_former_province_of(&self, owner: MajorNationId, former: NationId) -> bool {
        let regions = self.nations.majors[owner].common.owned_regions();
        regions
            .iter()
            .take(regions.len().saturating_sub(1))
            .any(|&province| self.map.provinces[province].former_owner() == Some(former))
    }

    pub(super) fn recovered_province_count(&self, owner: MajorNationId, former: NationId) -> i32 {
        let regions = self.nations.majors[owner].common.owned_regions();
        regions
            .iter()
            .take(regions.len().saturating_sub(1))
            .filter(|&&province| self.map.provinces[province].former_owner() == Some(former))
            .count() as i32
    }

    pub(super) fn ranked_independents(
        &mut self,
        source: NationId,
        majors_only: bool,
    ) -> Vec<NationId> {
        let mut ranked = Vec::new();
        let mut consider = |nation: NationId| {
            if nation == source || !self.nation_is_present(nation) || !self.is_independent(nation) {
                return;
            }
            let standing = self.diplomacy.standings[source][nation];
            insert_sorted_by_key(&mut self.rng, &mut ranked, (standing, nation), |entry| {
                entry.0
            });
        };
        if majors_only {
            MajorNationId::all()
                .map(MajorNationId::nation)
                .for_each(&mut consider);
        } else {
            MinorNationId::all()
                .map(MinorNationId::nation)
                .for_each(&mut consider);
        }
        ranked.into_iter().map(|(_, nation)| nation).collect()
    }

    pub(super) fn favorite_with_embassy(&mut self, minor: NationId) -> Option<MajorNationId> {
        self.ranked_independents(minor, true)
            .into_iter()
            .rev()
            .find(|&nation| {
                self.diplomacy.mission_levels[minor][nation] == DiplomaticMissionLevel::Embassy
            })
            .and_then(MajorNationId::from_nation)
    }

    pub(super) fn has_active_candidates(&mut self, nation: MajorNationId) -> bool {
        let mut any = false;
        for candidate in majors() {
            let present = self.nations.major_is_present(candidate);
            let flag = &mut self.nations.majors[nation].economy.candidate_nation_flags
                [candidate.nation()];
            if !present {
                *flag = 0;
            } else if *flag != 0 {
                any = true;
            }
        }
        for minor in MinorNationId::all().map(MinorNationId::nation) {
            if self.nations.majors[nation].economy.candidate_nation_flags[minor] == 0 {
                continue;
            }
            let empty = self
                .nations
                .common(minor)
                .is_none_or(|common| common.owned_regions().is_empty());
            if empty {
                self.nations.majors[nation].economy.candidate_nation_flags[minor] = 0;
                if self.at_war(nation.nation(), minor) {
                    self.set_nation_pair_relationship(
                        nation.nation(),
                        minor,
                        DiplomaticRelationship::Peace,
                        true,
                    );
                }
            } else {
                any = true;
            }
        }
        any
    }

    pub(crate) fn set_colony_boycott(
        &mut self,
        nation: MajorNationId,
        target: NationId,
        enabled: bool,
    ) {
        self.nations.majors[nation].economy.colony_boycott_flags[target] = u8::from(enabled);
        let policy = if enabled {
            TradePolicyScore::new(0x64 + 0xc8)
        } else {
            TradePolicyScore::NEUTRAL
        };
        for minor in MinorNationId::all().map(MinorNationId::nation) {
            if self
                .nations
                .common(minor)
                .is_some_and(|common| common.status() == CountryStatus::ColonyOf(nation.nation()))
            {
                self.set_one_trade(minor, target, policy);
            }
        }
    }

    pub(crate) fn at_war(&self, source: NationId, target: NationId) -> bool {
        self.diplomacy.relationships[source][target] == DiplomaticRelationship::War
    }

    pub(crate) fn is_auto(&self, nation: MajorNationId) -> bool {
        self.nations.major_is_present(nation) && self.nations.majors[nation].is_auto()
    }

    pub(super) fn is_independent(&self, nation: NationId) -> bool {
        self.nations
            .common(nation)
            .is_some_and(|common| common.status() == CountryStatus::Independent)
    }

    pub(crate) fn status_of(&self, nation: NationId) -> CountryStatus {
        self.nations
            .common(nation)
            .map(|common| common.status())
            .unwrap_or(CountryStatus::Independent)
    }

    pub(crate) fn owner_slot(&self, nation: NationId) -> NationId {
        match self.status_of(nation) {
            CountryStatus::ColonyOf(master) | CountryStatus::ProtectorateOf(master) => master,
            CountryStatus::Independent => nation,
        }
    }

    pub(crate) fn event_eligible(&self, nation: NationId) -> bool {
        if !self.nation_is_present(nation) {
            return false;
        }
        MajorNationId::from_nation(nation).is_none_or(|major| self.major_is_event_eligible(major))
    }

    pub(super) fn in_consortium_with(&self, minor: NationId, source: NationId) -> bool {
        self.nations.minors[MinorNationId::new(minor.get())]
            .as_ref()
            .is_some_and(|nation| {
                nation
                    .consortium_members
                    .iter()
                    .any(|member| member.nation() == source)
            })
    }

    pub(super) fn nation_is_present(&self, nation: NationId) -> bool {
        self.nations.common(nation).is_some()
    }

    pub(super) fn insert_sorted_proposal(
        &mut self,
        nation: MajorNationId,
        proposal: DiplomacyProposal,
    ) {
        insert_sorted_by_key(
            &mut self.rng,
            &mut self.pending.nations[nation].proposals,
            proposal,
            |entry| i16::from(entry.source.get()),
        );
    }

    pub(super) fn insert_sorted_notice(&mut self, nation: MajorNationId, notice: DiplomacyNotice) {
        insert_sorted_by_key(
            &mut self.rng,
            &mut self.pending.nations[nation].turn_events,
            notice,
            |entry| i16::from(entry.source.get()),
        );
    }
}

pub(super) fn majors() -> impl Iterator<Item = MajorNationId> {
    MajorNationId::all()
}

pub(super) fn at_least_one(score: f32) -> f32 {
    score.trunc().max(1.0)
}

pub(super) fn truncated_average(a: f32, b: f32) -> f32 {
    ((a as i32 + b as i32) / 2) as f32
}

pub(super) fn enemy_army_threshold(difficulty: Difficulty) -> i32 {
    match difficulty {
        Difficulty::Introductory => 0x15,
        Difficulty::Easy => 0x12,
        Difficulty::Normal => 0xf,
        Difficulty::Hard => 0xd,
        Difficulty::NighOnImpossible => 0xb,
    }
}

pub(super) fn enemy_navy_threshold(difficulty: Difficulty) -> i32 {
    match difficulty {
        Difficulty::Introductory => 0x1b,
        Difficulty::Easy => 0x17,
        Difficulty::Normal => 0x13,
        Difficulty::Hard => 0x10,
        Difficulty::NighOnImpossible => 0xe,
    }
}

pub(super) fn year_divisor(difficulty: Difficulty, year: i32) -> i32 {
    match difficulty {
        Difficulty::Introductory => year,
        Difficulty::Easy => year / 2,
        Difficulty::Normal => year / 3,
        Difficulty::Hard => year / 5,
        Difficulty::NighOnImpossible => 0,
    }
}

pub(super) fn coeff(table: &[f32], index: i16) -> f32 {
    table.get(index as usize).copied().unwrap_or(0.0)
}

pub(super) fn select_grant_amount(budget: i32) -> i32 {
    if budget < 3000 {
        1000
    } else if budget < 5000 {
        3000
    } else if budget < 10_000 {
        5000
    } else {
        10_000
    }
}

pub(super) fn grant_notice_code(grant: DiplomacyGrant) -> i16 {
    let amount = grant.amount as i16;
    if grant.recurring {
        amount | 0x4000
    } else {
        amount
    }
}

fn insert_sorted_by_key<T>(
    rng: &mut RngState,
    items: &mut Vec<T>,
    new_item: T,
    key: impl Fn(&T) -> i16,
) {
    let new_key = key(&new_item);
    let mut ordinal = 0;
    while ordinal < items.len() {
        let existing_key = key(&items[ordinal]);
        let cmp = if existing_key < new_key {
            1
        } else if new_key < existing_key {
            -1
        } else if rng.next_crt_rand() % 2 != 0 {
            1
        } else {
            -1
        };
        if cmp != 1 {
            items.insert(ordinal, new_item);
            return;
        }
        ordinal += 1;
    }
    items.push(new_item);
}
