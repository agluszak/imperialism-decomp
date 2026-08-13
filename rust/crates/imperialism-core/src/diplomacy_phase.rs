//! Diplomacy resolution (`TDiplomacyMgr::ApplyDiplomacyInterNationStatesForTurn`
//! plus per-nation `ReplyToDiplomacyOffers`).

use crate::*;

impl GameState {
    /// Applies posted diplomacy and replies to resulting offers.
    ///
    /// AI nations auto-reply. A human offer that retail would pose as a dialog
    /// returns [`DiplomacyPhaseResult::Offer`]; [`Self::resolve_diplomacy_offer`]
    /// continues the same pass.
    pub fn do_diplomacy(&mut self) -> DiplomacyPhaseResult {
        self.apply_diplomacy_inter_nation_states();
        self.reply_to_diplomacy_offers_from(0, 0)
    }

    /// Accepts or rejects the offer that stopped [`Self::do_diplomacy`], then
    /// continues the remaining replies.
    pub fn resolve_diplomacy_offer(
        &mut self,
        prompt: DiplomacyOfferPrompt,
        accept: bool,
    ) -> DiplomacyPhaseResult {
        let index = usize::from(prompt.index);
        let queued = self.pending.nations[prompt.nation]
            .proposals
            .get(index)
            .copied();
        debug_assert_eq!(
            queued,
            Some(DiplomacyProposal {
                source: prompt.source,
                policy: prompt.policy,
            })
        );
        self.apply_human_offer_decision(prompt.nation, index, accept);
        self.reply_to_diplomacy_offers_from(prompt.nation.get(), index + 1)
    }

    fn apply_diplomacy_inter_nation_states(&mut self) {
        for index in (0..MajorNationId::COUNT).rev() {
            let nation = MajorNationId::new(index);
            if !self.nations.majors[nation].economy.controller.is_human() {
                self.set_ai_diplomacy_policies(nation);
            }
        }

        for source in (0..MajorNationId::COUNT).map(MajorNationId::new) {
            for target in NationId::all() {
                if !self.nation_is_present(target) {
                    continue;
                }
                let grant = self.nations.majors[source]
                    .economy
                    .diplomacy_grants_by_nation[target];
                if let Some(grant) = grant {
                    if MajorNationId::from_nation(target).is_some() {
                        self.add_diplomacy_notice(
                            MajorNationId::from_nation(target).expect("major target"),
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
                        if !self.nations_are_at_war(source.nation(), target) {
                            self.queue_war_transition(source.nation(), target);
                        }
                    }
                    _ => self.add_diplomacy_offer(target, source.nation(), policy),
                }
            }
        }
    }

    fn set_ai_diplomacy_policies(&mut self, _nation: MajorNationId) {
        // `TForeignMinister::SetDiplomacyPolicies` posts AI grants, treaties, and
        // trade policy. This pass resolves already-posted orders.
    }

    fn give_grant_to(&mut self, source: MajorNationId, target: NationId) {
        let Some(grant) = self.nations.majors[source]
            .economy
            .diplomacy_grants_by_nation[target]
        else {
            return;
        };
        if grant.amount <= 0 {
            return;
        }

        if let Some(common) = self.nations.common_mut(target) {
            common.treasury += grant.amount;
        }
        self.nations.majors[source].economy.grant_total_cost -= grant.amount;

        if self.diplomacy.mission_levels[target][source.nation()] != DiplomaticMissionLevel::Embassy
        {
            return;
        }
        let standing = self.diplomacy.standings[source.nation()][target];
        let delta = match grant.amount {
            1_000 => 2,
            3_000 => 4,
            5_000 => 6,
            10_000 => 10,
            _ => 0,
        };
        self.set_relationship(source.nation(), target, standing + delta);
    }

    fn add_diplomacy_offer(&mut self, target: NationId, source: NationId, policy: DiplomacyPolicy) {
        if let Some(major) = MajorNationId::from_nation(target) {
            if self.nations.majors[major].kind == MajorNationKind::AutoGreatPower {
                match policy {
                    DiplomacyPolicy::JoinEmpire | DiplomacyPolicy::NonAggressionPact => return,
                    DiplomacyPolicy::Alliance | DiplomacyPolicy::JoinEmpireWithWarEntanglements
                        if self.has_alliance_guard(source, target) =>
                    {
                        return;
                    }
                    _ => {}
                }
            }
            self.insert_sorted_proposal(major, DiplomacyProposal { source, policy });
            return;
        }

        self.add_minor_diplomacy_offer(target, source, policy);
    }

    fn add_minor_diplomacy_offer(
        &mut self,
        target: NationId,
        source: NationId,
        policy: DiplomacyPolicy,
    ) {
        let independent = self
            .nations
            .common(target)
            .is_some_and(|nation| nation.status() == CountryStatus::Independent);
        match policy {
            DiplomacyPolicy::JoinEmpire => {
                let accepted = independent && self.minor_would_accept_join_empire(target, source);
                if accepted {
                    if self.has_alliance_guard(target, source) {
                        if let Some(major) = MajorNationId::from_nation(source) {
                            self.insert_sorted_proposal(
                                major,
                                DiplomacyProposal {
                                    source: target,
                                    policy: DiplomacyPolicy::JoinEmpireWithWarEntanglements,
                                },
                            );
                        }
                    } else {
                        self.nations
                            .set_country_status(target, CountryStatus::ColonyOf(source));
                        self.set_nation_pair_relationship(
                            target,
                            source,
                            DiplomaticRelationship::JoinedEmpire,
                            true,
                        );
                    }
                    self.add_treaty_event(InterNationNewsKind::JoinEmpireAccepted, target, source);
                    return;
                }
                if let Some(major) = MajorNationId::from_nation(source) {
                    self.add_diplomacy_notice(major, target, -policy.retail());
                }
                self.add_treaty_event(InterNationNewsKind::JoinEmpireRejected, source, target);
            }
            DiplomacyPolicy::NonAggressionPact if independent => {
                self.set_nation_pair_relationship(
                    target,
                    source,
                    DiplomaticRelationship::NonAggressionPact,
                    true,
                );
                if let Some(major) = MajorNationId::from_nation(source) {
                    self.add_diplomacy_notice(major, target, policy.retail());
                }
                self.add_treaty_event(
                    InterNationNewsKind::NonAggressionPactAccepted,
                    target,
                    source,
                );
            }
            DiplomacyPolicy::PeaceTreaty if independent => {
                self.set_nation_pair_relationship(
                    target,
                    source,
                    DiplomaticRelationship::Peace,
                    true,
                );
                if let Some(major) = MajorNationId::from_nation(source) {
                    self.add_diplomacy_notice(major, target, policy.retail());
                }
                self.add_treaty_event(InterNationNewsKind::PeaceTreatyAccepted, target, source);
            }
            _ => {}
        }
    }

    fn add_diplomacy_notice(&mut self, nation: MajorNationId, source: NationId, code: i16) {
        if self.nations.majors[nation].economy.controller.is_human() {
            self.insert_sorted_notice(nation, DiplomacyNotice { source, code });
        }

        if code == DiplomacyPolicy::PeaceTreaty.retail()
            && MajorNationId::from_nation(source).is_some()
        {
            for ally in self.eligible_major_ids().into_iter().flatten() {
                if self.diplomacy.relationships[nation.nation()][ally.nation()]
                    != DiplomaticRelationship::Alliance
                {
                    continue;
                }
                if self.nations_are_at_war(ally.nation(), source) {
                    self.apply_peace_relationship(nation.nation(), ally.nation(), true);
                }
            }
        }

        if code != DiplomacyPolicy::Alliance.retail() {
            return;
        }
        for other in self.eligible_major_ids().into_iter().flatten() {
            if self.nations_are_at_war(other.nation(), source)
                && !self.nations_are_at_war(other.nation(), nation.nation())
            {
                self.queue_war_transition(nation.nation(), other.nation());
            }
        }
    }

    fn reply_to_diplomacy_offers_from(
        &mut self,
        start_nation: u8,
        start_index: usize,
    ) -> DiplomacyPhaseResult {
        for nation_index in start_nation..MajorNationId::COUNT {
            let nation = MajorNationId::new(nation_index);
            let first = if nation_index == start_nation {
                start_index
            } else {
                0
            };
            let count = self.pending.nations[nation].proposals.len();
            for index in first..count {
                if let Some(prompt) = self.reply_to_one_diplomacy_offer(nation, index) {
                    return DiplomacyPhaseResult::Offer(prompt);
                }
            }
            self.reset_diplomacy_commitments(nation);
        }
        DiplomacyPhaseResult::Resolved
    }

    fn reply_to_one_diplomacy_offer(
        &mut self,
        nation: MajorNationId,
        index: usize,
    ) -> Option<DiplomacyOfferPrompt> {
        let DiplomacyProposal { source, policy } = self.pending.nations[nation].proposals[index];
        let matching = self.nations.majors[nation]
            .economy
            .diplomacy_policy_by_nation[source]
            == Some(policy);
        let human = self.nations.majors[nation].economy.controller.is_human();

        if human {
            if matching {
                self.apply_human_offer_decision(nation, index, true);
                return None;
            }
            if policy == DiplomacyPolicy::Alliance
                && self.diplomacy.relationships[nation.nation()][source]
                    != DiplomaticRelationship::Peace
            {
                self.reject_diplomacy_offer(nation, index);
                return None;
            }
            return Some(DiplomacyOfferPrompt {
                nation,
                index: index as u8,
                source,
                policy,
            });
        }

        let accept = if matching {
            true
        } else {
            match policy {
                DiplomacyPolicy::JoinEmpire => false,
                DiplomacyPolicy::Alliance => {
                    self.diplomacy.relationships[nation.nation()][source]
                        == DiplomaticRelationship::Peace
                        && !self.has_alliance_guard(source, nation.nation())
                }
                DiplomacyPolicy::NonAggressionPact => true,
                DiplomacyPolicy::PeaceTreaty => false,
                DiplomacyPolicy::JoinEmpireWithWarEntanglements => {
                    !self.has_alliance_guard(source, nation.nation())
                }
                _ => false,
            }
        };
        if accept {
            self.accept_diplomacy_offer(nation, index);
        } else {
            self.reject_diplomacy_offer(nation, index);
        }
        None
    }

    fn apply_human_offer_decision(&mut self, nation: MajorNationId, index: usize, accept: bool) {
        if !accept {
            self.reject_diplomacy_offer(nation, index);
            return;
        }
        let DiplomacyProposal { source, policy } = self.pending.nations[nation].proposals[index];
        if policy == DiplomacyPolicy::JoinEmpireWithWarEntanglements {
            for other in (0..MajorNationId::COUNT).map(MajorNationId::new) {
                if self.nations_are_at_war(source, other.nation())
                    && !self.nations_are_at_war(nation.nation(), other.nation())
                {
                    self.queue_war_transition(nation.nation(), other.nation());
                }
            }
            return;
        }
        self.accept_diplomacy_offer(nation, index);
    }

    fn accept_diplomacy_offer(&mut self, nation: MajorNationId, index: usize) {
        let DiplomacyProposal { source, policy } = self.pending.nations[nation].proposals[index];
        match policy {
            DiplomacyPolicy::JoinEmpire => {
                self.nations
                    .set_country_status(nation.nation(), CountryStatus::ProtectorateOf(source));
                self.add_treaty_event(
                    InterNationNewsKind::JoinEmpireAccepted,
                    nation.nation(),
                    source,
                );
            }
            DiplomacyPolicy::Alliance => {
                self.set_nation_pair_relationship(
                    nation.nation(),
                    source,
                    DiplomaticRelationship::Alliance,
                    true,
                );
                self.add_treaty_event(
                    InterNationNewsKind::AllianceAccepted,
                    nation.nation(),
                    source,
                );
                for other in (0..MajorNationId::COUNT).map(MajorNationId::new) {
                    if self.nations_are_at_war(other.nation(), source)
                        && !self.nations_are_at_war(nation.nation(), other.nation())
                    {
                        self.queue_war_transition(nation.nation(), other.nation());
                    }
                }
            }
            DiplomacyPolicy::NonAggressionPact => {
                self.set_nation_pair_relationship(
                    nation.nation(),
                    source,
                    DiplomaticRelationship::NonAggressionPact,
                    true,
                );
                self.add_treaty_event(
                    InterNationNewsKind::NonAggressionPactAccepted,
                    nation.nation(),
                    source,
                );
            }
            DiplomacyPolicy::PeaceTreaty => {
                self.set_nation_pair_relationship(
                    nation.nation(),
                    source,
                    DiplomaticRelationship::Peace,
                    true,
                );
                self.add_treaty_event(
                    InterNationNewsKind::PeaceTreatyAccepted,
                    nation.nation(),
                    source,
                );
                if MajorNationId::from_nation(source).is_some() {
                    for ally in self.eligible_major_ids().into_iter().flatten() {
                        if self.diplomacy.relationships[nation.nation()][ally.nation()]
                            == DiplomaticRelationship::Alliance
                            && self.nations_are_at_war(ally.nation(), source)
                        {
                            self.apply_peace_relationship(nation.nation(), ally.nation(), true);
                        }
                    }
                }
            }
            DiplomacyPolicy::JoinEmpireWithWarEntanglements => {
                self.nations
                    .set_country_status(source, CountryStatus::ColonyOf(nation.nation()));
                self.add_treaty_event(
                    InterNationNewsKind::JoinEmpireAccepted,
                    source,
                    nation.nation(),
                );
            }
            _ => {}
        }

        if let Some(source_major) = MajorNationId::from_nation(source)
            && self.major_is_event_eligible(source_major)
        {
            self.add_diplomacy_notice(source_major, nation.nation(), policy.retail());
        }
    }

    fn reject_diplomacy_offer(&mut self, nation: MajorNationId, index: usize) {
        let DiplomacyProposal { source, policy } = self.pending.nations[nation].proposals[index];
        if let Some(source_major) = MajorNationId::from_nation(source) {
            self.add_diplomacy_notice(source_major, nation.nation(), -policy.retail());
        }
        let news = match policy {
            DiplomacyPolicy::JoinEmpire => Some(InterNationNewsKind::JoinEmpireRejected),
            DiplomacyPolicy::Alliance => Some(InterNationNewsKind::AllianceRejected),
            DiplomacyPolicy::NonAggressionPact => {
                Some(InterNationNewsKind::NonAggressionPactRejected)
            }
            DiplomacyPolicy::PeaceTreaty => Some(InterNationNewsKind::PeaceTreatyRejected),
            _ => None,
        };
        if let Some(news) = news {
            self.add_treaty_event(news, source, nation.nation());
        }
    }

    fn queue_war_transition(&mut self, source: NationId, target: NationId) {
        self.pending.war_transitions.insert(
            0,
            WarTransition {
                first: source,
                second: target,
            },
        );
        self.set_nation_pair_relationship(source, target, DiplomaticRelationship::War, true);
    }

    fn set_mission_level(
        &mut self,
        source: NationId,
        target: NationId,
        level: DiplomaticMissionLevel,
    ) {
        self.diplomacy.mission_levels[source][target] = level;
        self.diplomacy.mission_levels[target][source] = level;
    }

    fn set_relationship(&mut self, source: NationId, target: NationId, standing: i16) {
        if standing == self.diplomacy.standings[source][target] {
            return;
        }
        let mut clamped = standing;
        if clamped < 0 {
            clamped = 0;
        }
        if standing > 0xff && source != target {
            clamped = 0xff;
        }
        if standing <= 0x31 {
            clamped = if self.nations_are_at_war(source, target) {
                standing.max(0)
            } else {
                0x32
            };
        }
        self.diplomacy.standings[source][target] = clamped;
        self.diplomacy.standings[target][source] = clamped;

        if MajorNationId::from_nation(source).is_some() {
            self.copy_colony_standings_from(source);
        }
        if MajorNationId::from_nation(target).is_some() {
            self.copy_colony_standings_from(target);
        }
    }

    fn copy_colony_standings_from(&mut self, master: NationId) {
        for minor in (MinorNationId::FIRST..NationId::COUNT).map(MinorNationId::new) {
            if self.nations.minors[minor]
                .as_ref()
                .is_some_and(|nation| nation.common.status() == CountryStatus::ColonyOf(master))
            {
                self.set_relationships_to_match(minor.nation(), master);
            }
        }
    }

    fn set_relationships_to_match(&mut self, destination: NationId, source: NationId) {
        for other in NationId::all() {
            self.diplomacy.standings[destination][other] = self.diplomacy.standings[source][other];
            self.diplomacy.standings[other][destination] = self.diplomacy.standings[other][source];
        }
    }

    fn set_nation_pair_relationship(
        &mut self,
        source: NationId,
        target: NationId,
        relationship: DiplomaticRelationship,
        update_standing: bool,
    ) {
        if self.diplomacy.relationships[source][target] == relationship {
            return;
        }
        self.diplomacy.relationships[source][target] = relationship;
        self.diplomacy.relationships[target][source] = relationship;
        let turn = self.turn.economic_turn as i16;
        self.diplomacy.relationship_turns[source][target] = Some(turn);
        self.diplomacy.relationship_turns[target][source] = Some(turn);

        if MajorNationId::from_nation(source).is_some() {
            self.dispatch_aligned_minor_relationship(source, target, relationship);
        }
        if MajorNationId::from_nation(target).is_some() {
            self.dispatch_aligned_minor_relationship(target, source, relationship);
        }

        match relationship {
            DiplomaticRelationship::Alliance => {
                self.add_treaty_event(
                    InterNationNewsKind::AllianceRelationshipEstablished,
                    source,
                    target,
                );
            }
            DiplomaticRelationship::NonAggressionPact => {
                let standing = self.diplomacy.standings[source][target];
                self.set_relationship(source, target, standing + 10);
            }
            DiplomaticRelationship::Peace => {
                if self.diplomacy.standings[source][target] <= 0x31 {
                    self.set_relationship(source, target, 0x32);
                }
                if MajorNationId::from_nation(source).is_some()
                    && MajorNationId::from_nation(target).is_some()
                {
                    self.set_mission_level(source, target, DiplomaticMissionLevel::Embassy);
                    self.set_pair_trade_policy(source, target, TradePolicyScore::NEUTRAL);
                }
            }
            DiplomaticRelationship::JoinedEmpire => {
                self.set_relationship(source, target, 0xff);
            }
            DiplomaticRelationship::War => {
                let source_independent = self
                    .nations
                    .common(source)
                    .is_some_and(|nation| nation.status() == CountryStatus::Independent);
                let target_not_colony = self
                    .nations
                    .common(target)
                    .is_some_and(|nation| !matches!(nation.status(), CountryStatus::ColonyOf(_)));
                if source_independent && target_not_colony {
                    self.add_treaty_event(
                        InterNationNewsKind::WarWithIndependentMinor,
                        source,
                        target,
                    );
                }
                self.set_pair_trade_policy(source, target, TradePolicyScore::BOYCOTT);
                self.set_mission_level(source, target, DiplomaticMissionLevel::None);
                if update_standing {
                    self.inflict_war_penalty(source, target);
                }
            }
        }
    }

    fn set_pair_trade_policy(
        &mut self,
        source: NationId,
        target: NationId,
        policy: TradePolicyScore,
    ) {
        if let Some(common) = self.nations.common_mut(source)
            && target != source
        {
            common.trade_policy_by_nation[target] = policy;
        }
        if let Some(common) = self.nations.common_mut(target)
            && source != target
        {
            common.trade_policy_by_nation[source] = policy;
        }
    }

    fn dispatch_aligned_minor_relationship(
        &mut self,
        master: NationId,
        counterpart: NationId,
        relationship: DiplomaticRelationship,
    ) {
        for minor in (MinorNationId::FIRST..NationId::COUNT).map(MinorNationId::new) {
            if !self.nations.minors[minor]
                .as_ref()
                .is_some_and(|nation| nation.common.status() == CountryStatus::ColonyOf(master))
            {
                continue;
            }
            if relationship == DiplomaticRelationship::War {
                if self.nations_are_at_war(minor.nation(), counterpart) {
                    continue;
                }
                self.set_nation_pair_relationship(
                    minor.nation(),
                    counterpart,
                    DiplomaticRelationship::War,
                    false,
                );
            } else {
                self.set_nation_pair_relationship(
                    minor.nation(),
                    counterpart,
                    DiplomaticRelationship::Peace,
                    true,
                );
            }
        }
    }

    fn apply_peace_relationship(
        &mut self,
        source: NationId,
        target: NationId,
        inflict_penalty: bool,
    ) {
        self.set_nation_pair_relationship(source, target, DiplomaticRelationship::Peace, true);
        if inflict_penalty {
            let standing = i32::from(self.diplomacy.standings[source][target]);
            let adjustment = ((0x5a - standing) * standing) / 200;
            if (adjustment as i16) < 0 {
                self.set_relationship(source, target, (standing + adjustment) as i16);
            }
        }
        if let Some(major) = MajorNationId::from_nation(target)
            && self.nations.majors[major].economy.controller.is_human()
        {
            self.add_diplomacy_notice(major, source, 0x139);
        }
        self.add_treaty_event(
            InterNationNewsKind::PeaceRelationshipPropagated,
            target,
            source,
        );
    }

    fn inflict_war_penalty(&mut self, source: NationId, target: NationId) {
        let standing = self.diplomacy.standings[source][target];
        if standing - 0x32 < 0x31 {
            self.set_relationship(source, target, standing - 0x32);
        } else {
            self.set_relationship(source, target, 0x31);
        }
    }

    fn has_alliance_guard(&self, nation: NationId, guarded: NationId) -> bool {
        if !(0..MajorNationId::COUNT)
            .any(|index| self.nations_are_at_war(nation, MajorNationId::new(index).nation()))
        {
            return false;
        }
        (0..MajorNationId::COUNT).any(|index| {
            let other = MajorNationId::new(index).nation();
            self.nations_are_at_war(other, nation) && !self.nations_are_at_war(guarded, other)
        })
    }

    fn minor_would_accept_join_empire(&self, minor: NationId, source: NationId) -> bool {
        let standing = self.diplomacy.standings[minor][source];
        if standing <= 0xf9 {
            return false;
        }
        (0..MajorNationId::COUNT).all(|index| {
            let peer = MajorNationId::new(index).nation();
            !self.nation_is_present(peer)
                || peer == source
                || (self.diplomacy.standings[minor][peer] - standing).abs() >= 10
        })
    }

    fn nations_are_at_war(&self, source: NationId, target: NationId) -> bool {
        self.diplomacy.relationships[source][target] == DiplomaticRelationship::War
    }

    fn eligible_majors(&self) -> impl Iterator<Item = MajorNationId> + '_ {
        (0..MajorNationId::COUNT)
            .map(MajorNationId::new)
            .filter(|&nation| self.major_is_event_eligible(nation))
    }

    fn eligible_major_ids(&self) -> [Option<MajorNationId>; MAJOR_NATION_COUNT] {
        let mut ids = [None; MAJOR_NATION_COUNT];
        for (slot, nation) in self.eligible_majors().enumerate() {
            ids[slot] = Some(nation);
        }
        ids
    }

    fn nation_is_present(&self, nation: NationId) -> bool {
        self.nations.common(nation).is_some()
    }

    fn insert_sorted_proposal(&mut self, nation: MajorNationId, proposal: DiplomacyProposal) {
        insert_sorted_by_source(
            &mut self.rng,
            &mut self.pending.nations[nation].proposals,
            proposal,
            |entry| entry.source.get(),
        );
    }

    fn insert_sorted_notice(&mut self, nation: MajorNationId, notice: DiplomacyNotice) {
        insert_sorted_by_source(
            &mut self.rng,
            &mut self.pending.nations[nation].turn_events,
            notice,
            |entry| entry.source.get(),
        );
    }
}

fn grant_notice_code(grant: DiplomacyGrant) -> i16 {
    let amount = grant.amount as i16;
    if grant.recurring {
        amount | 0x4000
    } else {
        amount
    }
}

fn insert_sorted_by_source<T>(
    rng: &mut RngState,
    items: &mut Vec<T>,
    new_item: T,
    source: impl Fn(&T) -> u8,
) {
    let new_key = source(&new_item);
    let mut ordinal = 0;
    while ordinal < items.len() {
        let existing_key = source(&items[ordinal]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{game_state, major_nation};

    fn major(id: u8) -> MajorNationId {
        MajorNationId::new(id)
    }

    fn nation(id: u8) -> NationId {
        NationId::new(id)
    }

    fn independent_minor(id: u8) -> MinorNation {
        MinorNation {
            common: NationCommonState::from_parts(
                format!("M{id}"),
                CountryStatus::Independent,
                Vec::new(),
                5_000,
                None,
                NationTable::default(),
            ),
            consortium_members: [MinorNationId::new(id); 4],
            trade: MinorTradeState::default(),
        }
    }

    fn computer_major() -> MajorNation {
        let mut nation = major_nation();
        nation.kind = MajorNationKind::AutoGreatPower;
        nation.economy.controller = MajorNationController::Computer;
        nation
    }

    #[test]
    fn grant_to_a_peer_transfers_treasury_and_raises_embassy_standing() {
        let mut state = game_state();
        let source = major(0);
        let target = nation(1);
        state.nations.majors[source].common.treasury = 20_000;
        assert!(state.set_diplomacy_grant(
            source,
            target,
            Some(DiplomacyGrant {
                amount: 1_000,
                recurring: false,
            }),
        ));
        let source_treasury = state.nations.majors[source].common.treasury;
        let target_treasury = state.nations.majors[major(1)].common.treasury;
        let standing = state.diplomacy.standings[source.nation()][target];

        assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);

        assert_eq!(
            state.nations.majors[source].common.treasury,
            source_treasury
        );
        assert_eq!(
            state.nations.majors[major(1)].common.treasury,
            target_treasury + 1_000
        );
        assert_eq!(
            state.diplomacy.standings[source.nation()][target],
            standing + 2
        );
        assert_eq!(
            state.nations.majors[source]
                .economy
                .diplomacy_grants_by_nation[target],
            None
        );
        assert_eq!(state.nations.majors[source].economy.grant_total_cost, 0);
        assert_eq!(
            state.pending.nations[major(1)].turn_events,
            [DiplomacyNotice {
                source: nation(0),
                code: 1_000,
            }]
        );
    }

    #[test]
    fn consulate_policy_sets_symmetric_mission_level_and_news() {
        let mut state = game_state();
        let source = major(0);
        let target = nation(7);
        state.nations.minors[MinorNationId::new(7)] = Some(independent_minor(7));
        state.nations.majors[source]
            .economy
            .diplomacy_policy_by_nation[target] = Some(DiplomacyPolicy::BuildConsulate);

        assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);

        assert_eq!(
            state.diplomacy.mission_levels[source.nation()][target],
            DiplomaticMissionLevel::TradeConsulate
        );
        assert_eq!(
            state.diplomacy.mission_levels[target][source.nation()],
            DiplomaticMissionLevel::TradeConsulate
        );
        assert_eq!(
            state.nations.majors[source]
                .economy
                .diplomacy_policy_by_nation[target],
            None
        );
        assert!(
            matches!(
                &state.pending.newspaper_events[..],
                [PendingNewspaperEvent::InterNation {
                    event: InterNationNewsKind::TradeConsulateEstablished,
                    subject,
                    related_nations,
                }] if *subject == source && related_nations[target]
            ),
            "{:?}",
            state.pending.newspaper_events
        );
    }

    #[test]
    fn minor_non_aggression_pact_is_accepted_immediately() {
        let mut state = game_state();
        let source = major(0);
        let target = nation(7);
        state.nations.minors[MinorNationId::new(7)] = Some(independent_minor(7));
        state.nations.majors[source]
            .economy
            .diplomacy_policy_by_nation[target] = Some(DiplomacyPolicy::NonAggressionPact);
        let standing = state.diplomacy.standings[source.nation()][target];

        assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);

        assert_eq!(
            state.diplomacy.relationships[source.nation()][target],
            DiplomaticRelationship::NonAggressionPact
        );
        assert_eq!(
            state.diplomacy.standings[source.nation()][target],
            standing + 10
        );
        assert_eq!(
            state.pending.nations[source].turn_events,
            [DiplomacyNotice {
                source: target,
                code: DiplomacyPolicy::NonAggressionPact.retail(),
            }]
        );
    }

    #[test]
    fn human_offer_stops_for_a_reply_and_accepting_forms_the_alliance() {
        let mut state = game_state();
        state.nations.majors[major(1)] = computer_major();
        state.nations.majors[major(1)]
            .economy
            .diplomacy_policy_by_nation[nation(0)] = Some(DiplomacyPolicy::Alliance);

        let prompt = match state.do_diplomacy() {
            DiplomacyPhaseResult::Offer(prompt) => prompt,
            other => panic!("expected an offer prompt, got {other:?}"),
        };
        assert_eq!(
            prompt,
            DiplomacyOfferPrompt {
                nation: major(0),
                index: 0,
                source: nation(1),
                policy: DiplomacyPolicy::Alliance,
            }
        );

        assert_eq!(
            state.resolve_diplomacy_offer(prompt, true),
            DiplomacyPhaseResult::Resolved
        );
        assert_eq!(
            state.diplomacy.relationships[nation(0)][nation(1)],
            DiplomaticRelationship::Alliance
        );
    }

    #[test]
    fn declare_war_queues_a_war_transition_and_sets_the_pair_at_war() {
        let mut state = game_state();
        let source = major(0);
        let target = nation(1);
        state.nations.majors[source]
            .economy
            .diplomacy_policy_by_nation[target] = Some(DiplomacyPolicy::DeclareWar);

        assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);

        assert_eq!(
            state.diplomacy.relationships[source.nation()][target],
            DiplomaticRelationship::War
        );
        assert_eq!(
            state.pending.war_transitions,
            [WarTransition {
                first: source.nation(),
                second: target,
            }]
        );
        assert_eq!(
            state.nations.majors[source].common.trade_policy_by_nation[target],
            TradePolicyScore::BOYCOTT
        );
        assert_eq!(
            state.diplomacy.mission_levels[source.nation()][target],
            DiplomaticMissionLevel::None
        );
    }
}
