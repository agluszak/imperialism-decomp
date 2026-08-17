use super::*;

impl GameState {
    pub(super) fn give_grant_to(&mut self, source: MajorNationId, target: NationId) {
        let Some(grant) = self
            .nations
            .major(source)
            .and_then(|major| major.economy.diplomacy_grants_by_nation[target])
        else {
            return;
        };
        if grant.amount <= 0 {
            return;
        }

        if let Some(common) = self.nations.common_mut(target) {
            common.treasury += grant.amount;
        }
        if let Some(major) = self.nations.major_mut(source) {
            major.economy.grant_total_cost -= grant.amount;
        }

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

    pub(super) fn add_diplomacy_offer(
        &mut self,
        target: NationId,
        source: NationId,
        policy: DiplomacyPolicy,
    ) {
        if let Some(major) = MajorNationId::from_nation(target) {
            if self.nations.major(major).is_some_and(MajorNation::is_auto) {
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

    pub(super) fn add_minor_diplomacy_offer(
        &mut self,
        target: NationId,
        source: NationId,
        policy: DiplomacyPolicy,
    ) {
        match policy {
            DiplomacyPolicy::JoinEmpire => {
                let accepted = self.is_independent(target)
                    && self.minor_would_accept_join_empire(target, source);
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
                        self.change_master(target, source);
                    }
                    self.add_treaty_event(InterNationNewsKind::JoinEmpireAccepted, target, source);
                    return;
                }
                if let Some(major) = MajorNationId::from_nation(source) {
                    self.add_diplomacy_notice(major, target, -policy.retail());
                }
                self.add_treaty_event(InterNationNewsKind::JoinEmpireRejected, source, target);
            }
            DiplomacyPolicy::NonAggressionPact if self.is_independent(target) => {
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
            DiplomacyPolicy::PeaceTreaty if self.is_independent(target) => {
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

    pub(super) fn add_diplomacy_notice(
        &mut self,
        nation: MajorNationId,
        source: NationId,
        code: i16,
    ) {
        if self
            .nations
            .major(nation)
            .is_some_and(|major| major.auto.is_none())
        {
            self.insert_sorted_notice(nation, DiplomacyNotice { source, code });
        }

        if code == DiplomacyPolicy::PeaceTreaty.retail()
            && MajorNationId::from_nation(source).is_some()
        {
            self.peace_allies_fighting(nation.nation(), source);
        }

        if code != DiplomacyPolicy::Alliance.retail() {
            return;
        }
        self.queue_wars_against_enemies_of(nation.nation(), source, None);
    }

    pub(super) fn reply_to_diplomacy_offers_from(
        &mut self,
        start_nation: u8,
        start_index: usize,
    ) -> DiplomacyPhaseResult {
        let nations: Vec<_> = self
            .nations
            .live_major_ids()
            .filter(|nation| nation.get() >= start_nation)
            .collect();
        for nation in nations {
            let first = if nation.get() == start_nation {
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
            self.nations
                .major_mut(nation)
                .expect("diplomacy offer recipient must remain live")
                .reset_diplomacy_commitments();
        }
        self.process_one_queued_war()
    }

    pub(super) fn reply_to_one_diplomacy_offer(
        &mut self,
        nation: MajorNationId,
        index: usize,
    ) -> Option<DiplomacyOfferPrompt> {
        let DiplomacyProposal { source, policy } = self.pending.nations[nation].proposals[index];
        let Some(major) = self.nations.major(nation) else {
            return None;
        };
        let matching = major.economy.diplomacy_policy_by_nation[source] == Some(policy);
        let human = major.auto.is_none();

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
                        && self.passes_alliance_strength(nation, source)
                }
                DiplomacyPolicy::NonAggressionPact => true,
                DiplomacyPolicy::PeaceTreaty => {
                    let join = self.evaluate_join_war(nation, source);
                    if join {
                        self.add_treaty_event(
                            InterNationNewsKind::NationJoinedWar,
                            nation.nation(),
                            source,
                        );
                    }
                    join
                }
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

    pub(super) fn apply_human_offer_decision(
        &mut self,
        nation: MajorNationId,
        index: usize,
        accept: bool,
    ) {
        if !accept {
            self.reject_diplomacy_offer(nation, index);
            return;
        }
        let DiplomacyProposal { source, policy } = self.pending.nations[nation].proposals[index];
        if policy == DiplomacyPolicy::JoinEmpireWithWarEntanglements {
            self.queue_wars_against_enemies_of(nation.nation(), source, Some(source));
            return;
        }
        self.accept_diplomacy_offer(nation, index);
    }

    pub(super) fn accept_diplomacy_offer(&mut self, nation: MajorNationId, index: usize) {
        let DiplomacyProposal { source, policy } = self.pending.nations[nation].proposals[index];
        match policy {
            DiplomacyPolicy::JoinEmpire => {
                self.change_master(nation.nation(), source);
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
                self.queue_wars_against_enemies_of(nation.nation(), source, None);
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
                    self.peace_allies_fighting(nation.nation(), source);
                }
            }
            DiplomacyPolicy::JoinEmpireWithWarEntanglements => {
                self.change_master(source, nation.nation());
                self.add_treaty_event(
                    InterNationNewsKind::JoinEmpireAccepted,
                    source,
                    nation.nation(),
                );
            }
            _ => {}
        }

        if let Some(source_major) = MajorNationId::from_nation(source)
            && self.event_eligible(source)
        {
            self.add_diplomacy_notice(source_major, nation.nation(), policy.retail());
        }
    }

    pub(super) fn reject_diplomacy_offer(&mut self, nation: MajorNationId, index: usize) {
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
}
