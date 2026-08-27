use super::*;

impl GameState {
    pub(super) fn queue_war(
        &mut self,
        source: NationId,
        target: NationId,
        annex: Option<NationId>,
    ) {
        if let Some(major) = MajorNationId::from_nation(source)
            && self.is_auto(major)
        {
            self.set_enemy(major, target);
        }
        self.pending.war_transitions.insert(
            0,
            WarTransition {
                first: source,
                second: target,
            },
        );
        self.set_nation_pair_relationship(source, target, DiplomaticRelationship::War, true);
        if let Some(minor) = annex
            && self.owner_slot(minor) != source
        {
            self.change_master(minor, source);
        }
    }

    pub(super) fn process_one_queued_war(&mut self) -> DiplomacyPhaseResult {
        let Some(pair) = self.pending.war_transitions.first().copied() else {
            return DiplomacyPhaseResult::Resolved;
        };
        self.pending.war_transitions.remove(0);
        if !self.at_war(pair.first, pair.second) {
            self.set_nation_pair_relationship(
                pair.first,
                pair.second,
                DiplomaticRelationship::War,
                false,
            );
        }
        if let Some(target) = MajorNationId::from_nation(pair.second) {
            if self.is_auto(target) {
                self.set_enemy(target, pair.first);
            }
            self.add_diplomacy_notice(target, pair.first, DiplomacyPolicy::DeclareWar.retail());
        }
        self.add_treaty_event(
            InterNationNewsKind::WarDeclaredAgainstSubject,
            pair.second,
            pair.first,
        );
        self.add_treaty_event(
            InterNationNewsKind::WarDeclaredBySubject,
            pair.first,
            pair.second,
        );
        if MajorNationId::from_nation(pair.second).is_some()
            && let Some(source) = MajorNationId::from_nation(pair.first)
        {
            self.add_diplomacy_notice(source, pair.second, 0xc8);
        }
        self.continue_war_reactions(pair.first, pair.second, 0)
    }

    pub(crate) fn continue_war_reactions(
        &mut self,
        first: NationId,
        second: NationId,
        start: u8,
    ) -> DiplomacyPhaseResult {
        if MajorNationId::from_nation(second).is_none() {
            if start == 0
                && self.is_independent(second)
                && let Some(favorite) = self.favorite_with_embassy(second)
            {
                let kind = if self.at_war(favorite.nation(), first) {
                    DiplomacyWarJoinKind::AnnexMinor
                } else {
                    DiplomacyWarJoinKind::DefendMinor
                };
                if self.nations.majors[&favorite].auto.is_none() {
                    return DiplomacyPhaseResult::WarJoin(DiplomacyWarJoinPrompt {
                        nation: favorite,
                        target: second,
                        source: first,
                        kind,
                        pair_first: first,
                        pair_second: second,
                        cursor: 1,
                    });
                }
                self.ai_handle_minor_war(favorite, second, first);
            }
            return DiplomacyPhaseResult::Resolved;
        }

        let mut cursor = start;
        while cursor < MajorNationId::COUNT {
            let other = MajorNationId::new(cursor);
            cursor += 1;
            if self.diplomacy.relationships[second][other.nation()]
                != DiplomaticRelationship::Alliance
                || self.at_war(other.nation(), first)
            {
                continue;
            }
            if self.nations.majors[&other].auto.is_none() {
                return DiplomacyPhaseResult::WarJoin(DiplomacyWarJoinPrompt {
                    nation: other,
                    target: second,
                    source: first,
                    kind: DiplomacyWarJoinKind::JoinTargetAlly,
                    pair_first: first,
                    pair_second: second,
                    cursor,
                });
            }
            self.ai_handle_role_swap(other, second, first, false);
        }
        while cursor < MajorNationId::COUNT * 2 {
            let other = MajorNationId::new(cursor - MajorNationId::COUNT);
            cursor += 1;
            if self.diplomacy.relationships[first][other.nation()]
                != DiplomaticRelationship::Alliance
                || self.at_war(other.nation(), second)
            {
                continue;
            }
            if self.nations.majors[&other].auto.is_none() {
                return DiplomacyPhaseResult::WarJoin(DiplomacyWarJoinPrompt {
                    nation: other,
                    target: second,
                    source: first,
                    kind: DiplomacyWarJoinKind::JoinSourceAlly,
                    pair_first: first,
                    pair_second: second,
                    cursor,
                });
            }
            self.ai_handle_role_swap(other, second, first, true);
        }
        DiplomacyPhaseResult::Resolved
    }

    pub(crate) fn apply_war_join_decision(&mut self, prompt: DiplomacyWarJoinPrompt, accept: bool) {
        let nation = prompt.nation.nation();
        match prompt.kind {
            DiplomacyWarJoinKind::DefendMinor if accept => {
                self.queue_war(nation, prompt.source, Some(prompt.target));
            }
            DiplomacyWarJoinKind::AnnexMinor if accept => {
                if self.owner_slot(prompt.target) != nation {
                    self.change_master(prompt.target, nation);
                }
            }
            DiplomacyWarJoinKind::JoinTargetAlly if accept => {
                self.queue_war(nation, prompt.source, None);
            }
            DiplomacyWarJoinKind::JoinTargetAlly => {
                self.apply_peace_relationship(nation, prompt.target, true);
            }
            DiplomacyWarJoinKind::JoinSourceAlly if accept => {
                self.queue_war(nation, prompt.target, None);
            }
            DiplomacyWarJoinKind::JoinSourceAlly => {
                self.apply_peace_relationship(nation, prompt.source, false);
            }
            _ => {}
        }
    }

    pub(super) fn ai_handle_minor_war(
        &mut self,
        nation: MajorNationId,
        minor: NationId,
        attacker: NationId,
    ) {
        let mut beatable = [false; MAJOR_NATION_COUNT];
        let mut all_beatable = true;
        for other in majors() {
            if !all_beatable {
                break;
            }
            if !self.event_eligible(other.nation()) || other == nation {
                continue;
            }
            if self.at_war(nation.nation(), other.nation()) || !self.at_war(minor, other.nation()) {
                continue;
            }
            let score = if self.are_nations_border_linked(minor, nation.nation()) {
                self.army_ratio_with_secondary(nation, attacker, minor)
                    + self.army_standing_pair(nation, attacker, minor)
            } else {
                self.navy_ratio_with_secondary(nation, attacker, minor)
                    + self.navy_standing_pair(nation, attacker, minor)
            };
            if self.war_number(nation) > score {
                all_beatable = false;
            } else {
                beatable[usize::from(other.get())] = true;
            }
        }
        if !all_beatable {
            return;
        }
        for other in majors() {
            if beatable[usize::from(other.get())] {
                self.queue_war(nation.nation(), other.nation(), Some(minor));
            }
        }
        if self.owner_slot(minor) != nation.nation() {
            self.change_master(minor, nation.nation());
        }
    }

    pub(super) fn ai_handle_role_swap(
        &mut self,
        nation: MajorNationId,
        target: NationId,
        source: NationId,
        swap: bool,
    ) {
        let already = if swap {
            self.at_war(nation.nation(), target)
        } else {
            self.at_war(nation.nation(), source)
        };
        if already {
            return;
        }
        let Some(source_major) = MajorNationId::from_nation(source) else {
            return;
        };
        let Some(target_major) = MajorNationId::from_nation(target) else {
            return;
        };
        let combined = if self.are_nations_border_linked(source, nation.nation()) {
            self.army_pair_ratio(nation, source_major, target_major, swap)
                + self.army_pair_standing(nation, source_major, target_major, swap)
        } else {
            self.navy_pair_ratio(nation, source_major, target_major, swap)
                + self.navy_pair_standing(nation, source_major, target_major, swap)
        };
        if self.war_number(nation) <= combined {
            if swap {
                self.queue_war(nation.nation(), target, None);
            } else {
                self.queue_war(nation.nation(), source, None);
            }
            return;
        }
        if swap {
            self.apply_peace_relationship(nation.nation(), source, false);
        } else {
            self.apply_peace_relationship(nation.nation(), target, true);
        }
    }

    pub(super) fn evaluate_join_war(&mut self, nation: MajorNationId, target: NationId) -> bool {
        let Some(target_major) = MajorNationId::from_nation(target) else {
            return false;
        };
        if self.is_capitol_threatened(target_major) {
            return false;
        }
        if self.accept_peace_number(nation) < self.peace_threat(nation, target_major) {
            self.peace_allies_fighting(nation.nation(), target);
            self.add_treaty_event(
                InterNationNewsKind::NationJoinedWar,
                target,
                nation.nation(),
            );
            return true;
        }
        false
    }

    pub(super) fn peace_allies_fighting(&mut self, nation: NationId, enemy: NationId) {
        let allies: Vec<_> = majors()
            .filter(|&ally| {
                self.event_eligible(ally.nation())
                    && self.diplomacy.relationships[nation][ally.nation()]
                        == DiplomaticRelationship::Alliance
                    && self.at_war(ally.nation(), enemy)
            })
            .collect();
        for ally in allies {
            self.apply_peace_relationship(nation, ally.nation(), true);
        }
    }

    pub(super) fn queue_wars_against_enemies_of(
        &mut self,
        nation: NationId,
        partner: NationId,
        annex: Option<NationId>,
    ) {
        let enemies: Vec<_> = majors()
            .filter(|&other| {
                self.event_eligible(other.nation())
                    && self.at_war(other.nation(), partner)
                    && !self.at_war(nation, other.nation())
            })
            .collect();
        for other in enemies {
            self.queue_war(nation, other.nation(), annex);
        }
    }

    pub(crate) fn set_enemy(&mut self, nation: MajorNationId, target: NationId) {
        if self.has_active_candidates(nation) {
            let others: Vec<_> = NationId::all()
                .filter(|&other| other != nation.nation() && !self.at_war(other, nation.nation()))
                .collect();
            for other in others {
                self.stop_being_enemies_with(nation, other);
            }
        }
        self.nations.majors[&nation].economy.candidate_nation_flags[target] = 1;
        if self
            .nations
            .common(target)
            .is_none_or(|common| common.owned_regions().is_empty())
        {
            return;
        }
        if matches!(self.status_of(target), CountryStatus::ProtectorateOf(_)) {
            return;
        }
        self.set_ai_zone_target(nation, target, AiTargetState::Candidate);
    }

    pub(super) fn stop_being_enemies_with(&mut self, nation: MajorNationId, target: NationId) {
        self.nations.majors[&nation].economy.candidate_nation_flags[target] = 0;
        if self
            .nations
            .common(target)
            .is_none_or(|common| common.owned_regions().is_empty())
        {
            return;
        }
        self.set_ai_zone_target(nation, target, AiTargetState::Unmarked);
    }

    pub(super) fn set_ai_zone_target(
        &mut self,
        nation: MajorNationId,
        target: NationId,
        flag: AiTargetState,
    ) {
        let Some(zone) = self.first_port_zone_for_nation(target) else {
            return;
        };
        let Some(targets) = self.nations.majors[&nation]
            .auto
            .as_mut()
            .map(|auto| &mut auto.zone_targets)
        else {
            return;
        };
        let index = usize::from(zone.get());
        if let Some(entry) = targets.get_mut(index) {
            *entry = flag;
        }
    }
}
