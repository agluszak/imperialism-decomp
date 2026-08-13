use super::*;

impl GameState {
    pub(super) fn set_mission_level(
        &mut self,
        source: NationId,
        target: NationId,
        level: DiplomaticMissionLevel,
    ) {
        self.diplomacy.mission_levels[source][target] = level;
        self.diplomacy.mission_levels[target][source] = level;
    }

    pub(super) fn reset_mission_row(&mut self, nation: NationId) {
        for other in NationId::all() {
            self.diplomacy.mission_levels[nation][other] = DiplomaticMissionLevel::None;
            self.diplomacy.mission_levels[other][nation] = DiplomaticMissionLevel::None;
        }
    }

    pub(super) fn set_relationship(&mut self, source: NationId, target: NationId, standing: i16) {
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
            clamped = if self.at_war(source, target) {
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

    pub(super) fn copy_colony_standings_from(&mut self, master: NationId) {
        for slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = MinorNationId::new(slot);
            if self.nations.minors[minor]
                .as_ref()
                .is_some_and(|nation| nation.common.status() == CountryStatus::ColonyOf(master))
            {
                self.set_relationships_to_match(minor.nation(), master);
            }
        }
    }

    pub(super) fn set_relationships_to_match(&mut self, destination: NationId, source: NationId) {
        for other in NationId::all() {
            self.diplomacy.standings[destination][other] = self.diplomacy.standings[source][other];
            self.diplomacy.standings[other][destination] = self.diplomacy.standings[other][source];
        }
    }

    pub(super) fn set_nation_pair_relationship(
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
                if let Some(major) = MajorNationId::from_nation(source) {
                    self.nations.majors[major].economy.candidate_nation_flags[target] = 0;
                }
                if let Some(major) = MajorNationId::from_nation(target) {
                    self.nations.majors[major].economy.candidate_nation_flags[source] = 0;
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
                let source_independent = self.is_independent(source);
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
                    self.inflict_war_penalty(source, target, true);
                }
            }
        }
    }

    pub(super) fn set_pair_trade_policy(
        &mut self,
        source: NationId,
        target: NationId,
        policy: TradePolicyScore,
    ) {
        self.set_one_trade(source, target, policy);
        self.set_one_trade(target, source, policy);
    }

    pub(super) fn set_one_trade(
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
    }

    pub(super) fn dispatch_aligned_minor_relationship(
        &mut self,
        master: NationId,
        counterpart: NationId,
        relationship: DiplomaticRelationship,
    ) {
        for slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = MinorNationId::new(slot);
            if !self.nations.minors[minor]
                .as_ref()
                .is_some_and(|nation| nation.common.status() == CountryStatus::ColonyOf(master))
            {
                continue;
            }
            if relationship == DiplomaticRelationship::War {
                if self.at_war(minor.nation(), counterpart) {
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

    pub(super) fn apply_peace_relationship(
        &mut self,
        source: NationId,
        target: NationId,
        inflict_penalty: bool,
    ) {
        self.set_nation_pair_relationship(source, target, DiplomaticRelationship::Peace, true);
        if inflict_penalty {
            self.inflict_war_penalty(source, target, false);
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

    pub(super) fn inflict_war_penalty(
        &mut self,
        source: NationId,
        target: NationId,
        war_cut: bool,
    ) {
        let pair_standing = self.diplomacy.standings[source][target];
        if war_cut {
            if pair_standing - 0x32 < 0x31 {
                self.set_relationship(source, target, pair_standing - 0x32);
            } else {
                self.set_relationship(source, target, 0x31);
            }
        } else {
            let adjustment = ((0x5a - i32::from(pair_standing)) * i32::from(pair_standing)) / 200;
            let delta = adjustment as i16;
            if delta < 0 {
                self.set_relationship(source, target, pair_standing + delta);
            }
        }

        for candidate in NationId::all() {
            if !self.event_eligible(candidate)
                || candidate == source
                || candidate == target
                || !self.is_independent(candidate)
            {
                continue;
            }
            let divisor = if MajorNationId::from_nation(target).is_none() {
                if MajorNationId::from_nation(candidate).is_none() {
                    if self.in_consortium_with(candidate, source) {
                        2
                    } else {
                        4
                    }
                } else {
                    8
                }
            } else if MajorNationId::from_nation(candidate).is_some() {
                4
            } else {
                8
            };
            let current = self.diplomacy.standings[source][candidate];
            let target_candidate = self.diplomacy.standings[target][candidate];
            let mut adjustment = ((0x5a - i32::from(target_candidate)) * i32::from(pair_standing))
                / (divisor * 0x32);
            if source == NationId::new(0) {
                adjustment = i32::from(adjustment as i16) / 2;
            }
            let delta = adjustment as i16;
            let applied = if current < 0x32 {
                if delta > 0 && current + delta > 0x31 {
                    0x31 - current
                } else {
                    delta
                }
            } else if current + delta < 0x32 {
                0x32 - current
            } else {
                delta
            };
            self.set_relationship(source, candidate, current + applied);
        }
    }
}
