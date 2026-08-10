use crate::*;

const CONSULATE_COST: i32 = 500;

impl GameState {
    /// Resolves the retail phase-six diplomacy pass for the evidenced Easy
    /// first-turn standalone branch.
    ///
    /// Broader proposal, war-transition, and later-turn AI branches remain
    /// unsupported. The complete branch is checked before retail's first
    /// mutation so an unsupported state cannot be partially advanced.
    pub fn resolve_diplomacy_phase(&mut self) -> TurnPhaseOutcome {
        let from = self.turn.phase;
        assert_eq!(
            from.retail(),
            6,
            "diplomacy phase resolved from the wrong phase"
        );

        if !self.supports_first_turn_diplomacy_phase() {
            return TurnPhaseOutcome::Blocked {
                phase: from,
                block: TurnBlock::Unsupported { phase: from },
            };
        }

        // AdvanceGlobalTurnStateMachine stores phase seven before invoking the
        // diplomacy manager.
        self.turn.phase = PhaseCode::from_retail(7);

        for slot in (0..MajorNationId::COUNT).rev() {
            let nation = MajorNationId::new(slot);
            if !self.nations.majors[nation].economy.controller.is_human() {
                self.run_first_turn_foreign_minister(nation);
            }
        }

        // FinishDiplomacyPhase is empty for every foreign-minister personality
        // represented by this branch. The manager then applies staged work in
        // source-major/target-nation order.
        for source_slot in 0..MajorNationId::COUNT {
            let source = MajorNationId::new(source_slot);
            for target in NationId::all() {
                if self.nations.majors[source]
                    .economy
                    .diplomacy_policy_by_nation[target]
                    == Some(DiplomacyPolicy::BuildConsulate)
                {
                    self.diplomacy.mission_levels[source.nation()][target] =
                        DiplomaticMissionLevel::TradeConsulate;
                    self.diplomacy.mission_levels[target][source.nation()] =
                        DiplomaticMissionLevel::TradeConsulate;
                    self.pending.queue_diplomatic_mission_event(
                        InterNationNewsKind::TradeConsulateEstablished,
                        source,
                        target,
                    );
                }
            }
        }

        // Empty offer queues still dispatch each nation's virtual reply and
        // reset all staged diplomacy commitments.
        for slot in 0..MajorNationId::COUNT {
            self.reset_diplomacy_commitments(MajorNationId::new(slot));
        }

        let human = (0..MajorNationId::COUNT)
            .map(MajorNationId::new)
            .find(|nation| self.nations.majors[*nation].economy.controller.is_human())
            .expect("supported diplomacy phase has exactly one human nation")
            .nation();
        let visible_ui = self
            .civilian_units
            .iter()
            .any(|unit| unit.nation() == human)
            .then_some(UiGate::DiplomacyMap);

        TurnPhaseOutcome::Continues {
            from,
            to: self.turn.phase,
            visible_ui,
        }
    }

    fn run_first_turn_foreign_minister(&mut self, source: MajorNationId) {
        match self.nations.majors[source]
            .economy
            .foreign_minister_personality
        {
            ForeignMinisterPersonality::Trader => {
                self.select_first_turn_consulates(source, 4, false)
            }
            ForeignMinisterPersonality::Bill => self.select_first_turn_consulates(source, 2, true),
            ForeignMinisterPersonality::Ted => self.select_first_turn_consulates(source, 4, true),
            ForeignMinisterPersonality::Diplomat => {
                let roll = self.rng.next_crt_rand() % 100;
                let first = match roll {
                    0..=24 => 7,
                    25..=49 => 11,
                    50..=74 => 15,
                    _ => 19,
                };
                for target in first..first + 4 {
                    self.stage_consulate(source, NationId::new(target));
                }
            }
            ForeignMinisterPersonality::Base
            | ForeignMinisterPersonality::Arms
            | ForeignMinisterPersonality::Textile => {}
        }
    }

    fn select_first_turn_consulates(
        &mut self,
        source: MajorNationId,
        wanted: usize,
        reject_shared_region: bool,
    ) {
        let mut selected = Vec::with_capacity(wanted);
        let mut attempts = 0;
        while selected.len() < wanted {
            if attempts > 15 {
                return;
            }
            attempts += 1;

            let target = NationId::new((self.rng.next_crt_rand() % 16 + 7) as u8);
            if selected.contains(&target)
                || reject_shared_region
                    && self.do_nation_territories_share_region_class(source.nation(), target)
            {
                continue;
            }

            selected.push(target);
            self.stage_consulate(source, target);
        }
    }

    fn stage_consulate(&mut self, source: MajorNationId, target: NationId) {
        let MajorNation {
            common, economy, ..
        } = &mut self.nations.majors[source];
        if economy.available_diplomacy_budget(common.treasury)
            - economy.grant_total_cost
            - CONSULATE_COST
            < 0
        {
            return;
        }

        common.treasury -= CONSULATE_COST;
        economy.diplomacy_policy_by_nation[target] = Some(DiplomacyPolicy::BuildConsulate);
    }

    fn supports_first_turn_diplomacy_phase(&self) -> bool {
        if self.turn.economic_turn != 1
            || self.turn.difficulty != Difficulty::Easy
            || !self.pending.war_transitions.is_empty()
            || !self.ships.is_empty()
        {
            return false;
        }

        let mut common_military_power = None;
        let mut human_count = 0;
        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            let major = &self.nations.majors[nation];
            let pending = &self.pending.nations[nation];
            if !pending.proposals.is_empty() || !pending.turn_events.is_empty() {
                return false;
            }

            if major.economy.controller.is_human() {
                human_count += 1;
            } else if major.economy.capacities.available_merchant != 0
                || major.common.treasury != 10_000
                // With defense skill zero, every evidenced foreign skill in
                // this range keeps the first-quarter alliance threshold above
                // the branch's maximum 1.25 power ratio.
                || !(0..=6).contains(&major.economy.foreign_minister_skill_index)
                || major.economy.defense_minister_skill_index != 0
                || all_resources().any(|resource| {
                    major.economy.unfilled_trade_turns_by_resource[resource] != 0
                })
            {
                return false;
            }

            if major.economy.grant_total_cost != 0
                || major.economy.pending_commitment_cost != 0
                || NationId::all().any(|target| {
                    major.economy.diplomacy_policy_by_nation[target].is_some()
                        || major.economy.diplomacy_grants_by_nation[target].is_some()
                        || major.economy.candidate_nation_flags[target] != 0
                        || major.economy.colony_boycott_flags[target] != 0
                        || major.economy.development_grant_by_nation[target] != 0
                        || major.common.trade_policy_by_nation[target] != TradePolicyScore::NEUTRAL
                })
            {
                return false;
            }

            let military_power = self.selected_military_power_score(nation.nation());
            if military_power > 18
                || common_military_power.is_some_and(|power| power != military_power)
                || major.city.stockpile[ResourceKind::Arms] != 0
            {
                return false;
            }
            common_military_power = Some(military_power);

            let metalworks = major.city.production_orders[ProductionSlot::Metalworks];
            if major.economy.controller.is_human() {
                if metalworks > 1 {
                    return false;
                }
            } else if metalworks != 0 {
                return false;
            }

            for target in NationId::all() {
                if self.diplomacy.relationships[nation.nation()][target]
                    != DiplomaticRelationship::Peace
                    || self.diplomacy.relationship_turns[nation.nation()][target].is_some()
                    || target.get() >= MajorNationId::COUNT
                        && self.diplomacy.mission_levels[nation.nation()][target]
                            != DiplomaticMissionLevel::None
                {
                    return false;
                }
            }
        }

        if human_count != 1 || common_military_power != Some(4) {
            return false;
        }

        for slot in MinorNationId::FIRST..NationId::COUNT {
            let Some(minor) = self.nations.minors[MinorNationId::new(slot)].as_ref() else {
                return false;
            };
            if minor.common.status != CountryStatus::Independent {
                return false;
            }
        }

        true
    }
}
