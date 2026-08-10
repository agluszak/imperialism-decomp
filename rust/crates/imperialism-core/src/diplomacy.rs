use crate::*;

const TRADE_CONSULATE_COST: i32 = 500;
const DIPLOMACY_PLANNING_QUARTER_BY_NATION: [i32; MajorNationId::COUNT as usize] =
    [0, 3, 1, 2, 1, 2, 0];
const SEEK_ALLIANCE_BY_FOREIGN_SKILL: [f32; 7] = [0.6, 0.7, 0.7, 0.7, 0.8, 0.6, 0.6];
const SEEK_ALLIANCE_BY_DEFENSE_SKILL: [f32; 5] = [0.7, 1.1, 1.3, 0.9, 1.0];

impl GameState {
    /// Whether every still-unported first-turn diplomacy call is provably a no-op.
    pub(crate) fn supports_first_turn_diplomacy_phase(&self) -> bool {
        if self.turn.economic_turn != 1
            || self.turn.difficulty != Difficulty::Easy
            || !self.pending.war_transitions.is_empty()
            || self
                .pending
                .nations
                .iter()
                .any(|work| !work.turn_events.is_empty() || !work.proposals.is_empty())
            || self.nations.majors.iter().any(|major| {
                NationId::all().any(|target| {
                    major.economy.diplomacy_policy_by_nation[target].is_some()
                        || major.economy.diplomacy_grants_by_nation[target].is_some()
                })
            })
        {
            return false;
        }

        let computer_nations = (0..MajorNationId::COUNT)
            .map(MajorNationId::new)
            .filter(|nation| !self.nations.majors[*nation].economy.controller.is_human())
            .collect::<Vec<_>>();
        if computer_nations.is_empty() {
            return true;
        }

        if !self.ships.is_empty()
            || (MinorNationId::FIRST..NationId::COUNT).any(|slot| {
                !matches!(
                    self.nations.common(NationId::new(slot)),
                    Some(common) if common.status == CountryStatus::Independent
                )
            })
        {
            return false;
        }

        for nation in &computer_nations {
            let major = &self.nations.majors[*nation];
            let economy = &major.economy;
            if major.common.treasury != 10_000
                || !(0..SEEK_ALLIANCE_BY_FOREIGN_SKILL.len() as i16)
                    .contains(&economy.foreign_minister_skill_index)
                || !(0..SEEK_ALLIANCE_BY_DEFENSE_SKILL.len() as i16)
                    .contains(&economy.defense_minister_skill_index)
                || economy.grant_total_cost != 0
                || economy.pending_commitment_cost != 0
                || all_resources()
                    .any(|resource| economy.unfilled_trade_turns_by_resource[resource] != 0)
                || NationId::all().any(|target| {
                    economy.candidate_nation_flags[target] != 0
                        || economy.colony_boycott_flags[target] != 0
                        || major.common.trade_policy_by_nation[target] != TradePolicyScore::NEUTRAL
                        || economy.development_grant_by_nation[target] != 0
                        || self.diplomacy.relationships[nation.nation()][target]
                            != DiplomaticRelationship::Peace
                })
                || (MinorNationId::FIRST..NationId::COUNT).any(|target| {
                    self.diplomacy.mission_levels[nation.nation()][NationId::new(target)]
                        != DiplomaticMissionLevel::None
                })
                || self.selected_military_power_score(nation.nation()) > 18
            {
                return false;
            }
        }

        computer_nations.into_iter().all(|nation| {
            DIPLOMACY_PLANNING_QUARTER_BY_NATION[usize::from(nation.get())] != 1
                || self.first_turn_treaty_planning_is_noop(nation)
        })
    }

    /// Runs the recovered single-player phase-six diplomacy pass for the first turn.
    ///
    /// Phase advancement remains the turn driver's responsibility.
    pub(crate) fn run_diplomacy_phase(&mut self) {
        assert_eq!(
            self.turn.economic_turn, 1,
            "only the first-turn diplomacy policy pass is recovered"
        );

        // `ApplyDiplomacyInterNationStatesForTurn` asks AI foreign ministers for
        // policies from major slot 6 down to slot 0.
        for slot in (0..MajorNationId::COUNT).rev() {
            let nation = MajorNationId::new(slot);
            if !self.nations.majors[nation].economy.controller.is_human() {
                self.set_first_turn_diplomacy_policies(nation);
            }
        }

        // The recovered first-turn `FinishDiplomacyPhase` and grant paths are
        // empty. Retail then applies policies in major-row/nation-column order.
        for source_slot in 0..MajorNationId::COUNT {
            let source = MajorNationId::new(source_slot);
            for target in NationId::all() {
                if self.nations.common(target).is_none() {
                    continue;
                }
                match self.nations.majors[source]
                    .economy
                    .diplomacy_policy_by_nation[target]
                {
                    Some(DiplomacyPolicy::BuildConsulate) => self.establish_diplomatic_mission(
                        source,
                        target,
                        DiplomaticMissionLevel::TradeConsulate,
                        InterNationNewsKind::TradeConsulateEstablished,
                    ),
                    Some(DiplomacyPolicy::BuildEmbassy) => self.establish_diplomatic_mission(
                        source,
                        target,
                        DiplomaticMissionLevel::Embassy,
                        InterNationNewsKind::EmbassyEstablished,
                    ),
                    _ => {}
                }
            }
        }

        // The beginning-save oracle has no incoming proposals. Each nation's
        // reply pass therefore performs only this ordinary commitment reset.
        for slot in 0..MajorNationId::COUNT {
            self.reset_diplomacy_commitments(MajorNationId::new(slot));
        }
    }

    pub(crate) fn first_turn_diplomacy_effects(&self) -> Vec<TurnEffect> {
        let has_tracked_human_civilian =
            (0..MajorNationId::COUNT)
                .map(MajorNationId::new)
                .any(|nation| {
                    self.nations.majors[nation].economy.controller.is_human()
                        && self
                            .civilian_units
                            .iter()
                            .any(|unit| unit.nation == nation.nation())
                });
        if !has_tracked_human_civilian {
            return Vec::new();
        }

        MajorNationId::from_nation(self.turn.active_nation)
            .map(|nation| vec![TurnEffect::ShowDiplomacyMap { nation }])
            .unwrap_or_default()
    }

    fn set_first_turn_diplomacy_policies(&mut self, nation: MajorNationId) {
        match self.nations.majors[nation]
            .economy
            .foreign_minister_personality
        {
            ForeignMinisterPersonality::Ted => self.select_random_trade_consulates(nation, 4, true),
            ForeignMinisterPersonality::Bill => {
                self.select_random_trade_consulates(nation, 2, true)
            }
            ForeignMinisterPersonality::Diplomat => {
                let first_minor = match self.rng.next_crt_rand() % 100 {
                    0..=24 => 7,
                    25..=49 => 11,
                    50..=74 => 15,
                    _ => 19,
                };
                for slot in first_minor..first_minor + 4 {
                    self.apply_trade_consulate_policy(nation, NationId::new(slot));
                }
            }
            ForeignMinisterPersonality::Trader => {
                self.select_random_trade_consulates(nation, 4, false)
            }
            ForeignMinisterPersonality::Base
            | ForeignMinisterPersonality::Arms
            | ForeignMinisterPersonality::Textile => {}
        }
    }

    fn select_random_trade_consulates(
        &mut self,
        nation: MajorNationId,
        wanted: usize,
        reject_shared_region_class: bool,
    ) {
        let mut selected = [None; 4];
        let mut selected_count = 0;
        let mut attempts = 0;

        while selected_count < wanted {
            if attempts > 15 {
                return;
            }
            attempts += 1;

            let candidate = MinorNationId::new(
                (self.rng.next_crt_rand() % i32::from(MinorNationId::COUNT)
                    + i32::from(MinorNationId::FIRST)) as u8,
            );
            if selected[..selected_count].contains(&Some(candidate))
                || self.nations.minor(candidate).is_none()
                || (reject_shared_region_class
                    && self.do_nation_territories_share_region_class(
                        nation.nation(),
                        candidate.nation(),
                    ))
            {
                continue;
            }

            selected[selected_count] = Some(candidate);
            self.apply_trade_consulate_policy(nation, candidate.nation());
            selected_count += 1;
        }
    }

    fn apply_trade_consulate_policy(&mut self, nation: MajorNationId, target: NationId) {
        let MajorNation {
            common, economy, ..
        } = &mut self.nations.majors[nation];
        if economy.available_diplomacy_budget(common.treasury)
            - economy.grant_total_cost
            - TRADE_CONSULATE_COST
            < 0
        {
            return;
        }

        common.treasury -= TRADE_CONSULATE_COST;
        economy.diplomacy_policy_by_nation[target] = Some(DiplomacyPolicy::BuildConsulate);
    }

    fn establish_diplomatic_mission(
        &mut self,
        subject: MajorNationId,
        related_nation: NationId,
        level: DiplomaticMissionLevel,
        event: InterNationNewsKind,
    ) {
        self.diplomacy.mission_levels[subject.nation()][related_nation] = level;
        self.diplomacy.mission_levels[related_nation][subject.nation()] = level;

        if let Some(PendingNewspaperEvent::InterNation {
            related_nations, ..
        }) = self.pending.newspaper_events.iter_mut().find(|record| {
            matches!(
                record,
                PendingNewspaperEvent::InterNation {
                    event: existing_event,
                    subject: existing_subject,
                    ..
                } if *existing_event == event && *existing_subject == subject
            )
        }) {
            related_nations[related_nation] = true;
            return;
        }

        let mut related_nations = NationTable::default();
        related_nations[related_nation] = true;
        self.pending
            .queue_newspaper_event(PendingNewspaperEvent::InterNation {
                event,
                subject,
                related_nations,
            });
    }

    fn first_turn_treaty_planning_is_noop(&self, source: MajorNationId) -> bool {
        let economy = &self.nations.majors[source].economy;
        let seek_alliance = SEEK_ALLIANCE_BY_FOREIGN_SKILL
            [economy.foreign_minister_skill_index as usize]
            + SEEK_ALLIANCE_BY_DEFENSE_SKILL[economy.defense_minister_skill_index as usize];
        let source_power = self.first_turn_military_power(source).max(1) as f32;

        (0..MajorNationId::COUNT)
            .map(MajorNationId::new)
            .filter(|target| *target != source)
            .all(|target| {
                let strength_ratio =
                    if self.are_nations_border_linked(source.nation(), target.nation()) {
                        self.first_turn_military_power(target) as f32 / source_power
                    } else {
                        // The supported boundary has no ships, so retail computes
                        // a zero target naval force over its clamped denominator.
                        0.0
                    };
                strength_ratio <= seek_alliance
            })
    }

    fn first_turn_military_power(&self, nation: MajorNationId) -> i32 {
        let major = &self.nations.majors[nation];
        let city = &major.city;
        let army_power = self.selected_military_power_score(nation.nation());
        let reinforcement = i32::from(city.population.strength)
            .min(i32::from(city.population.production_labor.low))
            .min(i32::from(city.stockpile[ResourceKind::Arms]))
            .min(army_power / 2);
        let production = i32::from(city.production_orders[ProductionSlot::Metalworks]);
        army_power + reinforcement + production.min(army_power / 4)
    }
}
