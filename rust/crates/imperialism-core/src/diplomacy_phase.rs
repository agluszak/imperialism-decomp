//! Diplomacy resolution (`TDiplomacyMgr::ApplyDiplomacyInterNationStatesForTurn`
//! plus per-nation `ReplyToDiplomacyOffers` and one queued war transition).

use crate::*;

const PLANNING_QUARTER: [i32; 7] = [0, 3, 1, 2, 1, 2, 0];
const WAR_FOREIGN: [f32; 8] = [0.7, 1.1, 1.2, 1.5, 1.0, 0.9, 0.7, 0.0];
const WAR_DEFENSE: [f32; 6] = [1.0, 1.0, 1.3, 1.3, 1.3, 0.0];
const SEEK_ALLIANCE_FOREIGN: [f32; 8] = [0.6, 0.7, 0.7, 0.7, 0.8, 0.6, 0.6, 0.0];
const SEEK_ALLIANCE_DEFENSE: [f32; 6] = [0.7, 1.1, 1.3, 0.9, 1.0, 0.0];
const ACCEPT_ALLIANCE_FOREIGN: [f32; 8] = [0.5, 0.6, 0.6, 0.6, 0.7, 0.5, 0.5, 0.0];
const ACCEPT_ALLIANCE_DEFENSE: [f32; 6] = [1.0, 1.0, 1.2, 0.8, 0.9, 0.0];
const SEEK_PEACE_FOREIGN: [f32; 8] = [0.4, 0.5, 0.5, 0.5, 0.6, 0.4, 0.4, 0.0];
const SEEK_PEACE_DEFENSE: [f32; 6] = [1.1, 1.0, 1.3, 0.7, 1.1, 0.0];
const ACCEPT_PEACE_FOREIGN: [f32; 8] = [0.4, 0.5, 0.5, 0.5, 0.6, 0.4, 0.4, 0.0];
const ACCEPT_PEACE_DEFENSE: [f32; 6] = [0.9, 0.8, 1.1, 0.5, 0.9, 0.0];
const ALLY_WEIGHT: f32 = -0.25;
const PEER_WEIGHT: f32 = -0.5;
const YEAR_BIAS: f32 = -90.0;
const STRENGTH_OFFSET: f32 = -100.0;
const ENEMY_THRESHOLDS: [i32; 10] = [0x15, 0x12, 0xf, 0xd, 0xb, 0x1b, 0x17, 0x13, 0x10, 0xe];
const MANUFACTURED: [ResourceKind; 4] = [
    ResourceKind::Clothing,
    ResourceKind::Furniture,
    ResourceKind::Hardware,
    ResourceKind::Arms,
];
const RAW_TRADE: [TradeCommodity; 7] = [
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

    /// Accepts or rejects the war-join dialog that stopped war-transition
    /// processing, then finishes the remaining reactions for that one war.
    pub fn resolve_diplomacy_war_join(
        &mut self,
        prompt: DiplomacyWarJoinPrompt,
        accept: bool,
    ) -> DiplomacyPhaseResult {
        self.apply_war_join_decision(prompt, accept);
        self.continue_war_reactions(prompt.pair_first, prompt.pair_second, prompt.cursor)
    }

    fn apply_diplomacy_inter_nation_states(&mut self) {
        for index in (0..MajorNationId::COUNT).rev() {
            let nation = MajorNationId::new(index);
            if self.is_auto(nation) {
                self.set_ai_diplomacy_policies(nation);
            }
        }

        for source in majors() {
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

    fn set_ai_diplomacy_policies(&mut self, nation: MajorNationId) {
        self.set_empire_policies(nation);
        self.do_propose_treaties(nation);
        self.goods_match_shipping(nation);
        self.do_development_grants(nation);
    }

    fn set_empire_policies(&mut self, nation: MajorNationId) {
        let turn = self.turn.economic_turn;
        if turn.unsigned_abs().is_multiple_of(4) && !self.manufactured_offers_exhausted(nation) {
            let ranked = self.ranked_independents(nation.nation(), false);
            for &minor in ranked.iter().rev() {
                let favorite = self.favorite_trade_partner(MinorNationId::new(minor.get()));
                let standing = self.diplomacy.standings[nation.nation()][minor];
                let trade = self.nations.majors[nation].common.trade_policy_by_nation[minor];
                if favorite != Some(nation) && standing > 0x31 && trade != TradePolicyScore::BOYCOTT
                {
                    self.decrement_trade_policy_score(nation, minor);
                    break;
                }
            }
        }

        if self.nations.majors[nation]
            .economy
            .capacities
            .available_merchant
            > 0
        {
            let shortage = RAW_TRADE.into_iter().find(|&commodity| {
                self.nations.majors[nation]
                    .economy
                    .unfilled_trade_turns_by_resource[commodity.resource()]
                    > 2
            });
            if let Some(commodity) = shortage {
                let ranked = self.ranked_independents(nation.nation(), false);
                let selected = ranked.iter().copied().rev().find(|&minor| {
                    self.market.rows[commodity].current_offer_by_nation[minor] != 0
                        && self.nations.majors[nation].common.trade_policy_by_nation[minor]
                            != TradePolicyScore::BOYCOTT
                });
                if let Some(minor) = selected {
                    if self.diplomacy.mission_levels[nation.nation()][minor].retail()
                        < DiplomaticMissionLevel::TradeConsulate.retail()
                    {
                        self.post_policy(nation, minor, DiplomacyPolicy::BuildConsulate);
                    } else {
                        self.decrement_trade_policy_score(nation, minor);
                    }
                }
            }
        }

        for slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = NationId::new(slot);
            let trade = self.nations.majors[nation].common.trade_policy_by_nation[minor];
            if self.diplomacy.mission_levels[nation.nation()][minor].retail()
                >= DiplomaticMissionLevel::TradeConsulate.retail()
                && trade.get() > 0x5f
                && trade.get() < 300
                && self.is_independent(minor)
            {
                self.set_one_trade(nation.nation(), minor, TradePolicyScore::new(0x5f));
            }
        }

        if self.nations.majors[nation].common.treasury < 0 {
            for slot in MinorNationId::FIRST..NationId::COUNT {
                let minor = NationId::new(slot);
                if self.nations.majors[nation].common.trade_policy_by_nation[minor].get() < 0x4b {
                    self.set_one_trade(nation.nation(), minor, TradePolicyScore::new(0x4b));
                }
            }
        }
    }

    fn do_propose_treaties(&mut self, nation: MajorNationId) {
        for slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = NationId::new(slot);
            if self.diplomacy.mission_levels[nation.nation()][minor]
                != DiplomaticMissionLevel::Embassy
            {
                continue;
            }
            if self.minor_would_accept_join_empire(minor, nation.nation()) {
                if !self.has_alliance_guard(minor, nation.nation()) {
                    self.post_policy(nation, minor, DiplomacyPolicy::JoinEmpire);
                }
            } else if self.diplomacy.relationships[nation.nation()][minor]
                == DiplomaticRelationship::Peace
            {
                self.post_policy(nation, minor, DiplomacyPolicy::NonAggressionPact);
            }
        }

        if !self.has_active_candidates(nation) {
            self.do_select_enemy(nation);
        }

        if self.turn.economic_turn.unsigned_abs() as i32 % 4
            != PLANNING_QUARTER[usize::from(nation.get())]
        {
            return;
        }

        let army = (self.military_power(nation) as i32).max(1) as f32;
        let navy = (self.naval_force(nation) as i32).max(1) as f32;
        let (allied_army, allied_navy) = self.allied_forces(nation);
        let mut stronger = false;
        for target in majors() {
            if target == nation || !self.event_eligible(target.nation()) {
                continue;
            }
            let ratio = if self.are_nations_border_linked(nation.nation(), target.nation()) {
                self.military_power(target) / (army + allied_army * 0.25)
            } else {
                self.naval_force(target) / (navy + allied_navy * 0.25)
            };
            if self.seek_alliance_number(nation) < ratio {
                stronger = true;
            }
        }
        if stronger {
            let ranked = self.ranked_independents(nation.nation(), true);
            if let Some(selected) = ranked.iter().copied().rev().find(|&candidate| {
                self.diplomacy.relationships[nation.nation()][candidate]
                    != DiplomaticRelationship::Alliance
                    && !self.has_alliance_guard(candidate, nation.nation())
            }) {
                self.post_policy(nation, selected, DiplomacyPolicy::Alliance);
            }
        }

        for target in majors() {
            if target == nation
                || !self.event_eligible(target.nation())
                || !self.war_stamp_stale(nation.nation(), target.nation())
            {
                continue;
            }
            if self.seek_peace_number(nation) < self.peace_threat(nation, target) {
                self.post_policy(nation, target.nation(), DiplomacyPolicy::PeaceTreaty);
                continue;
            }
            if self.turn.economic_turn / 4 >= 0x46 || self.deserves_to_be_enemy(nation, target) {
                continue;
            }
            if self.owns_former_province_of(target, nation.nation()) {
                continue;
            }
            let recovered = self.recovered_province_count(nation, target.nation());
            let required = (self.turn.economic_turn / 4 + 10) / 10;
            if recovered >= required {
                self.post_policy(nation, target.nation(), DiplomacyPolicy::PeaceTreaty);
            }
        }
    }

    fn goods_match_shipping(&mut self, nation: MajorNationId) {
        let has_colony = (MinorNationId::FIRST..NationId::COUNT).any(|slot| {
            self.nations
                .common(NationId::new(slot))
                .is_some_and(|common| common.status() == CountryStatus::ColonyOf(nation.nation()))
        });
        for target in majors() {
            if target == nation || !self.event_eligible(target.nation()) {
                continue;
            }
            let boycott =
                has_colony && self.diplomacy.standings[nation.nation()][target.nation()] < 0x96;
            self.set_colony_boycott(nation, target.nation(), boycott);
        }
    }

    fn do_development_grants(&mut self, nation: MajorNationId) {
        let mut budget =
            ((self.nations.majors[nation].common.treasury - 10_000) as f32 * 0.5) as i32;
        if budget <= 1000 {
            return;
        }
        let ranked = self.ranked_independents(nation.nation(), false);
        for &minor in ranked.iter().rev() {
            if budget <= 1000 {
                break;
            }
            let standing = self.diplomacy.standings[nation.nation()][minor];
            if standing < 0xff
                && self.diplomacy.mission_levels[nation.nation()][minor]
                    == DiplomaticMissionLevel::Embassy
            {
                let amount = select_grant_amount(budget);
                budget -= amount;
                let _ = self.set_diplomacy_grant(
                    nation,
                    minor,
                    Some(DiplomacyGrant {
                        amount,
                        recurring: false,
                    }),
                );
                self.nations.majors[nation]
                    .economy
                    .development_grant_by_nation[minor] += amount as i16;
            }
        }
        if budget > 1000 {
            for &minor in ranked.iter().rev() {
                if budget <= 1000 {
                    break;
                }
                if self.diplomacy.mission_levels[nation.nation()][minor]
                    == DiplomaticMissionLevel::TradeConsulate
                {
                    let amount = select_grant_amount(budget);
                    budget -= amount;
                    let _ = self.set_diplomacy_grant(
                        nation,
                        minor,
                        Some(DiplomacyGrant {
                            amount,
                            recurring: false,
                        }),
                    );
                    let cumulative = {
                        let slot = &mut self.nations.majors[nation]
                            .economy
                            .development_grant_by_nation[minor];
                        *slot += amount as i16;
                        *slot
                    };
                    if cumulative >= 5000 {
                        self.set_mission_level(
                            nation.nation(),
                            minor,
                            DiplomaticMissionLevel::Embassy,
                        );
                        self.add_treaty_event(
                            InterNationNewsKind::EmbassyEstablished,
                            nation.nation(),
                            minor,
                        );
                    }
                }
            }
        }
        if budget > 1000 {
            for &minor in ranked.iter().rev() {
                if self.diplomacy.standings[nation.nation()][minor] < 0xff
                    && self.diplomacy.mission_levels[nation.nation()][minor]
                        == DiplomaticMissionLevel::None
                {
                    self.post_policy(nation, minor, DiplomacyPolicy::BuildConsulate);
                    break;
                }
            }
        }
    }

    fn do_select_enemy(&mut self, nation: MajorNationId) {
        for target in majors() {
            if self.has_active_candidates(nation) {
                return;
            }
            if target != nation
                && self.event_eligible(target.nation())
                && self.deserves_to_be_enemy(nation, target)
            {
                self.set_enemy(nation, target.nation());
            }
        }
    }

    fn post_policy(&mut self, nation: MajorNationId, target: NationId, policy: DiplomacyPolicy) {
        let embassy = self.diplomacy.mission_levels[nation.nation()][target]
            == DiplomaticMissionLevel::Embassy;
        let mut apply = true;
        match policy {
            DiplomacyPolicy::JoinEmpire
            | DiplomacyPolicy::Alliance
            | DiplomacyPolicy::NonAggressionPact
                if !embassy =>
            {
                apply = false;
            }
            DiplomacyPolicy::DeclareWar => {
                self.queue_war(nation.nation(), target, None);
                if self.diplomacy.relationships[target][nation.nation()]
                    == DiplomaticRelationship::Alliance
                {
                    self.apply_peace_relationship(nation.nation(), target, true);
                }
                if let CountryStatus::ColonyOf(master) = self.status_of(target)
                    && !self.at_war(nation.nation(), master)
                {
                    self.post_policy(nation, master, DiplomacyPolicy::DeclareWar);
                }
                if self.nations.majors[nation].economy.controller.is_human() {
                    let _ = self.set_diplomacy_grant(nation, target, None);
                }
            }
            DiplomacyPolicy::BuildConsulate => {
                apply = self.can_afford_diplomacy(nation, 500);
                if apply {
                    self.nations.majors[nation].common.treasury -= 500;
                }
            }
            DiplomacyPolicy::BuildEmbassy => {
                apply = self.can_afford_diplomacy(nation, 5000);
                if apply {
                    self.nations.majors[nation].common.treasury -= 5000;
                }
            }
            _ => {}
        }
        if apply {
            self.nations.majors[nation]
                .economy
                .diplomacy_policy_by_nation[target] = Some(policy);
        }
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
            if self.is_auto(major) {
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

    fn add_diplomacy_notice(&mut self, nation: MajorNationId, source: NationId, code: i16) {
        if self.nations.majors[nation].economy.controller.is_human() {
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
        self.process_one_queued_war()
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

    fn apply_human_offer_decision(&mut self, nation: MajorNationId, index: usize, accept: bool) {
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

    fn accept_diplomacy_offer(&mut self, nation: MajorNationId, index: usize) {
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

    fn change_master(&mut self, subject: NationId, master: NationId) {
        self.set_nation_pair_relationship(
            subject,
            master,
            DiplomaticRelationship::JoinedEmpire,
            true,
        );
        self.nations
            .set_country_status(subject, CountryStatus::ColonyOf(master));
        self.set_one_trade(subject, master, TradePolicyScore::NEUTRAL);
        for other in NationId::all() {
            if !self.event_eligible(other) || other == subject || other == master {
                continue;
            }
            let policy = self
                .nations
                .common(other)
                .map(|common| common.trade_policy_by_nation[master])
                .unwrap_or(TradePolicyScore::NEUTRAL);
            self.set_one_trade(other, subject, policy);
        }
        self.reset_mission_row(subject);
        if matches!(self.status_of(subject), CountryStatus::ColonyOf(_)) {
            self.set_mission_level(subject, master, DiplomaticMissionLevel::Embassy);
        }

        if MajorNationId::from_nation(subject).is_none() {
            self.reset_master_diplomacy_for_colony(master, subject);
            for unit in &mut self.military_units {
                if unit.nation == subject {
                    unit.nation = master;
                    unit.owner_nation = master;
                }
            }
            self.set_boycott_policies_to_match(subject, master);
            self.set_relationships_to_match(subject, master);
            self.kill_enemy_civilians(subject);
            self.deport_civilians(subject);
            if let Some(major) = MajorNationId::from_nation(master) {
                let pending = &mut self.nations.majors[major].economy.pending_actions
                    [PendingActionKind::ColonyMonumentMerchantCapacity];
                if !pending.status().has_reached(PendingActionStatus::Level3) {
                    pending.queue(i16::from(subject.get()));
                }
            }
            self.add_treaty_event(InterNationNewsKind::NationJoinedEmpire, master, subject);
        }

        if let (Some(_), Some(master_major)) = (
            MajorNationId::from_nation(subject),
            MajorNationId::from_nation(master),
        ) {
            let pending = &mut self.nations.majors[master_major].economy.pending_actions
                [PendingActionKind::AnnexedGreatPowerCapitalExpansion];
            if !pending.status().has_reached(PendingActionStatus::Level3) {
                pending.queue(i16::from(subject.get()));
            }
        }
    }

    fn reset_master_diplomacy_for_colony(&mut self, master: NationId, colony: NationId) {
        self.set_one_trade(master, colony, TradePolicyScore::NEUTRAL);
        if let Some(major) = MajorNationId::from_nation(master) {
            let _ = self.set_diplomacy_grant(major, colony, None);
        }
        let enemies: Vec<_> = NationId::all()
            .filter(|&other| self.at_war(master, other))
            .collect();
        for enemy in enemies {
            self.declare_war_for_colonies(master, enemy);
        }
    }

    fn declare_war_for_colonies(&mut self, master: NationId, enemy: NationId) {
        for slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = NationId::new(slot);
            if !self
                .nations
                .common(minor)
                .is_some_and(|common| common.status() == CountryStatus::ColonyOf(master))
                || self.at_war(minor, enemy)
            {
                continue;
            }
            self.set_nation_pair_relationship(minor, enemy, DiplomaticRelationship::War, false);
            if let Some(target) = MajorNationId::from_nation(enemy)
                && self.event_eligible(enemy)
                && self.is_auto(target)
            {
                self.add_diplomacy_notice(target, minor, DiplomacyPolicy::DeclareWar.retail());
            }
            self.kill_enemy_civilians(minor);
        }
    }

    fn set_boycott_policies_to_match(&mut self, colony: NationId, master: NationId) {
        for other in NationId::all() {
            let war = self.at_war(master, other);
            let flagged = MajorNationId::from_nation(master).is_some_and(|major| {
                self.nations.majors[major].economy.colony_boycott_flags[other] != 0
            });
            let policy = if !war && (other == colony || !flagged) {
                TradePolicyScore::NEUTRAL
            } else {
                TradePolicyScore::BOYCOTT
            };
            self.set_one_trade(colony, other, policy);
        }
    }

    fn kill_enemy_civilians(&mut self, nation: NationId) {
        let owner = self.owner_slot(nation);
        let Some(common) = self.nations.common(nation) else {
            return;
        };
        let tiles: Vec<_> = common
            .owned_regions()
            .iter()
            .flat_map(|&province| self.map.provinces[province].linked_tiles.iter().copied())
            .collect();
        let enemies: [bool; MAJOR_NATION_COUNT] = std::array::from_fn(|index| {
            let other = MajorNationId::new(index as u8).nation();
            other != owner && self.nation_is_present(other) && self.at_war(owner, other)
        });
        self.civilian_units.retain(|unit| {
            let Some(tile) = unit.location.tile() else {
                return true;
            };
            if !tiles.contains(&tile) {
                return true;
            }
            let Some(owner) = MajorNationId::from_nation(unit.owner_nation) else {
                return true;
            };
            !enemies[usize::from(owner.get())]
        });
    }

    fn deport_civilians(&mut self, nation: NationId) {
        self.kill_boycotted_foreign_companies(nation);
        let owner = self.owner_slot(nation);
        let Some(common) = self.nations.common(nation) else {
            return;
        };
        let tiles: Vec<_> = common
            .owned_regions()
            .iter()
            .flat_map(|&province| self.map.provinces[province].linked_tiles.iter().copied())
            .collect();
        let targets: [bool; MAJOR_NATION_COUNT] = std::array::from_fn(|index| {
            let other = MajorNationId::new(index as u8).nation();
            other != owner && self.nation_is_present(other) && self.need_level_300(nation, other)
        });
        let mut index = 0;
        while index < self.civilian_units.len() {
            let unit = &self.civilian_units[index];
            let Some(tile) = unit.location.tile() else {
                index += 1;
                continue;
            };
            if !tiles.contains(&tile) {
                index += 1;
                continue;
            }
            let Some(owner) = MajorNationId::from_nation(unit.owner_nation) else {
                index += 1;
                continue;
            };
            if !targets[usize::from(owner.get())] {
                index += 1;
                continue;
            }
            let Some(home) = self.nations.majors[owner].common.home_tile else {
                self.civilian_units.remove(index);
                continue;
            };
            if let Some(destination) =
                self.map
                    .find_reachable_recruit_spawn_tile(&self.civilian_units, home, false)
            {
                self.civilian_units[index].location = CivilianLocation::OnMap(destination);
                index += 1;
            } else {
                self.civilian_units.remove(index);
            }
        }
    }

    fn kill_boycotted_foreign_companies(&mut self, nation: NationId) {
        let Some(common) = self.nations.common(nation) else {
            return;
        };
        let boycott: [bool; MAJOR_NATION_COUNT] = std::array::from_fn(|index| {
            common.trade_policy_by_nation[MajorNationId::new(index as u8).nation()]
                == TradePolicyScore::BOYCOTT
        });
        let tiles: Vec<_> = common
            .owned_regions()
            .iter()
            .flat_map(|&province| self.map.provinces[province].linked_tiles.iter().copied())
            .collect();
        let mut notify = [false; MAJOR_NATION_COUNT];
        for tile in tiles {
            let Some(owner) = self.map[tile].secondary_owner_nation else {
                continue;
            };
            let index = usize::from(owner.get());
            if boycott[index] {
                notify[index] = true;
                self.map[tile].secondary_owner_nation = None;
            }
        }
        for (index, flagged) in notify.into_iter().enumerate() {
            if !flagged {
                continue;
            }
            let major = MajorNationId::new(index as u8);
            self.add_diplomacy_notice(major, nation, 0x137);
            self.add_treaty_event(
                InterNationNewsKind::MinorTerritoryRelationshipAffected,
                major.nation(),
                nation,
            );
        }
    }

    fn need_level_300(&self, source: NationId, target: NationId) -> bool {
        self.nations.common(source).is_some_and(|common| {
            common.trade_policy_by_nation[target] == TradePolicyScore::BOYCOTT
        }) || self.nations.common(target).is_some_and(|common| {
            common.trade_policy_by_nation[source] == TradePolicyScore::BOYCOTT
        })
    }

    fn queue_war(&mut self, source: NationId, target: NationId, annex: Option<NationId>) {
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

    fn process_one_queued_war(&mut self) -> DiplomacyPhaseResult {
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

    fn continue_war_reactions(
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
                if self.nations.majors[favorite].economy.controller.is_human() {
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
            if self.nations.majors[other].economy.controller.is_human() {
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
            if self.nations.majors[other].economy.controller.is_human() {
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

    fn apply_war_join_decision(&mut self, prompt: DiplomacyWarJoinPrompt, accept: bool) {
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

    fn ai_handle_minor_war(&mut self, nation: MajorNationId, minor: NationId, attacker: NationId) {
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

    fn ai_handle_role_swap(
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

    fn set_mission_level(
        &mut self,
        source: NationId,
        target: NationId,
        level: DiplomaticMissionLevel,
    ) {
        self.diplomacy.mission_levels[source][target] = level;
        self.diplomacy.mission_levels[target][source] = level;
    }

    fn reset_mission_row(&mut self, nation: NationId) {
        for other in NationId::all() {
            self.diplomacy.mission_levels[nation][other] = DiplomaticMissionLevel::None;
            self.diplomacy.mission_levels[other][nation] = DiplomaticMissionLevel::None;
        }
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

    fn copy_colony_standings_from(&mut self, master: NationId) {
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

    fn set_pair_trade_policy(
        &mut self,
        source: NationId,
        target: NationId,
        policy: TradePolicyScore,
    ) {
        self.set_one_trade(source, target, policy);
        self.set_one_trade(target, source, policy);
    }

    fn set_one_trade(&mut self, source: NationId, target: NationId, policy: TradePolicyScore) {
        if let Some(common) = self.nations.common_mut(source)
            && target != source
        {
            common.trade_policy_by_nation[target] = policy;
        }
    }

    fn dispatch_aligned_minor_relationship(
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

    fn apply_peace_relationship(
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

    fn inflict_war_penalty(&mut self, source: NationId, target: NationId, war_cut: bool) {
        let pair_standing = self.diplomacy.standings[source][target];
        if war_cut {
            if pair_standing - 0x32 < 0x31 {
                self.set_relationship(source, target, pair_standing - 0x32);
            } else {
                self.set_relationship(source, target, 0x31);
            }
        } else {
            let adjustment = ((0x5a - i32::from(pair_standing)) * i32::from(pair_standing)) / 200;
            if (adjustment as i16) < 0 {
                self.set_relationship(source, target, pair_standing + adjustment as i16);
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
            if source.get() == 0 {
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

    fn has_alliance_guard(&self, nation: NationId, guarded: NationId) -> bool {
        if !majors().any(|index| self.at_war(nation, index.nation())) {
            return false;
        }
        majors().any(|index| {
            let other = index.nation();
            self.at_war(other, nation) && !self.at_war(guarded, other)
        })
    }

    fn minor_would_accept_join_empire(&self, minor: NationId, source: NationId) -> bool {
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

    fn evaluate_join_war(&mut self, nation: MajorNationId, target: NationId) -> bool {
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

    fn peace_allies_fighting(&mut self, nation: NationId, enemy: NationId) {
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

    fn queue_wars_against_enemies_of(
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

    fn passes_alliance_strength(&self, nation: MajorNationId, target: NationId) -> bool {
        if self.has_alliance_guard(target, nation.nation()) {
            return false;
        }
        let (ally_army, ally_navy) = self.allied_forces(nation);
        let army = self.military_power(nation);
        let navy = self.naval_force(nation);
        let own = army.max(navy);
        let ally = (ally_army as i32).max(ally_navy as i32) / 4;
        let mut strongest: f32 = 0.0;
        for peer in majors() {
            if !self.event_eligible(peer.nation()) {
                continue;
            }
            strongest = strongest
                .max(self.military_power(peer))
                .max(self.naval_force(peer));
        }
        let tick = (self.turn.economic_turn / 4).min(0x3c) as f32;
        let standing = f32::from(self.diplomacy.standings[nation.nation()][target]);
        let combined = own + ally as f32;
        #[allow(clippy::float_cmp)]
        let score =
            (strongest / combined + (standing + own) / (tick + combined - STRENGTH_OFFSET)) * 0.5;
        self.accept_alliance_number(nation) <= score
    }

    fn peace_threat(&self, nation: MajorNationId, target: MajorNationId) -> f32 {
        let self_army = (self.military_power(nation) as i32).max(1) as f32;
        let self_navy = (self.naval_force(nation) as i32).max(1) as f32;
        let mut allied_self_army = 0.0;
        let mut allied_self_navy = 0.0;
        let mut allied_target_army = 0.0;
        let mut allied_target_navy = 0.0;
        for other in majors() {
            if !self.event_eligible(other.nation()) {
                continue;
            }
            if self.at_war(other.nation(), nation.nation()) && other != target {
                allied_self_army += self.military_power(other);
                allied_self_navy += self.naval_force(other);
            }
            if self.at_war(other.nation(), target.nation()) && other != nation {
                allied_target_army += self.military_power(other);
                allied_target_navy += self.naval_force(other);
            }
        }
        let peer = -PEER_WEIGHT;
        if self.are_nations_border_linked(target.nation(), nation.nation()) {
            (self_army + allied_self_army * peer)
                / (self.military_power(target) + allied_target_army * peer)
        } else {
            (self_navy + allied_self_navy * peer)
                / (self.naval_force(target) + allied_target_navy * peer)
        }
    }

    fn deserves_to_be_enemy(&self, nation: MajorNationId, target: MajorNationId) -> bool {
        let difficulty = self.turn.difficulty as usize;
        let threshold_a = ENEMY_THRESHOLDS[difficulty];
        let threshold_b = ENEMY_THRESHOLDS[difficulty + 5];
        if !self.are_nations_border_linked(nation.nation(), target.nation()) {
            if threshold_b >= self.navy_arms(nation.nation()) {
                return false;
            }
            let average = ((self.navy_ratio(nation, target) as i32)
                + (self.navy_standing_ratio(nation, target) as i32))
                / 2;
            return self.war_number(nation) <= average as f32;
        }
        if threshold_a >= self.army_unit_power(nation.nation()) {
            return false;
        }
        let year = i32::from(self.turn.diplomacy_year_term_raw);
        let divisors = [year, year / 2, year / 3, year / 5, 0];
        let progress = (self.turn.economic_turn / 4 + year) / (divisors[difficulty] + year);
        let average = ((self.army_ratio(nation, target) as i32)
            + (self.army_standing_ratio(nation, target) as i32))
            / 2;
        self.war_number(nation) <= (progress as f32 * average as f32)
    }

    fn allied_forces(&self, nation: MajorNationId) -> (f32, f32) {
        let mut army = 0.0;
        let mut navy = 0.0;
        for ally in majors() {
            if self.diplomacy.relationships[nation.nation()][ally.nation()]
                == DiplomaticRelationship::Alliance
            {
                army += self.military_power(ally);
                navy += self.naval_force(ally);
            }
        }
        (army, navy)
    }

    fn allied_army(&self, nation: MajorNationId) -> f32 {
        self.allied_forces(nation).0
    }

    fn allied_navy(&self, nation: MajorNationId) -> f32 {
        self.allied_forces(nation).1
    }

    #[allow(clippy::float_cmp)]
    fn ratio(self_score: f32, target: f32, ally: f32) -> f32 {
        let denom = target - ally * ALLY_WEIGHT;
        if denom == 0.0 {
            self_score
        } else {
            self_score / denom
        }
    }

    fn army_ratio(&self, nation: MajorNationId, target: MajorNationId) -> f32 {
        Self::ratio(
            self.military_power(nation),
            self.military_power(target),
            self.allied_army(target),
        )
    }

    fn navy_ratio(&self, nation: MajorNationId, target: MajorNationId) -> f32 {
        Self::ratio(
            self.naval_force(nation),
            self.naval_force(target),
            self.allied_navy(target),
        )
    }

    #[allow(clippy::float_cmp)]
    fn standing_ratio(
        &self,
        nation: MajorNationId,
        target: MajorNationId,
        self_score: f32,
        target_score: f32,
        ally: f32,
    ) -> f32 {
        let year = self.clamped_quarter() as f32;
        let standing = f32::from(self.diplomacy.standings[nation.nation()][target.nation()]);
        let denom = standing - ally * ALLY_WEIGHT + target_score;
        let numer = year + self_score - YEAR_BIAS;
        if denom == 0.0 { numer } else { numer / denom }
    }

    fn army_standing_ratio(&self, nation: MajorNationId, target: MajorNationId) -> f32 {
        self.standing_ratio(
            nation,
            target,
            self.military_power(nation),
            self.military_power(target),
            self.allied_army(target),
        )
    }

    fn navy_standing_ratio(&self, nation: MajorNationId, target: MajorNationId) -> f32 {
        self.standing_ratio(
            nation,
            target,
            self.naval_force(nation),
            self.naval_force(target),
            self.allied_navy(target),
        )
    }

    fn target_force(&self, target: MajorNationId, linked: NationId) -> f32 {
        if self.are_nations_border_linked(target.nation(), linked) {
            self.military_power(target)
        } else {
            self.naval_force(target)
        }
    }

    fn army_ratio_with_secondary(
        &self,
        nation: MajorNationId,
        target: NationId,
        secondary: NationId,
    ) -> f32 {
        let Some(target) = MajorNationId::from_nation(target) else {
            return self.military_power(nation);
        };
        Self::ratio(
            self.military_power(nation),
            self.target_force(target, secondary),
            self.allied_army(target),
        )
    }

    fn navy_ratio_with_secondary(
        &self,
        nation: MajorNationId,
        target: NationId,
        secondary: NationId,
    ) -> f32 {
        let Some(target) = MajorNationId::from_nation(target) else {
            return self.naval_force(nation);
        };
        Self::ratio(
            self.naval_force(nation),
            self.target_force(target, secondary),
            self.allied_navy(target),
        )
    }

    #[allow(clippy::float_cmp)]
    fn standing_pair(
        &self,
        nation: MajorNationId,
        target: NationId,
        partner: NationId,
        self_score: f32,
        ally: f32,
    ) -> f32 {
        let Some(target_major) = MajorNationId::from_nation(target) else {
            return self_score;
        };
        let standing_target = f32::from(self.diplomacy.standings[nation.nation()][target]);
        let standing_partner = f32::from(self.diplomacy.standings[nation.nation()][partner]);
        let denom = standing_target - ally * ALLY_WEIGHT + self.target_force(target_major, partner);
        if denom == 0.0 {
            standing_partner + self_score
        } else {
            (standing_partner + self_score) / denom
        }
    }

    fn army_standing_pair(
        &self,
        nation: MajorNationId,
        target: NationId,
        partner: NationId,
    ) -> f32 {
        self.standing_pair(
            nation,
            target,
            partner,
            self.military_power(nation),
            self.allied_army_of(target),
        )
    }

    fn navy_standing_pair(
        &self,
        nation: MajorNationId,
        target: NationId,
        partner: NationId,
    ) -> f32 {
        self.standing_pair(
            nation,
            target,
            partner,
            self.naval_force(nation),
            self.allied_navy_of(target),
        )
    }

    fn allied_army_of(&self, nation: NationId) -> f32 {
        MajorNationId::from_nation(nation).map_or(0.0, |major| self.allied_army(major))
    }

    fn allied_navy_of(&self, nation: NationId) -> f32 {
        MajorNationId::from_nation(nation).map_or(0.0, |major| self.allied_navy(major))
    }

    #[allow(clippy::float_cmp)]
    fn pair_ratio(self_score: f32, opponent: f32, partner: f32, ally: f32, swap: bool) -> f32 {
        let denom = opponent - ally * ALLY_WEIGHT;
        let mut numer = if swap {
            self_score - partner * ALLY_WEIGHT
        } else {
            self_score - partner * PEER_WEIGHT
        };
        if denom != 0.0 {
            numer /= denom;
        }
        numer
    }

    fn pair_nations(
        &self,
        a: MajorNationId,
        b: MajorNationId,
        swap: bool,
    ) -> (MajorNationId, MajorNationId) {
        if swap { (b, a) } else { (a, b) }
    }

    fn army_pair_ratio(
        &self,
        nation: MajorNationId,
        a: MajorNationId,
        b: MajorNationId,
        swap: bool,
    ) -> f32 {
        let (opponent, partner) = self.pair_nations(a, b, swap);
        Self::pair_ratio(
            self.military_power(nation),
            self.military_power(opponent),
            self.military_power(partner),
            self.allied_army(opponent),
            swap,
        )
    }

    fn navy_pair_ratio(
        &self,
        nation: MajorNationId,
        a: MajorNationId,
        b: MajorNationId,
        swap: bool,
    ) -> f32 {
        let (opponent, partner) = self.pair_nations(a, b, swap);
        Self::pair_ratio(
            self.naval_force(nation),
            self.naval_force(opponent),
            self.naval_force(partner),
            self.allied_navy(opponent),
            swap,
        )
    }

    fn army_pair_standing(
        &self,
        nation: MajorNationId,
        a: MajorNationId,
        b: MajorNationId,
        swap: bool,
    ) -> f32 {
        self.pair_standing(nation, a, b, swap, false)
    }

    fn navy_pair_standing(
        &self,
        nation: MajorNationId,
        a: MajorNationId,
        b: MajorNationId,
        swap: bool,
    ) -> f32 {
        self.pair_standing(nation, a, b, swap, true)
    }

    #[allow(clippy::float_cmp)]
    fn pair_standing(
        &self,
        nation: MajorNationId,
        a: MajorNationId,
        b: MajorNationId,
        swap: bool,
        navy: bool,
    ) -> f32 {
        let (opponent, partner) = self.pair_nations(a, b, swap);
        let self_score = if navy {
            self.naval_force(nation)
        } else {
            self.military_power(nation)
        };
        let opponent_score = if navy {
            self.naval_force(opponent)
        } else {
            self.military_power(opponent)
        };
        let partner_score = if navy {
            self.naval_force(partner)
        } else {
            self.military_power(partner)
        };
        let ally = if navy {
            self.allied_navy(opponent)
        } else {
            self.allied_army(opponent)
        };
        let standing_opp = f32::from(self.diplomacy.standings[nation.nation()][opponent.nation()]);
        let standing_partner =
            f32::from(self.diplomacy.standings[nation.nation()][partner.nation()]);
        let denom = standing_opp - ally * ALLY_WEIGHT + opponent_score;
        let mut numer = if swap {
            standing_partner - partner_score * ALLY_WEIGHT + self_score
        } else {
            standing_partner - partner_score * PEER_WEIGHT + self_score
        };
        if denom != 0.0 {
            numer /= denom;
        }
        numer
    }

    fn war_number(&self, nation: MajorNationId) -> f32 {
        coeff(
            &WAR_FOREIGN,
            self.nations.majors[nation]
                .economy
                .foreign_minister_skill_index,
        ) + coeff(
            &WAR_DEFENSE,
            self.nations.majors[nation]
                .economy
                .defense_minister_skill_index,
        )
    }

    fn seek_alliance_number(&self, nation: MajorNationId) -> f32 {
        coeff(
            &SEEK_ALLIANCE_DEFENSE,
            self.nations.majors[nation]
                .economy
                .defense_minister_skill_index,
        ) + coeff(
            &SEEK_ALLIANCE_FOREIGN,
            self.nations.majors[nation]
                .economy
                .foreign_minister_skill_index,
        )
    }

    fn accept_alliance_number(&self, nation: MajorNationId) -> f32 {
        coeff(
            &ACCEPT_ALLIANCE_DEFENSE,
            self.nations.majors[nation]
                .economy
                .defense_minister_skill_index,
        ) + coeff(
            &ACCEPT_ALLIANCE_FOREIGN,
            self.nations.majors[nation]
                .economy
                .foreign_minister_skill_index,
        )
    }

    fn seek_peace_number(&self, nation: MajorNationId) -> f32 {
        coeff(
            &SEEK_PEACE_FOREIGN,
            self.nations.majors[nation]
                .economy
                .foreign_minister_skill_index,
        ) + coeff(
            &SEEK_PEACE_DEFENSE,
            self.nations.majors[nation]
                .economy
                .defense_minister_skill_index,
        )
    }

    fn accept_peace_number(&self, nation: MajorNationId) -> f32 {
        coeff(
            &ACCEPT_PEACE_FOREIGN,
            self.nations.majors[nation]
                .economy
                .foreign_minister_skill_index,
        ) + coeff(
            &ACCEPT_PEACE_DEFENSE,
            self.nations.majors[nation]
                .economy
                .defense_minister_skill_index,
        )
    }

    fn clamped_quarter(&self) -> i32 {
        (self.turn.economic_turn / 4).min(0x3c)
    }

    fn manufactured_offers_exhausted(&self, nation: MajorNationId) -> bool {
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

    fn can_afford_diplomacy(&self, nation: MajorNationId, cost: i32) -> bool {
        let major = &self.nations.majors[nation];
        major
            .economy
            .available_diplomacy_budget(major.common.treasury)
            - major.economy.grant_total_cost
            - cost
            >= 0
    }

    fn war_stamp_stale(&self, source: NationId, target: NationId) -> bool {
        self.at_war(source, target)
            && self.diplomacy.relationship_turns[source][target]
                != Some(self.turn.economic_turn as i16)
    }

    fn owns_former_province_of(&self, owner: MajorNationId, former: NationId) -> bool {
        let regions = self.nations.majors[owner].common.owned_regions();
        regions
            .iter()
            .take(regions.len().saturating_sub(1))
            .any(|&province| self.map.provinces[province].former_owner() == Some(former))
    }

    fn recovered_province_count(&self, owner: MajorNationId, former: NationId) -> i32 {
        let regions = self.nations.majors[owner].common.owned_regions();
        regions
            .iter()
            .take(regions.len().saturating_sub(1))
            .filter(|&&province| self.map.provinces[province].former_owner() == Some(former))
            .count() as i32
    }

    fn ranked_independents(&mut self, source: NationId, majors_only: bool) -> Vec<NationId> {
        let range = if majors_only {
            0..MajorNationId::COUNT
        } else {
            MinorNationId::FIRST..NationId::COUNT
        };
        let mut ranked = Vec::new();
        for slot in range {
            let nation = NationId::new(slot);
            if nation == source || !self.nation_is_present(nation) || !self.is_independent(nation) {
                continue;
            }
            let standing = self.diplomacy.standings[source][nation];
            insert_sorted_by_key(&mut self.rng, &mut ranked, (standing, nation), |entry| {
                entry.0
            });
        }
        ranked.into_iter().map(|(_, nation)| nation).collect()
    }

    fn favorite_with_embassy(&mut self, minor: NationId) -> Option<MajorNationId> {
        self.ranked_independents(minor, true)
            .into_iter()
            .rev()
            .find(|&nation| {
                self.diplomacy.mission_levels[minor][nation] == DiplomaticMissionLevel::Embassy
            })
            .and_then(MajorNationId::from_nation)
    }

    fn has_active_candidates(&mut self, nation: MajorNationId) -> bool {
        let mut any = false;
        for candidate in majors() {
            if self.nations.majors[nation].economy.candidate_nation_flags[candidate.nation()] != 0 {
                any = true;
            }
        }
        for slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = NationId::new(slot);
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

    fn set_enemy(&mut self, nation: MajorNationId, target: NationId) {
        if self.has_active_candidates(nation) {
            let others: Vec<_> = NationId::all()
                .filter(|&other| other != nation.nation() && !self.at_war(other, nation.nation()))
                .collect();
            for other in others {
                self.stop_being_enemies_with(nation, other);
            }
        }
        self.nations.majors[nation].economy.candidate_nation_flags[target] = 1;
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

    fn stop_being_enemies_with(&mut self, nation: MajorNationId, target: NationId) {
        self.nations.majors[nation].economy.candidate_nation_flags[target] = 0;
        if self
            .nations
            .common(target)
            .is_none_or(|common| common.owned_regions().is_empty())
        {
            return;
        }
        self.set_ai_zone_target(nation, target, AiTargetState::Unmarked);
    }

    fn set_ai_zone_target(&mut self, nation: MajorNationId, target: NationId, flag: AiTargetState) {
        let Some(zone) = self.first_port_zone_for_nation(target) else {
            return;
        };
        let Some(targets) = self.nations.majors[nation].economy.ai_zone_targets.as_mut() else {
            return;
        };
        let index = usize::from(zone.get());
        if let Some(entry) = targets.get_mut(index) {
            *entry = flag;
        }
    }

    fn set_colony_boycott(&mut self, nation: MajorNationId, target: NationId, enabled: bool) {
        self.nations.majors[nation].economy.colony_boycott_flags[target] = u8::from(enabled);
        let policy = if enabled {
            TradePolicyScore::new(0x64 + 0xc8)
        } else {
            TradePolicyScore::NEUTRAL
        };
        for slot in MinorNationId::FIRST..NationId::COUNT {
            let minor = NationId::new(slot);
            if self
                .nations
                .common(minor)
                .is_some_and(|common| common.status() == CountryStatus::ColonyOf(nation.nation()))
            {
                self.set_one_trade(minor, target, policy);
            }
        }
    }

    fn at_war(&self, source: NationId, target: NationId) -> bool {
        self.diplomacy.relationships[source][target] == DiplomaticRelationship::War
    }

    fn is_auto(&self, nation: MajorNationId) -> bool {
        self.nations.majors[nation].kind == MajorNationKind::AutoGreatPower
    }

    fn is_independent(&self, nation: NationId) -> bool {
        self.nations
            .common(nation)
            .is_some_and(|common| common.status() == CountryStatus::Independent)
    }

    fn status_of(&self, nation: NationId) -> CountryStatus {
        self.nations
            .common(nation)
            .map(|common| common.status())
            .unwrap_or(CountryStatus::Independent)
    }

    fn owner_slot(&self, nation: NationId) -> NationId {
        match self.status_of(nation) {
            CountryStatus::ColonyOf(master) | CountryStatus::ProtectorateOf(master) => master,
            CountryStatus::Independent => nation,
        }
    }

    fn event_eligible(&self, nation: NationId) -> bool {
        if !self.nation_is_present(nation) {
            return false;
        }
        MajorNationId::from_nation(nation).is_none_or(|major| self.major_is_event_eligible(major))
    }

    fn in_consortium_with(&self, minor: NationId, source: NationId) -> bool {
        self.nations.minors[MinorNationId::new(minor.get())]
            .as_ref()
            .is_some_and(|nation| {
                nation
                    .consortium_members
                    .iter()
                    .any(|member| member.nation() == source)
            })
    }

    fn nation_is_present(&self, nation: NationId) -> bool {
        self.nations.common(nation).is_some()
    }

    fn insert_sorted_proposal(&mut self, nation: MajorNationId, proposal: DiplomacyProposal) {
        insert_sorted_by_key(
            &mut self.rng,
            &mut self.pending.nations[nation].proposals,
            proposal,
            |entry| i16::from(entry.source.get()),
        );
    }

    fn insert_sorted_notice(&mut self, nation: MajorNationId, notice: DiplomacyNotice) {
        insert_sorted_by_key(
            &mut self.rng,
            &mut self.pending.nations[nation].turn_events,
            notice,
            |entry| i16::from(entry.source.get()),
        );
    }
}

fn majors() -> impl Iterator<Item = MajorNationId> {
    (0..MajorNationId::COUNT).map(MajorNationId::new)
}

fn coeff(table: &[f32], index: i16) -> f32 {
    table.get(index as usize).copied().unwrap_or(0.0)
}

fn select_grant_amount(budget: i32) -> i32 {
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

fn grant_notice_code(grant: DiplomacyGrant) -> i16 {
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
    fn declare_war_processes_one_transition_and_posts_declare_war_news() {
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
        assert!(state.pending.war_transitions.is_empty());
        assert_eq!(
            state.nations.majors[source].common.trade_policy_by_nation[target],
            TradePolicyScore::BOYCOTT
        );
        assert_eq!(
            state.diplomacy.mission_levels[source.nation()][target],
            DiplomaticMissionLevel::None
        );
        assert!(
            state.pending.newspaper_events.iter().any(|event| matches!(
                event,
                PendingNewspaperEvent::InterNation {
                    event: InterNationNewsKind::WarDeclaredBySubject,
                    subject,
                    ..
                } if *subject == source
            )),
            "{:?}",
            state.pending.newspaper_events
        );
        assert!(
            state.pending.newspaper_events.iter().any(|event| matches!(
                event,
                PendingNewspaperEvent::InterNation {
                    event: InterNationNewsKind::WarDeclaredAgainstSubject,
                    subject,
                    ..
                } if *subject == major(1)
            )),
            "{:?}",
            state.pending.newspaper_events
        );
    }

    #[test]
    fn accepted_join_empire_makes_the_subject_a_colony() {
        let mut state = game_state();
        let source = major(0);
        let target = nation(7);
        state.nations.minors[MinorNationId::new(7)] = Some(independent_minor(7));
        state.diplomacy.standings[target][source.nation()] = 0xff;
        state.diplomacy.standings[source.nation()][target] = 0xff;
        state.nations.majors[source]
            .economy
            .diplomacy_policy_by_nation[target] = Some(DiplomacyPolicy::JoinEmpire);

        assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);

        assert_eq!(
            state.nations.minors[MinorNationId::new(7)]
                .as_ref()
                .unwrap()
                .common
                .status(),
            CountryStatus::ColonyOf(source.nation())
        );
        assert_eq!(
            state.diplomacy.relationships[target][source.nation()],
            DiplomaticRelationship::JoinedEmpire
        );
        assert_eq!(
            state.nations.majors[source].economy.pending_actions
                [PendingActionKind::ColonyMonumentMerchantCapacity]
                .status(),
            PendingActionStatus::Queued
        );
        assert!(
            state.pending.newspaper_events.iter().any(|event| matches!(
                event,
                PendingNewspaperEvent::InterNation {
                    event: InterNationNewsKind::NationJoinedEmpire,
                    subject,
                    ..
                } if *subject == source
            )),
            "{:?}",
            state.pending.newspaper_events
        );
    }

    #[test]
    fn accepted_great_power_join_empire_is_a_colony_not_a_protectorate() {
        let mut state = game_state();
        state.nations.majors[major(1)] = computer_major();
        state.nations.majors[major(1)]
            .economy
            .diplomacy_policy_by_nation[nation(0)] = Some(DiplomacyPolicy::JoinEmpire);

        let prompt = match state.do_diplomacy() {
            DiplomacyPhaseResult::Offer(prompt) => prompt,
            other => panic!("expected an offer prompt, got {other:?}"),
        };
        assert_eq!(prompt.policy, DiplomacyPolicy::JoinEmpire);
        assert_eq!(
            state.resolve_diplomacy_offer(prompt, true),
            DiplomacyPhaseResult::Resolved
        );
        assert_eq!(
            state.nations.majors[major(0)].common.status(),
            CountryStatus::ColonyOf(nation(1))
        );
        assert_eq!(
            state.diplomacy.relationships[nation(0)][nation(1)],
            DiplomaticRelationship::JoinedEmpire
        );
        assert_eq!(
            state.nations.majors[major(1)].economy.pending_actions
                [PendingActionKind::AnnexedGreatPowerCapitalExpansion]
                .status(),
            PendingActionStatus::Queued
        );
        assert_eq!(
            state
                .nations
                .majors()
                .filter(|major| major.common.status() == CountryStatus::Independent)
                .count(),
            6
        );
    }

    #[test]
    fn war_penalty_adjusts_independent_third_parties() {
        let mut state = game_state();
        state.diplomacy.standings[nation(0)][nation(1)] = 0x5a;
        state.diplomacy.standings[nation(1)][nation(0)] = 0x5a;
        state.diplomacy.standings[nation(1)][nation(2)] = 0x20;
        state.diplomacy.standings[nation(2)][nation(1)] = 0x20;
        let before = state.diplomacy.standings[nation(0)][nation(2)];
        state.nations.majors[major(0)]
            .economy
            .diplomacy_policy_by_nation[nation(1)] = Some(DiplomacyPolicy::DeclareWar);

        assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);
        assert_ne!(state.diplomacy.standings[nation(0)][nation(2)], before);
    }

    #[test]
    fn declaring_war_on_an_independent_minor_stops_for_the_favorite_human() {
        let mut state = game_state();
        state.nations.majors[major(1)] = computer_major();
        state.nations.minors[MinorNationId::new(7)] = Some(independent_minor(7));
        state.diplomacy.mission_levels[nation(0)][nation(7)] = DiplomaticMissionLevel::Embassy;
        state.diplomacy.mission_levels[nation(7)][nation(0)] = DiplomaticMissionLevel::Embassy;
        state.diplomacy.standings[nation(7)][nation(0)] = 0xff;
        state.diplomacy.standings[nation(0)][nation(7)] = 0xff;
        state.nations.majors[major(1)]
            .economy
            .diplomacy_policy_by_nation[nation(7)] = Some(DiplomacyPolicy::DeclareWar);

        let prompt = match state.do_diplomacy() {
            DiplomacyPhaseResult::WarJoin(prompt) => prompt,
            other => panic!("expected a war-join prompt, got {other:?}"),
        };
        assert_eq!(prompt.kind, DiplomacyWarJoinKind::DefendMinor);
        assert_eq!(prompt.nation, major(0));
        assert_eq!(prompt.target, nation(7));
        assert_eq!(prompt.source, nation(1));

        assert_eq!(
            state.resolve_diplomacy_war_join(prompt, true),
            DiplomacyPhaseResult::Resolved
        );
        assert_eq!(
            state.nations.minors[MinorNationId::new(7)]
                .as_ref()
                .unwrap()
                .common
                .status(),
            CountryStatus::ColonyOf(nation(0))
        );
        assert_eq!(
            state.diplomacy.relationships[nation(0)][nation(1)],
            DiplomaticRelationship::War
        );
    }

    #[test]
    fn ai_posts_a_non_aggression_pact_to_a_peaceful_embassy_minor() {
        let mut state = game_state();
        state.nations.majors[major(1)] = computer_major();
        state.nations.minors[MinorNationId::new(7)] = Some(independent_minor(7));
        state.diplomacy.mission_levels[nation(1)][nation(7)] = DiplomaticMissionLevel::Embassy;
        state.diplomacy.mission_levels[nation(7)][nation(1)] = DiplomaticMissionLevel::Embassy;
        state.diplomacy.relationships[nation(1)][nation(7)] = DiplomaticRelationship::Peace;

        assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);
        assert_eq!(
            state.diplomacy.relationships[nation(1)][nation(7)],
            DiplomaticRelationship::NonAggressionPact
        );
    }

    fn empty_zone(neighbors: Vec<OceanZoneId>) -> Zone {
        Zone {
            display_name: String::new(),
            status_code: None,
            target_tile: None,
            seed_owner: None,
            active_tile: None,
            primary_neighbors: neighbors,
            secondary_neighbors: Vec::new(),
        }
    }

    fn province(owner: NationId, adjacency: &[u16], linked: &[u16]) -> ProvinceState {
        ProvinceState::new(
            Some(owner),
            Some(owner),
            0,
            adjacency.iter().copied().map(ProvinceId::new).collect(),
            vec![TileId::new(0); adjacency.len()],
            None,
            0,
            None,
            0,
            None,
            None,
            linked.iter().copied().map(TileId::new).collect(),
            ResourceTable::default(),
            MajorNationTable::default(),
            0,
            false,
            0,
            String::new(),
        )
    }

    #[test]
    fn colony_annex_clears_boycotted_companies_and_deports_civilians() {
        let mut state = game_state();
        let source = major(0);
        let target = nation(7);
        let mut minor = independent_minor(7);
        minor.add_province(ProvinceId::new(0));
        state.nations.minors[MinorNationId::new(7)] = Some(minor);
        state.map.provinces[ProvinceId::new(0)] = province(target, &[], &[20]);
        state.map[TileId::new(20)].secondary_owner_nation = Some(major(1));
        state.nations.majors[source].economy.colony_boycott_flags[nation(1)] = 1;
        state.civilian_units.push(
            CivilianUnitState::new(
                CivilianUnitId::new(1),
                nation(1),
                CivilianUnitKind::Miner,
                CivilianLocation::OnMap(TileId::new(20)),
                CivilianWorkOrder::Idle,
                nation(1),
                0,
                false,
            )
            .unwrap(),
        );
        state.diplomacy.standings[target][source.nation()] = 0xff;
        state.diplomacy.standings[source.nation()][target] = 0xff;
        state.nations.majors[source]
            .economy
            .diplomacy_policy_by_nation[target] = Some(DiplomacyPolicy::JoinEmpire);

        assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);

        assert_eq!(state.map[TileId::new(20)].secondary_owner_nation, None);
        assert_eq!(state.civilian_units.len(), 1);
        assert_eq!(
            state.civilian_units[0].location.tile(),
            state.nations.majors[major(1)].common.home_tile
        );
        assert!(
            state.pending.nations[major(1)]
                .turn_events
                .iter()
                .any(|notice| notice.source == target && notice.code == 0x137),
            "{:?}",
            state.pending.nations[major(1)].turn_events
        );
        assert!(
            state.pending.newspaper_events.iter().any(|event| matches!(
                event,
                PendingNewspaperEvent::InterNation {
                    event: InterNationNewsKind::MinorTerritoryRelationshipAffected,
                    subject,
                    ..
                } if *subject == major(1)
            )),
            "{:?}",
            state.pending.newspaper_events
        );
    }

    #[test]
    fn declaring_war_marks_the_target_first_port_zone_as_a_candidate() {
        let mut state = game_state();
        state.nations.majors[major(1)] = computer_major();
        state.nations.majors[major(1)].economy.ai_zone_targets =
            Some(vec![AiTargetState::Unmarked; 2]);
        let mut minor = independent_minor(7);
        minor.add_province(ProvinceId::new(0));
        state.nations.minors[MinorNationId::new(7)] = Some(minor);
        state.map[TileId::new(30)].former_owner_nation = Some(TileOwnerTag::from_nation(nation(7)));
        state.ocean.zones = vec![
            ZoneKind::Zone(empty_zone(Vec::new())),
            ZoneKind::PortZone(PortZone {
                zone: empty_zone(vec![OceanZoneId::new(0)]),
                port_tile: TileId::new(30),
            }),
        ];
        state.nations.majors[major(1)]
            .economy
            .diplomacy_policy_by_nation[nation(7)] = Some(DiplomacyPolicy::DeclareWar);

        assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);
        assert_eq!(
            state.nations.majors[major(1)]
                .economy
                .ai_zone_targets
                .as_ref(),
            Some(&vec![AiTargetState::Unmarked, AiTargetState::Candidate])
        );
        assert_eq!(
            state.nations.majors[major(1)]
                .economy
                .candidate_nation_flags[nation(7)],
            1
        );
    }

    fn peace_offer_from_human_to_ai() -> GameState {
        let mut state = game_state();
        state.nations.majors[major(1)] = computer_major();
        state.diplomacy.relationships[nation(0)][nation(1)] = DiplomaticRelationship::War;
        state.diplomacy.relationships[nation(1)][nation(0)] = DiplomaticRelationship::War;
        state.ships.extend((0..10).map(|_| ShipState {
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(0),
            task_force: None,
            aggression: 0,
            nation: nation(1),
            name: String::new(),
            strength: 900,
            experience: 0,
            selection: 0,
        }));
        state.nations.majors[major(0)]
            .economy
            .diplomacy_policy_by_nation[nation(1)] = Some(DiplomacyPolicy::PeaceTreaty);
        state
    }

    #[test]
    fn ai_accepts_peace_when_the_enemy_capitol_is_safe() {
        let mut state = peace_offer_from_human_to_ai();
        assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);
        assert_eq!(
            state.diplomacy.relationships[nation(1)][nation(0)],
            DiplomaticRelationship::Peace
        );
    }

    #[test]
    fn ai_rejects_peace_when_the_enemy_capitol_is_threatened() {
        let mut state = peace_offer_from_human_to_ai();
        state.nations.majors[major(0)].common.home_tile = Some(TileId::new(1));
        state.map[TileId::new(1)].province = Some(ProvinceId::new(0));
        state.map.provinces[ProvinceId::new(0)] = province(nation(0), &[1], &[]);
        state.map.provinces[ProvinceId::new(1)] = province(nation(2), &[0], &[]);
        state.diplomacy.relationships[nation(0)][nation(2)] = DiplomaticRelationship::War;
        state.diplomacy.relationships[nation(2)][nation(0)] = DiplomaticRelationship::War;
        state.military_units.push(MilitaryUnitState::new(
            MilitaryUnitId::new(1),
            nation(2),
            MilitaryUnitKind::Regulars,
            Some(ProvinceId::new(1)),
            MilitaryOrder::idle([None; 3], [None; 3]),
            nation(2),
            0,
            false,
            String::new(),
            500,
            0,
            0,
            0,
        ));

        assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);
        assert_eq!(
            state.diplomacy.relationships[nation(1)][nation(0)],
            DiplomaticRelationship::War
        );
    }
}
