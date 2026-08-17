use super::*;

impl GameState {
    pub(super) fn set_ai_diplomacy_policies(&mut self, nation: MajorNationId) {
        self.set_empire_policies(nation);
        self.do_propose_treaties(nation);
        self.goods_match_shipping(nation);
        self.do_development_grants(nation);
    }

    pub(super) fn set_empire_policies(&mut self, nation: MajorNationId) {
        if self.turn.planning_quarter() == 0 && !self.manufactured_offers_exhausted(nation) {
            let ranked = self.ranked_independents(nation.nation(), false);
            for &minor in ranked.iter().rev() {
                let favorite = self.favorite_trade_partner(MinorNationId::new(minor.get()));
                let standing = self.diplomacy.standings[nation.nation()][minor];
                let trade = self.nations.majors[&nation].common.trade_policy_by_nation[minor];
                if favorite != Some(nation) && standing > 0x31 && trade != TradePolicyScore::BOYCOTT
                {
                    self.decrement_trade_policy_score(nation, minor);
                    break;
                }
            }
        }

        if self.nations.majors[&nation]
            .economy
            .capacities
            .available_merchant
            > 0
        {
            let shortage = RAW_TRADE.into_iter().find(|&commodity| {
                self.nations.majors[&nation]
                    .economy
                    .unfilled_trade_turns_by_resource[commodity.resource()]
                    > 2
            });
            if let Some(commodity) = shortage {
                let ranked = self.ranked_independents(nation.nation(), false);
                let selected = ranked.iter().copied().rev().find(|&minor| {
                    self.market.rows[commodity].current_offer_by_nation[minor] != 0
                        && self.nations.majors[&nation].common.trade_policy_by_nation[minor]
                            != TradePolicyScore::BOYCOTT
                });
                if let Some(minor) = selected {
                    if self.diplomacy.mission_levels[nation.nation()][minor]
                        == DiplomaticMissionLevel::None
                    {
                        self.post_policy(nation, minor, DiplomacyPolicy::BuildConsulate);
                    } else {
                        self.decrement_trade_policy_score(nation, minor);
                    }
                }
            }
        }

        for minor in MinorNationId::all().map(MinorNationId::nation) {
            let trade = self.nations.majors[&nation].common.trade_policy_by_nation[minor];
            if self.diplomacy.mission_levels[nation.nation()][minor] != DiplomaticMissionLevel::None
                && trade.get() > 0x5f
                && trade.get() < 300
                && self.is_independent(minor)
            {
                self.set_one_trade(nation.nation(), minor, TradePolicyScore::new(0x5f));
            }
        }

        if self.nations.majors[&nation].common.treasury < 0 {
            for minor in MinorNationId::all().map(MinorNationId::nation) {
                if self.nations.majors[&nation].common.trade_policy_by_nation[minor].get() < 0x4b {
                    self.set_one_trade(nation.nation(), minor, TradePolicyScore::new(0x4b));
                }
            }
        }
    }

    pub(super) fn do_propose_treaties(&mut self, nation: MajorNationId) {
        for minor in MinorNationId::all().map(MinorNationId::nation) {
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

        if self.turn.planning_quarter() != PLANNING_QUARTER[nation] {
            return;
        }

        let army = at_least_one(self.military_power(nation));
        let navy = at_least_one(self.naval_force(nation));
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
            if self.turn.year_quarters() >= 0x46 || self.deserves_to_be_enemy(nation, target) {
                continue;
            }
            if self.owns_former_province_of(target, nation.nation()) {
                continue;
            }
            let recovered = self.recovered_province_count(nation, target.nation());
            let required = (self.turn.year_quarters() + 10) / 10;
            if recovered >= required {
                self.post_policy(nation, target.nation(), DiplomacyPolicy::PeaceTreaty);
            }
        }
    }

    pub(super) fn goods_match_shipping(&mut self, nation: MajorNationId) {
        let has_colony = MinorNationId::all().any(|minor| {
            self.nations
                .common(minor.nation())
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

    pub(super) fn do_development_grants(&mut self, nation: MajorNationId) {
        let mut budget =
            ((self.nations.majors[&nation].common.treasury - 10_000) as f32 * 0.5) as i32;
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
                self.nations.majors[&nation]
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
                        let slot = &mut self.nations.majors[&nation]
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

    pub(super) fn do_select_enemy(&mut self, nation: MajorNationId) {
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

    pub(crate) fn post_policy(
        &mut self,
        nation: MajorNationId,
        target: NationId,
        policy: DiplomacyPolicy,
    ) {
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
                if self.nations.majors[&nation].auto.is_none() {
                    let _ = self.set_diplomacy_grant(nation, target, None);
                }
            }
            DiplomacyPolicy::BuildConsulate => {
                apply = self.can_afford_diplomacy(nation, 500);
                if apply {
                    self.nations.majors[&nation].common.treasury -= 500;
                }
            }
            DiplomacyPolicy::BuildEmbassy => {
                apply = self.can_afford_diplomacy(nation, 5000);
                if apply {
                    self.nations.majors[&nation].common.treasury -= 5000;
                }
            }
            _ => {}
        }
        if apply {
            self.nations.majors[&nation]
                .economy
                .diplomacy_policy_by_nation[target] = Some(policy);
        }
    }
}
