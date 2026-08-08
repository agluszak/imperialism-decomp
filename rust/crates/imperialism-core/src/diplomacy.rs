use crate::{
    DiplomacyGrant, GameState, MajorNationId, MinorNationId, NationId, ResourceKind, RuleError,
    TradePolicyScore,
};

impl GameState {
    /// Credits a minor nation's resource-specific aid allocation.
    pub fn add_aid_allocation(
        &mut self,
        nation: MajorNationId,
        minor_nation: MinorNationId,
        resource: ResourceKind,
        amount: i32,
    ) -> Result<(), RuleError> {
        let major = self.major_mut(nation)?;
        major.common.treasury += amount;
        major.state.aid_allocation_by_minor_nation[minor_nation][resource] += amount;
        major.state.aid_allocation_total += amount;
        Ok(())
    }

    /// Sets one current diplomatic grant, refunding the replaced amount before
    /// charging the replacement.
    pub fn set_diplomacy_grant(
        &mut self,
        nation: MajorNationId,
        target: NationId,
        grant: Option<DiplomacyGrant>,
    ) -> Result<bool, RuleError> {
        let major = self.major_mut(nation)?;
        let current = major.state.diplomacy_grants_by_nation[target];
        if current == grant {
            return Ok(true);
        }
        let current_amount = current.map_or(0, |grant| grant.amount);
        let proposed_amount = grant.map_or(0, |grant| grant.amount);
        if grant.is_some()
            && current_amount - proposed_amount
                + major
                    .state
                    .available_diplomacy_budget(major.common.treasury)
                < 0
        {
            return Ok(false);
        }

        major.state.grant_total_cost += proposed_amount - current_amount;
        major.common.treasury += current_amount - proposed_amount;
        major.state.diplomacy_grants_by_nation[target] = grant;
        Ok(true)
    }

    /// Clears current diplomacy policies and one-time grants, then posts each
    /// recurring grant through the ordinary treasury path.
    pub fn reset_diplomacy_commitments(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        for target in NationId::all() {
            let recurring_grant = {
                let major = self.major_mut(nation)?;
                major.state.diplomacy_policy_by_nation[target] = None;
                let grant = major.state.diplomacy_grants_by_nation[target];
                major.state.diplomacy_grants_by_nation[target] = None;
                grant.filter(|grant| grant.recurring)
            };

            if let Some(grant) = recurring_grant {
                let _ = self.set_diplomacy_grant(nation, target, Some(grant))?;
            }
        }
        Ok(())
    }

    /// Applies one recovered decrement to a bilateral trade-policy score.
    pub fn decrement_trade_policy_score(
        &mut self,
        nation: MajorNationId,
        target: NationId,
    ) -> Result<(), RuleError> {
        let common = &mut self.major_mut(nation)?.common;
        let next = common.trade_policy_by_nation[target].decrement_step(common.treasury);
        common.trade_policy_by_nation[target] = next;
        Ok(())
    }

    /// Sets one bilateral trade policy and clears its grant for a boycott.
    pub fn set_trade_policy(
        &mut self,
        nation: MajorNationId,
        target: NationId,
        policy: TradePolicyScore,
    ) -> Result<(), RuleError> {
        let common = &mut self.major_mut(nation)?.common;
        if target != nation.nation() {
            common.trade_policy_by_nation[target] = policy;
        }

        if policy == TradePolicyScore::BOYCOTT {
            self.set_diplomacy_grant(nation, target, None)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DiplomacyPolicy, test_support};

    #[test]
    fn diplomacy_grant_settlement_replaces_or_rejects_grants() {
        let nation = MajorNationId::new(6);
        let target = NationId::new(8);
        let mut game = test_support::game_state();
        {
            let major = game.major_mut(nation).unwrap();
            major.common.treasury = 10_000;
            major.state.diplomacy_budget_base = 50_000;
        }
        let recurring_ten_thousand = DiplomacyGrant {
            amount: 10_000,
            recurring: true,
        };
        assert_eq!(
            game.set_diplomacy_grant(nation, target, Some(recurring_ten_thousand)),
            Ok(true)
        );

        let major = game.major(nation).unwrap();
        assert_eq!(major.common.treasury, 0);
        assert_eq!(major.state.grant_total_cost, 10_000);
        assert_eq!(
            major.state.diplomacy_grants_by_nation[target],
            Some(recurring_ten_thousand)
        );

        let before_rejected = game.clone();
        assert_eq!(
            game.set_diplomacy_grant(
                nation,
                NationId::new(9),
                Some(DiplomacyGrant {
                    amount: 1_000,
                    recurring: false,
                }),
            ),
            Ok(false)
        );
        assert_eq!(game, before_rejected);

        assert_eq!(
            game.set_diplomacy_grant(
                nation,
                target,
                Some(DiplomacyGrant {
                    amount: 3_000,
                    recurring: true,
                }),
            ),
            Ok(true)
        );
        assert_eq!(game.set_diplomacy_grant(nation, target, None), Ok(true));
        let major = game.major(nation).unwrap();
        assert_eq!(major.common.treasury, 10_000);
        assert_eq!(major.state.grant_total_cost, 0);
        assert_eq!(major.state.diplomacy_grants_by_nation[target], None);
    }

    #[test]
    fn reset_diplomacy_commitments_reposts_only_recurring_grants() {
        let nation = MajorNationId::new(6);
        let policy_target = NationId::new(0);
        let one_time_target = NationId::new(1);
        let recurring_target = NationId::new(2);
        let recurring_grant = DiplomacyGrant {
            amount: 3_000,
            recurring: true,
        };
        let mut game = test_support::game_state();
        {
            let major = game.major_mut(nation).unwrap();
            major.common.treasury = 10_000;
            major.state.diplomacy_policy_by_nation[policy_target] =
                Some(DiplomacyPolicy::BuildConsulate);
        }
        game.set_diplomacy_grant(
            nation,
            one_time_target,
            Some(DiplomacyGrant {
                amount: 1_000,
                recurring: false,
            }),
        )
        .unwrap();
        game.set_diplomacy_grant(nation, recurring_target, Some(recurring_grant))
            .unwrap();

        game.reset_diplomacy_commitments(nation).unwrap();

        let major = game.major(nation).unwrap();
        assert_eq!(major.state.diplomacy_policy_by_nation[policy_target], None);
        assert_eq!(
            major.state.diplomacy_grants_by_nation[one_time_target],
            None
        );
        assert_eq!(
            major.state.diplomacy_grants_by_nation[recurring_target],
            Some(recurring_grant)
        );
        assert_eq!(major.common.treasury, 3_000);
        assert_eq!(major.state.grant_total_cost, 7_000);
    }

    #[test]
    fn decrements_trade_policy_score_through_the_retail_steps() {
        let nation = MajorNationId::new(6);
        let target = NationId::new(0);
        let mut game = test_support::game_state();

        for (score, treasury, expected) in [
            (100, 0, 95),
            (95, 0, 90),
            (90, 0, 75),
            (75, 10_000, 75),
            (75, 10_001, 50),
            (300, 50_000, 300),
        ] {
            let common = &mut game.major_mut(nation).unwrap().common;
            common.trade_policy_by_nation[target] = TradePolicyScore::new(score);
            common.treasury = treasury;

            game.decrement_trade_policy_score(nation, target).unwrap();

            assert_eq!(
                game.major(nation).unwrap().common.trade_policy_by_nation[target],
                TradePolicyScore::new(expected)
            );
        }
    }
}
