//! Native transition differentials for diplomacy grants and aid.

use imperialism_core::*;
use imperialism_testkit::compare_native;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NationCase {
    nation: MajorNationId,
}

#[derive(Debug, Deserialize)]
struct DiplomacyGrantCase {
    nation: MajorNationId,
    target: NationId,
    amount: i32,
}

#[derive(Debug, Deserialize)]
struct AidAllocationCase {
    nation: MajorNationId,
    minor_nation: MinorNationId,
    resource: ResourceKind,
    amount: i32,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn diplomacy_grant_entry_updates_treasury() {
    compare_native(
        "diplomacy_grant_entry_updates_treasury",
        |state, case: DiplomacyGrantCase| {
            state.set_diplomacy_grant(
                case.nation,
                case.target,
                Some(DiplomacyGrant {
                    amount: case.amount,
                    recurring: false,
                }),
            )
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn diplomacy_reset_preserves_recurring_grants() {
    compare_native(
        "diplomacy_reset_preserves_recurring_grants",
        |state, case: NationCase| {
            state.reset_diplomacy_commitments(case.nation);
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn aid_allocation() {
    compare_native("aid_allocation", |state, case: AidAllocationCase| {
        state.add_aid_allocation(case.nation, case.minor_nation, case.resource, case.amount);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn diplomacy_phase_applies_grant_and_consulate() {
    compare_native(
        "diplomacy_phase_applies_grant_and_consulate",
        |state, (): ()| state.do_diplomacy(),
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn second_turn_diplomacy_phase() {
    compare_native("second_turn_diplomacy_phase", |state, (): ()| {
        state.do_diplomacy()
    })
    .unwrap();
}

#[derive(Debug, Deserialize)]
struct PlayerDiplomacyPolicyCase {
    source: MajorNationId,
    target: NationId,
    policy: DiplomacyPolicy,
    confirm_entanglements: bool,
}

#[derive(Debug, Deserialize)]
struct PlayerTradePolicyCase {
    source: MajorNationId,
    target: NationId,
    policy: TradePolicyScore,
}

#[derive(Debug, Deserialize)]
struct PlayerColonyBoycottCase {
    source: MajorNationId,
    target: NationId,
}

fn player_order_result(result: PlayerDiplomacyOrderResult) -> i32 {
    match result {
        PlayerDiplomacyOrderResult::Applied => 1,
        PlayerDiplomacyOrderResult::NotApplied => 0,
        PlayerDiplomacyOrderResult::NeedsEntanglementConfirmation => 2,
        PlayerDiplomacyOrderResult::SelectedNation => 3,
        PlayerDiplomacyOrderResult::Rejected(rejection) => -i32::from(rejection.proposal_mode()),
    }
}

fn player_policy_result(state: &mut GameState, case: PlayerDiplomacyPolicyCase) -> i32 {
    player_order_result(state.toggle_player_diplomacy_policy(
        case.source,
        case.target,
        case.policy,
        case.confirm_entanglements,
    ))
}

macro_rules! player_policy {
    ($name:ident, $case:literal) => {
        #[test]
        #[ignore = "requires the native C++ oracle"]
        fn $name() {
            compare_native($case, player_policy_result).unwrap();
        }
    };
}

player_policy!(
    player_diplomacy_policy_posts_join_empire,
    "player_diplomacy_policy_posts_join_empire"
);
player_policy!(
    player_diplomacy_policy_posts_alliance,
    "player_diplomacy_policy_posts_alliance"
);
player_policy!(
    player_diplomacy_policy_needs_alliance_entanglement,
    "player_diplomacy_policy_needs_alliance_entanglement"
);
player_policy!(
    player_diplomacy_policy_confirms_alliance_entanglement,
    "player_diplomacy_policy_confirms_alliance_entanglement"
);
player_policy!(
    player_diplomacy_policy_posts_non_aggression_pact,
    "player_diplomacy_policy_posts_non_aggression_pact"
);
player_policy!(
    player_diplomacy_policy_posts_peace_treaty,
    "player_diplomacy_policy_posts_peace_treaty"
);
player_policy!(
    player_diplomacy_policy_posts_declare_war,
    "player_diplomacy_policy_posts_declare_war"
);
player_policy!(
    player_diplomacy_policy_posts_embassy,
    "player_diplomacy_policy_posts_embassy"
);
player_policy!(
    player_diplomacy_policy_retracts_embassy,
    "player_diplomacy_policy_retracts_embassy"
);
player_policy!(
    player_diplomacy_policy_cannot_afford_committed_consulate,
    "player_diplomacy_policy_cannot_afford_committed_consulate"
);
player_policy!(
    player_diplomacy_policy_rejects_colony,
    "player_diplomacy_policy_rejects_colony"
);
player_policy!(
    player_diplomacy_policy_selects_self,
    "player_diplomacy_policy_selects_self"
);

fn player_trade_policy_result(state: &mut GameState, case: PlayerTradePolicyCase) -> i32 {
    player_order_result(state.toggle_player_trade_policy(case.source, case.target, case.policy))
}

macro_rules! player_trade_policy {
    ($name:ident, $case:literal) => {
        #[test]
        #[ignore = "requires the native C++ oracle"]
        fn $name() {
            compare_native($case, player_trade_policy_result).unwrap();
        }
    };
}

player_trade_policy!(
    player_trade_policy_posts_subsidy,
    "player_trade_policy_posts_subsidy"
);
player_trade_policy!(
    player_trade_policy_retracts_subsidy,
    "player_trade_policy_retracts_subsidy"
);
player_trade_policy!(
    player_trade_policy_boycott_clears_grant,
    "player_trade_policy_boycott_clears_grant"
);
player_trade_policy!(
    player_trade_policy_rejects_allied_boycott,
    "player_trade_policy_rejects_allied_boycott"
);

fn player_colony_boycott_result(state: &mut GameState, case: PlayerColonyBoycottCase) -> i32 {
    player_order_result(state.toggle_player_colony_boycott(case.source, case.target))
}

macro_rules! player_colony_boycott {
    ($name:ident, $case:literal) => {
        #[test]
        #[ignore = "requires the native C++ oracle"]
        fn $name() {
            compare_native($case, player_colony_boycott_result).unwrap();
        }
    };
}

player_colony_boycott!(
    player_colony_boycott_posts_and_propagates,
    "player_colony_boycott_posts_and_propagates"
);
player_colony_boycott!(
    player_colony_boycott_retracts_and_propagates,
    "player_colony_boycott_retracts_and_propagates"
);
player_colony_boycott!(
    player_colony_boycott_own_colony_no_op,
    "player_colony_boycott_own_colony_no_op"
);

#[test]
#[ignore = "requires the native C++ oracle"]
fn player_diplomacy_policy_posts_consulate() {
    compare_native(
        "player_diplomacy_policy_posts_consulate",
        |state, case: PlayerDiplomacyPolicyCase| {
            matches!(
                state.toggle_player_diplomacy_policy(
                    case.source,
                    case.target,
                    case.policy,
                    case.confirm_entanglements,
                ),
                PlayerDiplomacyOrderResult::Applied
            )
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn player_diplomacy_policy_rejects_consulate_on_major() {
    compare_native(
        "player_diplomacy_policy_rejects_consulate_on_major",
        |state, case: PlayerDiplomacyPolicyCase| {
            matches!(
                state.toggle_player_diplomacy_policy(
                    case.source,
                    case.target,
                    case.policy,
                    case.confirm_entanglements,
                ),
                PlayerDiplomacyOrderResult::Applied
            )
        },
    )
    .unwrap();
}
