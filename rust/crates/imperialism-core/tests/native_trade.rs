//! Native transition differentials for trade settlement and capacity.

use imperialism_core::*;
use imperialism_testkit::compare_native;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NationCase {
    nation: MajorNationId,
}

#[derive(Debug, Deserialize)]
struct TradeSettlement {
    resource: ResourceKind,
    amount: i16,
    price: i16,
}

#[derive(Debug, Deserialize)]
struct MajorTradeSettlementCase {
    nation: MajorNationId,
    settlements: Vec<TradeSettlement>,
}

#[derive(Debug, Deserialize)]
struct PurchasedItemsPhaseCase {
    nation: MajorNationId,
    purchases: Vec<TradeSettlement>,
}

#[derive(Debug, Deserialize)]
struct TradePolicyStepCase {
    source: MajorNationId,
    target: NationId,
}

#[derive(Debug, Deserialize)]
struct TradePolicySetCase {
    nation: MajorNationId,
    target: NationId,
    policy: TradePolicyScore,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn major_trade_settlement() {
    compare_native(
        "major_trade_settlement",
        |state, case: MajorTradeSettlementCase| {
            for settlement in case.settlements {
                state
                    .nations_mut()
                    .major_mut(case.nation)
                    .unwrap()
                    .purchase_item(settlement.resource, settlement.amount, settlement.price);
            }
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn purchased_items_phase() {
    compare_native(
        "purchased_items_phase",
        |state, case: PurchasedItemsPhaseCase| {
            state
                .nations_mut()
                .major_mut(case.nation)
                .unwrap()
                .remember_trade_bids();
            for purchase in case.purchases {
                state
                    .nations_mut()
                    .major_mut(case.nation)
                    .unwrap()
                    .purchase_item(purchase.resource, purchase.amount, purchase.price);
            }
            state
                .nations_mut()
                .major_mut(case.nation)
                .unwrap()
                .commit_purchased_items();
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn recall_trade_bids() {
    compare_native("recall_trade_bids", |state, case: NationCase| {
        state
            .nations_mut()
            .major_mut(case.nation)
            .unwrap()
            .recall_trade_bids();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn player_trade_phase_reset() {
    compare_native("player_trade_phase_reset", |state, case: NationCase| {
        state
            .nations_mut()
            .major_mut(case.nation)
            .unwrap()
            .reset_player_trade_phase();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn trade_capacity_refresh() {
    compare_native("trade_capacity_refresh", |state, case: NationCase| {
        state
            .nations_mut()
            .major_mut(case.nation)
            .unwrap()
            .refresh_merchant_capacity();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn trade_market_price() {
    compare_native("trade_market_price", |state, (): ()| {
        state.recalculate_trade_prices();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn trade_policy_step() {
    compare_native("trade_policy_step", |state, case: TradePolicyStepCase| {
        state
            .nations_mut()
            .major_mut(case.source)
            .unwrap()
            .decrement_trade_policy_score(case.target);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn trade_policy_set() {
    compare_native("trade_policy_set", |state, case: TradePolicySetCase| {
        state
            .nations_mut()
            .major_mut(case.nation)
            .unwrap()
            .set_trade_policy(case.nation, case.target, case.policy);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn trade_phase() {
    compare_native("trade_phase", |state, (): ()| {
        // Matches DrainRankedDealsWithHumanAutoAccept: settlement algorithm only,
        // not the production begin_trade_phase / reply_to_trade_offer contract.
        drain_ranked_deals_with_human_auto_accept(state);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn trade_phase_sell_only() {
    compare_native("trade_phase_sell_only", |state, (): ()| {
        drain_ranked_deals_with_human_auto_accept(state);
    })
    .unwrap();
}

fn drain_ranked_deals_with_human_auto_accept(state: &mut GameState) {
    let mut progress = state.begin_trade_phase();
    while let TradeProgress::Offer(offer) = progress {
        progress = state.reply_to_trade_offer(offer.amount, false);
    }
}
