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
                state.purchase_item(
                    case.nation,
                    settlement.resource,
                    settlement.amount,
                    settlement.price,
                );
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
            state.remember_trade_bids(case.nation);
            for purchase in case.purchases {
                state.purchase_item(
                    case.nation,
                    purchase.resource,
                    purchase.amount,
                    purchase.price,
                );
            }
            state.commit_purchased_items(case.nation);
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn recall_trade_bids() {
    compare_native("recall_trade_bids", |state, case: NationCase| {
        state.recall_trade_bids(case.nation);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn player_trade_phase_reset() {
    compare_native("player_trade_phase_reset", |state, case: NationCase| {
        state.reset_player_trade_phase(case.nation);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn trade_capacity_refresh() {
    compare_native("trade_capacity_refresh", |state, case: NationCase| {
        state.refresh_merchant_capacity(case.nation);
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
        state.decrement_trade_policy_score(case.source, case.target);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn trade_policy_set() {
    compare_native("trade_policy_set", |state, case: TradePolicySetCase| {
        state.set_trade_policy(case.nation, case.target, case.policy);
    })
    .unwrap();
}
