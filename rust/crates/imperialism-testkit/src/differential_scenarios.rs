//! Rust halves of the process-isolated semantic differential scenarios.
//!
//! Each scenario keeps its decoded case and direct Rust operation together.
//! The native runtime remains responsible for constructing the case and
//! observing the C++ result. Scenario names match the Rust test function names.

use crate::differential;
use imperialism_core::*;
use serde::{Deserialize, Serialize};

macro_rules! differential_test {
    ($name:ident, |$state:ident, _: $case_ty:ty| $body:block) => {
        #[test]
        #[ignore = "requires the native C++ runtime oracle"]
        fn $name() {
            differential(stringify!($name), |$state, _: $case_ty| $body).unwrap();
        }
    };
    ($name:ident, |$state:ident, $case:ident: $case_ty:ty| $body:block) => {
        #[test]
        #[ignore = "requires the native C++ runtime oracle"]
        fn $name() {
            differential(stringify!($name), |$state, $case: $case_ty| $body).unwrap();
        }
    };
}

#[derive(Deserialize)]
struct NationCase {
    nation: MajorNationId,
}

#[derive(Deserialize)]
struct TradeSettlement {
    resource: ResourceKind,
    amount: i16,
    price: i16,
}

#[derive(Deserialize)]
struct MajorTradeSettlementCase {
    nation: MajorNationId,
    settlements: Vec<TradeSettlement>,
}

#[derive(Deserialize)]
struct PurchasedItemsPhaseCase {
    nation: MajorNationId,
    purchases: Vec<TradeSettlement>,
}

#[derive(Deserialize)]
struct DiplomacyGrantCase {
    nation: MajorNationId,
    target: NationId,
    amount: i32,
}

#[derive(Deserialize)]
struct AidAllocationCase {
    nation: MajorNationId,
    minor_nation: MinorNationId,
    resource: ResourceKind,
    amount: i32,
}

#[derive(Deserialize)]
struct DirectTransportCase {
    nation: MajorNationId,
    resource: ResourceKind,
    requested: i16,
}

#[derive(Deserialize)]
struct CityItemOrderCase {
    nation: MajorNationId,
    output: ResourceKind,
    quantity: i16,
}

#[derive(Deserialize)]
struct PowerPlantUpgradeCase {
    nation: MajorNationId,
    enabled: bool,
}

#[derive(Deserialize)]
struct TradePolicyStepCase {
    source: MajorNationId,
    target: NationId,
}

#[derive(Deserialize)]
struct TradePolicySetCase {
    nation: MajorNationId,
    target: NationId,
    policy: TradePolicyScore,
}

#[derive(Deserialize)]
struct ResourceDevelopmentCase {
    extractive_worker: CivilianUnitId,
    surface_worker: CivilianUnitId,
}

#[derive(Deserialize)]
struct RailConstructionCase {
    civilian: CivilianUnitId,
}

#[derive(Deserialize)]
struct SpecialistRecruitmentCase {
    nation: MajorNationId,
    unit_kind: MilitaryUnitKind,
    quantity: i16,
}

#[derive(Debug, Deserialize)]
struct EasyTurnFromSaveCase {
    reject_offers: bool,
    expect_exactly_one_turn: bool,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum EasyTurnFromSaveResult {
    Completed {
        from_turn: i32,
        to_turn: i32,
        gates: Vec<ReportedUiGate>,
    },
}

/// Result-only gate labels for easy-turn captures. C++ still emits bare strings.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReportedUiGate {
    DealBook,
    Newspaper,
}

differential_test!(
    major_trade_settlement,
    |state, case: MajorTradeSettlementCase| {
        for settlement in case.settlements {
            state.purchase_item(
                case.nation,
                settlement.resource,
                settlement.amount,
                settlement.price,
            );
        }
    }
);

differential_test!(
    purchased_items_phase,
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
    }
);

differential_test!(created_items_phase, |state, case: NationCase| {
    state.add_created_items(case.nation);
});

differential_test!(first_turn_alert_phase, |state, _: ()| {
    let _ = state.advance_turn_step();
});

differential_test!(first_turn_diplomacy_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_trade_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_civilian_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_military_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_combat_movement_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_military_cleanup_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_diplomacy_offer_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_elimination_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_city_transport_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_great_power_pressure_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_deal_book_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_quarter_gate_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_season_advance_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_technology_advances_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_newspaper_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(first_turn_return_to_map_phase, |state, _: ()| {
    state.advance_turn_step()
});

differential_test!(easy_turn_from_save, |state, case: EasyTurnFromSaveCase| {
    assert!(case.reject_offers);
    assert!(case.expect_exactly_one_turn);
    let from_turn = state.turn().economic_turn;

    let mut outcome = state.finish_player_orders();
    loop {
        match outcome {
            AdvanceTurnOutcome::Blocked {
                yield_: TurnYield::Ui {
                    request: request @ (UiRequest::DiplomacyMap { .. } | UiRequest::OfferSheet { .. }),
                },
                ..
            } => {
                let _ = outcome.effects();
                outcome = state.resume_after_ui(request);
            }
            AdvanceTurnOutcome::Blocked {
                yield_: TurnYield::Ui {
                    request: UiRequest::DealBook,
                },
                ..
            } => break,
            other => panic!("expected deal-book yield after first-turn phases, got {other:?}"),
        }
    }

    let second = state.resume_after_ui(UiRequest::DealBook);
    assert!(matches!(
        second,
        AdvanceTurnOutcome::Blocked {
            yield_: TurnYield::Ui {
                request: UiRequest::Newspaper,
            },
            ..
        }
    ));
    let _ = second.effects();

    let third = state.resume_after_ui(UiRequest::Newspaper);
    assert!(matches!(
        third,
        AdvanceTurnOutcome::Blocked {
            yield_: TurnYield::PlayerOrders,
            ..
        }
    ));
    let _ = third.effects();
    assert_eq!(state.turn().economic_turn, from_turn + 1);

    EasyTurnFromSaveResult::Completed {
        from_turn,
        to_turn: state.turn().economic_turn,
        gates: vec![ReportedUiGate::DealBook, ReportedUiGate::Newspaper],
    }
});

differential_test!(transported_items_phase, |state, case: NationCase| {
    state.settle_transported_items(case.nation);
});

differential_test!(
    diplomacy_grant_entry_updates_treasury,
    |state, case: DiplomacyGrantCase| {
        state.set_diplomacy_grant(
            case.nation,
            case.target,
            Some(DiplomacyGrant {
                amount: case.amount,
                recurring: false,
            }),
        )
    }
);

differential_test!(
    diplomacy_reset_preserves_recurring_grants,
    |state, case: NationCase| {
        state.reset_diplomacy_commitments(case.nation);
    }
);

differential_test!(aid_allocation, |state, case: AidAllocationCase| {
    state.add_aid_allocation(case.nation, case.minor_nation, case.resource, case.amount);
});

differential_test!(direct_transport, |state, case: DirectTransportCase| {
    state.direct_transport(case.nation, case.resource, case.requested)
});

differential_test!(merchant_marine, |state, case: NationCase| {
    state.increase_merchant_marine(case.nation)
});

differential_test!(
    city_item_order_increase,
    |state, case: CityItemOrderCase| {
        state
            .set_city_order_quantity(case.nation, CityOrderId::Item(case.output), case.quantity)
            .applied()
    }
);

differential_test!(
    city_item_order_decrease,
    |state, case: CityItemOrderCase| {
        state
            .set_city_order_quantity(case.nation, CityOrderId::Item(case.output), case.quantity)
            .applied()
    }
);

differential_test!(power_plant_upgrade, |state, case: PowerPlantUpgradeCase| {
    state.set_power_plant_upgrade(case.nation, case.enabled);
});

differential_test!(trade_policy_step, |state, case: TradePolicyStepCase| {
    state.decrement_trade_policy_score(case.source, case.target);
});

differential_test!(trade_policy_set, |state, case: TradePolicySetCase| {
    state.set_trade_policy(case.nation, case.target, case.policy);
});

differential_test!(trade_capacity_refresh, |state, case: NationCase| {
    state.refresh_merchant_capacity(case.nation);
});

differential_test!(recall_trade_bids, |state, case: NationCase| {
    state.recall_trade_bids(case.nation);
});

differential_test!(transport_need_allocation, |state, case: NationCase| {
    state.allocate_transport_needs(case.nation);
});

differential_test!(player_trade_phase_reset, |state, case: NationCase| {
    state.reset_player_trade_phase(case.nation);
});

differential_test!(trade_market_price, |state, _: ()| {
    state.recalculate_trade_prices();
});

differential_test!(military_maintenance, |state, case: NationCase| {
    state.pay_for_military(case.nation);
});

differential_test!(
    completed_resource_development,
    |state, case: ResourceDevelopmentCase| {
        state.advance_civilian_work(case.extractive_worker);
        state.advance_civilian_work(case.surface_worker);
    }
);

differential_test!(
    completed_rail_section,
    |state, case: RailConstructionCase| {
        state.advance_civilian_work(case.civilian);
    }
);

differential_test!(
    specialist_recruitment,
    |state, case: SpecialistRecruitmentCase| {
        state.produce_military_recruits(case.nation, case.unit_kind, case.quantity);
    }
);

#[test]
#[ignore = "requires the native C++ runtime oracle"]
fn rolling_stock_cases() {
    for name in ["rolling_stock", "rolling_stock_insufficient_resources"] {
        differential(name, |state, case: NationCase| {
            state.increase_rolling_stock(case.nation)
        })
        .unwrap();
    }
}

#[test]
#[ignore = "requires the native C++ runtime oracle"]
fn nation_resource_yield_rebuild_cases() {
    for name in [
        "nation_resource_yield_rebuild",
        "ai_nation_resource_yield_rebuild_clamps_targets",
    ] {
        differential(name, |state, case: NationCase| {
            state.rebuild_nation_resource_yields(case.nation);
        })
        .unwrap();
    }
}
