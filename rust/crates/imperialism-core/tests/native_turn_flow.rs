//! Native interruption-boundary differentials for the outer turn state machine.

use imperialism_core::{GameState, TurnStop};
use imperialism_testkit::{
    assert_game_state_eq, compare_native, first_serialized_difference, load_save_backed_state,
    run_native,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NewspaperCase {
    story_ids: Vec<i32>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct TradeBoundaryResult {
    stop: String,
    phase: i32,
    category_index: usize,
    entry_ordinal: usize,
    buyer: u8,
    seller: u8,
    amount: i16,
    price: i16,
    commodity: i16,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn deal_book_dispatch_precedes_the_quarter_gate() {
    compare_native("turn_stop_deal_book", |state, (): ()| {
        stop_name(state.advance_turn(&[]))
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn city_and_transport_writes_the_resume_phase_before_the_body() {
    compare_native("turn_stop_city_and_transport", |state, (): ()| {
        assert_eq!(
            state.turn().phase(),
            imperialism_core::PhaseCode::CITY_AND_TRANSPORT
        );
        state.apply_city_and_transport_case();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn newspaper_dispatch_precedes_return_to_map() {
    let native = run_native::<NewspaperCase, String>("turn_stop_newspaper").unwrap();
    let mut actual = load_save_backed_state(native.before).unwrap();
    let expected = load_save_backed_state(native.after).unwrap();
    assert_eq!(
        stop_name(actual.advance_turn(&native.case.story_ids)),
        native.result
    );
    assert_game_state_eq(&expected, &actual).unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn technology_report_dispatch_precedes_newspaper() {
    compare_native("turn_stop_technology", |state, (): ()| {
        stop_name(state.advance_turn(&[]))
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn trade_offer_dispatch_precedes_the_offer_sheet_phase() {
    let native = run_native::<(), TradeBoundaryResult>("turn_stop_trade").unwrap();
    let mut actual = load_save_backed_state(native.before).unwrap();
    let expected = load_save_backed_state(native.after).unwrap();

    assert_eq!(actual.advance_turn(&[]), TurnStop::TradeOffer);
    let pending = actual
        .pending_trade_offer()
        .expect("trade stop requires a pending offer");
    let continuation = serde_json::to_value(&actual).unwrap()["continuation"]["Trade"].clone();
    let result = TradeBoundaryResult {
        stop: "trade_offer".to_owned(),
        phase: actual.turn().phase().retail(),
        category_index: continuation["category_index"].as_u64().unwrap() as usize,
        entry_ordinal: continuation["entry_ordinal"].as_u64().unwrap() as usize,
        buyer: pending.buyer.get(),
        seller: pending.seller.get(),
        amount: pending.amount,
        price: pending.price,
        commodity: pending.commodity.resource() as i16,
    };
    assert_eq!(result, native.result);
    assert_state_except_continuation(&expected, &actual);
}

fn assert_state_except_continuation(expected: &GameState, actual: &GameState) {
    let mut expected = serde_json::to_value(expected).unwrap();
    let mut actual = serde_json::to_value(actual).unwrap();
    expected.as_object_mut().unwrap().remove("continuation");
    actual.as_object_mut().unwrap().remove("continuation");
    assert_eq!(
        first_serialized_difference(&expected, &actual).unwrap(),
        None
    );
}

fn stop_name(stop: TurnStop) -> String {
    match stop {
        TurnStop::Newspaper => "newspaper",
        TurnStop::DealBook => "deal_book",
        TurnStop::TechnologyAdvance => "technology_advance",
        _ => panic!("unexpected turn stop {stop:?}"),
    }
    .to_owned()
}
