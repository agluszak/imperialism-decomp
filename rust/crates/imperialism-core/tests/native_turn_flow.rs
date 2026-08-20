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

#[derive(Debug, Deserialize)]
struct SecondTurnSequenceCase {
    story_ids: Vec<i32>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct SecondTurnSequenceResult {
    stops: Vec<String>,
    rng_states: Vec<u32>,
    economic_turn: i32,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct ConsecutiveTurnSequenceResult {
    stops: Vec<String>,
    rng_states: Vec<u32>,
    economic_turns: Vec<i32>,
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
fn second_turn_sequence_returns_through_deal_book_and_newspaper() {
    compare_native(
        "second_turn_sequence",
        |state, case: SecondTurnSequenceCase| {
            let mut stops = Vec::new();
            let mut rng_states = Vec::new();
            let mut stop = state.finish_player_orders(false, &case.story_ids);
            while matches!(stop, TurnStop::DiplomacyOffer | TurnStop::DiplomacyWarJoin) {
                stop = match stop {
                    TurnStop::DiplomacyOffer => {
                        state.answer_current_diplomacy_offer(false, &case.story_ids)
                    }
                    TurnStop::DiplomacyWarJoin => {
                        state.answer_current_diplomacy_war_join(false, &case.story_ids)
                    }
                    _ => unreachable!(),
                };
            }
            while stop == TurnStop::TradeOffer {
                stop = state.answer_trade_offer(0, false, &case.story_ids);
            }
            assert_eq!(stop, TurnStop::DealBook);
            stops.push("deal_book".to_owned());
            rng_states.push(state.rng().crt_rand.state());

            stop = state.close_turn_deal_book(&case.story_ids);
            while stop == TurnStop::TechnologyAdvance {
                stop = state.acknowledge_technology_report(&case.story_ids);
            }
            assert_eq!(stop, TurnStop::Newspaper);
            stops.push("newspaper".to_owned());
            rng_states.push(state.rng().crt_rand.state());

            assert_eq!(state.close_newspaper(true), TurnStop::PlayerOrders);
            stops.push("player_orders".to_owned());
            rng_states.push(state.rng().crt_rand.state());
            SecondTurnSequenceResult {
                stops,
                rng_states,
                economic_turn: state.turn().economic_turn,
            }
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn five_consecutive_turns_return_through_deal_book_and_newspaper() {
    let native = run_native::<SecondTurnSequenceCase, ConsecutiveTurnSequenceResult>(
        "consecutive_turn_sequence",
    )
    .unwrap();
    let mut state = load_save_backed_state(native.before).unwrap();
    let expected = load_save_backed_state(native.after).unwrap();
    let mut stops = Vec::new();
    let mut rng_states = Vec::new();
    let mut economic_turns = Vec::new();
    for _ in 0..5 {
        let mut stop = state.finish_player_orders(false, &native.case.story_ids);
        while matches!(stop, TurnStop::DiplomacyOffer | TurnStop::DiplomacyWarJoin) {
            stop = match stop {
                TurnStop::DiplomacyOffer => {
                    state.answer_current_diplomacy_offer(false, &native.case.story_ids)
                }
                TurnStop::DiplomacyWarJoin => {
                    state.answer_current_diplomacy_war_join(false, &native.case.story_ids)
                }
                _ => unreachable!(),
            };
        }
        while stop == TurnStop::TradeOffer {
            stop = state.answer_trade_offer(0, false, &native.case.story_ids);
        }
        assert_eq!(stop, TurnStop::DealBook);
        stops.push("deal_book".to_owned());
        rng_states.push(state.rng().crt_rand.state());

        stop = state.close_turn_deal_book(&native.case.story_ids);
        while stop == TurnStop::TechnologyAdvance {
            stop = state.acknowledge_technology_report(&native.case.story_ids);
        }
        assert_eq!(stop, TurnStop::Newspaper);
        stops.push("newspaper".to_owned());
        rng_states.push(state.rng().crt_rand.state());

        assert_eq!(state.close_newspaper(true), TurnStop::PlayerOrders);
        stops.push("player_orders".to_owned());
        rng_states.push(state.rng().crt_rand.state());
        economic_turns.push(state.turn().economic_turn);
    }
    let result = ConsecutiveTurnSequenceResult {
        stops,
        rng_states,
        economic_turns,
    };
    if let Err(error) = assert_game_state_eq(&expected, &state) {
        panic!("{error}; result C++ {:?}, Rust {result:?}", native.result);
    }
    assert_eq!(native.result, result);
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
    let (category_index, entry_ordinal) = actual
        .pending_trade_offer_cursor()
        .expect("trade stop requires an active deal cursor");
    let result = TradeBoundaryResult {
        stop: "trade_offer".to_owned(),
        phase: actual.turn().phase().retail(),
        category_index,
        entry_ordinal,
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
