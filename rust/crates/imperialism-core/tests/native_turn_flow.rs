//! Save-backed native differential for one composed peaceful turn.

use imperialism_core::*;
use imperialism_testkit::compare_native;

fn finish_peaceful_turn(state: &mut GameState) {
    let mut stop = state.finish_player_orders();
    loop {
        match stop {
            TurnStop::DiplomacyOffer(_) => {
                stop = state.answer_current_diplomacy_offer(false);
            }
            TurnStop::DiplomacyWarJoin(_) => {
                stop = state.answer_current_diplomacy_war_join(false);
            }
            TurnStop::TradeOffer(offer) => {
                stop = state.answer_trade_offer(offer.amount, false);
            }
            TurnStop::DealBook => break,
            other => panic!("unexpected stop before Deal Book: {other:?}"),
        }
    }
    assert_eq!(state.turn().phase(), PhaseCode::DEAL_BOOK);

    stop = state.close_deal_book();
    while let TurnStop::TechnologyAdvance(_) = stop {
        stop = state.acknowledge_technology_report();
    }
    assert_eq!(stop, TurnStop::Newspaper);
    assert_eq!(state.turn().phase(), PhaseCode::NEWSPAPER);
    assert_eq!(state.close_newspaper(), TurnStop::PlayerOrders);
    assert_eq!(state.turn().phase(), PhaseCode::STRATEGIC_MAP);
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn peaceful_whole_turn() {
    compare_native("peaceful_whole_turn", |state, (): ()| {
        finish_peaceful_turn(state);
    })
    .unwrap();
}
