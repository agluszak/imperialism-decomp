//! Save-backed native differential for one composed peaceful turn.

use imperialism_core::*;
use imperialism_testkit::compare_native;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct PeacefulWholeTurnCase {
    story_ids: Vec<i32>,
}

fn finish_peaceful_turn(state: &mut GameState, news_story_ids: &[i32]) {
    // Native news capture omits the Rust-only template table. Install it for
    // `start_newspaper_phase`, then drop it so the after-state matches.
    state.set_news_story_ids(news_story_ids);
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

    stop = state.close_turn_deal_book();
    while let TurnStop::TechnologyAdvance(_) = stop {
        stop = state.acknowledge_technology_report();
    }
    assert_eq!(stop, TurnStop::Newspaper);
    assert_eq!(state.turn().phase(), PhaseCode::NEWSPAPER);
    assert_eq!(state.close_newspaper(), TurnStop::PlayerOrders);
    assert_eq!(state.turn().phase(), PhaseCode::STRATEGIC_MAP);
    state.set_news_story_ids(&[]);
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn peaceful_whole_turn() {
    compare_native(
        "peaceful_whole_turn",
        |state, case: PeacefulWholeTurnCase| {
            finish_peaceful_turn(state, &case.story_ids);
        },
    )
    .unwrap();
}
