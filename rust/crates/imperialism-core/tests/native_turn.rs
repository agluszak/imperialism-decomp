//! Native transition differentials for turn-phase advances.

use imperialism_core::*;
use imperialism_testkit::{compare_native, compare_runtime_scenario};
use serde::Deserialize;

#[test]
#[ignore = "requires the native C++ oracle"]
fn first_turn_alert_phase() {
    compare_native("first_turn_alert_phase", |state, (): ()| {
        let _ = state.advance_turn_step();
    })
    .unwrap();
}

macro_rules! first_turn_phase {
    ($name:ident) => {
        #[test]
        #[ignore = "requires the native C++ oracle"]
        fn $name() {
            compare_native(stringify!($name), |state, (): ()| state.advance_turn_step()).unwrap();
        }
    };
}

first_turn_phase!(first_turn_diplomacy_phase);
first_turn_phase!(first_turn_trade_phase);
first_turn_phase!(first_turn_civilian_phase);
first_turn_phase!(first_turn_military_phase);
first_turn_phase!(first_turn_combat_movement_phase);
first_turn_phase!(first_turn_military_cleanup_phase);
first_turn_phase!(first_turn_diplomacy_offer_phase);
first_turn_phase!(first_turn_elimination_phase);
first_turn_phase!(first_turn_city_transport_phase);
first_turn_phase!(first_turn_great_power_pressure_phase);
first_turn_phase!(first_turn_deal_book_phase);
first_turn_phase!(first_turn_quarter_gate_phase);
first_turn_phase!(first_turn_season_advance_phase);
first_turn_phase!(first_turn_technology_advances_phase);
first_turn_phase!(first_turn_newspaper_phase);
first_turn_phase!(first_turn_return_to_map_phase);

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
        screens: Vec<GameScreen>,
    },
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn easy_turn_from_save() {
    compare_runtime_scenario(
        "easy_turn_from_save",
        |state, case: EasyTurnFromSaveCase| {
            assert!(case.reject_offers);
            assert!(case.expect_exactly_one_turn);
            let from_turn = state.turn().economic_turn;

            let first = state.finish_player_orders();
            assert_eq!(
                first,
                FlowStop::Show {
                    screen: GameScreen::DealBook
                }
            );

            let second = state.dismiss_blocking_screen();
            assert_eq!(
                second,
                FlowStop::Show {
                    screen: GameScreen::Newspaper
                }
            );

            let third = state.dismiss_blocking_screen();
            assert_eq!(third, FlowStop::PlayerOrders);
            assert_eq!(state.turn().economic_turn, from_turn + 1);

            EasyTurnFromSaveResult::Completed {
                from_turn,
                to_turn: state.turn().economic_turn,
                screens: vec![GameScreen::DealBook, GameScreen::Newspaper],
            }
        },
    )
    .unwrap();
}
