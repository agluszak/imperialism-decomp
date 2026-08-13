use bevy::prelude::*;
use imperialism_core::{GameState, TurnStop};

use crate::AppState;

/// Authoritative in-memory game owned by the running Bevy app.
#[derive(Resource, Debug, PartialEq)]
pub(crate) struct GameSession(pub(crate) GameState);

/// Maps one core turn stop onto the matching Bevy screen.
pub(crate) fn apply_turn_stop(stop: TurnStop, next_state: &mut NextState<AppState>) {
    match stop {
        TurnStop::PlayerOrders => next_state.set(AppState::StrategicMap),
        TurnStop::TradeOffer(_) => next_state.set(AppState::OfferSheet),
        TurnStop::DealBook => next_state.set(AppState::DealBook),
        TurnStop::TechnologyAdvance(_) => next_state.set(AppState::TechnologyAdvance),
        TurnStop::Newspaper => next_state.set(AppState::Newspaper),
        TurnStop::DiplomacyOffer(_) | TurnStop::DiplomacyWarJoin(_) => {
            panic!("diplomacy interrupt screens are not wired yet")
        }
        TurnStop::LandBattle => panic!("land battle screen is not wired yet"),
        TurnStop::DecadeCinematic => panic!("decade cinematic screen is not wired yet"),
        TurnStop::PlayerEliminated => panic!("player-eliminated screen is not wired yet"),
        TurnStop::Victory => panic!("victory screen is not wired yet"),
        TurnStop::Unimplemented(phase) => {
            panic!("core turn stopped at unimplemented phase {phase:?}")
        }
    }
}
