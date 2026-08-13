use bevy::prelude::*;
use imperialism_core::{GameState, TurnStop};
use imperialism_formats::RetailAssets;

use crate::AppState;

/// Authoritative in-memory game owned by the running Bevy app.
#[derive(Resource, Debug, PartialEq)]
pub(crate) struct GameSession(pub(crate) GameState);

/// Maps one core turn stop onto the matching Bevy screen.
pub(crate) fn apply_turn_stop(
    stop: TurnStop,
    session: &mut GameState,
    assets: &RetailAssets,
    next_state: &mut NextState<AppState>,
) {
    match stop {
        TurnStop::PlayerOrders => next_state.set(AppState::StrategicMap),
        TurnStop::TradeOffer(_) => next_state.set(AppState::OfferSheet),
        TurnStop::DealBook => next_state.set(AppState::DealBook),
        TurnStop::TechnologyAdvance(_) => next_state.set(AppState::TechnologyAdvance),
        TurnStop::Newspaper => {
            session.start_newspaper_phase(assets.news_table().story_ids());
            next_state.set(AppState::Newspaper);
        }
        TurnStop::DiplomacyOffer(_) | TurnStop::DiplomacyWarJoin(_) => {
            next_state.set(AppState::Diplomacy)
        }
        TurnStop::Unimplemented(phase) => {
            panic!("core turn stopped at unimplemented phase {phase:?}")
        }
    }
}
