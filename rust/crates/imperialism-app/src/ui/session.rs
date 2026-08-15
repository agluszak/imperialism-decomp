use bevy::prelude::*;
use imperialism_core::{GameState, TurnStop};
use imperialism_formats::RetailAssets;

use crate::AppState;

/// Authoritative in-memory game owned by the running Bevy app.
#[derive(Resource, Debug, PartialEq)]
pub(crate) struct GameSession {
    pub(crate) game: GameState,
}

impl GameSession {
    pub(crate) fn from_assets(mut game: GameState, assets: &RetailAssets) -> Self {
        game.set_news_story_ids(assets.news_table().story_ids());
        Self { game }
    }
}

/// Maps one core turn stop onto the matching Bevy screen.
pub(crate) fn apply_turn_stop(stop: TurnStop, next_state: &mut NextState<AppState>) {
    match stop {
        TurnStop::PlayerOrders | TurnStop::TurnAlerts => next_state.set(AppState::StrategicMap),
        TurnStop::TradeOffer => next_state.set(AppState::OfferSheet),
        TurnStop::DealBook => next_state.set(AppState::DealBook),
        TurnStop::TechnologyAdvance => next_state.set(AppState::TechnologyAdvance),
        TurnStop::Newspaper => next_state.set(AppState::Newspaper),
        TurnStop::DiplomacyOffer => next_state.set(AppState::Diplomacy),
        TurnStop::DiplomacyWarJoin => next_state.set(AppState::Diplomacy),
        TurnStop::LandBattle => next_state.set(AppState::LandBattle),
        TurnStop::GreatPowerLoss
        | TurnStop::PlayerEliminated
        | TurnStop::Victory
        | TurnStop::DecadeCinematic => next_state.set(AppState::OpeningCinematic),
        TurnStop::PostCombatReports => next_state.set(AppState::BattleReport),
        TurnStop::CouncilOfGovernors => next_state.set(AppState::CouncilOfGovernors),
        TurnStop::GameScore => next_state.set(AppState::GameScore),
        TurnStop::HighScores => next_state.set(AppState::HighScore),
        TurnStop::SessionEnded => next_state.set(AppState::MainMenu),
    }
}
