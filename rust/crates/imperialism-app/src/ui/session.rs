use crate::{AppState, ReturnTo};
use bevy::prelude::*;
use imperialism_core::{GameState, MajorNationId, TurnStop};
use imperialism_formats::RetailAssets;

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

    pub(crate) fn active_major_nation(&self) -> MajorNationId {
        MajorNationId::from_nation(self.game.turn().active_nation)
            .expect("interactive screens require an active major nation")
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
    }
}

pub(crate) fn clear_return_to(mut commands: Commands) {
    commands.remove_resource::<ReturnTo>();
}
