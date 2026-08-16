use crate::{AppState, RetailAssetsResource, ReturnTo};
use bevy::prelude::*;
use imperialism_core::{GameState, MajorNationId, TurnStop};

/// Authoritative in-memory game owned by the running Bevy app.
#[derive(Resource, Debug, PartialEq)]
pub(crate) struct GameSession {
    pub(crate) game: GameState,
}

impl GameSession {
    pub(crate) fn active_major_nation(&self) -> MajorNationId {
        MajorNationId::from_nation(self.game.turn().active_nation)
            .expect("interactive screens require an active major nation")
    }
}

pub(crate) fn news_story_ids(assets: Option<&RetailAssetsResource>) -> &[i32] {
    assets
        .map(RetailAssetsResource::news_story_ids)
        .unwrap_or(&[])
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
        // Core must stop at these retail presentation boundaries even before their
        // Bevy screens are ported. Staying on the current screen is safer than
        // silently advancing the simulation through an unresolved event.
        TurnStop::GreatPowerLoss
        | TurnStop::PostCombatDiplomacy
        | TurnStop::PlayerEliminated
        | TurnStop::Victory
        | TurnStop::DecadeCinematic
        | TurnStop::TopTenScores
        | TurnStop::OpeningCinematic => {}
    }
}

pub(crate) fn clear_return_to(mut commands: Commands) {
    commands.remove_resource::<ReturnTo>();
}