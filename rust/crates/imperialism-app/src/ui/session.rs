use crate::{AppState, RetailAssetsResource, ReturnTo};
use bevy::prelude::*;
use imperialism_core::{GameState, MajorNation, MajorNationId, TurnStop};

/// Authoritative in-memory game owned by the running Bevy app.
#[derive(Resource, Debug, PartialEq)]
pub(crate) struct GameSession {
    pub(crate) game: GameState,
}

impl GameSession {
    fn active_major_slot(&self) -> MajorNationId {
        MajorNationId::from_nation(self.game.turn().active_nation)
            .expect("interactive screens require a major nation slot")
    }

    pub(crate) fn active_major(&self) -> &MajorNation {
        self.game
            .nations()
            .major(self.active_major_slot())
            .expect("interactive screens require a live major nation")
    }

    pub(crate) fn active_major_mut(&mut self) -> &mut MajorNation {
        let nation = self.active_major_slot();
        self.game
            .nations_mut()
            .major_mut(nation)
            .expect("interactive screens require a live major nation")
    }

    pub(crate) fn active_major_nation(&self) -> MajorNationId {
        let nation = self.active_major_slot();
        self.game
            .nations()
            .major(nation)
            .expect("interactive screens require a live major nation");
        nation
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
        TurnStop::NavalBattle => next_state.set(AppState::NavalBattle),
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

pub(crate) fn clear_return_to(mut commands: Commands) {
    commands.remove_resource::<ReturnTo>();
}
