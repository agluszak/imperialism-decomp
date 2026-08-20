use crate::{AppState, RetailAssetsResource, ReturnTo};
use bevy::prelude::*;
use imperialism_core::{GameState, MajorNationId, TileId, TurnStop};
use imperialism_formats::{BattleReportText, CityWindowLayout, LoadedGame};

/// Authoritative in-memory game owned by the running Bevy app.
#[derive(Resource, Debug, PartialEq)]
pub(crate) struct GameSession {
    pub(crate) game: GameState,
    pub(crate) map_view_origin: TileId,
    pub(crate) city_windows: CityWindowLayout,
    pub(crate) battle_report_text: Vec<BattleReportText>,
}

impl GameSession {
    pub(crate) fn new(game: GameState) -> Self {
        Self {
            game,
            map_view_origin: TileId::new(1),
            city_windows: CityWindowLayout::default(),
            battle_report_text: Vec::new(),
        }
    }

    pub(crate) fn from_loaded(loaded: LoadedGame) -> Self {
        Self {
            game: loaded.game,
            map_view_origin: loaded.map_view_origin,
            city_windows: loaded.city_windows,
            battle_report_text: loaded.battle_report_text,
        }
    }

    pub(crate) fn scroll_map_viewport(&mut self, row_delta: i32, column_delta: i32) -> bool {
        let next =
            self.game
                .map()
                .scrolled_viewport_origin(self.map_view_origin, row_delta, column_delta);
        if next == self.map_view_origin {
            return false;
        }
        self.map_view_origin = next;
        true
    }

    pub(crate) fn set_map_viewport_upper_left(&mut self, column: i32, row: i32) {
        self.map_view_origin = self.game.map().viewport_origin_from_upper_left(column, row);
    }

    pub(crate) fn center_map_on(&mut self, tile: TileId) {
        self.map_view_origin = self.game.map().viewport_origin_centered_on(tile);
    }

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
        TurnStop::PlayerOrders | TurnStop::TurnAlerts(_) => next_state.set(AppState::StrategicMap),
        TurnStop::TownNaming => next_state.set(AppState::TownNaming),
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
