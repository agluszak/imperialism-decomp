use super::strategic_map::StrategicMapSession;
use crate::{AppState, RetailAssetsResource, ReturnTo};
use bevy::ecs::world::World;
use bevy::prelude::*;
use imperialism_core::{GameData, GameState, MajorNationId, TileId, TurnStop};
use imperialism_formats::{BattleReportText, CityWindowLayout, LoadedGame};

/// Authoritative in-memory game owned by the running Bevy app.
#[derive(Resource, Debug, PartialEq)]
pub(crate) struct GameSession {
    pub(crate) game: GameState,
}

/// Saved city-dialog positions. Presentation only; not gameplay.
#[derive(Resource, Debug, Default, PartialEq)]
pub(crate) struct CityWindows(pub CityWindowLayout);

/// Captured battle-report strings for the current post-combat book.
#[derive(Resource, Debug, Default, PartialEq)]
pub(crate) struct BattleReportPresentation(pub Vec<BattleReportText>);

impl GameSession {
    pub(crate) fn new(game: GameState) -> Self {
        Self { game }
    }

    pub(crate) fn active_major_nation(&self) -> MajorNationId {
        MajorNationId::from_nation(self.game.turn().active_nation)
            .expect("interactive screens require an active major nation")
    }
}

pub(crate) fn insert_loaded_game(commands: &mut Commands, loaded: LoadedGame) {
    commands.insert_resource(GameSession::new(loaded.game));
    commands.insert_resource(StrategicMapSession::from_origin(loaded.map_view_origin));
    commands.insert_resource(CityWindows(loaded.city_windows));
    commands.insert_resource(BattleReportPresentation(loaded.battle_report_text));
}

pub(crate) fn insert_loaded_game_world(world: &mut World, loaded: LoadedGame) {
    world.insert_resource(GameSession::new(loaded.game));
    world.insert_resource(StrategicMapSession::from_origin(loaded.map_view_origin));
    world.insert_resource(CityWindows(loaded.city_windows));
    world.insert_resource(BattleReportPresentation(loaded.battle_report_text));
}

pub(crate) fn insert_game_session(commands: &mut Commands, game: GameState) {
    insert_loaded_game(commands, loaded_from_game(game));
}

#[cfg(test)]
pub(crate) fn insert_game_session_world(world: &mut World, game: GameState) {
    insert_loaded_game_world(world, loaded_from_game(game));
}

pub(crate) fn remove_game_session(commands: &mut Commands) {
    commands.remove_resource::<GameSession>();
    commands.remove_resource::<StrategicMapSession>();
    commands.remove_resource::<CityWindows>();
    commands.remove_resource::<BattleReportPresentation>();
}

fn loaded_from_game(game: GameState) -> LoadedGame {
    LoadedGame {
        game,
        map_view_origin: TileId::new(1),
        city_windows: CityWindowLayout::default(),
        battle_report_text: Vec::new(),
    }
}

pub(crate) fn retail_game_data(assets: &RetailAssetsResource) -> GameData {
    GameData::from_news_story_ids(assets.assets().news_table().story_ids().to_vec())
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
