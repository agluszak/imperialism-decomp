use super::GameSession;
use crate::AppState;
use bevy::prelude::*;

pub(crate) struct NavalBattlePlugin;

impl Plugin for NavalBattlePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(OnEnter(AppState::NavalBattle), initialize_naval_battle);
    }
}

fn initialize_naval_battle(mut session: ResMut<GameSession>) {
    session.game.ensure_navy_battle();
}
