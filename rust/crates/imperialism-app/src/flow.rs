use bevy::prelude::*;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, States)]
pub enum AppState {
    #[default]
    Loading,
    MainMenu,
    RandomSetup,
    InGame,
}

pub struct ScreenFlowPlugin;

impl Plugin for ScreenFlowPlugin {
    fn build(&self, app: &mut App) {
        app.init_state::<AppState>();
    }
}
