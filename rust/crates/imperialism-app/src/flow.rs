use bevy::prelude::*;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, States)]
pub(crate) enum AppState {
    #[default]
    Loading,
    MainMenu,
    RandomSetup,
    #[allow(dead_code)] // The active-game transition has not been recovered yet.
    InGame,
}

pub(crate) struct ScreenFlowPlugin;

impl Plugin for ScreenFlowPlugin {
    fn build(&self, app: &mut App) {
        app.init_state::<AppState>();
    }
}
