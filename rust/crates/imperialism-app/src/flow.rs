use bevy::prelude::*;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, States)]
pub enum AppState {
    #[default]
    Loading,
    MainMenu,
    InGame,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GameScreen {
    MainMenu,
    RandomSetup,
}

#[derive(Resource, Clone, Debug, Eq, PartialEq)]
pub struct ScreenStack {
    pub base: GameScreen,
    pub overlays: Vec<GameScreen>,
    pub modals: Vec<GameScreen>,
}

impl Default for ScreenStack {
    fn default() -> Self {
        Self {
            base: GameScreen::MainMenu,
            overlays: Vec::new(),
            modals: Vec::new(),
        }
    }
}

pub struct ScreenFlowPlugin;

impl Plugin for ScreenFlowPlugin {
    fn build(&self, app: &mut App) {
        app.init_state::<AppState>().init_resource::<ScreenStack>();
    }
}
