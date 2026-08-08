#![forbid(unsafe_code)]

mod audio;
mod flow;
mod launcher;
mod session;
pub mod ui;

pub use audio::{
    AudioCue, AudioCuePlayback, RETAIL_MAIN_MENU_MUSIC, RETAIL_UI_CLICK_WAVE, RetailAudioAsset,
    RetailAudioPlugin, RetailMusicTrack, RetailMusicTrackError, RetailWaveId,
};
pub use flow::{AppState, ScreenFlowPlugin};
pub use launcher::{
    ExecutableConfigError, MainMenuConfig, MainMenuLoadError, PreparedMainMenu,
    build_main_menu_app, configure_main_menu_app, prepare_main_menu, run_main_menu,
};
pub use session::{DomainEventMessage, GameLoopSet, GameSession, SessionPlugin, SubmitCommand};
pub use ui::{Difficulty, RandomGameSetup, UiIntent, UiRuntimePlugin};
