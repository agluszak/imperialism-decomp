#![forbid(unsafe_code)]

mod audio;
mod flow;
mod launcher;
mod session;
pub mod ui;

pub use audio::{
    AudioCue, AudioCueFailed, AudioCuePlayback, AudioCueQueued, RETAIL_MAIN_MENU_MUSIC,
    RETAIL_UI_CLICK_WAVE, RetailAudioAsset, RetailAudioError, RetailAudioPlayback,
    RetailAudioPlugin, RetailMusicTrack, RetailMusicTrackError, RetailWaveId,
    resolve_retail_audio_path,
};
pub use flow::{AppState, GameScreen, ScreenFlowPlugin, ScreenStack};
pub use launcher::{
    ExecutableConfigError, MainMenuConfig, MainMenuLoadError, PreparedMainMenu,
    RetailAssetPackResource, build_main_menu_app, configure_main_menu_app, prepare_main_menu,
    run_main_menu,
};
pub use session::{
    CommandRejectedMessage, DomainEventMessage, GameLoopSet, GameSession, SessionCommandError,
    SessionPlugin, SubmitCommand,
};
pub use ui::{UiIntent, UiRuntimePlugin};
