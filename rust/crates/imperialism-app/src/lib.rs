#![forbid(unsafe_code)]

mod app;
mod flow;
mod input;
mod launcher;
mod session;
pub mod strategic_map;
pub mod ui;

pub use app::{
    ViewerConfig, ViewerConfigError, ViewerInput, ViewerLoadError, example_asset_manifest_path,
    load_viewer, run_viewer,
};
pub use flow::{AppState, GameScreen, ScreenFlowPlugin, ScreenStack};
pub use input::GameInputPlugin;
pub use launcher::{
    ExecutableConfigError, ExecutableMode, MainMenuConfig, MainMenuLoadError, PreparedMainMenu,
    RetailAssetPackResource, build_main_menu_app, configure_main_menu_app, prepare_main_menu,
    run_main_menu,
};
pub use session::{
    CommandRejectedMessage, DomainEventMessage, GameLoopSet, GameSession, SessionCommandError,
    SessionPlugin, SubmitCommand,
};
pub use strategic_map::{
    CityRef, MilitaryUnitRef, NationRef, ShipRef, StrategicMapLayout, StrategicMapPlugin, TileRef,
};
pub use ui::{UiIntent, UiRuntimePlugin};
