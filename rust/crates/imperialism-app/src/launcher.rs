use crate::audio::RetailAudioPlugin;
use crate::flow::{AppState, ScreenFlowPlugin};
use crate::session::SessionPlugin;
use crate::ui::{StartupUiPlugin, UiCatalogResource, UiRuntimePlugin};
use bevy::prelude::*;
use bevy::window::WindowPlugin;
use imperialism_formats::{RetailAssetError, RetailAssets, UiCatalog};
use std::ffi::OsString;
use std::path::PathBuf;

const COMPILED_UI_CATALOG: &str = include_str!("../../imperialism-formats/assets/ui_catalog.json");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MainMenuConfig {
    pub retail_dir: PathBuf,
}

impl MainMenuConfig {
    pub fn usage() -> &'static str {
        concat!(
            "usage: imperialism-app --retail-dir PATH\n",
            "\n",
            "Normal launch requires an English GOG Windows installation. The retail path is\n",
            "validated before Bevy creates a window and is never persisted.",
        )
    }

    pub fn parse(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Option<Self>, ExecutableConfigError> {
        let arguments = arguments.into_iter().collect::<Vec<_>>();
        if arguments
            .iter()
            .any(|argument| argument == "--help" || argument == "-h")
        {
            return Ok(None);
        }

        let mut retail_dir = None;
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            match argument.to_str() {
                Some("--retail-dir") => {
                    if retail_dir.is_some() {
                        return Err(ExecutableConfigError::DuplicateOption("--retail-dir"));
                    }
                    retail_dir =
                        Some(PathBuf::from(arguments.next().ok_or(
                            ExecutableConfigError::MissingOptionValue("--retail-dir"),
                        )?));
                }
                Some(value) if value.starts_with('-') => {
                    return Err(ExecutableConfigError::UnknownOption(argument));
                }
                _ => return Err(ExecutableConfigError::UnexpectedArgument(argument)),
            }
        }
        Ok(Some(Self {
            retail_dir: retail_dir.ok_or(ExecutableConfigError::MissingRetailDirectory)?,
        }))
    }
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExecutableConfigError {
    #[error("normal launch requires --retail-dir PATH")]
    MissingRetailDirectory,
    #[error("{0} requires a path")]
    MissingOptionValue(&'static str),
    #[error("{0} may be supplied only once")]
    DuplicateOption(&'static str),
    #[error("unknown option {0:?}")]
    UnknownOption(OsString),
    #[error("unexpected argument {0:?}")]
    UnexpectedArgument(OsString),
}

pub struct PreparedMainMenu {
    retail_assets: RetailAssets,
    ui_catalog: UiCatalog,
}

pub fn prepare_main_menu(config: &MainMenuConfig) -> Result<PreparedMainMenu, RetailAssetError> {
    let retail_assets = RetailAssets::open(&config.retail_dir)?;
    let ui_catalog = serde_json::from_str::<UiCatalog>(COMPILED_UI_CATALOG)
        .expect("the compiled UI catalog must deserialize");
    Ok(PreparedMainMenu {
        retail_assets,
        ui_catalog,
    })
}

#[derive(Resource)]
pub(crate) struct RetailAssetsResource(RetailAssets);

impl RetailAssetsResource {
    pub(crate) fn new(assets: RetailAssets) -> Self {
        Self(assets)
    }

    pub(crate) const fn assets(&self) -> &RetailAssets {
        &self.0
    }
}

pub fn configure_main_menu_app(app: &mut App, prepared: PreparedMainMenu) {
    let catalog = UiCatalogResource::new(prepared.ui_catalog);
    app.insert_resource(catalog)
        .insert_resource(RetailAssetsResource::new(prepared.retail_assets))
        .add_plugins((
            SessionPlugin,
            ScreenFlowPlugin,
            UiRuntimePlugin,
            StartupUiPlugin,
            RetailAudioPlugin,
        ))
        .add_systems(Startup, enter_main_menu);
}

pub fn build_main_menu_app(prepared: PreparedMainMenu) -> App {
    let logical_resolution = prepared.ui_catalog.logical_resolution;
    let mut app = App::new();
    app.insert_resource(ClearColor(Color::BLACK)).add_plugins(
        DefaultPlugins
            .set(ImagePlugin::default_nearest())
            .set(WindowPlugin {
                primary_window: Some(Window {
                    title: "Imperialism".to_owned(),
                    resolution: (logical_resolution[0], logical_resolution[1]).into(),
                    ..default()
                }),
                ..default()
            }),
    );
    configure_main_menu_app(&mut app, prepared);
    app
}

pub fn run_main_menu(prepared: PreparedMainMenu) {
    build_main_menu_app(prepared).run();
}

fn enter_main_menu(mut next_state: ResMut<NextState<AppState>>) {
    next_state.set(AppState::MainMenu);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_launch_requires_an_explicit_retail_directory() {
        assert_eq!(
            MainMenuConfig::parse(Vec::<OsString>::new()).unwrap_err(),
            ExecutableConfigError::MissingRetailDirectory
        );
        let config =
            MainMenuConfig::parse([OsString::from("--retail-dir"), OsString::from("gog")]).unwrap();
        assert_eq!(
            config,
            Some(MainMenuConfig {
                retail_dir: PathBuf::from("gog"),
            })
        );
        assert!(matches!(
            MainMenuConfig::parse([OsString::from("--unknown"), OsString::from("value")]),
            Err(ExecutableConfigError::UnknownOption(_))
        ));
    }

    #[test]
    fn missing_retail_inputs_fail_during_preparation() {
        let config = MainMenuConfig {
            retail_dir: std::env::temp_dir().join(format!(
                "imperialism-app-missing-retail-{}",
                std::process::id()
            )),
        };

        assert!(matches!(
            prepare_main_menu(&config),
            Err(RetailAssetError::MissingFiles(_))
        ));
    }
}
