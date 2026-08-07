use crate::app::{ViewerConfig, ViewerConfigError};
use crate::flow::{AppState, ScreenFlowPlugin};
use crate::session::{GameSession, SessionPlugin};
use crate::ui::{StartupUiPlugin, UiCatalogResource, UiRuntimePlugin};
use bevy::prelude::*;
use bevy::window::WindowPlugin;
use imperialism_formats::{
    ImportedRetailAssets, RetailAssetImportError, RetailAssetPackManifestV1, UiCatalogError,
    UiCatalogV1, default_retail_cache_dir, import_english_gog_assets,
};
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

const COMPILED_UI_CATALOG: &str =
    include_str!("../../imperialism-formats/assets/ui_catalog_v1.json");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MainMenuConfig {
    pub retail_dir: PathBuf,
    pub cache_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutableMode {
    MainMenu(MainMenuConfig),
    SnapshotViewer(ViewerConfig),
    Help,
}

impl ExecutableMode {
    pub fn usage() -> &'static str {
        concat!(
            "usage:\n",
            "  imperialism-app --retail-dir PATH [--cache-dir PATH]\n",
            "  imperialism-app viewer SNAPSHOT.json [--assets ASSET_PACK]\n",
            "\n",
            "Normal launch requires an English GOG Windows installation. The retail path is\n",
            "validated before Bevy creates a window and is never persisted. Derived assets are\n",
            "stored in a content-addressed cache. The viewer subcommand is diagnostic only.",
        )
    }

    pub fn parse(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, ExecutableConfigError> {
        let arguments = arguments.into_iter().collect::<Vec<_>>();
        if arguments
            .iter()
            .any(|argument| argument == "--help" || argument == "-h")
        {
            return Ok(Self::Help);
        }
        if arguments
            .first()
            .is_some_and(|argument| argument == "viewer")
        {
            return ViewerConfig::parse(arguments.into_iter().skip(1))
                .map_err(ExecutableConfigError::Viewer)
                .map(|config| config.map_or(Self::Help, Self::SnapshotViewer));
        }

        let mut retail_dir = None;
        let mut cache_dir = None;
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
                Some("--cache-dir") => {
                    if cache_dir.is_some() {
                        return Err(ExecutableConfigError::DuplicateOption("--cache-dir"));
                    }
                    cache_dir =
                        Some(PathBuf::from(arguments.next().ok_or(
                            ExecutableConfigError::MissingOptionValue("--cache-dir"),
                        )?));
                }
                Some(value) if value.starts_with('-') => {
                    return Err(ExecutableConfigError::UnknownOption(argument));
                }
                _ => return Err(ExecutableConfigError::UnexpectedArgument(argument)),
            }
        }
        Ok(Self::MainMenu(MainMenuConfig {
            retail_dir: retail_dir.ok_or(ExecutableConfigError::MissingRetailDirectory)?,
            cache_dir,
        }))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ExecutableConfigError {
    MissingRetailDirectory,
    MissingOptionValue(&'static str),
    DuplicateOption(&'static str),
    UnknownOption(OsString),
    UnexpectedArgument(OsString),
    Viewer(ViewerConfigError),
}

impl fmt::Display for ExecutableConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRetailDirectory => {
                formatter.write_str("normal launch requires --retail-dir PATH")
            }
            Self::MissingOptionValue(option) => write!(formatter, "{option} requires a path"),
            Self::DuplicateOption(option) => {
                write!(formatter, "{option} may be supplied only once")
            }
            Self::UnknownOption(option) => write!(formatter, "unknown option {option:?}"),
            Self::UnexpectedArgument(argument) => write!(
                formatter,
                "unexpected argument {argument:?}; use the viewer subcommand for snapshots"
            ),
            Self::Viewer(error) => write!(formatter, "invalid viewer arguments: {error}"),
        }
    }
}

impl Error for ExecutableConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Viewer(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct PreparedMainMenu {
    retail_assets: ImportedRetailAssets,
    ui_catalog: UiCatalogV1,
}

pub fn prepare_main_menu(config: &MainMenuConfig) -> Result<PreparedMainMenu, MainMenuLoadError> {
    let cache_dir = match &config.cache_dir {
        Some(path) => path.clone(),
        None => default_retail_cache_dir().map_err(MainMenuLoadError::RetailAssets)?,
    };
    let retail_assets = import_english_gog_assets(&config.retail_dir, &cache_dir)
        .map_err(MainMenuLoadError::RetailAssets)?;
    let ui_catalog = serde_json::from_str::<UiCatalogV1>(COMPILED_UI_CATALOG)
        .map_err(UiCatalogError::Json)
        .map_err(MainMenuLoadError::UiCatalog)?;
    ui_catalog
        .validate()
        .map_err(MainMenuLoadError::UiCatalog)?;
    Ok(PreparedMainMenu {
        retail_assets,
        ui_catalog,
    })
}

#[derive(Debug)]
pub enum MainMenuLoadError {
    RetailAssets(RetailAssetImportError),
    UiCatalog(UiCatalogError),
}

impl fmt::Display for MainMenuLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RetailAssets(error) => error.fmt(formatter),
            Self::UiCatalog(error) => error.fmt(formatter),
        }
    }
}

impl Error for MainMenuLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RetailAssets(error) => Some(error),
            Self::UiCatalog(error) => Some(error),
        }
    }
}

#[derive(Resource)]
pub struct RetailAssetPackResource(ImportedRetailAssets);

impl RetailAssetPackResource {
    pub fn cache_root(&self) -> &Path {
        &self.0.cache_root
    }

    pub fn pack_dir(&self) -> &Path {
        &self.0.pack_dir
    }

    pub const fn manifest(&self) -> &RetailAssetPackManifestV1 {
        &self.0.manifest
    }
}

pub fn configure_main_menu_app(
    app: &mut App,
    prepared: PreparedMainMenu,
) -> Result<(), UiCatalogError> {
    let catalog = UiCatalogResource::new(prepared.ui_catalog)?;
    app.insert_resource(GameSession::pre_game())
        .insert_resource(catalog)
        .insert_resource(RetailAssetPackResource(prepared.retail_assets))
        .add_plugins((
            SessionPlugin,
            ScreenFlowPlugin,
            UiRuntimePlugin,
            StartupUiPlugin,
        ))
        .add_systems(Startup, enter_main_menu);
    Ok(())
}

pub fn build_main_menu_app(prepared: PreparedMainMenu) -> Result<App, UiCatalogError> {
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
    configure_main_menu_app(&mut app, prepared)?;
    Ok(app)
}

pub fn run_main_menu(prepared: PreparedMainMenu) -> Result<(), UiCatalogError> {
    build_main_menu_app(prepared)?.run();
    Ok(())
}

fn enter_main_menu(mut next_state: ResMut<NextState<AppState>>) {
    next_state.set(AppState::MainMenu);
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_formats::RETAIL_ASSET_PACK_SCHEMA;

    fn compiled_catalog() -> UiCatalogV1 {
        serde_json::from_str(COMPILED_UI_CATALOG).unwrap()
    }

    fn prepared() -> PreparedMainMenu {
        PreparedMainMenu {
            retail_assets: ImportedRetailAssets {
                cache_root: PathBuf::from("cache"),
                pack_dir: PathBuf::from("cache/packs/v1/test"),
                manifest: RetailAssetPackManifestV1 {
                    schema: RETAIL_ASSET_PACK_SCHEMA.to_owned(),
                    cache_key: "0".repeat(64),
                    logical_resolution: [640, 480],
                    bitmap_lookup_is_name_then_numeric: true,
                    sources: Vec::new(),
                    resources: Vec::new(),
                    strings: Vec::new(),
                    fonts: Vec::new(),
                    music: Vec::new(),
                },
            },
            ui_catalog: compiled_catalog(),
        }
    }

    #[test]
    fn normal_launch_requires_an_explicit_retail_directory() {
        assert_eq!(
            ExecutableMode::parse(Vec::<OsString>::new()).unwrap_err(),
            ExecutableConfigError::MissingRetailDirectory
        );
        let mode = ExecutableMode::parse([
            OsString::from("--retail-dir"),
            OsString::from("gog"),
            OsString::from("--cache-dir"),
            OsString::from("cache"),
        ])
        .unwrap();
        assert_eq!(
            mode,
            ExecutableMode::MainMenu(MainMenuConfig {
                retail_dir: PathBuf::from("gog"),
                cache_dir: Some(PathBuf::from("cache")),
            })
        );
    }

    #[test]
    fn snapshots_require_the_explicit_viewer_subcommand() {
        let ambiguous = ExecutableMode::parse([OsString::from("snapshot.json")]).unwrap_err();
        assert!(matches!(
            ambiguous,
            ExecutableConfigError::UnexpectedArgument(_)
        ));
        let viewer = ExecutableMode::parse([
            OsString::from("viewer"),
            OsString::from("snapshot.json"),
            OsString::from("--assets"),
            OsString::from("assets"),
        ])
        .unwrap();
        assert_eq!(
            viewer,
            ExecutableMode::SnapshotViewer(ViewerConfig {
                snapshot: PathBuf::from("snapshot.json"),
                asset_manifest: PathBuf::from("assets/manifest.json"),
            })
        );
    }

    #[test]
    fn missing_retail_inputs_fail_during_preparation() {
        let config = MainMenuConfig {
            retail_dir: std::env::temp_dir().join(format!(
                "imperialism-app-missing-retail-{}",
                std::process::id()
            )),
            cache_dir: Some(std::env::temp_dir()),
        };

        let error = prepare_main_menu(&config).unwrap_err();

        assert!(matches!(error, MainMenuLoadError::RetailAssets(_)));
    }

    #[test]
    fn headless_wiring_enters_main_menu_with_required_resources() {
        let mut app = App::new();
        app.add_plugins(bevy::state::app::StatesPlugin);
        configure_main_menu_app(&mut app, prepared()).unwrap();
        app.update();
        app.update();

        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::MainMenu
        );
        assert!(app.world().resource::<GameSession>().is_pre_game());
        assert!(app.world().contains_resource::<UiCatalogResource>());
        assert!(app.world().contains_resource::<RetailAssetPackResource>());
    }
}
