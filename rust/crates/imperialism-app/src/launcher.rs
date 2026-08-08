use crate::audio::RetailAudioPlugin;
use crate::session::{GameSession, SessionPlugin};
use crate::ui::{StartupUiPlugin, UiCatalogResource, UiRuntimePlugin};
use bevy::prelude::*;
use bevy::window::WindowPlugin;
use clap::Parser;
use imperialism_formats::{
    ImportedRetailAssets, RetailAssetImportError, RetailAssetPackManifest, UiCatalog,
    UiCatalogError, default_retail_cache_dir, import_english_gog_assets,
};
use std::path::{Path, PathBuf};

const COMPILED_UI_CATALOG: &str = include_str!("../../imperialism-formats/assets/ui_catalog.json");

#[derive(Clone, Debug, Eq, Parser, PartialEq)]
#[command(
    name = "imperialism-app",
    about = "Launch Imperialism from an English GOG installation."
)]
pub struct MainMenuConfig {
    #[arg(long)]
    pub retail_dir: PathBuf,
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,
}

#[derive(Debug)]
pub struct PreparedMainMenu {
    retail_assets: ImportedRetailAssets,
    ui_catalog: UiCatalog,
}

pub fn prepare_main_menu(config: &MainMenuConfig) -> Result<PreparedMainMenu, MainMenuLoadError> {
    let cache_dir = match &config.cache_dir {
        Some(path) => path.clone(),
        None => default_retail_cache_dir().map_err(MainMenuLoadError::RetailAssets)?,
    };
    let retail_assets = import_english_gog_assets(&config.retail_dir, &cache_dir)
        .map_err(MainMenuLoadError::RetailAssets)?;
    let ui_catalog = serde_json::from_str::<UiCatalog>(COMPILED_UI_CATALOG)
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

#[derive(Debug, thiserror::Error)]
pub enum MainMenuLoadError {
    #[error(transparent)]
    RetailAssets(#[from] RetailAssetImportError),
    #[error(transparent)]
    UiCatalog(#[from] UiCatalogError),
}

#[derive(Resource)]
pub struct RetailAssetPackResource(ImportedRetailAssets);

impl RetailAssetPackResource {
    #[cfg(test)]
    pub(crate) fn new(imported: ImportedRetailAssets) -> Self {
        Self(imported)
    }

    pub fn cache_root(&self) -> &Path {
        &self.0.cache_root
    }

    pub fn pack_dir(&self) -> &Path {
        &self.0.pack_dir
    }

    pub const fn manifest(&self) -> &RetailAssetPackManifest {
        &self.0.manifest
    }

    pub(crate) fn object_path(&self, object: &imperialism_formats::CachedRetailObject) -> PathBuf {
        self.0.object_path(object)
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
            UiRuntimePlugin,
            StartupUiPlugin,
            RetailAudioPlugin,
        ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    fn compiled_catalog() -> UiCatalog {
        serde_json::from_str(COMPILED_UI_CATALOG).unwrap()
    }

    fn prepared() -> PreparedMainMenu {
        PreparedMainMenu {
            retail_assets: ImportedRetailAssets {
                cache_root: PathBuf::from("cache"),
                pack_dir: PathBuf::from("cache/packs/test"),
                manifest: RetailAssetPackManifest {
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
            MainMenuConfig::try_parse_from(["imperialism-app"])
                .unwrap_err()
                .kind(),
            ErrorKind::MissingRequiredArgument
        );
        let config = MainMenuConfig::try_parse_from([
            "imperialism-app",
            "--retail-dir",
            "gog",
            "--cache-dir",
            "cache",
        ])
        .unwrap();
        assert_eq!(
            config,
            MainMenuConfig {
                retail_dir: PathBuf::from("gog"),
                cache_dir: Some(PathBuf::from("cache")),
            }
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
        configure_main_menu_app(&mut app, prepared()).unwrap();
        app.update();
        app.update();

        assert!(
            app.world()
                .resource::<crate::ui::StartupScreenInstances>()
                .main_menu()
                .is_some()
        );
        assert!(app.world().resource::<GameSession>().is_pre_game());
        assert!(app.world().contains_resource::<UiCatalogResource>());
        assert!(app.world().contains_resource::<RetailAssetPackResource>());
    }
}
