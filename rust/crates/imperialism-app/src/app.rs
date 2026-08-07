use crate::flow::{AppState, ScreenFlowPlugin};
use crate::input::GameInputPlugin;
use crate::session::{GameSession, SessionPlugin};
use crate::strategic_map::{
    PresentedAssets, PresentedLayout, StrategicMapLayout, StrategicMapPlugin,
};
use crate::ui::UiRuntimePlugin;
use bevy::prelude::*;
use bevy::window::WindowPlugin;
use imperialism_core::{GameState, STRATEGIC_MAP_HEIGHT, STRATEGIC_MAP_WIDTH};
use imperialism_formats::{
    AssetManifestError, NormalizedAssetManifestV1, SnapshotReadError, game_state_from_snapshot,
    read_game_snapshot, read_normalized_asset_manifest,
};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewerConfig {
    pub snapshot: PathBuf,
    pub asset_manifest: PathBuf,
}

impl ViewerConfig {
    pub fn usage() -> &'static str {
        "usage: imperialism-app viewer SNAPSHOT.json [--assets ASSET_PACK]\n\
         \n\
         ASSET_PACK defaults to imported-assets and must contain manifest.json."
    }

    pub fn parse(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Option<Self>, ViewerConfigError> {
        let mut snapshot = None;
        let mut asset_pack = PathBuf::from("imported-assets");
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            if argument == "--help" || argument == "-h" {
                return Ok(None);
            }
            if argument == "--assets" {
                asset_pack = PathBuf::from(
                    arguments
                        .next()
                        .ok_or(ViewerConfigError::MissingAssetPack)?,
                );
                continue;
            }
            if argument.to_string_lossy().starts_with('-') {
                return Err(ViewerConfigError::UnknownOption(argument));
            }
            if snapshot.replace(PathBuf::from(argument)).is_some() {
                return Err(ViewerConfigError::MultipleSnapshots);
            }
        }
        let snapshot = snapshot.ok_or(ViewerConfigError::MissingSnapshot)?;
        Ok(Some(Self {
            snapshot,
            asset_manifest: asset_pack.join("manifest.json"),
        }))
    }
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum ViewerConfigError {
    #[error("missing canonical snapshot path")]
    MissingSnapshot,
    #[error("--assets requires a directory")]
    MissingAssetPack,
    #[error("only one snapshot may be viewed")]
    MultipleSnapshots,
    #[error("unknown option {0:?}")]
    UnknownOption(OsString),
}

#[derive(Debug, thiserror::Error)]
pub enum ViewerLoadError {
    #[error(transparent)]
    Snapshot(#[from] SnapshotReadError),
    #[error(transparent)]
    Assets(#[from] AssetManifestError),
    #[error("cannot present snapshot: {0}")]
    Presentation(String),
}

pub struct ViewerInput {
    game: GameState,
    assets: NormalizedAssetManifestV1,
}

pub fn load_viewer(config: &ViewerConfig) -> Result<ViewerInput, ViewerLoadError> {
    let snapshot = read_game_snapshot(&config.snapshot)?;
    let game = game_state_from_snapshot(snapshot).map_err(SnapshotReadError::Validation)?;
    let assets =
        read_normalized_asset_manifest(&config.asset_manifest).map_err(ViewerLoadError::Assets)?;
    validate_presentation(&game, &assets)?;
    Ok(ViewerInput { game, assets })
}

fn validate_presentation(
    game: &GameState,
    assets: &NormalizedAssetManifestV1,
) -> Result<(), ViewerLoadError> {
    if game.world.width != STRATEGIC_MAP_WIDTH || game.world.height != STRATEGIC_MAP_HEIGHT {
        return Err(ViewerLoadError::Presentation(format!(
            "expected a {}x{} strategic map, found {}x{}",
            STRATEGIC_MAP_WIDTH, STRATEGIC_MAP_HEIGHT, game.world.width, game.world.height
        )));
    }
    for (index, tile) in game.world.tiles.iter().enumerate() {
        let terrain = usize::try_from(tile.terrain_kind).map_err(|_| {
            ViewerLoadError::Presentation(format!(
                "tile {index} has negative terrain kind {}",
                tile.terrain_kind
            ))
        })?;
        if terrain >= assets.strategic_map.terrain_palette.len() {
            return Err(ViewerLoadError::Presentation(format!(
                "tile {index} terrain kind {terrain} is absent from the asset palette"
            )));
        }
    }
    Ok(())
}

pub fn run_viewer(input: ViewerInput) {
    let logical_resolution = input.assets.logical_resolution;
    let layout = StrategicMapLayout::new(&input.assets.strategic_map);
    App::new()
        .insert_resource(ClearColor(Color::srgb_u8(18, 18, 20)))
        .insert_resource(GameSession::new(input.game))
        .insert_resource(PresentedAssets(input.assets))
        .insert_resource(PresentedLayout(layout))
        .add_plugins(
            DefaultPlugins
                .set(ImagePlugin::default_nearest())
                .set(WindowPlugin {
                    primary_window: Some(Window {
                        title: "Imperialism strategic-map snapshot".to_owned(),
                        resolution: (logical_resolution[0], logical_resolution[1]).into(),
                        ..default()
                    }),
                    ..default()
                }),
        )
        .add_plugins((
            SessionPlugin,
            ScreenFlowPlugin,
            UiRuntimePlugin,
            StrategicMapPlugin,
            GameInputPlugin,
        ))
        .add_systems(Startup, enter_viewer_state)
        .run();
}

fn enter_viewer_state(mut next_state: ResMut<NextState<AppState>>) {
    next_state.set(AppState::InGame);
}

pub fn example_asset_manifest_path() -> &'static Path {
    Path::new("assets.example/manifest.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_snapshot_and_asset_pack_paths() {
        let config = ViewerConfig::parse([
            OsString::from("snapshot.json"),
            OsString::from("--assets"),
            OsString::from("local-assets"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(config.snapshot, Path::new("snapshot.json"));
        assert_eq!(
            config.asset_manifest,
            Path::new("local-assets/manifest.json")
        );
    }
}
