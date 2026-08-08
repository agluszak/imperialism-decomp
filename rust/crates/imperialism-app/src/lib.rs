#![forbid(unsafe_code)]

mod ui;

use bevy::prelude::*;
use bevy::window::WindowPlugin;
use imperialism_formats::{RetailAssets, UiCatalog};

const COMPILED_UI_CATALOG: &str = include_str!("../../imperialism-formats/assets/ui_catalog.json");

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, States)]
pub(crate) enum AppState {
    #[default]
    MainMenu,
    RandomSetup,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, SystemSet)]
pub(crate) enum GameLoopSet {
    TranslateUiIntents,
    UpdatePresentation,
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

pub fn run(retail_assets: RetailAssets) {
    let ui_catalog = serde_json::from_str::<UiCatalog>(COMPILED_UI_CATALOG)
        .expect("the compiled UI catalog must deserialize");

    let logical_resolution = ui_catalog.logical_resolution;
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
    app.insert_resource(ui::UiCatalogResource::new(ui_catalog))
        .insert_resource(RetailAssetsResource::new(retail_assets))
        .init_state::<AppState>()
        .configure_sets(
            Update,
            (
                GameLoopSet::TranslateUiIntents,
                GameLoopSet::UpdatePresentation,
            )
                .chain(),
        )
        .add_plugins((
            ui::UiRuntimePlugin,
            ui::StartupUiPlugin,
            ui::MapPreviewPlugin,
        ));
    app.world_mut().spawn(Camera2d);
    app.run();
}
