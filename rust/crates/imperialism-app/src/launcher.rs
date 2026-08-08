use crate::audio::RetailAudioPlugin;
use crate::flow::{AppState, ScreenFlowPlugin};
use crate::session::SessionPlugin;
use crate::ui::{StartupUiPlugin, UiCatalogResource, UiRuntimePlugin};
use bevy::prelude::*;
use bevy::window::WindowPlugin;
use imperialism_formats::{RetailAssets, UiCatalog};

const COMPILED_UI_CATALOG: &str = include_str!("../../imperialism-formats/assets/ui_catalog.json");

pub(crate) fn run(retail_assets: RetailAssets) {
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
    app.insert_resource(UiCatalogResource::new(ui_catalog))
        .insert_resource(RetailAssetsResource::new(retail_assets))
        .add_plugins((
            SessionPlugin,
            ScreenFlowPlugin,
            UiRuntimePlugin,
            StartupUiPlugin,
            RetailAudioPlugin,
        ))
        .add_systems(Startup, enter_main_menu)
        .run();
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

fn enter_main_menu(mut next_state: ResMut<NextState<AppState>>) {
    next_state.set(AppState::MainMenu);
}
