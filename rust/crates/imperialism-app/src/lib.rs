#![forbid(unsafe_code)]

mod ui;

use bevy::input_focus::tab_navigation::TabNavigationPlugin;
use bevy::prelude::*;
use bevy::window::WindowPlugin;
use imperialism_formats::{RetailAssets, UiCatalog};

const COMPILED_UI_CATALOG: &str = include_str!("../../imperialism-formats/assets/ui_catalog.json");

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, States)]
pub(crate) enum AppState {
    #[default]
    MainMenu,
    RandomSetup,
    CitySite,
    StrategicMap,
    Trade,
    City,
    Transport,
    Diplomacy,
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
    let ui_catalog = ui::UiCatalogResource::new(ui_catalog)
        .expect("compiled UI catalog must be structurally valid");
    ui::validate_application_bindings(&ui_catalog)
        .expect("compiled UI catalog must contain every application binding");
    app.insert_resource(ui_catalog)
        .insert_resource(RetailAssetsResource::new(retail_assets))
        .init_state::<AppState>()
        .add_plugins((
            TabNavigationPlugin,
            ui::UiCatalogPlugin,
            ui::MainMenuPlugin,
            ui::RandomSetupPlugin,
            ui::MapPreviewPlugin,
            ui::CitySitePlugin,
            ui::GameShellPlugin,
            ui::CityPlugin,
            ui::TransportPlugin,
            ui::TradePlugin,
        ));
    app.world_mut().spawn(Camera2d);
    app.run();
}
