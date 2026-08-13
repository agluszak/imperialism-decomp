#![forbid(unsafe_code)]

mod ui;

use bevy::input_focus::tab_navigation::TabNavigationPlugin;
use bevy::prelude::*;
use bevy::window::WindowPlugin;
use imperialism_core::{GameState, RandomGameNames};
use imperialism_formats::RetailAssets;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, States)]
pub(crate) enum AppState {
    #[default]
    MainMenu,
    RandomSetup,
    LoadGame,
    SaveGame,
    CitySite,
    StrategicMap,
    Trade,
    City,
    Transport,
    Diplomacy,
    DealBook,
    OfferSheet,
    TechnologyAdvance,
    Newspaper,
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

    pub(crate) fn string(
        &self,
        group: i16,
        direct_index: i16,
    ) -> Result<String, imperialism_formats::RetailAssetError> {
        self.0.string(group, direct_index)
    }

    /// `TSimMgr::GetString`: adds one before the direct lookup.
    pub(crate) fn get_string(&self, group: i16, offset: i16) -> String {
        self.string(group, offset + 1)
            .expect("retail hover-help string")
    }
}

#[derive(Resource)]
pub(crate) struct RandomGameNamesResource(pub(crate) RandomGameNames);

pub fn run(
    retail_assets: RetailAssets,
    initial_game: Option<GameState>,
    save_directory: PathBuf,
) -> anyhow::Result<()> {
    let random_game_names = retail_assets.random_game_names()?;
    let logical_resolution = ui::generated::LOGICAL_RESOLUTION;
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
    app.insert_resource(RetailAssetsResource::new(retail_assets))
        .insert_resource(RandomGameNamesResource(random_game_names))
        .insert_resource(ui::SaveDirectory(save_directory));
    if let Some(game) = initial_game {
        assert_eq!(
            game.turn().phase(),
            imperialism_core::PhaseCode::STRATEGIC_MAP,
            "Bevy may only start from a strategic-map core phase"
        );
        app.insert_resource(ui::GameSession(game))
            .insert_state(AppState::StrategicMap);
    } else {
        app.init_state::<AppState>();
    }
    app.add_plugins((
        TabNavigationPlugin,
        ui::RetailUiPlugin,
        ui::QueryFloaterPlugin,
        ui::MainMenuPlugin,
        ui::LoadSavePlugin,
        ui::RandomSetupPlugin,
        ui::MapPreviewPlugin,
        ui::CitySitePlugin,
        ui::GameShellPlugin,
        ui::CityPlugin,
        ui::TransportPlugin,
        ui::TradePlugin,
        ui::DiplomacyPlugin,
        ui::DealBookPlugin,
        ui::OfferSheetPlugin,
    ))
    .add_plugins((ui::TechnologyAdvancePlugin, ui::NewspaperPlugin));
    app.world_mut()
        .spawn((Camera2d, Msaa::Off, UiAntiAlias::Off));
    app.run();
    Ok(())
}
