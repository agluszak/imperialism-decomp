#![forbid(unsafe_code)]

mod media;
mod ui;

use bevy::input_focus::tab_navigation::TabNavigationPlugin;
use bevy::prelude::*;
use bevy::window::WindowPlugin;
use imperialism_core::RandomGameNames;
use imperialism_formats::{LoadedGame, RetailAssets};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, States)]
pub(crate) enum AppState {
    #[default]
    MainMenu,
    RandomSetup,
    LoadSave,
    CitySite,
    StrategicMap,
    Trade,
    City,
    Transport,
    Diplomacy,
    DealBook,
    OfferSheet,
    TechnologyAdvance,
    TechnologyStore,
    Newspaper,
    LandBattle,
    NavalBattle,
    OpeningCinematic,
    CouncilOfGovernors,
    BattleReport,
    GameScore,
    HighScore,
    Credits,
    Preferences,
}

/// Screen restored when leaving an overlay such as Credits, Preferences,
/// Load/Save, or Deal Book.
#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReturnTo(pub(crate) AppState);

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

    pub(crate) fn text(
        &self,
        resource_id: u16,
    ) -> Result<String, imperialism_formats::RetailAssetError> {
        self.0.text(resource_id)
    }

    pub(crate) fn catalog_string(&self, string: imperialism_formats::RetailString) -> String {
        let id = imperialism_formats::retail_string(string);
        self.string(id.group, id.index)
            .unwrap_or_else(|_| panic!("retail string {:#x}:{} must load", id.group, id.index))
    }

    /// `TSimMgr::GetString`: adds one before the direct lookup.
    pub(crate) fn get_string(&self, group: i16, offset: i16) -> String {
        self.string(group, offset + 1)
            .expect("retail hover-help string")
    }

    pub(crate) fn news_story_ids(&self) -> &[i32] {
        self.0.news_table().story_ids()
    }
}

#[derive(Resource)]
pub(crate) struct RandomGameNamesResource(pub(crate) RandomGameNames);

fn add_game_plugins(app: &mut App) {
    app.add_plugins((
        TabNavigationPlugin,
        ui::RetailUiPlugin,
        ui::RetailViewportPlugin,
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
    ))
    .add_plugins((
        media::ImperialismMediaPlugin,
        ui::CursorPlugin,
        ui::TechnologyAdvancePlugin,
        ui::TechnologyStorePlugin,
        ui::NewspaperPlugin,
        ui::LandBattlePlugin,
        ui::NavalBattlePlugin,
        ui::EndgamePlugin,
        ui::BattleReportPlugin,
        ui::CreditsPlugin,
        ui::PreferencesPlugin,
        ui::OfferSheetPlugin,
    ));
}

pub fn run(
    retail_assets: RetailAssets,
    initial_game: Option<LoadedGame>,
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
                    decorations: false,
                    ..default()
                }),
                ..default()
            }),
    );
    if let Some(loaded) = initial_game {
        assert_eq!(
            loaded.game.turn().phase(),
            imperialism_core::PhaseCode::STRATEGIC_MAP,
            "Bevy may only start from a strategic-map core phase"
        );
        app.insert_resource(ui::GameSession::from_loaded(loaded))
            .insert_state(AppState::StrategicMap);
    } else {
        app.insert_state(AppState::OpeningCinematic);
    }
    app.insert_resource(RetailAssetsResource::new(retail_assets))
        .insert_resource(RandomGameNamesResource(random_game_names))
        .insert_resource(ui::SaveDirectory(save_directory));
    add_game_plugins(&mut app);
    app.world_mut()
        .spawn((Camera2d, Msaa::Off, UiAntiAlias::Off));
    app.run();
    Ok(())
}
