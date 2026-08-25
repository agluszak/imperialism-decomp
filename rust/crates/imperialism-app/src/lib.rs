#![forbid(unsafe_code)]

mod fonts;
mod media;
mod ui;

use bevy::input_focus::tab_navigation::TabNavigationPlugin;
use bevy::prelude::*;
use bevy::window::WindowPlugin;
use imperialism_core::{GameData, RandomGameNames};
use imperialism_formats::{LoadedGame, RetailAssets};
use std::path::PathBuf;

pub(crate) use fonts::{RetailFont, RetailFonts};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, States)]
pub(crate) enum AppState {
    #[default]
    MainMenu,
    RandomSetup,
    ScenarioSetup,
    CitySite,
    TownNaming,
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
}

/// Screen restored when closing Deal Book opened from another game screen.
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

    /// `TSimMgr::GetString`: adds one before the direct lookup.
    pub(crate) fn get_string(&self, group: i16, offset: i16) -> String {
        self.string(group, offset + 1)
            .expect("retail hover-help string")
    }
}

#[derive(Resource)]
pub(crate) struct RandomGameNamesResource(pub(crate) RandomGameNames);

fn add_game_plugins(app: &mut App) {
    app.add_plugins(ui::UiWindowPlugin)
        .add_plugins((
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
            ui::ScenarioSetupPlugin,
            ui::TownNamingPlugin,
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
    if let Some(mut loaded) = initial_game {
        assert_eq!(
            loaded.game.turn().phase(),
            imperialism_core::PhaseCode::STRATEGIC_MAP,
            "Bevy may only start from a strategic-map core phase"
        );
        loaded.game.set_game_data(GameData::from_news_story_ids(
            retail_assets.news_table().story_ids().to_vec(),
        ));
        ui::insert_loaded_game_world(app.world_mut(), loaded);
        app.insert_state(AppState::StrategicMap);
    } else {
        app.insert_state(AppState::OpeningCinematic);
    }
    app.insert_resource(RetailAssetsResource::new(retail_assets))
        .insert_resource(RandomGameNamesResource(random_game_names))
        .insert_resource(ui::SaveDirectory(save_directory));
    add_game_plugins(&mut app);
    let retail_fonts =
        app.world_mut()
            .resource_scope(|world, mut font_assets: Mut<Assets<Font>>| {
                RetailFonts::load(
                    world.resource::<RetailAssetsResource>().assets(),
                    &mut font_assets,
                )
            })?;
    app.insert_resource(retail_fonts);
    app.world_mut()
        .spawn((Camera2d, Msaa::Off, UiAntiAlias::Off));
    app.run();
    Ok(())
}
