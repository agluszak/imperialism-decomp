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

fn add_game_plugins(app: &mut App) {
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
}

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
    add_game_plugins(&mut app);
    app.world_mut()
        .spawn((Camera2d, Msaa::Off, UiAntiAlias::Off));
    app.run();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevy::ecs::schedule::{ScheduleLabel, Schedules};

    fn initialize_schedule(app: &mut App, label: impl ScheduleLabel + Clone) {
        if app.world().resource::<Schedules>().contains(label.clone()) {
            app.world_mut()
                .schedule_scope(label, |world, schedule| schedule.initialize(world))
                .expect("game schedules must initialize before opening a window");
        }
    }

    #[test]
    fn game_schedules_initialize_without_system_parameter_conflicts() {
        let mut app = App::new();
        app.add_plugins(bevy::state::app::StatesPlugin)
            .init_state::<AppState>();
        add_game_plugins(&mut app);

        initialize_schedule(&mut app, Update);
        for state in [
            AppState::MainMenu,
            AppState::RandomSetup,
            AppState::LoadGame,
            AppState::SaveGame,
            AppState::CitySite,
            AppState::StrategicMap,
            AppState::Trade,
            AppState::City,
            AppState::Transport,
            AppState::Diplomacy,
            AppState::DealBook,
            AppState::OfferSheet,
            AppState::TechnologyAdvance,
            AppState::Newspaper,
        ] {
            initialize_schedule(&mut app, OnEnter(state));
            initialize_schedule(&mut app, OnExit(state));
        }
    }
}
