use super::GameSession;
use super::format_currency;
use super::game_shell::{bind_native_game_screen_nav, project_date_and_treasury};
use super::generated;
use super::retail::{ModalDialog, RetailUiAssets};
use super::retail::{RetailTag, find_descendant};
use crate::*;
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::log::warn;
use bevy::picking::events::{Click, Drag, Pointer, Press};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, Button as UiButton, ValueChange};
use imperialism_core::*;
use imperialism_formats::*;
use std::time::Duration;

mod bindings;
mod building_visuals;
mod common_controls;
mod dialogs;
mod input;
mod lifecycle;

pub(super) use building_visuals::{CityBuildingActionVisual, CityBuildingVisual};

use bindings::*;
use building_visuals::*;
use common_controls::*;
use dialogs::*;
use input::*;
use lifecycle::*;

pub(crate) struct CityPlugin;

impl Plugin for CityPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::City),
            (enter_city_screen, bind_city_screen).chain(),
        )
        .add_systems(OnExit(AppState::City), leave_city_screen)
        .add_systems(
            Update,
            animate_city_building_actions.run_if(in_state(AppState::City)),
        )
        .add_systems(
            Update,
            (
                restore_city_dialogs,
                bind_building_change_dialogs,
                bind_city_dialogs,
            )
                .chain()
                .run_if(in_state(AppState::City)),
        )
        .add_systems(
            Update,
            (
                sync_city_summary,
                sync_city_hover_title,
                sync_city_buildings,
                sync_city_order_quantities,
                sync_industry_texts,
                sync_industry_indicators,
                sync_industry_bars,
                sync_warehouse_dialog,
                sync_food_dialog,
                sync_transport_capacity_dialog,
                sync_population_dialog,
                sync_training_dialog,
                sync_armory_selection,
                sync_armory_details,
                sync_university_selection,
                sync_university_details,
                sync_shipyard_selection,
                sync_shipyard_details,
            )
                .run_if(in_state(AppState::City)),
        )
        .add_observer(on_city_dialog_pressed.run_if(in_state(AppState::City)));
    }
}
