use super::catalog::*;
use super::format_currency;
use super::game_shell::*;
use super::random_setup::GameSession;
use crate::*;
use bevy::log::warn;
use bevy::picking::events::{Click, Drag, Pointer, Press};
use bevy::prelude::*;
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

use bindings::*;
use building_visuals::*;
use common_controls::*;
use dialogs::*;
use input::*;
use lifecycle::*;

pub(crate) struct CityPlugin;

impl Plugin for CityPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(OnEnter(AppState::City), enter_city_screen)
            .add_systems(OnExit(AppState::City), leave_city_screen)
            .add_systems(
                Update,
                animate_city_building_actions.run_if(in_state(AppState::City)),
            )
            .add_systems(
                Update,
                (
                    restore_city_dialogs,
                    sync_city_screen,
                    sync_industry_dialog,
                    sync_warehouse_dialog,
                    sync_food_dialog,
                    sync_power_dialog,
                    sync_transport_capacity_dialog,
                    sync_population_dialog,
                    sync_training_dialog,
                    sync_armory_dialog,
                    sync_university_dialog,
                    sync_shipyard_dialog,
                )
                    .chain()
                    .run_if(in_state(AppState::City)),
            )
            .add_observer(on_city_dialog_pressed.run_if(in_state(AppState::City)))
            .add_observer(on_city_dialog_dragged.run_if(in_state(AppState::City)))
            .add_observer(on_city_dialog_close.run_if(in_state(AppState::City)))
            .add_observer(on_city_canvas_click.run_if(in_state(AppState::City)))
            .add_observer(on_armory_row_selected.run_if(in_state(AppState::City)))
            .add_observer(on_university_row_selected.run_if(in_state(AppState::City)))
            .add_observer(on_shipyard_row_selected.run_if(in_state(AppState::City)))
            .add_observer(on_armory_order_selected.run_if(in_state(AppState::City)))
            .add_observer(on_university_order_selected.run_if(in_state(AppState::City)))
            .add_observer(on_shipyard_order_selected.run_if(in_state(AppState::City)))
            .add_observer(on_city_amount_bar_click.run_if(in_state(AppState::City)))
            .add_observer(on_city_expansion_open.run_if(in_state(AppState::City)))
            .add_observer(on_city_building_change_choice.run_if(in_state(AppState::City)))
            .add_observer(on_city_order_adjust.run_if(in_state(AppState::City)));
    }
}

#[cfg(test)]
mod tests;
