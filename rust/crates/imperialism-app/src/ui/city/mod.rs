use super::GameSession;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::retail::{ModalDialog, RetailTree, RetailUiAssets};
use crate::*;
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::log::warn;
use bevy::picking::events::{Click, Drag, Pointer, Press};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, Button as UiButton, ValueChange};
use enum_map::Enum;
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

pub(in crate::ui::city) fn city_projection_idle(session: &Res<GameSession>, added: bool) -> bool {
    super::projection_idle(session, added)
}

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
                sync_city_row_selection,
                sync_armory_details,
                sync_university_details,
                sync_shipyard_details,
            )
                .run_if(in_state(AppState::City)),
        )
        .add_observer(on_city_dialog_pressed.run_if(in_state(AppState::City)))
        .add_observer(on_city_canvas_click.run_if(in_state(AppState::City)))
        .add_observer(on_city_row_selected.run_if(in_state(AppState::City)))
        .add_observer(on_city_recruitment_order_selected.run_if(in_state(AppState::City)))
        .add_observer(on_city_amount_bar_click.run_if(in_state(AppState::City)))
        .add_observer(on_city_expansion_open.run_if(in_state(AppState::City)))
        .add_observer(on_city_building_change_choice.run_if(in_state(AppState::City)))
        .add_observer(on_city_order_adjust.run_if(in_state(AppState::City)));
    }
}
