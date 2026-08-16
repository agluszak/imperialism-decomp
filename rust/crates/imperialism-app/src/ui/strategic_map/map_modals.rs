//! Map-triggered recovered report/roster/garrison dialogs.

use crate::AppState;
use crate::ui::generated;
use crate::ui::retail::{ModalDialog, RetailTree};
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::prelude::*;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::ProvinceId;
use imperialism_formats::fourcc;

#[derive(Component)]
struct MapModal;

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        bind_added_map_modals.run_if(in_state(AppState::StrategicMap)),
    );
}

pub(crate) fn spawn_garrison(commands: &mut Commands, _province: ProvinceId) {
    let root = commands.spawn_scene(generated::mapview_3500()).id();
    spawn_modal(commands, root);
}

pub(crate) fn spawn_army_report(commands: &mut Commands, _province: ProvinceId) {
    let root = commands.spawn_scene(generated::mapview_3100()).id();
    spawn_modal(commands, root);
}

pub(crate) fn spawn_fleet_report(commands: &mut Commands, friendly: bool) {
    let root = if friendly {
        commands.spawn_scene(generated::mapview_9474()).id()
    } else {
        commands.spawn_scene(generated::mapview_9475()).id()
    };
    spawn_modal(commands, root);
}

pub(crate) fn spawn_navy_roster(commands: &mut Commands) {
    let root = commands.spawn_scene(generated::mapview_9478()).id();
    spawn_modal(commands, root);
}

pub(crate) fn spawn_army_roster(commands: &mut Commands) {
    let root = commands.spawn_scene(generated::mapview_9460()).id();
    spawn_modal(commands, root);
}

#[allow(dead_code)]
pub(crate) fn spawn_combat_report(commands: &mut Commands) {
    let root = commands.spawn_scene(generated::mapview_1350()).id();
    spawn_modal(commands, root);
}

fn spawn_modal(commands: &mut Commands, root: Entity) {
    commands
        .entity(root)
        .insert((MapModal, ModalDialog, TabGroup::modal(), GlobalZIndex(30)));
}

fn bind_added_map_modals(
    mut commands: Commands,
    added: Query<Entity, Added<MapModal>>,
    tree: RetailTree,
) {
    for root in &added {
        for tag in [fourcc!("okay"), fourcc!("end ")] {
            if let Some(entity) = tree.try_find(root, tag) {
                commands
                    .entity(entity)
                    .insert(ActivateOnPress)
                    .observe(on_map_modal_close);
            }
        }
    }
}

fn on_map_modal_close(
    activate: On<Activate>,
    mut commands: Commands,
    child_of: Query<&ChildOf>,
    modals: Query<Entity, With<MapModal>>,
) {
    let mut entity = activate.entity;
    for _ in 0..8 {
        if modals.contains(entity) {
            commands.entity(entity).despawn();
            return;
        }
        let Ok(parent) = child_of.get(entity) else {
            return;
        };
        entity = parent.parent();
    }
}
