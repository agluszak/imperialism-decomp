use crate::AppState;
use crate::ui::catalog::{SpawnedView, UiCatalogResource, UiPictureResources, spawn_view};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, Button as UiButton};
use imperialism_formats::{ScopedViewId, UiView as CatalogView};

const STARTUP_RESOURCE_FILE: &str = "Startup.rsrc";
const CITY_SITE_RESOURCE_ID: i16 = 952;
const NEW_CITY_RESOURCE_ID: i16 = 953;

pub(crate) fn city_site_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: STARTUP_RESOURCE_FILE.to_owned(),
        resource_id: CITY_SITE_RESOURCE_ID,
    }
}

fn new_city_dialog_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: STARTUP_RESOURCE_FILE.to_owned(),
        resource_id: NEW_CITY_RESOURCE_ID,
    }
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum CitySiteAction {
    Cancel,
    OpenNewCity,
}

#[derive(Component)]
struct NewCityDialogRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum NewCityAction {
    Accept,
    Cancel,
}

pub(crate) struct CitySitePlugin;

impl Plugin for CitySitePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(OnEnter(AppState::CitySite), enter_city_site)
            .add_observer(on_city_site_activate)
            .add_observer(on_new_city_activate);
    }
}

fn enter_city_site(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut pictures: UiPictureResources,
) {
    let Some(spawned) = spawn_view(
        &mut commands,
        catalog.catalog(),
        &city_site_view_id(),
        &mut pictures,
    ) else {
        return;
    };
    let view = catalog
        .catalog()
        .views
        .iter()
        .find(|view| view.id == city_site_view_id())
        .expect("city site view was just spawned");
    bind_city_site_controls(&mut commands, view, &spawned);
    commands
        .entity(spawned.root)
        .insert(DespawnOnExit(AppState::CitySite));
}

fn bind_city_site_controls(commands: &mut Commands, view: &CatalogView, spawned: &SpawnedView) {
    if let Some(entity) = spawned.tagged(view, "canc") {
        commands
            .entity(entity)
            .insert((UiButton, CitySiteAction::Cancel))
            .remove::<InteractionDisabled>();
    }
    // `send` stays catalog-disabled until tile selection validates a site.
    let _ = (view, spawned, CitySiteAction::OpenNewCity);
}

fn on_city_site_activate(
    activate: On<Activate>,
    actions: Query<&CitySiteAction>,
    dialog_open: Query<(), With<NewCityDialogRoot>>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut pictures: UiPictureResources,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    if !dialog_open.is_empty() {
        return;
    }
    match *action {
        CitySiteAction::Cancel => next_state.set(AppState::RandomSetup),
        CitySiteAction::OpenNewCity => {
            open_new_city_dialog(&mut commands, &catalog, &mut pictures);
        }
    }
}

fn open_new_city_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    pictures: &mut UiPictureResources,
) {
    let Some(spawned) = spawn_view(
        commands,
        catalog.catalog(),
        &new_city_dialog_view_id(),
        pictures,
    ) else {
        return;
    };
    let view = catalog
        .catalog()
        .views
        .iter()
        .find(|view| view.id == new_city_dialog_view_id())
        .expect("new city dialog was just spawned");
    commands
        .entity(spawned.root)
        .insert((NewCityDialogRoot, ZIndex(10), Pickable::default()));
    if let Some(okay) = spawned.tagged(view, "okay") {
        commands
            .entity(okay)
            .insert((UiButton, NewCityAction::Accept))
            .remove::<InteractionDisabled>();
    }
    if let Some(cancel) = spawned.tagged(view, "cncl") {
        commands
            .entity(cancel)
            .insert((UiButton, NewCityAction::Cancel))
            .remove::<InteractionDisabled>();
    }
}

fn on_new_city_activate(
    activate: On<Activate>,
    actions: Query<&NewCityAction>,
    dialogs: Query<Entity, With<NewCityDialogRoot>>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    match *action {
        NewCityAction::Accept => {
            for root in &dialogs {
                commands.entity(root).despawn();
            }
            next_state.set(AppState::StrategicMap);
        }
        NewCityAction::Cancel => {
            for root in &dialogs {
                commands.entity(root).despawn();
            }
        }
    }
}
