use crate::AppState;
use crate::RetailAssetsResource;
use crate::ui::catalog::{ModalDialog, UiAssetResources, UiCatalogResource, UiSpawner, spawn_view};
use crate::ui::random_setup::GameSession;
use crate::ui::random_setup_map::{
    compose_owner_preview_indices, preview_image_from_indices, tile_at_preview_position,
};
use bevy::log::warn;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::RelativeCursorPosition;
use bevy::ui_widgets::Activate;
use imperialism_core::{
    MajorNationId, TileId, confirm_capital_site, validate_capital_site_selection,
};
use imperialism_formats::ScopedViewId;

const STARTUP_RESOURCE_FILE: &str = "Startup.rsrc";
const CITY_SITE_RESOURCE_ID: i16 = 952;
const NEW_CITY_RESOURCE_ID: i16 = 953;
const MAP_TAG: &str = "DLOG";

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
}

#[derive(Component)]
struct CitySiteMap {
    palette_indices: Vec<imperialism_formats::PaletteIndex>,
}

#[derive(Component)]
struct NewCityDialogRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum NewCityAction {
    Accept,
    Cancel,
}

/// Pending town tile filled by a validated map click before `ShowNewCityDialog`.
#[derive(Resource, Clone, Copy, Debug, Eq, PartialEq)]
struct PendingCapitalSite {
    tile: TileId,
}

pub(crate) struct CitySitePlugin;

impl Plugin for CitySitePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(OnEnter(AppState::CitySite), enter_city_site)
            .add_systems(
                Update,
                render_city_site_map.run_if(in_state(AppState::CitySite)),
            )
            .add_observer(on_city_site_activate)
            .add_observer(on_city_site_map_click)
            .add_observer(on_new_city_activate);
    }
}

fn enter_city_site(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut assets: UiAssetResources,
) {
    let Some(view) = catalog.view(&city_site_view_id()) else {
        return;
    };
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut assets);
    bind_city_site_controls(&mut commands, &catalog, &spawned);
    commands
        .entity(spawned.root)
        .insert(DespawnOnExit(AppState::CitySite));
}

fn bind_city_site_controls(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &crate::ui::catalog::SpawnedView,
) {
    if let Ok(entity) = spawned.require_unique(catalog, "canc") {
        commands.entity(entity).insert(CitySiteAction::Cancel);
    }
    // Retail opens the New City dialog from a validated map click, not from `send`.
    if let Ok(entity) = spawned.require_unique(catalog, MAP_TAG) {
        commands.entity(entity).insert(CitySiteMap {
            palette_indices: Vec::new(),
        });
    }
}

fn render_city_site_map(
    mut commands: Commands,
    session: Res<GameSession>,
    retail_assets: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut maps: Query<(Entity, &mut CitySiteMap, Option<&mut ImageNode>)>,
) {
    let selected = MajorNationId::from_nation(session.0.turn.active_nation)
        .unwrap_or_else(|| MajorNationId::new(0));
    let owners: Vec<i8> = session
        .0
        .world
        .tiles
        .iter()
        .map(|tile| {
            tile.owner_nation
                .map(|owner| i8::try_from(owner.get()).unwrap_or(-1))
                .unwrap_or(-1)
        })
        .collect();
    let palette_indices = compose_owner_preview_indices(&owners, selected);
    let palette = match retail_assets.assets().default_dib_palette() {
        Ok(palette) => palette,
        Err(error) => {
            warn!("could not load the retail city-site map palette: {error}");
            return;
        }
    };
    let image = preview_image_from_indices(&palette_indices, &palette);
    for (entity, mut map, image_node) in &mut maps {
        map.palette_indices = palette_indices.clone();
        if let Some(mut image_node) = image_node {
            if let Some(mut existing) = images.get_mut(&image_node.image) {
                *existing = image.clone();
            } else {
                image_node.image = images.add(image.clone());
            }
        } else {
            commands
                .entity(entity)
                .insert(ImageNode::new(images.add(image.clone())));
        }
    }
}

fn on_city_site_activate(
    activate: On<Activate>,
    actions: Query<&CitySiteAction>,
    dialog_open: Query<(), With<ModalDialog>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    if !dialog_open.is_empty() {
        return;
    }
    match *action {
        CitySiteAction::Cancel => next_state.set(AppState::RandomSetup),
    }
}

fn on_city_site_map_click(
    click: On<Pointer<Click>>,
    dialog_open: Query<(), With<ModalDialog>>,
    session: Res<GameSession>,
    maps: Query<(&RelativeCursorPosition, &CitySiteMap)>,
    mut ui: UiSpawner,
) {
    if !dialog_open.is_empty() {
        return;
    }
    let Ok((cursor, _map)) = maps.get(click.entity) else {
        return;
    };
    if !cursor.cursor_over() {
        return;
    }
    let Some(normalized) = cursor.normalized else {
        return;
    };
    let Some(tile) = tile_at_preview_position(normalized) else {
        return;
    };
    if validate_capital_site_selection(&session.0, tile).is_err() {
        return;
    }
    ui.commands.insert_resource(PendingCapitalSite { tile });
    open_new_city_dialog(&mut ui);
}

fn open_new_city_dialog(ui: &mut UiSpawner) {
    let Some(spawned) = ui.spawn_modal(new_city_dialog_view_id()) else {
        return;
    };
    ui.commands.entity(spawned.root).insert(NewCityDialogRoot);
    let _ = ui.attach(&spawned, "okay", NewCityAction::Accept);
    let _ = ui.attach(&spawned, "cncl", NewCityAction::Cancel);
}

fn on_new_city_activate(
    activate: On<Activate>,
    actions: Query<&NewCityAction>,
    dialogs: Query<Entity, With<NewCityDialogRoot>>,
    pending: Option<Res<PendingCapitalSite>>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    match *action {
        NewCityAction::Accept => {
            let Some(pending) = pending.as_deref().copied() else {
                return;
            };
            if confirm_capital_site(&mut session.0, pending.tile).is_err() {
                return;
            }
            for root in &dialogs {
                commands.entity(root).despawn();
            }
            commands.remove_resource::<PendingCapitalSite>();
            next_state.set(AppState::StrategicMap);
        }
        NewCityAction::Cancel => {
            for root in &dialogs {
                commands.entity(root).despawn();
            }
            commands.remove_resource::<PendingCapitalSite>();
        }
    }
}
