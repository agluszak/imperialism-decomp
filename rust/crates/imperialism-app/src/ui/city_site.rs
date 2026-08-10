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
use imperialism_core::*;
use imperialism_formats::{FourCc, OKAY, ScopedViewId, fourcc};

const STARTUP_RESOURCE_FILE: &str = "Startup.rsrc";
const CITY_SITE_RESOURCE_ID: i16 = 952;
const NEW_CITY_RESOURCE_ID: i16 = 953;
const MAP_TAG: FourCc = fourcc!("DLOG");

pub(crate) fn city_site_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: STARTUP_RESOURCE_FILE.to_owned(),
        resource_id: CITY_SITE_RESOURCE_ID,
    }
}

pub(crate) fn new_city_dialog_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: STARTUP_RESOURCE_FILE.to_owned(),
        resource_id: NEW_CITY_RESOURCE_ID,
    }
}

pub(crate) fn validate_application_bindings(catalog: &UiCatalogResource) -> Result<(), String> {
    catalog.require_unique_bindings(&city_site_view_id(), &[fourcc!("canc"), MAP_TAG])?;
    catalog.require_unique_bindings(&new_city_dialog_view_id(), &[OKAY, fourcc!("cncl")])
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum CitySiteAction {
    Cancel,
}

#[derive(Component)]
struct CitySiteMap;

#[derive(Component)]
struct NewCityDialogRoot(CapitalSite);

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum NewCityAction {
    Accept,
    Cancel,
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
    let view = catalog
        .view(&city_site_view_id())
        .expect("validated city-site catalog view");
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut assets);
    bind_city_site_controls(&mut commands, &spawned);
    commands
        .entity(spawned.root)
        .insert(DespawnOnExit(AppState::CitySite));
}

fn bind_city_site_controls(commands: &mut Commands, spawned: &crate::ui::catalog::SpawnedView) {
    let cancel = spawned
        .require_unique(fourcc!("canc"))
        .expect("validated city-site cancel binding");
    commands.entity(cancel).insert(CitySiteAction::Cancel);
    // Retail opens the New City dialog from a validated map click, not from `send`.
    let map = spawned
        .require_unique(MAP_TAG)
        .expect("validated city-site map binding");
    commands.entity(map).insert(CitySiteMap);
}

fn render_city_site_map(
    mut commands: Commands,
    session: Res<GameSession>,
    retail_assets: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut maps: Query<(Entity, Option<&mut ImageNode>), Added<CitySiteMap>>,
) {
    if maps.is_empty() {
        return;
    }
    let Some(selected) = MajorNationId::from_nation(session.0.turn.active_nation) else {
        warn!(
            "city-site map render skipped: active nation {:?} is not a major nation",
            session.0.turn.active_nation
        );
        return;
    };
    let palette_indices =
        compose_owner_preview_indices(|tile| session.0.world[tile].owner_nation, selected);
    let palette = retail_assets.assets().default_dib_palette();
    let image = preview_image_from_indices(&palette_indices, palette);
    for (entity, image_node) in &mut maps {
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
    let Some(nation) = MajorNationId::from_nation(session.0.turn.active_nation) else {
        return;
    };
    let Ok(site) = validate_capital_site_selection(&session.0, nation, tile) else {
        return;
    };
    open_new_city_dialog(&mut ui, site);
}

fn open_new_city_dialog(ui: &mut UiSpawner, site: CapitalSite) {
    let spawned = ui.spawn_modal(new_city_dialog_view_id());
    ui.commands
        .entity(spawned.root)
        .insert(NewCityDialogRoot(site));
    ui.attach(&spawned, OKAY, NewCityAction::Accept);
    ui.attach(&spawned, fourcc!("cncl"), NewCityAction::Cancel);
}

fn on_new_city_activate(
    activate: On<Activate>,
    actions: Query<&NewCityAction>,
    dialogs: Query<(Entity, &NewCityDialogRoot)>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    match *action {
        NewCityAction::Accept => {
            let Ok((_, dialog)) = dialogs.single() else {
                return;
            };
            confirm_capital_site(&mut session.0, dialog.0);
            for (root, _) in &dialogs {
                commands.entity(root).despawn();
            }
            next_state.set(AppState::StrategicMap);
        }
        NewCityAction::Cancel => {
            for (root, _) in &dialogs {
                commands.entity(root).despawn();
            }
        }
    }
}
