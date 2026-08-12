use crate::ui::catalog::{ModalDialog, UiAssetResources, UiCatalogResource, UiSpawner, spawn_view};
use crate::ui::random_setup::GameSession;
use crate::ui::strategic_map::{
    StrategicBaseTerrainCanvas, bind_strategic_base_terrain, compose_city_site_terrain,
    strategic_base_terrain_tile_at_cursor,
};
use crate::{AppState, RetailAssetsResource};
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::RelativeCursorPosition;
use bevy::ui_widgets::Activate;
use imperialism_core::*;
use imperialism_formats::{OKAY, ScopedViewId, fourcc};

const STARTUP_RESOURCE_FILE: &str = "Startup.rsrc";
const CITY_SITE_RESOURCE_ID: i16 = 952;
const NEW_CITY_RESOURCE_ID: i16 = 953;
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

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum CitySiteAction {
    Cancel,
}

#[derive(Component)]
struct NewCityDialogRoot(CapitalSite);

#[derive(Component, Default)]
struct CitySiteHover(Option<TileId>);

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
                sync_city_site_hover.run_if(in_state(AppState::CitySite)),
            )
            .add_observer(on_city_site_activate.run_if(in_state(AppState::CitySite)))
            .add_observer(on_city_site_map_click.run_if(in_state(AppState::CitySite)))
            .add_observer(on_new_city_activate.run_if(in_state(AppState::CitySite)));
    }
}

fn enter_city_site(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut assets: UiAssetResources,
    session: Res<GameSession>,
) {
    let view = catalog.required_view(&city_site_view_id());
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut assets);
    bind_city_site_controls(&mut commands, &spawned);
    let map = bind_strategic_base_terrain(&mut commands, &spawned, &mut assets, &session.0);
    commands.entity(map).insert(CitySiteHover::default());
    commands
        .entity(spawned.root)
        .insert(DespawnOnExit(AppState::CitySite));
}

fn sync_city_site_hover(
    session: Res<GameSession>,
    retail_assets: Res<RetailAssetsResource>,
    dialog_open: Query<(), With<ModalDialog>>,
    mut images: ResMut<Assets<Image>>,
    mut maps: Query<(
        &StrategicBaseTerrainCanvas,
        &RelativeCursorPosition,
        &ImageNode,
        &mut CitySiteHover,
    )>,
) {
    if !dialog_open.is_empty() {
        return;
    }
    let Some(nation) = MajorNationId::from_nation(session.0.turn().active_nation) else {
        return;
    };
    for (canvas, cursor, image_node, mut hover) in &mut maps {
        let Some(tile) = strategic_base_terrain_tile_at_cursor(&session.0, cursor) else {
            continue;
        };
        if hover.0 == Some(tile) && !session.is_changed() {
            continue;
        }
        hover.0 = Some(tile);
        let highlighted = highlights_city_site_candidate(&session.0, nation, tile).then_some(tile);
        let image = compose_city_site_terrain(
            &session.0,
            canvas,
            nation,
            highlighted,
            retail_assets.assets().default_dib_palette(),
        );
        let Some(mut existing) = images.get_mut(&image_node.image) else {
            continue;
        };
        *existing = image;
    }
}

fn highlights_city_site_candidate(state: &GameState, nation: MajorNationId, tile: TileId) -> bool {
    let tile_state = state.map[tile];
    tile_state.owner_nation == Some(TileOwnerTag::from_nation(nation.nation()))
        && !matches!(
            tile_state.terrain,
            TerrainKind::Hills | TerrainKind::Mountain | TerrainKind::Swamp
        )
        && is_valid_secondary_nation_home_tile_candidate(&state.map, tile)
}

fn bind_city_site_controls(commands: &mut Commands, spawned: &crate::ui::catalog::SpawnedView) {
    let cancel = spawned.unique(fourcc!("canc"));
    commands.entity(cancel).insert(CitySiteAction::Cancel);
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
    maps: Query<&RelativeCursorPosition, With<StrategicBaseTerrainCanvas>>,
    mut ui: UiSpawner,
) {
    if !dialog_open.is_empty() {
        return;
    }
    let Ok(cursor) = maps.get(click.entity) else {
        return;
    };
    let Some(tile) = strategic_base_terrain_tile_at_cursor(&session.0, cursor) else {
        return;
    };
    let Some(nation) = MajorNationId::from_nation(session.0.turn().active_nation) else {
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
