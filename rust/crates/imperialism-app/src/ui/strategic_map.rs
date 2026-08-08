use crate::AppState;
use crate::ui::catalog::{UiCatalogResource, UiPictureResources, spawn_view};
use bevy::prelude::*;
use imperialism_formats::ScopedViewId;

const MAP_VIEW_RESOURCE_FILE: &str = "MapView.rsrc";
const STRATEGIC_MAP_RESOURCE_ID: i16 = 2013;

pub(crate) fn strategic_map_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: MAP_VIEW_RESOURCE_FILE.to_owned(),
        resource_id: STRATEGIC_MAP_RESOURCE_ID,
    }
}

pub(crate) struct StrategicMapPlugin;

impl Plugin for StrategicMapPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(OnEnter(AppState::StrategicMap), enter_strategic_map);
    }
}

fn enter_strategic_map(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut pictures: UiPictureResources,
) {
    let Some(spawned) = spawn_view(
        &mut commands,
        catalog.catalog(),
        &strategic_map_view_id(),
        &mut pictures,
    ) else {
        return;
    };
    // First slice: retail shell only. Viewport/camera map rendering follows later.
    commands
        .entity(spawned.root)
        .insert(DespawnOnExit(AppState::StrategicMap));
}
