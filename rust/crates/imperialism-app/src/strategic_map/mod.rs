mod layout;
mod render;

pub use layout::StrategicMapLayout;

use crate::session::GameLoopSet;
use bevy::camera::visibility::RenderLayers;
use bevy::prelude::*;
use imperialism_core::{CityId, MilitaryUnitId, NationId, ShipId, TileId};
use imperialism_formats::NormalizedAssetManifestV1;

pub(crate) const GAME_LAYERS: RenderLayers = RenderLayers::layer(0);
pub(crate) const DISPLAY_LAYERS: RenderLayers = RenderLayers::layer(1);

#[derive(Resource)]
pub(crate) struct PresentedAssets(pub NormalizedAssetManifestV1);

#[derive(Resource, Clone, Copy)]
pub(crate) struct PresentedLayout(pub StrategicMapLayout);

#[derive(Resource, Default)]
pub(crate) struct HoveredTile(pub Option<TileId>);

#[derive(Component)]
pub(crate) struct LogicalCanvas;

#[derive(Component)]
pub(crate) struct DisplayCamera;

#[derive(Component)]
pub(crate) struct SelectionMarker;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub struct TileRef(pub TileId);

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub struct NationRef(pub NationId);

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub struct CityRef(pub CityId);

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub struct MilitaryUnitRef(pub MilitaryUnitId);

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShipRef(pub ShipId);

pub struct StrategicMapPlugin;

impl Plugin for StrategicMapPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<HoveredTile>()
            .init_resource::<render::PresentedRevision>()
            .add_systems(Startup, render::setup_viewer)
            .add_systems(
                Update,
                (render::fit_canvas, render::refresh_projection)
                    .chain()
                    .in_set(GameLoopSet::UpdatePresentation),
            );
    }
}
