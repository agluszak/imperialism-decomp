use crate::RetailAssetsResource;
use bevy::asset::RenderAssetUsages;
use bevy::image::ImageSampler;
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use bevy::window::{CursorIcon, CustomCursor, CustomCursorImage, PrimaryWindow, SystemCursorIcon};
use imperialism_formats::{RetailAssets, RetailCursor};

/// `TViewMgr::turnEventCursors`, indexed as `resource_id - 1000`.
#[derive(Resource)]
struct TurnEventCursors([CursorIcon; RetailAssets::TURN_EVENT_CURSOR_COUNT]);

/// Windows `SetCursor` request for the current hover.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Resource)]
pub(crate) enum RequestedCursor {
    #[default]
    Arrow,
    TurnEvent(u16),
}

pub(crate) struct CursorPlugin;

impl Plugin for CursorPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<RequestedCursor>()
            .add_systems(Startup, load_turn_event_cursors)
            .add_systems(Update, apply_requested_cursor);
    }
}

pub(crate) fn request_turn_event_cursor(requested: &mut ResMut<RequestedCursor>, resource_id: u16) {
    requested.set_if_neq(RequestedCursor::TurnEvent(resource_id));
}

pub(crate) fn request_arrow_cursor(requested: &mut ResMut<RequestedCursor>) {
    requested.set_if_neq(RequestedCursor::Arrow);
}

fn load_turn_event_cursors(
    mut commands: Commands,
    assets: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
) {
    let decoded = assets
        .assets()
        .turn_event_cursors()
        .expect("retail turn-event cursors ~C1000..=~C1053");
    commands.insert_resource(TurnEventCursors(std::array::from_fn(|index| {
        cursor_icon(&mut images, &decoded[index])
    })));
}

fn cursor_icon(images: &mut Assets<Image>, cursor: &RetailCursor) -> CursorIcon {
    let mut image = Image::new(
        Extent3d {
            width: cursor.width,
            height: cursor.height,
            depth_or_array_layers: 1,
        },
        TextureDimension::D2,
        cursor.rgba.clone(),
        TextureFormat::Rgba8UnormSrgb,
        RenderAssetUsages::MAIN_WORLD | RenderAssetUsages::RENDER_WORLD,
    );
    image.sampler = ImageSampler::nearest();
    CursorIcon::Custom(CustomCursor::Image(CustomCursorImage {
        handle: images.add(image),
        hotspot: (cursor.hotspot_x, cursor.hotspot_y),
        ..default()
    }))
}

fn apply_requested_cursor(
    mut commands: Commands,
    requested: Res<RequestedCursor>,
    cursors: Option<Res<TurnEventCursors>>,
    window: Single<Entity, With<PrimaryWindow>>,
) {
    if !requested.is_changed() {
        return;
    }
    let icon = match *requested {
        RequestedCursor::Arrow => CursorIcon::System(SystemCursorIcon::Default),
        RequestedCursor::TurnEvent(resource_id) => {
            let Some(cursors) = cursors.as_deref() else {
                return;
            };
            let index = usize::from(
                resource_id
                    .checked_sub(RetailAssets::TURN_EVENT_CURSOR_BASE)
                    .expect("turn-event cursor ids are 1000..=1053"),
            );
            cursors.0[index].clone()
        }
    };
    commands.entity(*window).insert(icon);
}
