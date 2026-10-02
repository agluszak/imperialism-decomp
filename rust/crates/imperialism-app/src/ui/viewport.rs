use super::retail::RetailScene;
use super::window::ModalWindow;
use crate::RetailAssetsResource;
use bevy::asset::RenderAssetUsages;
use bevy::image::{CompressedImageFormats, ImageSampler, ImageType};
use bevy::prelude::*;
use bevy::ui::widget::NodeImageMode;
use bevy::window::PrimaryWindow;

const RETAIL_WIDTH: f32 = 640.0;
const RETAIL_HEIGHT: f32 = 480.0;

pub(crate) struct RetailViewportPlugin;

/// Permanent 640x480 owner for recovered screens, floating windows, and modal barriers.
#[derive(Component, Debug, Default)]
pub(crate) struct RetailCanvas;

impl Plugin for RetailViewportPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Startup, (maximize_window, spawn_retail_viewport).chain())
            .add_systems(Update, parent_new_retail_roots);
    }
}

fn maximize_window(mut window: Single<&mut Window, With<PrimaryWindow>>) {
    window.set_maximized(true);
}

fn spawn_retail_viewport(
    mut commands: Commands,
    retail: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
) {
    let bytes = retail
        .assets()
        .chrome_backdrop()
        .expect("retail host-frame backdrop must decode");
    let image = Image::from_buffer(
        &bytes,
        ImageType::Format(ImageFormat::Bmp),
        CompressedImageFormats::NONE,
        true,
        ImageSampler::nearest(),
        RenderAssetUsages::default(),
    )
    .expect("retail host-frame backdrop must be a BMP");
    let handle = images.add(image);
    commands
        .spawn((
            Name::new("Retail viewport host"),
            Node {
                width: Val::Percent(100.0),
                height: Val::Percent(100.0),
                justify_content: JustifyContent::Center,
                align_items: AlignItems::Center,
                ..default()
            },
            Pickable::IGNORE,
        ))
        .with_children(|host| {
            host.spawn((
                Name::new("Retail host-frame backdrop"),
                Node {
                    position_type: PositionType::Absolute,
                    width: Val::Percent(100.0),
                    height: Val::Percent(100.0),
                    ..default()
                },
                ImageNode::new(handle).with_mode(NodeImageMode::Tiled {
                    tile_x: true,
                    tile_y: true,
                    stretch_value: 1.0,
                }),
                GlobalZIndex(-100),
                Pickable::IGNORE,
            ));
            host.spawn((
                Name::new("Retail canvas"),
                RetailCanvas,
                Node {
                    width: Val::Px(RETAIL_WIDTH),
                    height: Val::Px(RETAIL_HEIGHT),
                    ..default()
                },
                Pickable::IGNORE,
            ));
        });
}

fn parent_new_retail_roots(
    canvases: Query<Entity, With<RetailCanvas>>,
    scenes: Query<Entity, (Added<RetailScene>, Without<ChildOf>)>,
    modals: Query<Entity, (Added<ModalWindow>, Without<ChildOf>)>,
    mut commands: Commands,
) {
    if scenes.is_empty() && modals.is_empty() {
        return;
    }
    let canvas = canvases
        .single()
        .expect("retail viewport must contain exactly one RetailCanvas");
    for root in scenes.iter().chain(&modals) {
        commands.entity(root).insert(ChildOf(canvas));
    }
}
