use crate::RetailAssetsResource;
use bevy::asset::RenderAssetUsages;
use bevy::image::{CompressedImageFormats, ImageSampler, ImageType};
use bevy::prelude::*;
use bevy::ui::widget::NodeImageMode;
use bevy::window::PrimaryWindow;

const RETAIL_WIDTH: f32 = 640.0;
const RETAIL_HEIGHT: f32 = 480.0;

pub(crate) struct RetailViewportPlugin;

impl Plugin for RetailViewportPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Startup, (maximize_window, spawn_chrome_backdrop).chain())
            .add_systems(Update, center_retail_views);
    }
}

fn maximize_window(mut window: Single<&mut Window, With<PrimaryWindow>>) {
    window.set_maximized(true);
}

fn spawn_chrome_backdrop(
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
    commands.spawn((
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
}

fn center_retail_views(
    window: Single<&Window, With<PrimaryWindow>>,
    mut roots: Query<&mut Node, Without<ChildOf>>,
) {
    let left = ((window.resolution.width() - RETAIL_WIDTH) / 2.0).max(0.0);
    let top = ((window.resolution.height() - RETAIL_HEIGHT) / 2.0).max(0.0);
    for mut node in &mut roots {
        if node.position_type == PositionType::Absolute
            && node.width == Val::Px(RETAIL_WIDTH)
            && node.height == Val::Px(RETAIL_HEIGHT)
        {
            node.left = Val::Px(left);
            node.top = Val::Px(top);
        }
    }
}
