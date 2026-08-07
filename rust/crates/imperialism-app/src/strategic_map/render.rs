use super::{
    CityRef, DISPLAY_LAYERS, DisplayCamera, GAME_LAYERS, HoveredTile, LogicalCanvas,
    MilitaryUnitRef, NationRef, PresentedAssets, PresentedLayout, SelectionMarker, ShipRef,
    StrategicMapLayout, TileRef,
};
use crate::session::GameSession;
use bevy::asset::RenderAssetUsages;
use bevy::camera::RenderTarget;
use bevy::ecs::system::SystemParam;
use bevy::prelude::*;
use bevy::render::render_resource::{
    Extent3d, TextureDescriptor, TextureDimension, TextureFormat, TextureUsages,
};
use bevy::window::WindowResized;
use imperialism_core::{CityId, GameState, TileId};
use imperialism_formats::{NormalizedAssetManifestV1, Rgba8};

#[derive(Component)]
struct GameCamera;

#[derive(Component)]
pub(super) struct StrategicProjection;

#[derive(Component)]
pub(super) struct StrategicTerrain;

#[derive(Resource, Default)]
pub(super) struct PresentedRevision(u64);

#[derive(SystemParam)]
pub(super) struct ProjectionRefreshResources<'w> {
    session: Res<'w, GameSession>,
    assets: Res<'w, PresentedAssets>,
    layout: Res<'w, PresentedLayout>,
    presented: ResMut<'w, PresentedRevision>,
    hovered: ResMut<'w, HoveredTile>,
    images: ResMut<'w, Assets<Image>>,
}

pub(super) fn setup_viewer(
    mut commands: Commands,
    session: Res<GameSession>,
    assets: Res<PresentedAssets>,
    layout: Res<PresentedLayout>,
    mut images: ResMut<Assets<Image>>,
) {
    spawn_projection(
        &mut commands,
        session.simulation().state(),
        &assets.0,
        layout.0,
        &mut images,
    );

    let [logical_width, logical_height] = assets.0.logical_resolution;
    let extent = Extent3d {
        width: logical_width,
        height: logical_height,
        depth_or_array_layers: 1,
    };
    let mut canvas = Image {
        texture_descriptor: TextureDescriptor {
            label: Some("imperialism logical canvas"),
            size: extent,
            dimension: TextureDimension::D2,
            format: TextureFormat::Bgra8UnormSrgb,
            mip_level_count: 1,
            sample_count: 1,
            usage: TextureUsages::TEXTURE_BINDING
                | TextureUsages::COPY_DST
                | TextureUsages::RENDER_ATTACHMENT,
            view_formats: &[],
        },
        ..default()
    };
    canvas.resize(extent);
    let canvas = images.add(canvas);

    commands.spawn((
        Camera2d,
        Camera {
            order: -1,
            clear_color: ClearColorConfig::Custom(Color::srgb_u8(18, 18, 20)),
            ..default()
        },
        RenderTarget::Image(canvas.clone().into()),
        Msaa::Off,
        GameCamera,
        GAME_LAYERS,
    ));
    commands.spawn((Sprite::from_image(canvas), LogicalCanvas, DISPLAY_LAYERS));
    commands.spawn((Camera2d, Msaa::Off, DisplayCamera, DISPLAY_LAYERS));
}

pub(super) fn refresh_projection(
    mut commands: Commands,
    mut resources: ProjectionRefreshResources,
    existing: Query<Entity, With<StrategicProjection>>,
    terrain: Query<&Sprite, With<StrategicTerrain>>,
) {
    if resources.presented.0 == resources.session.revision() {
        return;
    }
    for sprite in &terrain {
        resources.images.remove(sprite.image.id());
    }
    for entity in &existing {
        commands.entity(entity).despawn();
    }
    spawn_projection(
        &mut commands,
        resources.session.simulation().state(),
        &resources.assets.0,
        resources.layout.0,
        &mut resources.images,
    );
    resources.presented.0 = resources.session.revision();
    resources.hovered.0 = None;
}

fn spawn_projection(
    commands: &mut Commands,
    game: &GameState,
    assets: &NormalizedAssetManifestV1,
    layout: StrategicMapLayout,
    images: &mut Assets<Image>,
) {
    let terrain = images.add(terrain_image(&game.world.tiles, assets, layout));
    commands.spawn((
        Sprite::from_image(terrain),
        Transform::from_xyz(0.0, 0.0, 0.0),
        StrategicTerrain,
        StrategicProjection,
        GAME_LAYERS,
    ));

    spawn_semantic_markers(commands, game, assets, layout);
    commands.spawn((
        Sprite::from_color(
            color(assets.strategic_map.selection_marker),
            Vec2::new(layout.tile_width, layout.tile_height),
        ),
        Transform::from_xyz(0.0, 0.0, 10.0),
        Visibility::Hidden,
        SelectionMarker,
        StrategicProjection,
        TileRef(TileId::new(0)),
        GAME_LAYERS,
    ));
}

fn terrain_image(
    tiles: &[imperialism_core::TileState],
    assets: &NormalizedAssetManifestV1,
    layout: StrategicMapLayout,
) -> Image {
    let [width, height] = layout.pixel_size();
    let mut pixels = vec![0_u8; width as usize * height as usize * 4];
    for (index, tile) in tiles.iter().enumerate() {
        let tile_id = TileId::new(index as u16);
        let center = layout.tile_center_pixel(tile_id);
        let rgba = assets.strategic_map.terrain_palette[tile.terrain_kind as usize].0;
        let min_x = (center.x - layout.tile_width * 0.5).floor().max(0.0) as u32;
        let max_x = (center.x + layout.tile_width * 0.5)
            .ceil()
            .min(width as f32) as u32;
        let min_y = (center.y - layout.tile_height * 0.5).floor().max(0.0) as u32;
        let max_y = (center.y + layout.tile_height * 0.5)
            .ceil()
            .min(height as f32) as u32;
        for y in min_y..max_y {
            for x in min_x..max_x {
                if !layout.contains_pixel(center, Vec2::new(x as f32 + 0.5, y as f32 + 0.5)) {
                    continue;
                }
                let offset = (y as usize * width as usize + x as usize) * 4;
                pixels[offset..offset + 4].copy_from_slice(&rgba);
            }
        }
    }
    Image::new(
        Extent3d {
            width,
            height,
            depth_or_array_layers: 1,
        },
        TextureDimension::D2,
        pixels,
        TextureFormat::Rgba8UnormSrgb,
        RenderAssetUsages::RENDER_WORLD,
    )
}

fn spawn_semantic_markers(
    commands: &mut Commands,
    game: &GameState,
    assets: &NormalizedAssetManifestV1,
    layout: StrategicMapLayout,
) {
    for nation in game.nations.iter().flatten() {
        let Ok(tile_index) = u16::try_from(nation.common.home_tile) else {
            continue;
        };
        let tile = TileId::new(tile_index);
        let Some(center) = layout.tile_center(tile) else {
            continue;
        };
        let nation_color = assets.strategic_map.nation_palette[usize::from(nation.id.get())];
        commands.spawn((
            Sprite::from_color(color(nation_color), Vec2::splat(5.0)),
            Transform::from_xyz(center.x - 2.0, center.y + 2.0, 3.0),
            NationRef(nation.id),
            TileRef(tile),
            StrategicProjection,
            GAME_LAYERS,
        ));
    }

    for (slot, city) in game.cities.iter().enumerate() {
        let Some(city) = city else {
            continue;
        };
        let Ok(tile_index) = u16::try_from(city.home_town_tile) else {
            continue;
        };
        let tile = TileId::new(tile_index);
        let Some(center) = layout.tile_center(tile) else {
            continue;
        };
        commands.spawn((
            Sprite::from_color(color(assets.strategic_map.city_marker), Vec2::splat(3.0)),
            Transform::from_xyz(center.x + 2.0, center.y - 2.0, 4.0),
            CityRef(CityId::new(slot as u16)),
            TileRef(tile),
            StrategicProjection,
            GAME_LAYERS,
        ));
    }

    for unit in &game.military_units {
        let Some(tile) = first_tile_for_region(game, unit.stationed_province) else {
            continue;
        };
        let center = layout
            .tile_center(tile)
            .expect("tile came from the retail map");
        commands.spawn((
            Sprite::from_color(color(assets.strategic_map.army_marker), Vec2::splat(2.0)),
            Transform::from_xyz(center.x, center.y, 5.0),
            MilitaryUnitRef(unit.id),
            TileRef(tile),
            StrategicProjection,
            GAME_LAYERS,
        ));
    }

    for ship in &game.ships {
        let Some(tile) = first_tile_for_region(game, ship.location) else {
            continue;
        };
        let center = layout
            .tile_center(tile)
            .expect("tile came from the retail map");
        commands.spawn((
            Sprite::from_color(color(assets.strategic_map.navy_marker), Vec2::splat(2.0)),
            Transform::from_xyz(center.x, center.y, 6.0),
            ShipRef(ship.id),
            TileRef(tile),
            StrategicProjection,
            GAME_LAYERS,
        ));
    }
}

fn first_tile_for_region(game: &GameState, region: i16) -> Option<TileId> {
    game.world
        .tiles
        .iter()
        .position(|tile| tile.province == Some(region))
        .map(|index| TileId::new(index as u16))
}

fn color(rgba: Rgba8) -> Color {
    let [red, green, blue, alpha] = rgba.0;
    Color::srgba_u8(red, green, blue, alpha)
}

pub(super) fn fit_canvas(
    mut resize_messages: MessageReader<WindowResized>,
    assets: Res<PresentedAssets>,
    mut canvas: Single<&mut Transform, With<LogicalCanvas>>,
) {
    for resized in resize_messages.read() {
        let [logical_width, logical_height] = assets.0.logical_resolution;
        let scale = (resized.width / logical_width as f32)
            .min(resized.height / logical_height as f32)
            .max(0.01);
        canvas.scale = Vec3::splat(scale);
    }
}
