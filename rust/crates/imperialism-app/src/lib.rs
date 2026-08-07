#![forbid(unsafe_code)]

use bevy::asset::RenderAssetUsages;
use bevy::camera::{RenderTarget, visibility::RenderLayers};
use bevy::prelude::*;
use bevy::render::render_resource::{
    Extent3d, TextureDescriptor, TextureDimension, TextureFormat, TextureUsages,
};
use bevy::window::{PrimaryWindow, WindowPlugin, WindowResized};
use imperialism_core::{
    CityId, GameSnapshotV1, GameState, MilitaryUnitId, NationId, STRATEGIC_MAP_HEIGHT,
    STRATEGIC_MAP_WIDTH, STRATEGIC_TILE_COUNT, ShipId, TileId,
};
use imperialism_formats::{
    AssetManifestError, NormalizedAssetManifestV1, Rgba8, StrategicMapAssetManifest,
    read_normalized_asset_manifest,
};
use std::fs;
use std::path::Path;
use std::sync::Arc;

const GAME_LAYERS: RenderLayers = RenderLayers::layer(0);
const DISPLAY_LAYERS: RenderLayers = RenderLayers::layer(1);

#[derive(Debug, thiserror::Error)]
pub enum ViewerLoadError {
    #[error("could not read snapshot: {0}")]
    SnapshotIo(#[source] std::io::Error),
    #[error("could not decode snapshot: {0}")]
    SnapshotJson(#[source] serde_json::Error),
    #[error("invalid snapshot: {0}")]
    SnapshotValidation(#[source] imperialism_core::SnapshotValidationError),
    #[error(transparent)]
    Assets(#[from] AssetManifestError),
    #[error("cannot present snapshot: {0}")]
    Presentation(String),
}

pub struct ViewerInput {
    game: GameState,
    assets: NormalizedAssetManifestV1,
}

pub fn load_viewer(
    snapshot_path: &Path,
    asset_manifest_path: &Path,
) -> Result<ViewerInput, ViewerLoadError> {
    let bytes = fs::read(snapshot_path).map_err(ViewerLoadError::SnapshotIo)?;
    let value = serde_json::from_slice::<serde_json::Value>(&bytes)
        .map_err(ViewerLoadError::SnapshotJson)?;
    let snapshot_value = value.get("game_snapshot").unwrap_or(&value).clone();
    let snapshot = serde_json::from_value::<GameSnapshotV1>(snapshot_value)
        .map_err(ViewerLoadError::SnapshotJson)?;
    let game = GameState::try_from(snapshot).map_err(ViewerLoadError::SnapshotValidation)?;
    let assets = read_normalized_asset_manifest(asset_manifest_path)?;
    validate_presentation(&game, &assets)?;
    Ok(ViewerInput { game, assets })
}

fn validate_presentation(
    game: &GameState,
    assets: &NormalizedAssetManifestV1,
) -> Result<(), ViewerLoadError> {
    if game.world.width != STRATEGIC_MAP_WIDTH || game.world.height != STRATEGIC_MAP_HEIGHT {
        return Err(ViewerLoadError::Presentation(format!(
            "expected a {}x{} strategic map, found {}x{}",
            STRATEGIC_MAP_WIDTH, STRATEGIC_MAP_HEIGHT, game.world.width, game.world.height
        )));
    }
    for (index, tile) in game.world.tiles.iter().enumerate() {
        let terrain = usize::try_from(tile.terrain_kind).map_err(|_| {
            ViewerLoadError::Presentation(format!(
                "tile {index} has negative terrain kind {}",
                tile.terrain_kind
            ))
        })?;
        if terrain >= assets.strategic_map.terrain_palette.len() {
            return Err(ViewerLoadError::Presentation(format!(
                "tile {index} terrain kind {terrain} is absent from the asset palette"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StrategicMapLayout {
    tile_width: f32,
    tile_height: f32,
    row_stride: f32,
    odd_row_offset: f32,
    pixel_width: u32,
    pixel_height: u32,
}

impl StrategicMapLayout {
    pub fn new(manifest: &StrategicMapAssetManifest) -> Self {
        let [tile_width, tile_height] = manifest.tile_size;
        let pixel_width = u32::from(STRATEGIC_MAP_WIDTH) * tile_width + manifest.odd_row_offset;
        let pixel_height =
            (u32::from(STRATEGIC_MAP_HEIGHT) - 1) * manifest.row_stride + tile_height;
        Self {
            tile_width: tile_width as f32,
            tile_height: tile_height as f32,
            row_stride: manifest.row_stride as f32,
            odd_row_offset: manifest.odd_row_offset as f32,
            pixel_width,
            pixel_height,
        }
    }

    pub const fn pixel_size(self) -> [u32; 2] {
        [self.pixel_width, self.pixel_height]
    }

    pub fn tile_center(self, tile: TileId) -> Option<Vec2> {
        if usize::from(tile.get()) >= STRATEGIC_TILE_COUNT {
            return None;
        }
        let row = tile.get() / STRATEGIC_MAP_WIDTH;
        let column = tile.get() % STRATEGIC_MAP_WIDTH;
        let x = f32::from(column) * self.tile_width
            + if row & 1 != 0 {
                self.odd_row_offset
            } else {
                0.0
            }
            + self.tile_width * 0.5;
        let y = f32::from(row) * self.row_stride + self.tile_height * 0.5;
        Some(self.pixel_to_world(Vec2::new(x, y)))
    }

    pub fn hit_test(self, logical_position: Vec2) -> Option<TileId> {
        let pixel = self.world_to_pixel(logical_position);
        let mut best = None;
        let mut best_distance = f32::INFINITY;
        for index in 0..STRATEGIC_TILE_COUNT {
            let tile = TileId::new(index as u16);
            let center = self.tile_center_pixel(tile);
            if !self.contains_pixel(center, pixel) {
                continue;
            }
            let distance = center.distance_squared(pixel);
            if distance < best_distance {
                best = Some(tile);
                best_distance = distance;
            }
        }
        best
    }

    fn tile_center_pixel(self, tile: TileId) -> Vec2 {
        let row = tile.get() / STRATEGIC_MAP_WIDTH;
        let column = tile.get() % STRATEGIC_MAP_WIDTH;
        Vec2::new(
            f32::from(column) * self.tile_width
                + if row & 1 != 0 {
                    self.odd_row_offset
                } else {
                    0.0
                }
                + self.tile_width * 0.5,
            f32::from(row) * self.row_stride + self.tile_height * 0.5,
        )
    }

    fn contains_pixel(self, center: Vec2, point: Vec2) -> bool {
        let delta = (point - center).abs();
        let half_width = self.tile_width * 0.5;
        let half_height = self.tile_height * 0.5;
        if delta.y > half_height {
            return false;
        }
        let quarter_height = self.tile_height * 0.25;
        let allowed_x = if delta.y <= quarter_height {
            half_width
        } else {
            half_width - (delta.y - quarter_height) * (half_width * 0.5 / quarter_height)
        };
        delta.x <= allowed_x
    }

    fn world_to_pixel(self, point: Vec2) -> Vec2 {
        Vec2::new(
            point.x + self.pixel_width as f32 * 0.5,
            self.pixel_height as f32 * 0.5 - point.y,
        )
    }

    fn pixel_to_world(self, point: Vec2) -> Vec2 {
        Vec2::new(
            point.x - self.pixel_width as f32 * 0.5,
            self.pixel_height as f32 * 0.5 - point.y,
        )
    }
}

#[derive(Resource)]
struct PresentedGame(Arc<GameState>);

#[derive(Resource)]
struct PresentedAssets(NormalizedAssetManifestV1);

#[derive(Resource, Clone, Copy)]
struct PresentedLayout(StrategicMapLayout);

#[derive(Resource, Default)]
struct HoveredTile(Option<TileId>);

#[derive(Component)]
struct LogicalCanvas;

#[derive(Component)]
struct GameCamera;

#[derive(Component)]
struct DisplayCamera;

#[derive(Component)]
struct SelectionMarker;

type SelectionMarkerFilter = (With<SelectionMarker>, Without<LogicalCanvas>);
type SelectionMarkerQuery<'w, 's> = Single<
    'w,
    's,
    (
        &'static mut Transform,
        &'static mut Visibility,
        &'static mut TileRef,
    ),
    SelectionMarkerFilter,
>;

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

pub fn run_viewer(input: ViewerInput) {
    let logical_resolution = input.assets.logical_resolution;
    let layout = StrategicMapLayout::new(&input.assets.strategic_map);
    App::new()
        .insert_resource(ClearColor(Color::srgb_u8(18, 18, 20)))
        .insert_resource(PresentedGame(Arc::new(input.game)))
        .insert_resource(PresentedAssets(input.assets))
        .insert_resource(PresentedLayout(layout))
        .insert_resource(HoveredTile::default())
        .add_plugins(
            DefaultPlugins
                .set(ImagePlugin::default_nearest())
                .set(WindowPlugin {
                    primary_window: Some(Window {
                        title: "Imperialism strategic-map snapshot".to_owned(),
                        resolution: (logical_resolution[0], logical_resolution[1]).into(),
                        ..default()
                    }),
                    ..default()
                }),
        )
        .add_systems(Startup, setup_viewer)
        .add_systems(Update, (fit_canvas, update_hovered_tile))
        .run();
}

fn setup_viewer(
    mut commands: Commands,
    game: Res<PresentedGame>,
    assets: Res<PresentedAssets>,
    layout: Res<PresentedLayout>,
    mut images: ResMut<Assets<Image>>,
) {
    let terrain = images.add(terrain_image(&game.0.world.tiles, &assets.0, layout.0));
    commands.spawn((
        Sprite::from_image(terrain),
        Transform::from_xyz(0.0, 0.0, 0.0),
        GAME_LAYERS,
    ));

    spawn_semantic_markers(&mut commands, &game.0, &assets.0, layout.0);
    let selection_color = color(assets.0.strategic_map.selection_marker);
    commands.spawn((
        Sprite::from_color(
            selection_color,
            Vec2::new(layout.0.tile_width, layout.0.tile_height),
        ),
        Transform::from_xyz(0.0, 0.0, 10.0),
        Visibility::Hidden,
        SelectionMarker,
        TileRef(TileId::new(0)),
        GAME_LAYERS,
    ));

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
        let Ok(tile_index) = u16::try_from(nation.home_tile) else {
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
            GAME_LAYERS,
        ));
    }
}

fn first_tile_for_region(game: &GameState, region: i16) -> Option<TileId> {
    game.world
        .tiles
        .iter()
        .position(|tile| tile.city_or_province_index == i64::from(region))
        .map(|index| TileId::new(index as u16))
}

fn color(rgba: Rgba8) -> Color {
    let [red, green, blue, alpha] = rgba.0;
    Color::srgba_u8(red, green, blue, alpha)
}

fn fit_canvas(
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

fn update_hovered_tile(
    game: Res<PresentedGame>,
    layout: Res<PresentedLayout>,
    mut hovered: ResMut<HoveredTile>,
    mut window: Single<&mut Window, With<PrimaryWindow>>,
    display_camera: Single<(&Camera, &GlobalTransform), With<DisplayCamera>>,
    canvas: Single<&Transform, (With<LogicalCanvas>, Without<SelectionMarker>)>,
    selection: SelectionMarkerQuery,
) {
    let next = window.cursor_position().and_then(|cursor| {
        display_camera
            .0
            .viewport_to_world_2d(display_camera.1, cursor)
            .ok()
            .and_then(|world| layout.0.hit_test(world / canvas.scale.x))
    });
    if hovered.0 == next {
        return;
    }
    hovered.0 = next;
    let (mut transform, mut visibility, mut tile_ref) = selection.into_inner();
    if let Some(tile) = next {
        let center = layout
            .0
            .tile_center(tile)
            .expect("hit-tested tile is valid");
        transform.translation.x = center.x;
        transform.translation.y = center.y;
        *visibility = Visibility::Visible;
        tile_ref.0 = tile;
        let state = &game.0.world.tiles[usize::from(tile.get())];
        window.title = format!(
            "Imperialism snapshot — tile {} terrain {} owner {} region {}",
            tile.get(),
            state.terrain_kind,
            state.owner_nation,
            state.city_or_province_index
        );
    } else {
        *visibility = Visibility::Hidden;
        window.title = "Imperialism strategic-map snapshot".to_owned();
    }
}

pub fn example_asset_manifest_path() -> &'static Path {
    Path::new("assets.example/manifest.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_manifest() -> StrategicMapAssetManifest {
        StrategicMapAssetManifest {
            tile_size: [8, 8],
            row_stride: 6,
            odd_row_offset: 4,
            terrain_palette: vec![Rgba8([0, 0, 0, 255]); 8],
            nation_palette: vec![Rgba8([0, 0, 0, 255]); 23],
            city_marker: Rgba8([0, 0, 0, 255]),
            army_marker: Rgba8([0, 0, 0, 255]),
            navy_marker: Rgba8([0, 0, 0, 255]),
            selection_marker: Rgba8([0, 0, 0, 255]),
        }
    }

    #[test]
    fn maps_retail_hex_centers_back_to_typed_tiles() {
        let layout = StrategicMapLayout::new(&map_manifest());
        for tile in [TileId::new(0), TileId::new(108), TileId::new(6479)] {
            let center = layout.tile_center(tile).unwrap();
            assert_eq!(layout.hit_test(center), Some(tile));
        }
    }

    #[test]
    fn rejects_points_outside_the_rendered_map() {
        let layout = StrategicMapLayout::new(&map_manifest());
        assert_eq!(layout.pixel_size(), [868, 362]);
        assert_eq!(layout.hit_test(Vec2::new(-500.0, 0.0)), None);
        assert_eq!(layout.hit_test(Vec2::new(0.0, 300.0)), None);
    }
}
