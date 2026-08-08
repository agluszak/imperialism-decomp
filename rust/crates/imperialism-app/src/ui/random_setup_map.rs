use super::catalog::{SpawnedView, UiAssetResources};
use super::random_setup::{RandomGameSetup, RandomSetupPreview, random_setup_view_id};
use crate::RetailAssetsResource;
use bevy::asset::RenderAssetUsages;
use bevy::image::ImageSampler;
use bevy::log::warn;
use bevy::math::Rect;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use bevy::ui::RelativeCursorPosition;
use imperialism_core::{
    MajorNationId, MapGeometry, MapTopology, STRATEGIC_TILE_COUNT, TileId, TileOwnerTag,
};
use imperialism_formats::{DibPalette, FourCc, PictureId, Rgb, fourcc};

const MAP_TAG: FourCc = fourcc!("map ");
const COAT_TAG: FourCc = fourcc!("coat");
const FLAG_TAG: FourCc = fourcc!("flag");
const FIRST_MAJOR_NATION_COAT_PICTURE: i16 = 0x11c6;
const FLAG_ATLAS_PICTURE: PictureId = PictureId::new(8699);
const FLAG_WIDTH: usize = 32;
const FLAG_HEIGHT: usize = 24;
const TRANSPARENT_FLAG_RGB: Rgb = Rgb::new(0xff, 0, 0xff);
const PREVIEW_WIDTH: usize = 324;
const PREVIEW_HEIGHT: usize = 180;
const PREVIEW_PIXEL_COUNT: usize = PREVIEW_WIDTH * PREVIEW_HEIGHT;
const OFF_MAP_PALETTE: u8 = 0x10;
const SELECTED_EDGE_PALETTE: u8 = 0x13;
const MAJOR_NATION_PALETTES: [u8; MajorNationId::COUNT as usize] =
    [0x16, 0x2a, 0x22, 0x1c, 0x2b, 0x1e, 0x2e];

/// The retail 8-bit map surface retained for both display and click sampling.
#[derive(Component, Default)]
struct RandomSetupMapPreview {
    palette_indices: Vec<u8>,
    rendered: bool,
}

#[derive(Component, Default)]
struct RandomSetupCoat {
    nation: Option<MajorNationId>,
}

#[derive(Component, Default)]
struct RandomSetupFlag {
    nation: Option<MajorNationId>,
}

pub(crate) struct MapPreviewPlugin;

impl Plugin for MapPreviewPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            Update,
            (
                render_map_preview,
                sync_random_setup_coat,
                sync_random_setup_flag,
            )
                .chain()
                .run_if(in_state(crate::AppState::RandomSetup)),
        )
        .add_observer(on_map_preview_click);
    }
}

/// Attach map/coat/flag screen meanings once when random-setup is created.
pub(crate) fn attach_random_setup_meanings(commands: &mut Commands, spawned: &SpawnedView) {
    debug_assert_eq!(spawned.view_id, random_setup_view_id());
    // PointerCanvas behavior already adds RelativeCursorPosition for the map.
    let map = spawned
        .tag(MAP_TAG)
        .expect("validated random-setup map binding");
    commands
        .entity(map)
        .insert(RandomSetupMapPreview::default());
    let coat = spawned
        .tag(COAT_TAG)
        .expect("validated random-setup coat binding");
    commands.entity(coat).insert(RandomSetupCoat::default());
    let flag = spawned
        .tag(FLAG_TAG)
        .expect("validated random-setup flag binding");
    commands.entity(flag).insert(RandomSetupFlag::default());
}

fn sync_random_setup_coat(
    setup: Res<RandomGameSetup>,
    mut pictures: UiAssetResources,
    added_coats: Query<(), Added<RandomSetupCoat>>,
    mut coats: Query<(&mut RandomSetupCoat, &mut ImageNode)>,
) {
    if !setup.is_changed() && added_coats.is_empty() {
        return;
    }
    for (mut coat, mut image_node) in &mut coats {
        if coat.nation == Some(setup.nation) {
            continue;
        }
        let picture_id = coat_picture_id(setup.nation);
        let handle = match pictures.picture(picture_id) {
            Ok(handle) => handle,
            Err(error) => {
                warn!(
                    "could not load retail setup coat picture {:?}: {error}",
                    picture_id
                );
                continue;
            }
        };
        image_node.image = handle;
        coat.nation = Some(setup.nation);
    }
}

fn coat_picture_id(nation: MajorNationId) -> PictureId {
    PictureId::new(FIRST_MAJOR_NATION_COAT_PICTURE + i16::from(nation.get()))
}

fn sync_random_setup_flag(
    mut commands: Commands,
    setup: Res<RandomGameSetup>,
    mut pictures: UiAssetResources,
    added_flags: Query<(), Added<RandomSetupFlag>>,
    mut flags: Query<(Entity, &mut RandomSetupFlag, Option<&mut ImageNode>)>,
    mut atlas_transparency_applied: Local<bool>,
) {
    if !setup.is_changed() && added_flags.is_empty() {
        return;
    }
    let handle = match pictures.picture(FLAG_ATLAS_PICTURE) {
        Ok(handle) => handle,
        Err(error) => {
            warn!(
                "could not load retail setup flag atlas {:?}: {error}",
                FLAG_ATLAS_PICTURE
            );
            return;
        }
    };
    if !*atlas_transparency_applied {
        match pictures.with_picture_image_mut(FLAG_ATLAS_PICTURE, apply_flag_atlas_transparency) {
            Ok(()) => *atlas_transparency_applied = true,
            Err(error) => {
                warn!(
                    "could not apply transparency to retail setup flag atlas {:?}: {error}",
                    FLAG_ATLAS_PICTURE
                );
                return;
            }
        }
    }

    for (entity, mut flag, image_node) in &mut flags {
        if flag.nation == Some(setup.nation) {
            continue;
        }
        let left = f32::from(setup.nation.get()) * FLAG_WIDTH as f32;
        let rect = Rect::new(left, 0.0, left + FLAG_WIDTH as f32, FLAG_HEIGHT as f32);
        if let Some(mut image_node) = image_node {
            image_node.image = handle.clone();
            image_node.rect = Some(rect);
        } else {
            commands.entity(entity).insert(ImageNode {
                image: handle.clone(),
                rect: Some(rect),
                ..default()
            });
        }
        flag.nation = Some(setup.nation);
    }
}

fn apply_flag_atlas_transparency(image: &mut Image) {
    let Some(pixels) = image.data.as_mut() else {
        return;
    };
    for pixel in pixels.chunks_exact_mut(4) {
        // TGWorldPartView blits with palette index 0x10 as its transparent
        // background; in the default DIB that palette entry is #ff00ff.
        if pixel[..3] == TRANSPARENT_FLAG_RGB.to_array() {
            pixel[3] = 0;
        }
    }
}

fn render_map_preview(
    mut commands: Commands,
    setup: Res<RandomGameSetup>,
    generated_preview: Res<RandomSetupPreview>,
    retail_assets: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut maps: Query<(Entity, &mut RandomSetupMapPreview, Option<&mut ImageNode>)>,
) {
    let state_changed = setup.is_changed() || generated_preview.is_changed();
    for (entity, mut map_preview, image_node) in &mut maps {
        if !state_changed && map_preview.rendered {
            continue;
        }
        map_preview.rendered = true;

        let generated = &generated_preview.0;

        map_preview.palette_indices = compose_preview_indices(generated.map.tiles(), setup.nation);
        let palette = match retail_assets.assets().default_dib_palette() {
            Ok(palette) => palette,
            Err(error) => {
                warn!("could not load the retail random-map preview palette: {error}");
                commands.entity(entity).remove::<ImageNode>();
                continue;
            }
        };
        let image = preview_image(&map_preview.palette_indices, &palette);
        if let Some(mut image_node) = image_node {
            if let Some(mut existing) = images.get_mut(&image_node.image) {
                *existing = image;
            } else {
                image_node.image = images.add(image);
            }
        } else {
            commands
                .entity(entity)
                .insert(ImageNode::new(images.add(image)));
        }
    }
}

fn on_map_preview_click(
    click: On<Pointer<Click>>,
    mut setup: ResMut<RandomGameSetup>,
    maps: Query<(&RelativeCursorPosition, &RandomSetupMapPreview)>,
) {
    let Ok((cursor, map_preview)) = maps.get(click.entity) else {
        return;
    };
    if !cursor.cursor_over() {
        return;
    }
    let Some(normalized) = cursor.normalized else {
        return;
    };
    let Some(nation) = nation_at_preview_position(&map_preview.palette_indices, normalized) else {
        return;
    };
    if setup.nation != nation {
        setup.nation = nation;
    }
}

pub(crate) fn compose_owner_preview_indices(
    owner_at: impl Fn(TileId) -> Option<TileOwnerTag>,
    selected_nation: MajorNationId,
) -> Vec<u8> {
    let mut pixels = vec![OFF_MAP_PALETTE; PREVIEW_PIXEL_COUNT];
    // TMapPreviewView always requests bounded neighbors, even if the selected
    // setup topology wraps horizontally.
    let geometry = MapGeometry::new(MapTopology::Bounded);

    for tile_index in 0..STRATEGIC_TILE_COUNT {
        let tile_id = TileId::new(tile_index as u16);
        let (row, column) = geometry.row_column(tile_id);
        let odd_row = row & 1 != 0;
        let px = 3 * usize::from(column) + usize::from(odd_row);
        let py = 3 * usize::from(row);
        let neighbor_tags = geometry
            .neighbors(tile_id)
            .map(|neighbor| owner_tag(&owner_at, neighbor));
        let self_tag = owner_tag(&owner_at, Some(tile_id));

        let tag = if self_tag == neighbor_tags[5] {
            self_tag
        } else if (odd_row && neighbor_tags[5] == neighbor_tags[4])
            || (!odd_row
                && neighbor_tags[5] == neighbor_tags[0]
                && neighbor_tags[4] == neighbor_tags[0])
        {
            neighbor_tags[5]
        } else {
            PreviewOwner::Border
        };
        write_preview_pixel(&mut pixels, py, px, preview_palette(tag));

        if odd_row {
            let tag = if self_tag == neighbor_tags[5] {
                self_tag
            } else {
                PreviewOwner::Border
            };
            write_preview_pixel(&mut pixels, py, px + 1, preview_palette(tag));
            let tag = if self_tag == neighbor_tags[0]
                || (self_tag == neighbor_tags[1] && self_tag == neighbor_tags[5])
            {
                self_tag
            } else {
                PreviewOwner::Border
            };
            write_preview_pixel(&mut pixels, py, px + 2, preview_palette(tag));
        } else {
            let tag = if self_tag == neighbor_tags[0] || self_tag == neighbor_tags[5] {
                self_tag
            } else {
                PreviewOwner::Border
            };
            write_preview_pixel(&mut pixels, py, px + 1, preview_palette(tag));
            let tag = if self_tag == neighbor_tags[0] {
                self_tag
            } else {
                PreviewOwner::Border
            };
            write_preview_pixel(&mut pixels, py, px + 2, preview_palette(tag));
        }

        let tag = if self_tag == neighbor_tags[4] {
            self_tag
        } else {
            PreviewOwner::Border
        };
        write_preview_pixel(&mut pixels, py + 1, px, preview_palette(tag));
        write_preview_pixel(&mut pixels, py + 2, px, preview_palette(tag));
        let self_palette = preview_palette(self_tag);
        write_preview_pixel(&mut pixels, py + 1, px + 1, self_palette);
        write_preview_pixel(&mut pixels, py + 2, px + 1, self_palette);
        write_preview_pixel(&mut pixels, py + 1, px + 2, self_palette);
        write_preview_pixel(&mut pixels, py + 2, px + 2, self_palette);
    }

    enhance_preview_selection(&mut pixels, selected_nation);
    pixels
}

fn compose_preview_indices(
    tiles: &[imperialism_core::GeneratedTerrainTile],
    selected_nation: MajorNationId,
) -> Vec<u8> {
    compose_owner_preview_indices(|tile| tiles[usize::from(tile.get())].owner, selected_nation)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreviewOwner {
    Border,
    Unowned,
    Tagged(TileOwnerTag),
}

fn owner_tag(
    owner_at: &impl Fn(TileId) -> Option<TileOwnerTag>,
    tile: Option<TileId>,
) -> PreviewOwner {
    match tile {
        Some(tile) => owner_at(tile).map_or(PreviewOwner::Unowned, PreviewOwner::Tagged),
        None => PreviewOwner::Unowned,
    }
}

fn preview_palette(owner: PreviewOwner) -> u8 {
    match owner {
        PreviewOwner::Border => 0,
        PreviewOwner::Unowned => OFF_MAP_PALETTE,
        PreviewOwner::Tagged(tag) => match tag.nation() {
            Some(nation) => match MajorNationId::from_nation(nation) {
                Some(major) => major_nation_palette(major),
                None => 0x0b,
            },
            None => OFF_MAP_PALETTE,
        },
    }
}

fn write_preview_pixel(pixels: &mut [u8], row: usize, column: usize, palette: u8) {
    // The native 324-byte row stride lets the final odd-row hex write x=324,
    // which becomes x=0 on the next visible row. Keep that linear behavior;
    // only the one write past the allocated final row is not visible here.
    if let Some(pixel) = pixels.get_mut(row * PREVIEW_WIDTH + column) {
        *pixel = palette;
    }
}

fn enhance_preview_selection(pixels: &mut [u8], selected_nation: MajorNationId) {
    let selected_palette = major_nation_palette(selected_nation);
    for row in 1..PREVIEW_HEIGHT - 1 {
        for column in 1..PREVIEW_WIDTH - 1 {
            let index = row * PREVIEW_WIDTH + column;
            if !is_selection_maskable(pixels[index]) {
                continue;
            }
            pixels[index] = if pixels[index - 1] == selected_palette
                || pixels[index + 1] == selected_palette
                || pixels[index - PREVIEW_WIDTH] == selected_palette
                || pixels[index + PREVIEW_WIDTH] == selected_palette
            {
                SELECTED_EDGE_PALETTE
            } else {
                0
            };
        }
    }
}

fn is_selection_maskable(palette: u8) -> bool {
    palette == SELECTED_EDGE_PALETTE || matches!(palette, 0 | 2 | 0x0f | 6 | 0x20 | 5 | 0xca)
}

fn major_nation_palette(nation: MajorNationId) -> u8 {
    MAJOR_NATION_PALETTES[usize::from(nation.get())]
}

pub(crate) fn tile_at_preview_position(normalized_position: Vec2) -> Option<TileId> {
    let column_px = ((normalized_position.x + 0.5) * PREVIEW_WIDTH as f32).floor();
    let row_px = ((normalized_position.y + 0.5) * PREVIEW_HEIGHT as f32).floor();
    if !(0.0..PREVIEW_WIDTH as f32).contains(&column_px)
        || !(0.0..PREVIEW_HEIGHT as f32).contains(&row_px)
    {
        return None;
    }
    let row = (row_px as u16) / 3;
    if row >= 60 {
        return None;
    }
    let odd_row = row & 1 != 0;
    let adjusted = column_px as i32 - i32::from(odd_row);
    if adjusted < 0 {
        return None;
    }
    let column = (adjusted as u16) / 3;
    MapGeometry::new(MapTopology::Bounded).tile(row, column)
}

fn nation_at_preview_position(
    palette_indices: &[u8],
    normalized_position: Vec2,
) -> Option<MajorNationId> {
    let column = ((normalized_position.x + 0.5) * PREVIEW_WIDTH as f32).floor();
    let row = ((normalized_position.y + 0.5) * PREVIEW_HEIGHT as f32).floor();
    if !(0.0..PREVIEW_WIDTH as f32).contains(&column)
        || !(0.0..PREVIEW_HEIGHT as f32).contains(&row)
    {
        return None;
    }
    let index = row as usize * PREVIEW_WIDTH + column as usize;
    palette_indices
        .get(index)
        .copied()
        .and_then(nation_for_palette)
}

fn nation_for_palette(palette: u8) -> Option<MajorNationId> {
    MAJOR_NATION_PALETTES
        .iter()
        .position(|candidate| *candidate == palette)
        .map(|nation| MajorNationId::new(nation as u8))
}

pub(crate) fn preview_image_from_indices(palette_indices: &[u8], palette: &DibPalette) -> Image {
    preview_image(palette_indices, palette)
}

fn preview_image(palette_indices: &[u8], palette: &DibPalette) -> Image {
    let mut rgba = Vec::with_capacity(PREVIEW_PIXEL_COUNT * 4);
    for &palette_index in palette_indices {
        // TMapPreviewView uses the QuickDraw transparent blit mode with
        // palette entry 0x10 as its background key.  This is an index-based
        // rule: only that entry is transparent, even if another palette entry
        // happens to share its RGB value.
        let alpha = if palette_index == OFF_MAP_PALETTE {
            0
        } else {
            0xff
        };
        palette[palette_index].write_rgba(alpha, &mut rgba);
    }
    let mut image = Image::new(
        Extent3d {
            width: PREVIEW_WIDTH as u32,
            height: PREVIEW_HEIGHT as u32,
            depth_or_array_layers: 1,
        },
        TextureDimension::D2,
        rgba,
        TextureFormat::Rgba8UnormSrgb,
        RenderAssetUsages::default(),
    );
    image.sampler = ImageSampler::nearest();
    image
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_core::{GeneratedTerrainTile, STRATEGIC_MAP_WIDTH, TerrainKind, TileOwnerTag};

    fn tiles(owner: Option<TileOwnerTag>) -> Vec<GeneratedTerrainTile> {
        vec![
            GeneratedTerrainTile {
                terrain: TerrainKind::Plains,
                river: None,
                owner,
                gate: None,
                province: None,
            };
            STRATEGIC_TILE_COUNT
        ]
    }

    #[test]
    fn renders_major_nation_palette_indices() {
        let pixels =
            compose_preview_indices(&tiles(Some(TileOwnerTag::new(0))), MajorNationId::new(1));

        assert_eq!(pixels.len(), PREVIEW_PIXEL_COUNT);
        assert_eq!(pixels[90 * PREVIEW_WIDTH + 90], 0x16);
    }

    #[test]
    fn selection_enhancement_uses_the_retail_white_palette_index() {
        let mut pixels = vec![OFF_MAP_PALETTE; PREVIEW_PIXEL_COUNT];
        let index = 90 * PREVIEW_WIDTH + 90;
        pixels[index] = 0;
        pixels[index + 1] = major_nation_palette(MajorNationId::new(4));

        enhance_preview_selection(&mut pixels, MajorNationId::new(4));

        assert_eq!(pixels[index], SELECTED_EDGE_PALETTE);
    }

    #[test]
    fn retains_the_native_odd_row_stride_spill() {
        let mut map = tiles(None);
        map[STRATEGIC_MAP_WIDTH as usize + 107].owner = Some(TileOwnerTag::new(0));

        let pixels = compose_preview_indices(&map, MajorNationId::new(1));

        assert_eq!(pixels[5 * PREVIEW_WIDTH], 0x16);
    }

    #[test]
    fn click_sampling_uses_composed_major_palette_indices() {
        let mut pixels = vec![OFF_MAP_PALETTE; PREVIEW_PIXEL_COUNT];
        pixels[PREVIEW_WIDTH + 1] = major_nation_palette(MajorNationId::new(4));

        assert_eq!(
            nation_at_preview_position(
                &pixels,
                Vec2::new(
                    -0.5 + 1.5 / PREVIEW_WIDTH as f32,
                    -0.5 + 1.5 / PREVIEW_HEIGHT as f32
                )
            ),
            Some(MajorNationId::new(4))
        );
        assert_eq!(
            nation_at_preview_position(&pixels, Vec2::new(0.5, 0.0)),
            None
        );
        assert_eq!(nation_for_palette(SELECTED_EDGE_PALETTE), None);
    }

    #[test]
    fn preview_image_keys_only_the_retail_off_map_palette_entry() {
        let mut palette = DibPalette::default();
        palette[OFF_MAP_PALETTE] = Rgb::new(0xff, 0, 0xff);
        palette[0] = Rgb::new(0, 0, 0);
        palette[SELECTED_EDGE_PALETTE] = Rgb::new(0xff, 0xff, 0xff);
        palette[0x16] = Rgb::new(0x57, 0x8b, 0xa6);
        let mut indices = vec![0x16; PREVIEW_PIXEL_COUNT];
        indices[..4].copy_from_slice(&[OFF_MAP_PALETTE, 0, SELECTED_EDGE_PALETTE, 0x16]);
        let image = preview_image(&indices, &palette);

        assert_eq!(image.texture_descriptor.size.width, PREVIEW_WIDTH as u32);
        assert_eq!(image.texture_descriptor.size.height, PREVIEW_HEIGHT as u32);
        assert_eq!(
            image.data.as_ref().unwrap()[..16],
            [
                0xff, 0, 0xff, 0, // off-map transparent key
                0, 0, 0, 0xff, // contested/border black
                0xff, 0xff, 0xff, 0xff, // selected white edge
                0x57, 0x8b, 0xa6, 0xff, // major nation
            ]
        );
        assert_eq!(image.sampler, ImageSampler::nearest());
    }

    #[test]
    fn selected_nation_uses_the_retail_coat_picture_range() {
        assert_eq!(
            coat_picture_id(MajorNationId::new(0)),
            PictureId::new(0x11c6)
        );
        assert_eq!(
            coat_picture_id(MajorNationId::new(6)),
            PictureId::new(0x11cc)
        );
    }

    #[test]
    fn flag_atlas_transparency_keys_retail_magenta() {
        let pixels = vec![0xff_u8, 0x00, 0xff, 0xff, 0x11, 0x22, 0x33, 0xff];
        let mut image = Image::new(
            Extent3d {
                width: 2,
                height: 1,
                depth_or_array_layers: 1,
            },
            TextureDimension::D2,
            pixels,
            TextureFormat::Rgba8UnormSrgb,
            RenderAssetUsages::default(),
        );
        apply_flag_atlas_transparency(&mut image);
        assert_eq!(&image.data.as_ref().unwrap()[..4], &[0xff, 0, 0xff, 0]);
        assert_eq!(
            &image.data.as_ref().unwrap()[4..],
            &[0x11, 0x22, 0x33, 0xff]
        );
    }
}
