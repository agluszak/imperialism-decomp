use super::runtime::SpawnedView;
use super::startup::{RandomGameSetup, RandomSetupPreview, random_setup_view_id};
use crate::{AppState, RetailAssetsResource};
use bevy::asset::RenderAssetUsages;
use bevy::image::{CompressedImageFormats, ImageFormat, ImageSampler, ImageType};
use bevy::log::warn;
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use bevy::ui::RelativeCursorPosition;
use imperialism_core::{MajorNationId, MapGeometry, STRATEGIC_TILE_COUNT, TileId};
use imperialism_formats::{DibPalette, PaletteIndex, Rgb, UiView as CatalogView};

const MAP_TAG: &str = "map ";
const COAT_TAG: &str = "coat";
const FLAG_TAG: &str = "flag";
const FIRST_MAJOR_NATION_COAT_PICTURE: i16 = 0x11c6;
const FLAG_ATLAS_PICTURE: i16 = 8699;
const FLAG_WIDTH: usize = 32;
const FLAG_HEIGHT: usize = 24;
const TRANSPARENT_FLAG_RGB: Rgb = Rgb::new(0xff, 0, 0xff);
const PREVIEW_WIDTH: usize = 324;
const PREVIEW_HEIGHT: usize = 180;
const PREVIEW_PIXEL_COUNT: usize = PREVIEW_WIDTH * PREVIEW_HEIGHT;
const OFF_MAP_PALETTE: PaletteIndex = PaletteIndex::new(0x10);
const SELECTED_EDGE_PALETTE: PaletteIndex = PaletteIndex::new(0x13);
const MAJOR_NATION_PALETTES: [PaletteIndex; MajorNationId::COUNT as usize] = [
    PaletteIndex::new(0x16),
    PaletteIndex::new(0x2a),
    PaletteIndex::new(0x22),
    PaletteIndex::new(0x1c),
    PaletteIndex::new(0x2b),
    PaletteIndex::new(0x1e),
    PaletteIndex::new(0x2e),
];

/// The retail 8-bit map surface retained for both display and click sampling.
#[derive(Component, Default)]
struct RandomSetupMapPreview {
    palette_indices: Vec<PaletteIndex>,
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
                .chain(),
        )
        .add_systems(Update, select_nation_from_map_preview);
    }
}

/// Attach map/coat/flag components once when the random-setup screen is created.
pub(crate) fn attach_random_setup_widgets(
    commands: &mut Commands,
    view: &CatalogView,
    spawned: &SpawnedView,
) {
    debug_assert_eq!(view.id, random_setup_view_id());
    if let Some(entity) = spawned.tagged(view, MAP_TAG) {
        commands.entity(entity).insert((
            RandomSetupMapPreview::default(),
            RelativeCursorPosition::default(),
        ));
    }
    if let Some(entity) = spawned.tagged(view, COAT_TAG) {
        commands.entity(entity).insert(RandomSetupCoat::default());
    }
    if let Some(entity) = spawned.tagged(view, FLAG_TAG) {
        commands.entity(entity).insert(RandomSetupFlag::default());
    }
}

fn sync_random_setup_coat(
    setup: Res<RandomGameSetup>,
    retail_assets: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut coats: Query<(&mut RandomSetupCoat, &mut ImageNode)>,
) {
    for (mut coat, mut image_node) in &mut coats {
        if coat.nation == Some(setup.nation) {
            continue;
        }
        let picture_id = coat_picture_id(setup.nation);
        let bytes = match retail_assets.assets().picture(picture_id, 0) {
            Ok(bytes) => bytes,
            Err(error) => {
                warn!("could not load retail setup coat picture {picture_id}: {error}");
                continue;
            }
        };
        let image = match Image::from_buffer(
            &bytes,
            ImageType::Format(ImageFormat::Bmp),
            CompressedImageFormats::NONE,
            true,
            ImageSampler::nearest(),
            RenderAssetUsages::default(),
        ) {
            Ok(image) => image,
            Err(error) => {
                warn!("could not decode retail setup coat picture {picture_id}: {error}");
                continue;
            }
        };
        image_node.image = images.add(image);
        coat.nation = Some(setup.nation);
    }
}

fn coat_picture_id(nation: MajorNationId) -> i16 {
    FIRST_MAJOR_NATION_COAT_PICTURE + i16::from(nation.get())
}

fn sync_random_setup_flag(
    mut commands: Commands,
    setup: Res<RandomGameSetup>,
    retail_assets: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut flags: Query<(Entity, &mut RandomSetupFlag, Option<&mut ImageNode>)>,
) {
    for (entity, mut flag, image_node) in &mut flags {
        if flag.nation == Some(setup.nation) {
            continue;
        }
        let bytes = match retail_assets.assets().picture(FLAG_ATLAS_PICTURE, 0) {
            Ok(bytes) => bytes,
            Err(error) => {
                warn!("could not load retail setup flag atlas {FLAG_ATLAS_PICTURE}: {error}");
                continue;
            }
        };
        let atlas = match Image::from_buffer(
            &bytes,
            ImageType::Format(ImageFormat::Bmp),
            CompressedImageFormats::NONE,
            true,
            ImageSampler::nearest(),
            RenderAssetUsages::default(),
        ) {
            Ok(image) => image,
            Err(error) => {
                warn!("could not decode retail setup flag atlas {FLAG_ATLAS_PICTURE}: {error}");
                continue;
            }
        };
        let image = match crop_setup_flag(&atlas, setup.nation) {
            Ok(image) => image,
            Err(error) => {
                warn!("could not crop retail setup flag atlas {FLAG_ATLAS_PICTURE}: {error}");
                continue;
            }
        };
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
        flag.nation = Some(setup.nation);
    }
}

fn crop_setup_flag(atlas: &Image, nation: MajorNationId) -> Result<Image, &'static str> {
    if atlas.texture_descriptor.dimension != TextureDimension::D2
        || atlas.texture_descriptor.size.depth_or_array_layers != 1
        || atlas.texture_descriptor.format != TextureFormat::Rgba8UnormSrgb
    {
        return Err("flag atlas is not a single RGBA 2D image");
    }
    let width = atlas.texture_descriptor.size.width as usize;
    let height = atlas.texture_descriptor.size.height as usize;
    let left = usize::from(nation.get()) * FLAG_WIDTH;
    if width < left + FLAG_WIDTH || height < FLAG_HEIGHT {
        return Err("flag atlas does not contain the selected 32 by 24 cell");
    }
    let source = atlas.data.as_deref().ok_or("flag atlas has no pixels")?;
    if source.len() < width * height * 4 {
        return Err("flag atlas pixels are truncated");
    }

    let mut pixels = Vec::with_capacity(FLAG_WIDTH * FLAG_HEIGHT * 4);
    for row in 0..FLAG_HEIGHT {
        let start = (row * width + left) * 4;
        let end = start + FLAG_WIDTH * 4;
        pixels.extend_from_slice(&source[start..end]);
    }
    for pixel in pixels.chunks_exact_mut(4) {
        // TGWorldPartView blits with palette index 0x10 as its transparent
        // background; in the default DIB that palette entry is #ff00ff.
        if pixel[..3] == TRANSPARENT_FLAG_RGB.to_array() {
            pixel[3] = 0;
        }
    }

    let mut image = Image::new(
        Extent3d {
            width: FLAG_WIDTH as u32,
            height: FLAG_HEIGHT as u32,
            depth_or_array_layers: 1,
        },
        TextureDimension::D2,
        pixels,
        TextureFormat::Rgba8UnormSrgb,
        RenderAssetUsages::default(),
    );
    image.sampler = ImageSampler::nearest();
    Ok(image)
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

        let Some(generated) = generated_preview.preview.as_ref() else {
            map_preview.palette_indices.clear();
            if image_node.is_some() {
                commands.entity(entity).remove::<ImageNode>();
            }
            continue;
        };

        map_preview.palette_indices = compose_preview_indices(&generated.map.tiles, setup.nation);
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

fn select_nation_from_map_preview(
    state: Res<State<AppState>>,
    mut setup: ResMut<RandomGameSetup>,
    maps: Query<
        (
            &Interaction,
            &RelativeCursorPosition,
            &RandomSetupMapPreview,
        ),
        Changed<Interaction>,
    >,
) {
    if *state.get() != AppState::RandomSetup {
        return;
    }
    for (interaction, cursor, map_preview) in &maps {
        if *interaction != Interaction::Pressed || !cursor.cursor_over() {
            continue;
        }
        let Some(normalized) = cursor.normalized else {
            continue;
        };
        let Some(nation) = nation_at_preview_position(&map_preview.palette_indices, normalized)
        else {
            continue;
        };
        if setup.nation != nation {
            setup.nation = nation;
        }
    }
}

fn compose_preview_indices(
    tiles: &[imperialism_core::GeneratedTerrainTile],
    selected_nation: MajorNationId,
) -> Vec<PaletteIndex> {
    let mut pixels = vec![OFF_MAP_PALETTE; PREVIEW_PIXEL_COUNT];
    // TMapPreviewView always requests bounded neighbors, even if the selected
    // setup topology wraps horizontally.
    let geometry = MapGeometry::new(false);

    for tile_index in 0..STRATEGIC_TILE_COUNT {
        let tile_id = TileId::new(tile_index as u16);
        let (row, column) = geometry
            .row_column(tile_id)
            .expect("the strategic tile loop stays in the retail map bounds");
        let odd_row = row & 1 != 0;
        let px = 3 * usize::from(column) + usize::from(odd_row);
        let py = 3 * usize::from(row);
        let neighbor_tags = geometry
            .neighbors(tile_id)
            .map(|neighbor| owner_tag(tiles, neighbor));
        let self_tag = owner_tag(tiles, Some(tile_id));

        let tag = if self_tag == neighbor_tags[5] {
            self_tag
        } else if (odd_row && neighbor_tags[5] == neighbor_tags[4])
            || (!odd_row
                && neighbor_tags[5] == neighbor_tags[0]
                && neighbor_tags[4] == neighbor_tags[0])
        {
            neighbor_tags[5]
        } else {
            -2
        };
        write_preview_pixel(&mut pixels, py, px, preview_palette(tag));

        if odd_row {
            let tag = if self_tag == neighbor_tags[5] {
                self_tag
            } else {
                -2
            };
            write_preview_pixel(&mut pixels, py, px + 1, preview_palette(tag));
            let tag = if self_tag == neighbor_tags[0]
                || (self_tag == neighbor_tags[1] && self_tag == neighbor_tags[5])
            {
                self_tag
            } else {
                -2
            };
            write_preview_pixel(&mut pixels, py, px + 2, preview_palette(tag));
        } else {
            let tag = if self_tag == neighbor_tags[0] || self_tag == neighbor_tags[5] {
                self_tag
            } else {
                -2
            };
            write_preview_pixel(&mut pixels, py, px + 1, preview_palette(tag));
            let tag = if self_tag == neighbor_tags[0] {
                self_tag
            } else {
                -2
            };
            write_preview_pixel(&mut pixels, py, px + 2, preview_palette(tag));
        }

        let tag = if self_tag == neighbor_tags[4] {
            self_tag
        } else {
            -2
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

fn owner_tag(tiles: &[imperialism_core::GeneratedTerrainTile], tile: Option<TileId>) -> i8 {
    tile.and_then(|tile| tiles.get(usize::from(tile.get())))
        .map_or(-1, |tile| tile.owner_nation)
}

fn preview_palette(owner_tag: i8) -> PaletteIndex {
    let owner_tag = if (7..0x17).contains(&owner_tag) {
        0x0b
    } else if owner_tag >= 0x17 {
        -1
    } else {
        owner_tag
    };
    match owner_tag {
        -2 => PaletteIndex::new(0),
        -1 => OFF_MAP_PALETTE,
        0..=6 => MAJOR_NATION_PALETTES[owner_tag as usize],
        7 => PaletteIndex::new(0x0a),
        8 => PaletteIndex::new(0x0b),
        9 => PaletteIndex::new(0x0d),
        10 => PaletteIndex::new(0x29),
        11 => PaletteIndex::new(0xde),
        12 => PaletteIndex::new(0xdf),
        13 => PaletteIndex::new(0xfa),
        14 => PaletteIndex::new(0x2c),
        15 => PaletteIndex::new(0x31),
        16 => PaletteIndex::new(0x33),
        17 => PaletteIndex::new(0x41),
        18 => PaletteIndex::new(0x48),
        19 => PaletteIndex::new(0xd0),
        20 => PaletteIndex::new(0xcd),
        21 => PaletteIndex::new(0xce),
        22 => PaletteIndex::new(0xcf),
        _ => PaletteIndex::new(0xff),
    }
}

fn write_preview_pixel(
    pixels: &mut [PaletteIndex],
    row: usize,
    column: usize,
    palette: PaletteIndex,
) {
    // The native 324-byte row stride lets the final odd-row hex write x=324,
    // which becomes x=0 on the next visible row. Keep that linear behavior;
    // only the one write past the allocated final row is not visible here.
    if let Some(pixel) = pixels.get_mut(row * PREVIEW_WIDTH + column) {
        *pixel = palette;
    }
}

fn enhance_preview_selection(pixels: &mut [PaletteIndex], selected_nation: MajorNationId) {
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
                PaletteIndex::new(0)
            };
        }
    }
}

fn is_selection_maskable(palette: PaletteIndex) -> bool {
    palette == SELECTED_EDGE_PALETTE || matches!(palette.get(), 0 | 2 | 0x0f | 6 | 0x20 | 5 | 0xca)
}

fn major_nation_palette(nation: MajorNationId) -> PaletteIndex {
    MAJOR_NATION_PALETTES[usize::from(nation.get())]
}

fn nation_at_preview_position(
    palette_indices: &[PaletteIndex],
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

fn nation_for_palette(palette: PaletteIndex) -> Option<MajorNationId> {
    MAJOR_NATION_PALETTES
        .iter()
        .position(|candidate| *candidate == palette)
        .map(|nation| MajorNationId::new(nation as u8))
}

fn preview_image(palette_indices: &[PaletteIndex], palette: &DibPalette) -> Image {
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
    use imperialism_core::{GeneratedTerrainTile, STRATEGIC_MAP_WIDTH};

    fn tiles(owner: i8) -> Vec<GeneratedTerrainTile> {
        vec![
            GeneratedTerrainTile {
                terrain_kind: 0,
                river_sprite_code: 0,
                owner_nation: owner,
                gate_flag: -1,
                province_index: -1,
            };
            STRATEGIC_TILE_COUNT
        ]
    }

    #[test]
    fn renders_major_nation_palette_indices() {
        let pixels = compose_preview_indices(&tiles(0), MajorNationId::new(1));

        assert_eq!(pixels.len(), PREVIEW_PIXEL_COUNT);
        assert_eq!(pixels[90 * PREVIEW_WIDTH + 90], PaletteIndex::new(0x16));
    }

    #[test]
    fn selection_enhancement_uses_the_retail_white_palette_index() {
        let mut pixels = vec![OFF_MAP_PALETTE; PREVIEW_PIXEL_COUNT];
        let index = 90 * PREVIEW_WIDTH + 90;
        pixels[index] = PaletteIndex::new(0);
        pixels[index + 1] = major_nation_palette(MajorNationId::new(4));

        enhance_preview_selection(&mut pixels, MajorNationId::new(4));

        assert_eq!(pixels[index], SELECTED_EDGE_PALETTE);
    }

    #[test]
    fn retains_the_native_odd_row_stride_spill() {
        let mut map = tiles(-1);
        map[STRATEGIC_MAP_WIDTH as usize + 107].owner_nation = 0;

        let pixels = compose_preview_indices(&map, MajorNationId::new(1));

        assert_eq!(pixels[5 * PREVIEW_WIDTH], PaletteIndex::new(0x16));
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
        let mut indices = vec![PaletteIndex::new(0x16); PREVIEW_PIXEL_COUNT];
        indices[..4].copy_from_slice(&[
            OFF_MAP_PALETTE,
            PaletteIndex::new(0),
            SELECTED_EDGE_PALETTE,
            PaletteIndex::new(0x16),
        ]);
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
        assert_eq!(coat_picture_id(MajorNationId::new(0)), 0x11c6);
        assert_eq!(coat_picture_id(MajorNationId::new(6)), 0x11cc);
    }

    #[test]
    fn crops_the_selected_flag_cell_and_keys_retail_magenta() {
        let atlas_width = FLAG_WIDTH * 2;
        let mut pixels = vec![0; atlas_width * FLAG_HEIGHT * 4];
        for row in 0..FLAG_HEIGHT {
            for column in 0..atlas_width {
                let offset = (row * atlas_width + column) * 4;
                pixels[offset..offset + 4].copy_from_slice(&[column as u8, row as u8, 0x7f, 0xff]);
            }
        }
        pixels[(FLAG_WIDTH * 4)..(FLAG_WIDTH * 4 + 4)].copy_from_slice(&[0xff, 0, 0xff, 0xff]);
        let atlas = Image::new(
            Extent3d {
                width: atlas_width as u32,
                height: FLAG_HEIGHT as u32,
                depth_or_array_layers: 1,
            },
            TextureDimension::D2,
            pixels,
            TextureFormat::Rgba8UnormSrgb,
            RenderAssetUsages::default(),
        );

        let flag = crop_setup_flag(&atlas, MajorNationId::new(1)).unwrap();

        assert_eq!(flag.texture_descriptor.size.width, FLAG_WIDTH as u32);
        assert_eq!(flag.texture_descriptor.size.height, FLAG_HEIGHT as u32);
        assert_eq!(&flag.data.as_ref().unwrap()[..4], &[0xff, 0, 0xff, 0]);
        assert_eq!(&flag.data.as_ref().unwrap()[4..8], &[33, 0, 0x7f, 0xff]);
        assert_eq!(flag.sampler, ImageSampler::nearest());

        let short_atlas = Image::new(
            Extent3d {
                width: FLAG_WIDTH as u32,
                height: FLAG_HEIGHT as u32,
                depth_or_array_layers: 1,
            },
            TextureDimension::D2,
            vec![0; FLAG_WIDTH * FLAG_HEIGHT * 4],
            TextureFormat::Rgba8UnormSrgb,
            RenderAssetUsages::default(),
        );
        assert!(crop_setup_flag(&short_atlas, MajorNationId::new(1)).is_err());
    }
}
