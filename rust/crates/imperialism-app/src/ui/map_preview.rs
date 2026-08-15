use bevy::asset::RenderAssetUsages;
use bevy::image::ImageSampler;
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use imperialism_core::{
    MAJOR_NATION_COUNT, MajorNationId, MapGeometry, MapTopology, NationId, TileId, TileOwnerTag,
};
use imperialism_formats::{DibPalette, Rgb};

pub(crate) const PREVIEW_WIDTH: usize = 324;
pub(crate) const PREVIEW_HEIGHT: usize = 180;
pub(crate) const PREVIEW_PIXEL_COUNT: usize = PREVIEW_WIDTH * PREVIEW_HEIGHT;
pub(crate) const OFF_MAP_PALETTE: u8 = 0x10;
const SELECTED_EDGE_PALETTE: u8 = 0x13;
const MAJOR_NATION_PALETTES: [u8; MAJOR_NATION_COUNT] = [0x16, 0x2a, 0x22, 0x1c, 0x2b, 0x1e, 0x2e];

pub(crate) fn compose_owner_preview_indices(
    owner_at: impl Fn(TileId) -> Option<TileOwnerTag>,
    selected_nation: NationId,
) -> Vec<u8> {
    compose_owner_preview_indices_with_fill(owner_at, selected_nation, nation_owner_palette)
}

pub(crate) fn compose_owner_preview_indices_with_fill(
    owner_at: impl Fn(TileId) -> Option<TileOwnerTag>,
    selected_nation: NationId,
    fill: impl Fn(NationId) -> u8,
) -> Vec<u8> {
    let mut pixels = vec![OFF_MAP_PALETTE; PREVIEW_PIXEL_COUNT];
    let mut pixel_owners = vec![None; PREVIEW_PIXEL_COUNT];
    // TMapPreviewView always requests bounded neighbors, even if the selected
    // setup topology wraps horizontally.
    let geometry = MapGeometry::new(MapTopology::Bounded);

    for tile_id in TileId::all() {
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
        write_preview_pixel(&mut pixels, &mut pixel_owners, py, px, tag, &fill);

        if odd_row {
            let tag = if self_tag == neighbor_tags[5] {
                self_tag
            } else {
                PreviewOwner::Border
            };
            write_preview_pixel(&mut pixels, &mut pixel_owners, py, px + 1, tag, &fill);
            let tag = if self_tag == neighbor_tags[0]
                || (self_tag == neighbor_tags[1] && self_tag == neighbor_tags[5])
            {
                self_tag
            } else {
                PreviewOwner::Border
            };
            write_preview_pixel(&mut pixels, &mut pixel_owners, py, px + 2, tag, &fill);
        } else {
            let tag = if self_tag == neighbor_tags[0] || self_tag == neighbor_tags[5] {
                self_tag
            } else {
                PreviewOwner::Border
            };
            write_preview_pixel(&mut pixels, &mut pixel_owners, py, px + 1, tag, &fill);
            let tag = if self_tag == neighbor_tags[0] {
                self_tag
            } else {
                PreviewOwner::Border
            };
            write_preview_pixel(&mut pixels, &mut pixel_owners, py, px + 2, tag, &fill);
        }

        let tag = if self_tag == neighbor_tags[4] {
            self_tag
        } else {
            PreviewOwner::Border
        };
        write_preview_pixel(&mut pixels, &mut pixel_owners, py + 1, px, tag, &fill);
        write_preview_pixel(&mut pixels, &mut pixel_owners, py + 2, px, tag, &fill);
        write_preview_pixel(
            &mut pixels,
            &mut pixel_owners,
            py + 1,
            px + 1,
            self_tag,
            &fill,
        );
        write_preview_pixel(
            &mut pixels,
            &mut pixel_owners,
            py + 2,
            px + 1,
            self_tag,
            &fill,
        );
        write_preview_pixel(
            &mut pixels,
            &mut pixel_owners,
            py + 1,
            px + 2,
            self_tag,
            &fill,
        );
        write_preview_pixel(
            &mut pixels,
            &mut pixel_owners,
            py + 2,
            px + 2,
            self_tag,
            &fill,
        );
    }

    enhance_preview_selection(&mut pixels, &pixel_owners, selected_nation);
    pixels
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

fn preview_palette(owner: PreviewOwner, fill: &impl Fn(NationId) -> u8) -> u8 {
    match owner {
        PreviewOwner::Border => 0,
        PreviewOwner::Unowned => OFF_MAP_PALETTE,
        PreviewOwner::Tagged(tag) => match tag.nation() {
            Some(nation) => fill(nation),
            None => OFF_MAP_PALETTE,
        },
    }
}

fn nation_owner_palette(nation: NationId) -> u8 {
    match MajorNationId::from_nation(nation) {
        Some(major) => major_nation_palette(major),
        None => 0x0b,
    }
}

fn write_preview_pixel(
    pixels: &mut [u8],
    pixel_owners: &mut [Option<NationId>],
    row: usize,
    column: usize,
    owner: PreviewOwner,
    fill: &impl Fn(NationId) -> u8,
) {
    // The native 324-byte row stride lets the final odd-row hex write x=324,
    // which becomes x=0 on the next visible row. Keep that linear behavior;
    // only the one write past the allocated final row is not visible here.
    let index = row * PREVIEW_WIDTH + column;
    if let Some(pixel) = pixels.get_mut(index) {
        *pixel = preview_palette(owner, fill);
        pixel_owners[index] = match owner {
            PreviewOwner::Tagged(tag) => tag.nation(),
            PreviewOwner::Border | PreviewOwner::Unowned => None,
        };
    }
}

fn enhance_preview_selection(
    pixels: &mut [u8],
    pixel_owners: &[Option<NationId>],
    selected_nation: NationId,
) {
    for row in 1..PREVIEW_HEIGHT - 1 {
        for column in 1..PREVIEW_WIDTH - 1 {
            let index = row * PREVIEW_WIDTH + column;
            if !is_selection_maskable(pixels[index]) {
                continue;
            }
            pixels[index] = if pixel_owners[index - 1] == Some(selected_nation)
                || pixel_owners[index + 1] == Some(selected_nation)
                || pixel_owners[index - PREVIEW_WIDTH] == Some(selected_nation)
                || pixel_owners[index + PREVIEW_WIDTH] == Some(selected_nation)
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

pub(crate) fn major_nation_palette(nation: MajorNationId) -> u8 {
    MAJOR_NATION_PALETTES[usize::from(nation.get())]
}

pub(crate) fn preview_image_from_indices(palette_indices: &[u8], palette: &DibPalette) -> Image {
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
    use imperialism_core::{STRATEGIC_MAP_WIDTH, STRATEGIC_TILE_COUNT, TileOwnerTag};

    fn owners(owner: Option<TileOwnerTag>) -> Vec<Option<TileOwnerTag>> {
        vec![owner; STRATEGIC_TILE_COUNT]
    }

    fn compose(owners: &[Option<TileOwnerTag>], selected: NationId) -> Vec<u8> {
        compose_owner_preview_indices(|tile| owners[usize::from(tile.get())], selected)
    }

    #[test]
    fn renders_major_nation_palette_indices() {
        let pixels = compose(
            &owners(Some(TileOwnerTag::new(0))),
            MajorNationId::new(1).nation(),
        );

        assert_eq!(pixels.len(), PREVIEW_PIXEL_COUNT);
        assert_eq!(pixels[90 * PREVIEW_WIDTH + 90], 0x16);
    }

    #[test]
    fn selection_enhancement_uses_the_retail_white_palette_index() {
        let mut pixels = vec![OFF_MAP_PALETTE; PREVIEW_PIXEL_COUNT];
        let index = 90 * PREVIEW_WIDTH + 90;
        pixels[index] = 0;
        pixels[index + 1] = major_nation_palette(MajorNationId::new(4));
        let mut pixel_owners = vec![None; PREVIEW_PIXEL_COUNT];
        pixel_owners[index + 1] = Some(MajorNationId::new(4).nation());

        enhance_preview_selection(&mut pixels, &pixel_owners, MajorNationId::new(4).nation());

        assert_eq!(pixels[index], SELECTED_EDGE_PALETTE);
    }

    #[test]
    fn retains_the_native_odd_row_stride_spill() {
        let mut map = owners(None);
        map[STRATEGIC_MAP_WIDTH as usize + 107] = Some(TileOwnerTag::new(0));

        let pixels = compose(&map, MajorNationId::new(1).nation());

        assert_eq!(pixels[5 * PREVIEW_WIDTH], 0x16);
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
        let image = preview_image_from_indices(&indices, &palette);

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
}
