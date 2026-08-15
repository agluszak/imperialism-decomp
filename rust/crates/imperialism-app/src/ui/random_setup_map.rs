use super::RetailUiAssets;
use super::map_preview::{
    PREVIEW_HEIGHT, PREVIEW_WIDTH, compose_owner_preview_indices, major_nation_palette,
    preview_image_from_indices,
};
use super::random_setup::{RandomGameSetup, RandomSetupPreview};
use super::retail::{RetailTag, find_descendant};
use crate::RetailAssetsResource;
use bevy::log::warn;
use bevy::math::Rect;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::RelativeCursorPosition;
use imperialism_core::MajorNationId;
use imperialism_formats::{FourCc, PictureId, Rgb, fourcc};

const MAP_TAG: FourCc = fourcc!("map ");
const COAT_TAG: FourCc = fourcc!("coat");
const FLAG_TAG: FourCc = fourcc!("flag");
const FIRST_MAJOR_NATION_COAT_PICTURE: i16 = 0x11c6;
const FLAG_ATLAS_PICTURE: PictureId = PictureId::new(8699);
const FLAG_WIDTH: usize = 32;
const FLAG_HEIGHT: usize = 24;
const TRANSPARENT_FLAG_RGB: Rgb = Rgb::new(0xff, 0, 0xff);

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
        );
    }
}

/// Attach map/coat/flag screen meanings once when random-setup is created.
pub(crate) fn attach_random_setup_meanings(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) {
    // PointerCanvas behavior already adds RelativeCursorPosition for the map.
    let map = find_descendant(root, MAP_TAG, children, tags);
    commands
        .entity(map)
        .insert(RandomSetupMapPreview::default())
        .observe(on_map_preview_click);
    let coat = find_descendant(root, COAT_TAG, children, tags);
    commands.entity(coat).insert(RandomSetupCoat::default());
    let flag = find_descendant(root, FLAG_TAG, children, tags);
    commands.entity(flag).insert(RandomSetupFlag::default());
}

fn sync_random_setup_coat(
    setup: Res<RandomGameSetup>,
    mut pictures: RetailUiAssets,
    mut coats: Query<(&mut RandomSetupCoat, &mut ImageNode)>,
) {
    let added = coats.iter_mut().any(|(coat, _)| coat.is_added());
    if !setup.is_changed() && !added {
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
    mut pictures: RetailUiAssets,
    mut flags: Query<(Entity, &mut RandomSetupFlag, Option<&mut ImageNode>)>,
    mut atlas_transparency_applied: Local<bool>,
) {
    let added = flags.iter_mut().any(|(_, flag, _)| flag.is_added());
    if !setup.is_changed() && !added {
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
        let palette = retail_assets.assets().default_dib_palette();
        let image = preview_image_from_indices(&map_preview.palette_indices, palette);
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
    let (cursor, map_preview) = maps
        .get(click.entity)
        .expect("map preview click is bound on RandomSetupMapPreview");
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

fn compose_preview_indices(
    tiles: &[imperialism_core::GeneratedTerrainTile],
    selected_nation: MajorNationId,
) -> Vec<u8> {
    compose_owner_preview_indices(
        |tile| tiles[usize::from(tile.get())].owner,
        selected_nation.nation(),
    )
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
    MajorNationId::all().find(|&nation| major_nation_palette(nation) == palette)
}

#[cfg(test)]
mod tests {
    use super::super::map_preview::{OFF_MAP_PALETTE, PREVIEW_PIXEL_COUNT};
    use super::*;
    use bevy::asset::RenderAssetUsages;
    use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};

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
        assert_eq!(nation_for_palette(0x13), None);
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
