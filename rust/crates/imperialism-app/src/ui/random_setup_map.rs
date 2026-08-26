use super::RetailUiAssets;
use super::random_setup::{RandomGameSetup, RandomSetupPreview};
use super::retail::RetailTree;
use super::satellite_preview::SatellitePreview;
use crate::RetailAssetsResource;
use bevy::log::warn;
use bevy::math::Rect;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::RelativeCursorPosition;
use imperialism_core::MajorNationId;
use imperialism_formats::{FourCc, PictureId, fourcc};

const MAP_TAG: FourCc = fourcc!("map ");
const COAT_TAG: FourCc = fourcc!("coat");
const FLAG_TAG: FourCc = fourcc!("flag");
const FIRST_MAJOR_NATION_COAT_PICTURE: i16 = 0x11c6;
const FLAG_ATLAS_PICTURE: PictureId = PictureId::new(8699);
const FLAG_WIDTH: usize = 32;
const FLAG_HEIGHT: usize = 24;
const OFF_MAP_PALETTE: u8 = 0x10;

/// The retail 8-bit map surface retained for both display and click sampling.
#[derive(Component, Default)]
struct RandomSetupMapPreview {
    preview: SatellitePreview,
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
    tree: &RetailTree,
) {
    let map = tree.find(root, MAP_TAG);
    commands
        .entity(map)
        .insert((
            RandomSetupMapPreview::default(),
            RelativeCursorPosition::default(),
        ))
        .observe(on_map_preview_click);
    let coat = tree.find(root, COAT_TAG);
    commands.entity(coat).insert(RandomSetupCoat::default());
    let flag = tree.find(root, FLAG_TAG);
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
    mut transparent_atlas: Local<Option<Handle<Image>>>,
) {
    let added = flags.iter_mut().any(|(_, flag, _)| flag.is_added());
    if !setup.is_changed() && !added {
        return;
    }
    let handle = if let Some(handle) = transparent_atlas.clone() {
        handle
    } else {
        match pictures.transparent_picture(FLAG_ATLAS_PICTURE, OFF_MAP_PALETTE) {
            Ok(handle) => {
                *transparent_atlas = Some(handle.clone());
                handle
            }
            Err(error) => {
                warn!(
                    "could not apply transparency to retail setup flag atlas {:?}: {error}",
                    FLAG_ATLAS_PICTURE
                );
                return;
            }
        }
    };

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

        map_preview.preview = compose_preview(generated.map.tiles(), setup.nation);
        let palette = retail_assets.assets().default_dib_palette();
        let image = map_preview.preview.to_image(palette);
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
    let Some(nation) = map_preview.preview.major_nation_at(normalized) else {
        return;
    };
    if setup.nation != nation {
        setup.nation = nation;
    }
}

fn compose_preview(
    tiles: &[imperialism_core::GeneratedTerrainTile],
    selected_nation: MajorNationId,
) -> SatellitePreview {
    let mut preview = SatellitePreview::compose(|tile| tiles[usize::from(tile.get())].owner);
    preview.enhance(selected_nation.nation());
    preview
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
