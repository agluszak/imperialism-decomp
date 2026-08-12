use crate::RetailAssetsResource;
use bevy::asset::RenderAssetUsages;
use bevy::ecs::system::SystemParam;
use bevy::image::{CompressedImageFormats, ImageSampler, ImageType, TextureError};
use bevy::prelude::*;
use bevy::ui::{Checked, Pressed};
use imperialism_formats::*;
use std::collections::HashMap;

/// Provenance tag recovered from the retail View resource.
#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetailTag(pub FourCc);

/// Images displayed by a retail picture control in its resting and active states.
#[derive(Component, Clone, Debug)]
pub struct RetailPictureSwap {
    pub idle: Handle<Image>,
    pub active: Handle<Image>,
}

#[derive(Debug, thiserror::Error)]
pub enum RetailTextError {
    #[error(transparent)]
    Style(#[from] RetailTextStyleError),
    #[error(transparent)]
    Assets(#[from] RetailAssetError),
}

#[derive(Debug, thiserror::Error)]
pub enum RetailPictureError {
    #[error(transparent)]
    Assets(#[from] RetailAssetError),
    #[error("could not decode retail picture {picture_id}: {source}")]
    BmpDecode {
        picture_id: PictureId,
        #[source]
        source: TextureError,
    },
}

#[derive(Resource, Default)]
struct RetailPictureHandles(HashMap<PictureId, Handle<Image>>);

#[derive(Resource, Default)]
struct RetailFontHandles(HashMap<RetailFontFace, Handle<Font>>);

#[derive(SystemParam)]
pub struct RetailUiAssets<'w> {
    retail_assets: Res<'w, RetailAssetsResource>,
    images: ResMut<'w, Assets<Image>>,
    handles: ResMut<'w, RetailPictureHandles>,
    fonts: ResMut<'w, Assets<Font>>,
    font_handles: ResMut<'w, RetailFontHandles>,
}

impl RetailUiAssets<'_> {
    pub fn default_dib_palette(&self) -> &DibPalette {
        self.retail_assets.assets().default_dib_palette()
    }

    pub fn add_image(&mut self, image: Image) -> Handle<Image> {
        self.images.add(image)
    }

    pub fn replace_image(&mut self, handle: &Handle<Image>, image: Image) {
        *self
            .images
            .get_mut(handle)
            .expect("application-owned image handle remains loaded") = image;
    }

    pub fn palette_color(&self, index: u8) -> Color {
        let [red, green, blue] = self.default_dib_palette()[index].to_array();
        Color::srgb_u8(red, green, blue)
    }

    pub fn string(&self, group: i16, direct_index: i16) -> Result<String, RetailAssetError> {
        self.retail_assets.assets().string(group, direct_index)
    }

    pub fn picture(&mut self, picture_id: PictureId) -> Result<Handle<Image>, RetailPictureError> {
        load_retail_picture(
            picture_id,
            &self.retail_assets,
            &mut self.images,
            &mut self.handles,
        )
    }

    pub fn with_picture_image_mut<R>(
        &mut self,
        picture_id: PictureId,
        f: impl FnOnce(&mut Image) -> R,
    ) -> Result<R, RetailPictureError> {
        let handle = self.picture(picture_id)?;
        let mut image = self
            .images
            .get_mut(&handle)
            .expect("picture handle was just resolved");
        Ok(f(&mut image))
    }

    pub fn transformed_picture(
        &mut self,
        picture_id: PictureId,
        transform: impl FnOnce(&mut Image),
    ) -> Result<Handle<Image>, RetailPictureError> {
        let handle = self.picture(picture_id)?;
        let mut image = self
            .images
            .get(&handle)
            .expect("picture handle was just resolved")
            .clone();
        transform(&mut image);
        Ok(self.images.add(image))
    }

    pub fn indexed_picture(
        &self,
        picture_id: PictureId,
    ) -> Result<IndexedPicture, RetailAssetError> {
        self.retail_assets.assets().indexed_picture(picture_id)
    }

    pub fn text_style(
        &mut self,
        preset: RetailTextStylePreset,
    ) -> Result<(TextFont, TextLayout, bool), RetailTextError> {
        let style = resolve_retail_text_style(preset)?;
        let bytes = self.retail_assets.assets().font_bytes(style.face);
        let handle = match self.font_handles.0.get(&style.face) {
            Some(handle) => handle.clone(),
            None => {
                let handle = self.fonts.add(Font::from_bytes(bytes.to_vec()));
                self.font_handles.0.insert(style.face, handle.clone());
                handle
            }
        };
        let mut font = TextFont::from_font_size(style.logical_pixel_height as f32)
            .with_font(handle)
            .with_font_smoothing(FontSmoothing::None);
        if style.italic {
            font.style = FontStyle::Italic;
        }
        let justify = match style.alignment {
            RetailTextAlignment::Left => Justify::Left,
            RetailTextAlignment::Center => Justify::Center,
            RetailTextAlignment::Right => Justify::Right,
        };
        Ok((font, TextLayout::justify(justify), style.underline))
    }
}

#[derive(Component, Debug, Default)]
pub struct ModalDialog;

pub struct RetailUiPlugin;

impl Plugin for RetailUiPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<RetailPictureHandles>()
            .init_resource::<RetailFontHandles>()
            .add_systems(Update, sync_retail_picture_swaps);
    }
}

fn sync_retail_picture_swaps(
    mut nodes: Query<(
        &RetailPictureSwap,
        &mut ImageNode,
        Has<Pressed>,
        Has<Checked>,
    )>,
) {
    for (swap, mut image, pressed, checked) in &mut nodes {
        image.image = if pressed || checked {
            swap.active.clone()
        } else {
            swap.idle.clone()
        };
    }
}

fn load_retail_picture(
    picture_id: PictureId,
    retail_assets: &RetailAssetsResource,
    images: &mut Assets<Image>,
    picture_handles: &mut RetailPictureHandles,
) -> Result<Handle<Image>, RetailPictureError> {
    if let Some(handle) = picture_handles.0.get(&picture_id) {
        return Ok(handle.clone());
    }
    let bytes = retail_assets.assets().picture(picture_id)?;
    let image = Image::from_buffer(
        &bytes,
        ImageType::Format(ImageFormat::Bmp),
        CompressedImageFormats::NONE,
        true,
        ImageSampler::nearest(),
        RenderAssetUsages::default(),
    )
    .map_err(|source| RetailPictureError::BmpDecode { picture_id, source })?;
    let handle = images.add(image);
    picture_handles.0.insert(picture_id, handle.clone());
    Ok(handle)
}

pub fn find_descendant(
    root: Entity,
    tag: FourCc,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) -> Entity {
    let mut pending = children
        .get(root)
        .map(|children| children.iter().collect::<Vec<_>>())
        .unwrap_or_default();
    let mut found = None;
    while let Some(entity) = pending.pop() {
        if tags.get(entity).is_ok_and(|candidate| candidate.0 == tag) {
            assert!(
                found.replace(entity).is_none(),
                "retail tag {tag:?} is ambiguous"
            );
        }
        if let Ok(descendants) = children.get(entity) {
            pending.extend(descendants.iter());
        }
    }
    found.unwrap_or_else(|| panic!("retail tag {tag:?} is missing below {root:?}"))
}

pub fn find_child_or_descendant(
    ancestor: Entity,
    tag: FourCc,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) -> Entity {
    find_descendant(ancestor, tag, children, tags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picture_swap_selects_preloaded_idle_and_active_handles() {
        let mut app = App::new();
        app.init_resource::<Assets<Image>>()
            .add_systems(Update, sync_retail_picture_swaps);
        let (idle, active) = {
            let mut images = app.world_mut().resource_mut::<Assets<Image>>();
            (images.add(Image::default()), images.add(Image::default()))
        };
        let entity = app
            .world_mut()
            .spawn((
                ImageNode::new(active.clone()),
                RetailPictureSwap {
                    idle: idle.clone(),
                    active: active.clone(),
                },
            ))
            .id();

        app.update();
        assert_eq!(app.world().get::<ImageNode>(entity).unwrap().image, idle);

        app.world_mut().entity_mut(entity).insert(Pressed);
        app.update();
        assert_eq!(app.world().get::<ImageNode>(entity).unwrap().image, active);
    }
}
