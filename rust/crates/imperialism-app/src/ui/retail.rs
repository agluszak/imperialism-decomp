use crate::RetailAssetsResource;
use bevy::asset::RenderAssetUsages;
use bevy::ecs::system::SystemParam;
use bevy::ecs::template::TemplateContext;
use bevy::image::{CompressedImageFormats, ImageSampler, ImageType, TextureError};
use bevy::prelude::*;
use bevy::text::{EditableText, EditableTextFilter, TextCursorStyle};
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

pub fn retail_view(name: &'static str) -> impl Scene {
    bsn! {
        Node {
            position_type: PositionType::Absolute,
            left: px(0),
            top: px(0),
            width: px(640),
            height: px(480),
        }
        Name(name)
        Pickable
    }
}

pub fn retail_node(tag: FourCc, x: i32, y: i32, width: i32, height: i32) -> impl Scene {
    bsn! {
        Node {
            position_type: PositionType::Absolute,
            left: px(x),
            top: px(y),
            width: px(width),
            height: px(height),
        }
        template(move |_context| Ok(RetailTag(tag)))
    }
}

pub fn retail_picture(id: i16) -> impl Scene {
    bsn! {
        template(move |context| {
            Ok(ImageNode::new(load_template_picture(
                context,
                PictureId::new(id),
            )?))
        })
    }
}

pub fn retail_picture_swap(idle: i16, active: i16) -> impl Scene {
    bsn! {
        template(move |context| {
            let idle = load_template_picture(context, PictureId::new(idle))?;
            let active = match load_template_picture(context, PictureId::new(active)) {
                Ok(active) => active,
                Err(error) => {
                    warn!("could not preload active retail picture {active}: {error}");
                    idle.clone()
                }
            };
            context.entity.insert(RetailPictureSwap {
                idle: idle.clone(),
                active,
            });
            Ok(ImageNode::new(idle))
        })
    }
}

pub fn retail_text_style(
    font_family: i32,
    face_flags: i32,
    point_size: i32,
    alignment: i32,
) -> impl Scene {
    let style = resolve_retail_text_style(RetailTextStylePreset {
        font_family,
        face_flags,
        point_size,
        alignment,
    })
    .expect("generated retail text style must resolve");
    let underline = style.underline.then(|| bsn! { Underline });
    bsn! {
        template(move |context| {
            Ok(retail_text_components(
                style,
                load_template_font(context, style.face),
            ).0)
        })
        TextLayout::justify(match style.alignment {
            RetailTextAlignment::Left => Justify::Left,
            RetailTextAlignment::Center => Justify::Center,
            RetailTextAlignment::Right => Justify::Right,
        })
        {underline}
    }
}

pub fn retail_text_color(index: u8) -> impl Scene {
    bsn! {
        template(move |context| Ok(TextColor(template_palette_color(context, index))))
    }
}

pub fn retail_text_shadow(index: u8, x: i32, y: i32) -> impl Scene {
    bsn! {
        template(move |context| Ok(TextShadow {
            offset: Vec2::new(x as f32, y as f32),
            color: template_palette_color(context, index),
        }))
    }
}

pub fn retail_editable_text(value: &'static str, max_characters: Option<usize>) -> impl Scene {
    bsn! {
        template(move |_context| {
            let mut text = EditableText::new(value);
            text.allow_newlines = false;
            text.max_characters = max_characters;
            Ok(text)
        })
        TextCursorStyle
        template(move |_context| {
            Ok(EditableTextFilter::new(|character| !character.is_control()))
        })
    }
}

pub fn retail_centered_text_padding(
    font_family: i32,
    face_flags: i32,
    point_size: i32,
    height: i32,
    top: i32,
) -> impl Scene {
    let text_height = resolve_retail_text_style(RetailTextStylePreset {
        font_family,
        face_flags,
        point_size,
        alignment: 0,
    })
    .expect("generated retail text style must resolve")
    .logical_pixel_height;
    bsn! {
        Node {
            padding: UiRect {
                top: px(top + (height - text_height).max(0) / 2),
            },
        }
    }
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
        let handle = load_retail_font(
            style.face,
            &self.retail_assets,
            &mut self.fonts,
            &mut self.font_handles,
        );
        Ok(retail_text_components(style, handle))
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
        super::hover_help::register_hover_help(app);
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
    let image = decode_retail_picture(picture_id, &bytes)?;
    let handle = images.add(image);
    picture_handles.0.insert(picture_id, handle.clone());
    Ok(handle)
}

fn decode_retail_picture(picture_id: PictureId, bytes: &[u8]) -> Result<Image, RetailPictureError> {
    Image::from_buffer(
        bytes,
        ImageType::Format(ImageFormat::Bmp),
        CompressedImageFormats::NONE,
        true,
        ImageSampler::nearest(),
        RenderAssetUsages::default(),
    )
    .map_err(|source| RetailPictureError::BmpDecode { picture_id, source })
}

fn load_template_picture(
    context: &mut TemplateContext,
    picture_id: PictureId,
) -> bevy::ecs::error::Result<Handle<Image>> {
    Ok(context.entity.world_scope(|world| {
        world.resource_scope(|world, mut handles: Mut<RetailPictureHandles>| {
            world.resource_scope(|world, mut images: Mut<Assets<Image>>| {
                load_retail_picture(
                    picture_id,
                    world.resource::<RetailAssetsResource>(),
                    &mut images,
                    &mut handles,
                )
            })
        })
    })?)
}

fn load_template_font(context: &mut TemplateContext, face: RetailFontFace) -> Handle<Font> {
    context.entity.world_scope(|world| {
        world.resource_scope(|world, mut handles: Mut<RetailFontHandles>| {
            world.resource_scope(|world, mut fonts: Mut<Assets<Font>>| {
                load_retail_font(
                    face,
                    world.resource::<RetailAssetsResource>(),
                    &mut fonts,
                    &mut handles,
                )
            })
        })
    })
}

fn load_retail_font(
    face: RetailFontFace,
    retail_assets: &RetailAssetsResource,
    fonts: &mut Assets<Font>,
    font_handles: &mut RetailFontHandles,
) -> Handle<Font> {
    if let Some(handle) = font_handles.0.get(&face) {
        return handle.clone();
    }
    let bytes = retail_assets.assets().font_bytes(face).to_vec();
    let handle = fonts.add(Font::from_bytes(bytes));
    font_handles.0.insert(face, handle.clone());
    handle
}

fn retail_text_components(
    style: ResolvedRetailTextStyle,
    handle: Handle<Font>,
) -> (TextFont, TextLayout, bool) {
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
    (font, TextLayout::justify(justify), style.underline)
}

fn template_palette_color(context: &TemplateContext, index: u8) -> Color {
    let [red, green, blue] = context
        .resource::<RetailAssetsResource>()
        .assets()
        .default_dib_palette()[index]
        .to_array();
    Color::srgb_u8(red, green, blue)
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

pub fn find_child(
    parent: Entity,
    tag: FourCc,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) -> Entity {
    let mut found = None;
    for entity in children.get(parent).into_iter().flatten() {
        if let Ok(candidate) = tags.get(*entity)
            && candidate.0 == tag
        {
            assert!(
                found.replace(*entity).is_none(),
                "retail tag {tag:?} is ambiguous directly below {parent:?}"
            );
        }
    }
    found.unwrap_or_else(|| panic!("retail tag {tag:?} is missing directly below {parent:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevy::ecs::system::SystemState;

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

    #[test]
    fn child_lookup_ignores_a_nested_duplicate_tag() {
        let mut app = App::new();
        let parent = app.world_mut().spawn_empty().id();
        let direct = app
            .world_mut()
            .spawn((RetailTag(fourcc!("trad")), ChildOf(parent)))
            .id();
        let container = app
            .world_mut()
            .spawn((RetailTag(fourcc!("clus")), ChildOf(parent)))
            .id();
        app.world_mut()
            .spawn((RetailTag(fourcc!("trad")), ChildOf(container)));

        let mut state = SystemState::<(Query<&Children>, Query<&RetailTag>)>::new(app.world_mut());
        let (children, tags) = state.get(app.world()).unwrap();

        assert_eq!(
            find_child(parent, fourcc!("trad"), &children, &tags),
            direct
        );
    }
}
