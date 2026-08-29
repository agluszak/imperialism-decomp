use super::retail_raster::IndexedRasterExt;
use crate::{RetailAssetsResource, RetailFont, RetailFonts};
use bevy::asset::RenderAssetUsages;
use bevy::ecs::system::SystemParam;
use bevy::ecs::template::TemplateContext;
use bevy::image::{CompressedImageFormats, ImageSampler, ImageType, TextureError};
use bevy::prelude::*;
use bevy::reflect::Is;
use bevy::text::{EditableText, EditableTextFilter, LineHeight, TextCursorStyle};
use bevy::ui::{Checked, InteractionDisabled, Pressed};
use imperialism_formats::*;
use std::collections::HashMap;

pub use super::retail_amount_bar::{
    AmountBarParts, retail_production_amount_bar, retail_trade_amount_bar,
};
pub use super::retail_numbered_arrow::{NumberedArrowParts, retail_numbered_arrow};
pub use super::retail_placard::{
    PlacardParts, placard_text_layout, retail_army_placard, retail_placard, retail_ship_placard,
};
pub use super::retail_sideways_arrow::Step;
pub use super::retail_slider::{RetailTwoPicSliderParts, retail_two_pic_slider};
pub use super::retail_transport_gauge::{
    TransportGaugeParts, transport_allocation_gauge, transport_capacity_gauge,
    transport_gauge_width,
};

/// Provenance tag recovered from the retail View resource.
#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetailTag(pub FourCc);

/// Images displayed by a retail picture control in its resting and active states.
#[derive(Component, Clone, Debug)]
pub struct RetailPictureSwap {
    pub idle: Handle<Image>,
    pub active: Handle<Image>,
}

/// A `TPictureButton` down-state bitmap drawn only while the control is pressed.
#[derive(Component, Debug, Default, Clone)]
pub struct RetailPressedOverlay;

/// Retained overlay child for a [`retail_picture_button`] hierarchy.
#[derive(Component, FromTemplate, Clone, Copy)]
struct PictureButtonParts {
    overlay: Entity,
}

/// `TMadnessButton::CheckTheLook` bitmap frames: base+0..=4 from checked/pressed/disabled.
#[derive(Component, Clone, Debug)]
pub struct RetailMadnessPicture {
    pub frames: [Handle<Image>; 5],
}

pub fn retail_view(name: &'static str) -> impl Scene {
    // TView clips each child's paint rectangle to its parent content bounds.
    bsn! {
        Node {
            position_type: PositionType::Absolute,
            left: px(0),
            top: px(0),
            width: px(640),
            height: px(480),
            overflow: Overflow::clip(),
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
            overflow: Overflow::clip(),
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
            Ok(ImageNode::new(load_template_picture(
                context,
                PictureId::new(idle),
            )?))
        })
        template(move |context| {
            let idle = load_template_picture(context, PictureId::new(idle))?;
            let active = load_template_picture(context, PictureId::new(active))?;
            Ok(RetailPictureSwap { idle, active })
        })
    }
}

/// `TPictureButton` base art plus a child overlay shown only while pressed.
pub fn retail_picture_button(idle: i16, overlay: i16) -> impl Scene {
    bsn! {
        PictureButtonParts { overlay: #Overlay }
        retail_picture(idle)
        Children [
            (
                #Overlay
                template(move |context| {
                    let image = load_template_picture(context, PictureId::new(overlay))?;
                    let mut node = ImageNode::new(image);
                    node.color.set_alpha(0.0);
                    Ok(node)
                })
                RetailPressedOverlay
                Pickable::IGNORE
            )
        ]
    }
}

/// `TMadnessButton` multi-offset CzechBox skin over stock `Checkbox`.
pub fn retail_madness_picture(base: i16) -> impl Scene {
    bsn! {
        template(move |context| {
            Ok(ImageNode::new(
                load_madness_frames(context, base)[0].clone(),
            ))
        })
        template(move |context| {
            Ok(RetailMadnessPicture {
                frames: load_madness_frames(context, base),
            })
        })
    }
}

pub fn retail_text_style(
    font_family: i32,
    face_flags: i32,
    point_size: i32,
    alignment: i32,
) -> impl Scene {
    retail_text_style_preset(RetailTextStylePreset::explicit(
        font_family,
        face_flags,
        point_size,
        alignment,
    ))
}

/// `BuildUiTextStyleDescriptor`: family derives from point size (Book Antiqua below 12pt).
pub fn retail_built_text_style(point_size: i32, alignment: i32) -> impl Scene {
    retail_text_style_preset(RetailTextStylePreset::built(point_size, alignment))
}

fn retail_text_style_preset(preset: RetailTextStylePreset) -> impl Scene {
    let style =
        resolve_retail_text_style(preset).expect("generated retail text style must resolve");
    let underline = style.underline.then(|| bsn! { Underline });
    let line_height = LineHeight::Px(style.logical_pixel_height as f32);
    bsn! {
        template(move |context| {
            Ok(context.entity.world_scope(|world| {
                retail_text_components(style, world.resource::<RetailFonts>().get(style.face)).0
            }))
        })
        template(move |_context| Ok(line_height))
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

pub fn retail_background_color(index: u8) -> impl Scene {
    bsn! {
        template(move |context| Ok(BackgroundColor(template_palette_color(context, index))))
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

/// Windows `TEditText::Open` hosts a `CEdit` with `WS_BORDER | WS_EX_CLIENTEDGE`.
/// Palette `0x13` is recovered white (`COLOR_WINDOW`); index 0 is black.
pub fn retail_edit_field() -> impl Scene {
    bsn! {
        Node {
            border: UiRect::all(px(2)),
        }
        template(move |context| Ok(BackgroundColor(template_palette_color(context, 0x13))))
        template(move |context| Ok(BorderColor::all(template_palette_color(context, 0))))
    }
}

/// `TRadioTextCluster` constructor defaults: selected theme `0x49`, pressed `0x4b`.
/// `TViewMgr::GetColor` maps those to palettes `0xfa` and `0x66`.
pub const RADIO_TEXT_SELECTED_PALETTE: u8 = 0xfa;
pub const RADIO_TEXT_PRESSED_PALETTE: u8 = 0x66;

/// `TSetupRandomMapPicture::DoPostCreate` sets `frameThemeCode90 = 0x2b6b` on
/// the difficulty and names clusters; `GetColor` maps that theme to palette `0xd2`.
pub const RADIO_CLUSTER_FRAME_PALETTE: u8 = 0xd2;

/// Headless `TRadioText` selection fill. `TRadioText::Draw` fills the option
/// when selected or pressed; picture radios keep their art swap instead.
#[derive(Component, Clone, Copy, Debug)]
pub struct RetailRadioTextFill {
    pub selected: Color,
    pub pressed: Color,
}

pub fn retail_radio_text_fill() -> impl Scene {
    bsn! {
        BackgroundColor(Color::NONE)
        template(move |context| {
            Ok(RetailRadioTextFill {
                selected: template_palette_color(context, RADIO_TEXT_SELECTED_PALETTE),
                pressed: template_palette_color(context, RADIO_TEXT_PRESSED_PALETTE),
            })
        })
    }
}

/// Vertically center a caption inside recovered control bounds.
pub fn retail_centered_text_padding(
    font_family: i32,
    face_flags: i32,
    point_size: i32,
    height: i32,
    top: i32,
) -> impl Scene {
    let text_height = resolve_retail_text_style(RetailTextStylePreset::explicit(
        font_family,
        face_flags,
        point_size,
        0,
    ))
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RetailImageKey {
    Opaque(PictureId),
    Transparent(PictureId, u8),
}

#[derive(Resource, Default)]
struct RetailPictureHandles(HashMap<RetailImageKey, Handle<Image>>);

#[derive(SystemParam)]
pub struct RetailUiAssets<'w> {
    retail_assets: Res<'w, RetailAssetsResource>,
    images: ResMut<'w, Assets<Image>>,
    handles: ResMut<'w, RetailPictureHandles>,
    retail_fonts: Res<'w, RetailFonts>,
}

pub fn apply_index_transparency(image: &mut Image, indexed: &IndexedPicture, index: u8) -> bool {
    let width = image.width() as usize;
    let height = image.height() as usize;
    let Some(pixels) = image.data.as_mut() else {
        return false;
    };
    if width == 0
        || height == 0
        || indexed.width as usize != width
        || indexed.height as usize != height
        || pixels.len() != width * height * 4
        || indexed.pixels.len() != width * height
    {
        return false;
    }
    for (pixel, &palette_index) in pixels.chunks_exact_mut(4).zip(&indexed.pixels) {
        if palette_index == index {
            pixel[3] = 0;
        }
    }
    true
}

impl RetailUiAssets<'_> {
    pub fn assets(&self) -> &RetailAssets {
        self.retail_assets.assets()
    }

    pub fn default_dib_palette(&self) -> &DibPalette {
        self.assets().default_dib_palette()
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

    pub fn string(&self, id: StringResourceId) -> String {
        self.retail_assets.string(id)
    }

    /// `TSimMgr::GetString`: zero-based offset (adds one before the direct lookup).
    pub fn get_string(&self, group: u16, offset: u16) -> String {
        self.retail_assets.get_string(group, offset)
    }

    /// Direct `LoadUiStringResourceByGroupAndIndex` / `LoadStringA` group/index.
    pub fn ui_string(&self, group: u16, index: u16) -> String {
        self.retail_assets.ui_string(group, index)
    }

    /// Soft-fail picture load for cases where retail itself tolerates a missing bitmap.
    fn try_picture(&mut self, picture_id: PictureId) -> Result<Handle<Image>, RetailPictureError> {
        load_retail_image(
            RetailImageKey::Opaque(picture_id),
            &self.retail_assets,
            &mut self.images,
            &mut self.handles,
        )
    }

    pub fn picture(&mut self, picture_id: PictureId) -> Handle<Image> {
        self.try_picture(picture_id)
            .unwrap_or_else(|error| panic!("retail picture {picture_id} must load: {error}"))
    }

    pub fn transformed_picture(
        &mut self,
        picture_id: PictureId,
        transform: impl FnOnce(&mut Image),
    ) -> Handle<Image> {
        let handle = self.picture(picture_id);
        let mut image = self
            .images
            .get(&handle)
            .expect("picture handle was just resolved")
            .clone();
        transform(&mut image);
        self.images.add(image)
    }

    pub fn keyed_picture(
        &mut self,
        picture_id: PictureId,
        transparent_palette_index: u8,
    ) -> Handle<Image> {
        load_retail_image(
            RetailImageKey::Transparent(picture_id, transparent_palette_index),
            &self.retail_assets,
            &mut self.images,
            &mut self.handles,
        )
        .unwrap_or_else(|error| {
            panic!(
                "retail keyed picture {picture_id}/{transparent_palette_index} must load: {error}"
            )
        })
    }

    pub fn try_indexed_picture(
        &self,
        picture_id: PictureId,
    ) -> Result<IndexedPicture, RetailAssetError> {
        self.retail_assets.assets().indexed_picture(picture_id)
    }

    pub fn indexed_picture(&self, picture_id: PictureId) -> IndexedPicture {
        self.try_indexed_picture(picture_id)
            .unwrap_or_else(|error| panic!("retail picture {picture_id} must load: {error}"))
    }

    pub fn text_style(
        &self,
        preset: RetailTextStylePreset,
    ) -> (TextFont, TextLayout, LineHeight, bool) {
        let style = resolve_retail_text_style(preset)
            .unwrap_or_else(|error| panic!("retail text style {preset:?} must resolve: {error}"));
        retail_text_components(style, self.retail_fonts.get(style.face))
    }
}

pub struct RetailUiPlugin;

impl Plugin for RetailUiPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<RetailPictureHandles>()
            .add_observer(on_retail_picture_swap_state::<Add, RetailPictureSwap>)
            .add_observer(on_retail_picture_swap_state::<Add, Pressed>)
            .add_observer(on_retail_picture_swap_state::<Remove, Pressed>)
            .add_observer(on_retail_picture_swap_state::<Add, Checked>)
            .add_observer(on_retail_picture_swap_state::<Remove, Checked>)
            .add_observer(on_retail_pressed_overlay_state::<Add>)
            .add_observer(on_retail_pressed_overlay_state::<Remove>)
            .add_observer(on_retail_madness_picture_state::<Add, RetailMadnessPicture>)
            .add_observer(on_retail_madness_picture_state::<Add, Pressed>)
            .add_observer(on_retail_madness_picture_state::<Remove, Pressed>)
            .add_observer(on_retail_madness_picture_state::<Add, Checked>)
            .add_observer(on_retail_madness_picture_state::<Remove, Checked>)
            .add_observer(on_retail_madness_picture_state::<Add, InteractionDisabled>)
            .add_observer(on_retail_madness_picture_state::<Remove, InteractionDisabled>)
            .add_observer(on_radio_text_fill_state::<Add, Pressed>)
            .add_observer(on_radio_text_fill_state::<Remove, Pressed>)
            .add_observer(on_radio_text_fill_state::<Add, Checked>)
            .add_observer(on_radio_text_fill_state::<Remove, Checked>)
            .add_observer(on_radio_text_fill_state::<Add, RetailRadioTextFill>);
        super::retail_slider::register_slider(app);
        super::retail_numbered_arrow::register_numbered_arrow(app);
        super::retail_sideways_arrow::register_sideways_arrow(app);
        super::retail_page_corner::register_page_corner(app);
        super::hover_help::register_hover_help(app);
    }
}

fn on_retail_pressed_overlay_state<E: EntityEvent>(
    event: On<E, Pressed>,
    buttons: Query<(&PictureButtonParts, Has<Pressed>)>,
    mut overlays: Query<&mut ImageNode, With<RetailPressedOverlay>>,
) {
    let Ok((parts, pressed)) = buttons.get(event.event_target()) else {
        return;
    };
    let Ok(mut image) = overlays.get_mut(parts.overlay) else {
        return;
    };
    let pressed = pressed && !E::is::<Remove>();
    image.color.set_alpha(if pressed { 1.0 } else { 0.0 });
}

fn load_madness_frames(context: &mut TemplateContext, base: i16) -> [Handle<Image>; 5] {
    std::array::from_fn(|index| {
        let id = base + index as i16;
        load_template_picture(context, PictureId::new(id))
            .unwrap_or_else(|error| panic!("retail madness picture {id} must load: {error}"))
    })
}

fn madness_frame_index(checked: bool, pressed: bool, disabled: bool) -> usize {
    // `TMadnessButton::CheckTheLook`: disabled => +4; else (!on => +2) + (pressed => +1).
    if disabled {
        4
    } else {
        usize::from(!checked) * 2 + usize::from(pressed)
    }
}

fn on_retail_madness_picture_state<E: EntityEvent, C: Component>(
    event: On<E, C>,
    mut nodes: Query<MadnessPictureQuery>,
) {
    let Ok((skin, mut image, pressed, checked, disabled)) = nodes.get_mut(event.event_target())
    else {
        return;
    };
    let pressed = pressed && !(E::is::<Remove>() && C::is::<Pressed>());
    let checked = checked && !(E::is::<Remove>() && C::is::<Checked>());
    let disabled = disabled && !(E::is::<Remove>() && C::is::<InteractionDisabled>());
    image.image = skin.frames[madness_frame_index(checked, pressed, disabled)].clone();
}

type MadnessPictureQuery = (
    &'static RetailMadnessPicture,
    &'static mut ImageNode,
    Has<Pressed>,
    Has<Checked>,
    Has<InteractionDisabled>,
);

fn on_retail_picture_swap_state<E: EntityEvent, C: Component>(
    event: On<E, C>,
    mut nodes: Query<(
        &RetailPictureSwap,
        &mut ImageNode,
        Has<Pressed>,
        Has<Checked>,
    )>,
) {
    let Ok((swap, mut image, pressed, checked)) = nodes.get_mut(event.event_target()) else {
        return;
    };
    // `Remove` fires before the component is gone, so it still matches `Has<Pressed>`/`Has<Checked>`.
    let pressed = pressed && !(E::is::<Remove>() && C::is::<Pressed>());
    let checked = checked && !(E::is::<Remove>() && C::is::<Checked>());
    image.image = if pressed || checked {
        swap.active.clone()
    } else {
        swap.idle.clone()
    };
}

fn on_radio_text_fill_state<E: EntityEvent, C: Component>(
    event: On<E, C>,
    mut fills: Query<(
        &RetailRadioTextFill,
        &mut BackgroundColor,
        Has<Pressed>,
        Has<Checked>,
    )>,
) {
    let Ok((fill, mut background, pressed, checked)) = fills.get_mut(event.event_target()) else {
        return;
    };
    let pressed = pressed && !(E::is::<Remove>() && C::is::<Pressed>());
    let checked = checked && !(E::is::<Remove>() && C::is::<Checked>());
    background.0 = if pressed {
        fill.pressed
    } else if checked {
        fill.selected
    } else {
        Color::NONE
    };
}

fn load_retail_image(
    key: RetailImageKey,
    retail_assets: &RetailAssetsResource,
    images: &mut Assets<Image>,
    picture_handles: &mut RetailPictureHandles,
) -> Result<Handle<Image>, RetailPictureError> {
    if let Some(handle) = picture_handles.0.get(&key) {
        return Ok(handle.clone());
    }
    let image = match key {
        RetailImageKey::Opaque(picture_id) => {
            let bytes = retail_assets.assets().picture(picture_id)?;
            decode_retail_picture(picture_id, &bytes)?
        }
        RetailImageKey::Transparent(picture_id, palette_index) => {
            // Decode the indexed DIB once into the UI image instead of applying an
            // alpha mask to Bevy's BMP decoder output. The latter has a distinct
            // scanline layout for some retail DIBs, so its index rows can diverge
            // from the visible RGBA rows (notably atlas 0xee2).
            let indexed = retail_assets.assets().indexed_picture(picture_id)?;
            indexed.to_keyed_image(retail_assets.assets().default_dib_palette(), palette_index)
        }
    };
    let handle = images.add(image);
    picture_handles.0.insert(key, handle.clone());
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

pub(super) fn load_template_picture(
    context: &mut TemplateContext,
    picture_id: PictureId,
) -> bevy::ecs::error::Result<Handle<Image>> {
    load_template_image(context, RetailImageKey::Opaque(picture_id))
}

/// Load a palette-keyed transparent picture, cached by `(picture_id, key)`.
pub(super) fn load_template_transparent_picture(
    context: &mut TemplateContext,
    picture_id: PictureId,
    palette_index: u8,
) -> bevy::ecs::error::Result<Handle<Image>> {
    load_template_image(
        context,
        RetailImageKey::Transparent(picture_id, palette_index),
    )
}

fn load_template_image(
    context: &mut TemplateContext,
    key: RetailImageKey,
) -> bevy::ecs::error::Result<Handle<Image>> {
    Ok(context.entity.world_scope(|world| {
        world.resource_scope(|world, mut handles: Mut<RetailPictureHandles>| {
            world.resource_scope(|world, mut images: Mut<Assets<Image>>| {
                load_retail_image(
                    key,
                    world.resource::<RetailAssetsResource>(),
                    &mut images,
                    &mut handles,
                )
            })
        })
    })?)
}

pub(super) fn retail_text_components(
    style: ResolvedRetailTextStyle,
    font: &RetailFont,
) -> (TextFont, TextLayout, LineHeight, bool) {
    let mut text_font =
        TextFont::from_font_size(font.size_for_cell_height(style.logical_pixel_height) as f32)
            .with_font(font.handle().clone())
            .with_font_smoothing(match style.face {
                RetailFontFace::System => FontSmoothing::None,
                _ => FontSmoothing::AntiAliased,
            });
    if style.italic {
        text_font.style = FontStyle::Italic;
    }
    let justify = match style.alignment {
        RetailTextAlignment::Left => Justify::Left,
        RetailTextAlignment::Center => Justify::Center,
        RetailTextAlignment::Right => Justify::Right,
    };
    (
        text_font,
        TextLayout::justify(justify),
        LineHeight::Px(style.logical_pixel_height as f32),
        style.underline,
    )
}

fn template_palette_color(context: &TemplateContext, index: u8) -> Color {
    let [red, green, blue] = context
        .resource::<RetailAssetsResource>()
        .assets()
        .default_dib_palette()[index]
        .to_array();
    Color::srgb_u8(red, green, blue)
}

/// Hierarchy lookup for recovered View tags. The same FourCc can appear in
/// different subtrees, so searches stay scoped to a root rather than a global index.
#[derive(SystemParam)]
pub struct RetailTree<'w, 's> {
    pub children: Query<'w, 's, &'static Children>,
    tags: Query<'w, 's, &'static RetailTag>,
}

impl<'w, 's> RetailTree<'w, 's> {
    pub fn view<'a>(&'a self, root: Entity) -> RetailView<'a, 'w, 's> {
        RetailView { tree: self, root }
    }

    pub fn try_find(&self, root: Entity, tag: FourCc) -> Option<Entity> {
        let mut matches = self
            .children
            .iter_descendants_depth_first(root)
            .filter(|&entity| {
                self.tags
                    .get(entity)
                    .is_ok_and(|candidate| candidate.0 == tag)
            });
        let found = matches.next();
        assert!(matches.next().is_none(), "retail tag {tag:?} is ambiguous");
        found
    }

    pub fn find(&self, root: Entity, tag: FourCc) -> Entity {
        self.try_find(root, tag)
            .unwrap_or_else(|| panic!("retail tag {tag:?} is missing below {root:?}"))
    }

    pub fn child(&self, parent: Entity, tag: FourCc) -> Entity {
        let mut found = None;
        for entity in self.children.get(parent).into_iter().flatten() {
            if let Ok(candidate) = self.tags.get(*entity)
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
}

pub struct RetailView<'a, 'w, 's> {
    tree: &'a RetailTree<'w, 's>,
    root: Entity,
}

impl RetailView<'_, '_, '_> {
    pub fn find(&self, tag: FourCc) -> Entity {
        self.tree.find(self.root, tag)
    }

    pub fn child(&self, tag: FourCc) -> Entity {
        self.tree.child(self.root, tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bevy::ecs::system::SystemState;
    use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
    use bevy::text::{FontSize, FontSource};

    #[test]
    fn index_transparency_does_not_key_an_equal_rgb_entry() {
        let indexed = IndexedPicture {
            width: 2,
            height: 1,
            pixels: vec![0x10, 0x11],
        };
        let mut image = Image::new(
            Extent3d {
                width: 2,
                height: 1,
                depth_or_array_layers: 1,
            },
            TextureDimension::D2,
            vec![0xff, 0, 0xff, 0xff, 0xff, 0, 0xff, 0xff],
            TextureFormat::Rgba8UnormSrgb,
            RenderAssetUsages::default(),
        );

        assert!(apply_index_transparency(&mut image, &indexed, 0x10));
        assert_eq!(image.data.as_ref().unwrap()[3], 0);
        assert_eq!(image.data.as_ref().unwrap()[7], 0xff);
    }

    fn scene_app() -> App {
        let mut app = App::new();
        app.init_resource::<Assets<Image>>()
            .add_plugins((
                MinimalPlugins,
                AssetPlugin::default(),
                bevy::scene::ScenePlugin,
            ))
            .add_plugins(RetailUiPlugin);
        app
    }

    #[test]
    fn picture_swap_initializes_checked_state_when_spawned_from_scene() {
        let mut app = scene_app();
        let (idle, active) = {
            let mut images = app.world_mut().resource_mut::<Assets<Image>>();
            (images.add(Image::default()), images.add(Image::default()))
        };
        let idle_for_swap = idle.clone();
        let active_for_assert = active.clone();
        let entity = app
            .world_mut()
            .spawn_scene(bsn! {
                template(move |_| Ok(ImageNode::new(idle.clone())))
                template(move |_| {
                    Ok(RetailPictureSwap {
                        idle: idle_for_swap.clone(),
                        active: active.clone(),
                    })
                })
                Checked
            })
            .expect("picture swap scene")
            .id();
        app.update();

        assert_eq!(
            app.world().get::<ImageNode>(entity).unwrap().image,
            active_for_assert
        );
    }

    #[test]
    fn madness_picture_initializes_unchecked_frame_when_spawned_from_scene() {
        let mut app = scene_app();
        let frames: [Handle<Image>; 5] = {
            let mut images = app.world_mut().resource_mut::<Assets<Image>>();
            std::array::from_fn(|_| images.add(Image::default()))
        };
        let expected = frames[madness_frame_index(false, false, false)].clone();
        let frames_for_skin = frames.clone();
        let entity = app
            .world_mut()
            .spawn_scene(bsn! {
                template(move |_| Ok(ImageNode::new(frames[0].clone())))
                template(move |_| Ok(RetailMadnessPicture { frames: frames_for_skin.clone() }))
            })
            .expect("madness picture scene")
            .id();
        app.update();

        assert_eq!(
            app.world().get::<ImageNode>(entity).unwrap().image,
            expected
        );
    }

    #[test]
    fn picture_button_overlay_is_visible_only_while_parent_is_pressed() {
        let mut app = scene_app();
        let button = app
            .world_mut()
            .spawn_scene(bsn! {
                PictureButtonParts { overlay: #Overlay }
                ImageNode::default()
                Children [
                    (
                        #Overlay
                        template(|_| {
                            let mut node = ImageNode::default();
                            node.color.set_alpha(0.0);
                            Ok(node)
                        })
                        RetailPressedOverlay
                    )
                ]
            })
            .expect("picture button scene")
            .id();
        app.update();

        let overlay = app
            .world()
            .get::<PictureButtonParts>(button)
            .expect("picture button retains overlay child")
            .overlay;
        assert_eq!(
            app.world().get::<ImageNode>(overlay).unwrap().color.alpha(),
            0.0
        );

        app.world_mut().entity_mut(button).insert(Pressed);
        app.update();
        assert_eq!(
            app.world().get::<ImageNode>(overlay).unwrap().color.alpha(),
            1.0
        );

        app.world_mut().entity_mut(button).remove::<Pressed>();
        app.update();
        assert_eq!(
            app.world().get::<ImageNode>(overlay).unwrap().color.alpha(),
            0.0
        );
    }

    #[test]
    fn radio_text_fill_initializes_checked_state_when_spawned_from_scene() {
        let mut app = scene_app();
        let selected = Color::srgb(1.0, 0.0, 0.0);
        let pressed = Color::srgb(0.0, 1.0, 0.0);
        let entity = app
            .world_mut()
            .spawn_scene(bsn! {
                BackgroundColor(Color::NONE)
                template(move |_| Ok(RetailRadioTextFill { selected, pressed }))
                Checked
            })
            .expect("radio text fill scene")
            .id();
        app.update();

        assert_eq!(
            app.world().get::<BackgroundColor>(entity).unwrap().0,
            selected
        );
    }

    #[test]
    fn radio_text_fill_follows_pressed_and_checked() {
        let mut app = scene_app();
        let selected = Color::srgb(1.0, 0.0, 0.0);
        let pressed = Color::srgb(0.0, 1.0, 0.0);
        let entity = app
            .world_mut()
            .spawn_scene(bsn! {
                BackgroundColor(Color::NONE)
                template(move |_| Ok(RetailRadioTextFill { selected, pressed }))
            })
            .expect("radio text fill scene")
            .id();
        app.update();

        assert_eq!(
            app.world().get::<BackgroundColor>(entity).unwrap().0,
            Color::NONE
        );

        app.world_mut().entity_mut(entity).insert(Checked);
        app.update();
        assert_eq!(
            app.world().get::<BackgroundColor>(entity).unwrap().0,
            selected
        );

        app.world_mut().entity_mut(entity).insert(Pressed);
        app.update();
        assert_eq!(
            app.world().get::<BackgroundColor>(entity).unwrap().0,
            pressed
        );

        app.world_mut().entity_mut(entity).remove::<Pressed>();
        app.update();
        assert_eq!(
            app.world().get::<BackgroundColor>(entity).unwrap().0,
            selected
        );

        app.world_mut().entity_mut(entity).remove::<Checked>();
        app.update();
        assert_eq!(
            app.world().get::<BackgroundColor>(entity).unwrap().0,
            Color::NONE
        );
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

        let mut state = SystemState::<RetailTree>::new(app.world_mut());
        let tree = state.get(app.world()).unwrap();

        assert_eq!(tree.child(parent, fourcc!("trad")), direct);
        assert_eq!(tree.view(parent).child(fourcc!("trad")), direct);
        assert_eq!(tree.view(parent).find(fourcc!("clus")), container);
    }

    #[test]
    fn family_zero_bevy_text_uses_the_registered_system_font() {
        let mut font_assets = Assets::<Font>::default();
        let fonts = crate::fonts::load_test_fonts(&mut font_assets);
        let style = resolve_retail_text_style(RetailTextStylePreset::explicit(0, 0, 12, 1))
            .expect("family 0 resolves to System");
        assert_eq!(style.face, RetailFontFace::System);

        let system = fonts.get(RetailFontFace::System);
        let registered = font_assets
            .get(system.handle())
            .expect("System is registered as a Bevy Font");
        assert_eq!(
            registered.data.as_ref(),
            include_bytes!("../fonts/system.ttf").as_slice()
        );

        let (text_font, _, line_height, underline) = retail_text_components(style, system);
        assert_eq!(text_font.font, FontSource::from(system.handle().clone()));
        assert_eq!(text_font.font_smoothing, FontSmoothing::None);
        assert_eq!(
            text_font.font_size,
            FontSize::Px(system.size_for_cell_height(style.logical_pixel_height) as f32)
        );
        assert_eq!(
            line_height,
            LineHeight::Px(style.logical_pixel_height as f32)
        );
        assert!(!underline);
    }
}
