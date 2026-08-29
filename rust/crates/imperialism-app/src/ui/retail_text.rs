//! Recovered retail text presentation for generated UI scenes.

use super::retail::{retail_edit_field, retail_editable_text, retail_text_style};
use crate::RetailAssetsResource;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use imperialism_formats::RetailTextStylePreset;

/// Recovered caption/style facts for one generated text node.
#[derive(Clone, Copy, Debug)]
pub struct RetailTextSpec {
    pub text: &'static str,
    pub font_family: i32,
    pub face_flags: i32,
    pub point_size: i32,
    pub alignment: i32,
    pub color_index: Option<u8>,
    pub shadow_color_index: Option<u8>,
    pub shadow_offset: (i32, i32),
    pub center_vertically: bool,
}

impl RetailTextSpec {
    #[allow(dead_code)]
    pub fn plain(
        text: &'static str,
        font_family: i32,
        face_flags: i32,
        point_size: i32,
        alignment: i32,
    ) -> Self {
        Self {
            text,
            font_family,
            face_flags,
            point_size,
            alignment,
            color_index: None,
            shadow_color_index: None,
            shadow_offset: (0, 0),
            center_vertically: false,
        }
    }
}

/// Map recovered family 0 (system) to the renderable face used by retail text helpers.
pub fn retail_font_family(family: i32) -> i32 {
    if family == 0 { 1 } else { family }
}

fn shipped_font(family: i32) -> bool {
    matches!(retail_font_family(family), 1..=3)
}

fn palette_color(context: &bevy::ecs::template::TemplateContext, index: u8) -> Color {
    let [red, green, blue] = context
        .resource::<RetailAssetsResource>()
        .assets()
        .default_dib_palette()[index]
        .to_array();
    Color::srgb_u8(red, green, blue)
}

/// Shared recovered color, shadow, and optional vertical-centering presentation.
fn retail_text_presentation(
    spec: RetailTextSpec,
    vertical_layout: Option<(i32, i32)>,
) -> impl Scene {
    let color = bsn! {
        template(move |context| {
            Ok(TextColor(
                spec.color_index
                    .map(|index| palette_color(context, index))
                    .unwrap_or(Color::BLACK),
            ))
        })
    };
    let shadow = spec.shadow_color_index.map(|index| {
        let offset = spec.shadow_offset;
        bsn! {
            template(move |context| {
                Ok(TextShadow {
                    offset: Vec2::new(offset.0 as f32, offset.1 as f32),
                    color: palette_color(context, index),
                })
            })
        }
    });
    let vertical = vertical_layout.map(|(height, inset_top)| {
        bsn! {
            template(move |_context| {
                let preset = RetailTextStylePreset::explicit(
                    retail_font_family(spec.font_family),
                    spec.face_flags,
                    spec.point_size,
                    spec.alignment,
                );
                let style = imperialism_formats::resolve_retail_text_style(preset)
                    .expect("generated retail text style must resolve");
                let text_height = style.logical_pixel_height;
                Ok(Node {
                    padding: UiRect {
                        top: Val::Px((inset_top + (height - text_height).max(0) / 2) as f32),
                        ..default()
                    },
                    ..default()
                })
            })
        }
    });
    bsn! {
        {color}
        {shadow}
        {vertical}
    }
}

fn retail_text_disabled(enabled: bool, input_gate: bool) -> impl Scene {
    let disabled = (!enabled || !input_gate).then(|| bsn! { InteractionDisabled });
    bsn! {
        {disabled}
    }
}

/// Static caption with recovered style, color, shadow, and optional vertical centering.
pub fn retail_text(spec: RetailTextSpec, height: i32, inset_top: i32) -> impl Scene {
    let family = retail_font_family(spec.font_family);
    let vertical = spec
        .center_vertically
        .then_some((height, inset_top))
        .filter(|_| shipped_font(spec.font_family));
    bsn! {
        template(move |_context| Ok(Text::new(spec.text)))
        retail_text_presentation(spec, vertical)
        retail_text_style(family, spec.face_flags, spec.point_size, spec.alignment)
    }
}

/// Number field with the same recovered presentation as static text plus input gating.
pub fn retail_number_text(
    spec: RetailTextSpec,
    height: i32,
    inset_top: i32,
    enabled: bool,
    input_gate: bool,
) -> impl Scene {
    let family = retail_font_family(spec.font_family);
    let vertical = spec
        .center_vertically
        .then_some((height, inset_top))
        .filter(|_| shipped_font(spec.font_family));
    bsn! {
        template(move |_context| Ok(Text::new(spec.text)))
        retail_text_presentation(spec, vertical)
        retail_text_style(family, spec.face_flags, spec.point_size, spec.alignment)
        retail_text_disabled(enabled, input_gate)
    }
}

/// Editable field with recovered style, presentation, and optional character limit.
pub fn retail_text_field(
    spec: RetailTextSpec,
    max_characters: Option<usize>,
    enabled: bool,
    input_gate: bool,
) -> impl Scene {
    let family = retail_font_family(spec.font_family);
    bsn! {
        retail_edit_field()
        retail_editable_text(spec.text, max_characters)
        retail_text_presentation(spec, None)
        retail_text_style(family, spec.face_flags, spec.point_size, spec.alignment)
        retail_text_disabled(enabled, input_gate)
    }
}
