//! Recovered retail text presentation for generated UI scenes.

use super::retail::{retail_edit_field, retail_editable_text, retail_text_style};
use crate::RetailAssetsResource;
use bevy::prelude::*;
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
    matches!(retail_font_family(family), 1 | 2 | 3)
}

fn palette_color(context: &bevy::ecs::template::TemplateContext, index: u8) -> Color {
    let [red, green, blue] = context
        .resource::<RetailAssetsResource>()
        .assets()
        .default_dib_palette()[index]
        .to_array();
    Color::srgb_u8(red, green, blue)
}

/// Static caption with recovered style, color, shadow, and optional vertical centering.
pub fn retail_text(spec: RetailTextSpec, height: i32, inset_top: i32) -> impl Scene {
    let family = retail_font_family(spec.font_family);
    bsn! {
        template(move |context| {
            context.entity.insert(TextColor(
                spec.color_index
                    .map(|index| palette_color(context, index))
                    .unwrap_or(Color::BLACK),
            ));
            if let Some(index) = spec.shadow_color_index {
                context.entity.insert(TextShadow {
                    offset: Vec2::new(
                        spec.shadow_offset.0 as f32,
                        spec.shadow_offset.1 as f32,
                    ),
                    color: palette_color(context, index),
                });
            }
            if spec.center_vertically && shipped_font(spec.font_family) {
                let preset = RetailTextStylePreset::explicit(
                    family,
                    spec.face_flags,
                    spec.point_size,
                    spec.alignment,
                );
                let style = imperialism_formats::resolve_retail_text_style(preset)
                    .expect("generated retail text style must resolve");
                let text_height = style.logical_pixel_height;
                context.entity.insert(Node {
                    padding: UiRect {
                        top: Val::Px((inset_top + (height - text_height).max(0) / 2) as f32),
                        ..default()
                    },
                    ..default()
                });
            }
            Ok(Text::new(spec.text))
        })
        retail_text_style(family, spec.face_flags, spec.point_size, spec.alignment)
    }
}

/// Editable field with recovered style and optional character limit.
pub fn retail_text_field(spec: RetailTextSpec, max_characters: Option<usize>) -> impl Scene {
    let family = retail_font_family(spec.font_family);
    bsn! {
        retail_edit_field()
        retail_editable_text(spec.text, max_characters)
        retail_text_style(family, spec.face_flags, spec.point_size, spec.alignment)
    }
}
