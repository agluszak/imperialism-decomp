//! Recovered `TPlacard` as a reusable Bevy widget.
//!
//! Owns numeric value, zero-hides visibility, decimal formatting, digit-aware
//! layout padding, fixed text style, and shadow. Screens only write `value`.

use super::retail::retail_text_components;
use crate::{RetailAssetsResource, RetailFonts};
use bevy::prelude::*;
use bevy::text::LineHeight;
use imperialism_formats::{RetailTextStyleError, RetailTextStylePreset, resolve_retail_text_style};

const PLACARD_TEXT_STYLE: RetailTextStylePreset = RetailTextStylePreset {
    font_family: 3,
    face_flags: 0,
    point_size: 10,
    alignment: 1,
};

/// Recovered placard presentation state (`TPlacard::glyph90`).
#[derive(Component, Clone, Copy, Debug, Default)]
pub struct RetailPlacard {
    pub value: i16,
}

#[derive(Component, Clone, Copy, Debug)]
struct PlacardText(Entity);

pub(super) fn register_placard(app: &mut App) {
    app.add_systems(PostUpdate, (spawn_placard_text, draw_placards).chain());
}

fn palette_color(assets: &RetailAssetsResource, index: u8) -> Color {
    let [red, green, blue] = assets.assets().default_dib_palette()[index].to_array();
    Color::srgb_u8(red, green, blue)
}

fn placard_text_style(
    fonts: &RetailFonts,
) -> Result<(TextFont, TextLayout, LineHeight, f32), RetailTextStyleError> {
    let style = resolve_retail_text_style(PLACARD_TEXT_STYLE)?;
    let (font, layout, line_height, _) = retail_text_components(style, fonts.get(style.face));
    let line_px = match line_height {
        LineHeight::Px(value) => value,
        LineHeight::RelativeToFont(_) => unreachable!("absolute line height"),
    };
    Ok((font, layout, line_height, line_px))
}

#[allow(clippy::type_complexity)]
fn spawn_placard_text(
    mut commands: Commands,
    placards: Query<(Entity, &Node), (Added<RetailPlacard>, Without<PlacardText>)>,
    fonts: Res<RetailFonts>,
    assets: Res<RetailAssetsResource>,
) {
    let Ok((font, layout, line_height, line_px)) = placard_text_style(&fonts) else {
        return;
    };
    let text_color = palette_color(&assets, 0x28);
    let shadow_color = palette_color(&assets, 0);
    for (entity, node) in &placards {
        let Val::Px(height) = node.height else {
            continue;
        };
        let text = commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(0.0),
                    top: Val::Px(0.0),
                    width: Val::Percent(100.0),
                    height: Val::Percent(100.0),
                    padding: UiRect::top(Val::Px((height - line_px).max(0.0))),
                    ..default()
                },
                Text::new(""),
                font.clone(),
                layout,
                line_height,
                TextColor(text_color),
                TextShadow {
                    offset: Vec2::ONE,
                    color: shadow_color,
                },
                Pickable::IGNORE,
                Visibility::Inherited,
                ChildOf(entity),
            ))
            .id();
        commands.entity(entity).insert(PlacardText(text));
    }
}

#[allow(clippy::type_complexity)]
fn draw_placards(
    placards: Query<
        (Entity, &RetailPlacard, &PlacardText),
        Or<(Changed<RetailPlacard>, Added<PlacardText>)>,
    >,
    mut commands: Commands,
    mut texts: Query<&mut Text>,
) {
    for (entity, placard, PlacardText(text)) in &placards {
        let shown = placard.value != 0;
        let visibility = if shown {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        commands.entity(entity).insert(visibility);
        commands.entity(*text).insert(visibility);
        if let Ok(mut label) = texts.get_mut(*text) {
            label.0 = if shown {
                placard.value.to_string()
            } else {
                String::new()
            };
        }
    }
}
