//! Recovered `TArmyPlacard`-style picture with a right-aligned count overlay.
//!
//! Screen code selects the `ImageNode`; this widget owns the count child only.

use super::retail::retail_text_components;
use crate::{RetailAssetsResource, RetailFonts};
use bevy::prelude::*;
use bevy::text::LineHeight;
use imperialism_formats::{RetailTextStyleError, RetailTextStylePreset, resolve_retail_text_style};

const COUNT_PALETTE: u8 = 0x28;
const COUNT_SHADOW_PALETTE: u8 = 0xd2;

/// Count overlay for a picture placard. `None` clears the label.
#[derive(Component, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetailCountedPicture {
    pub value: Option<i32>,
}

#[derive(Component, Clone, Copy)]
struct CountedPictureText(Entity);

pub(super) fn register_counted_picture(app: &mut App) {
    app.add_systems(
        PostUpdate,
        (spawn_counted_picture_text, draw_counted_pictures).chain(),
    );
}

#[allow(clippy::type_complexity)]
fn spawn_counted_picture_text(
    mut commands: Commands,
    placards: Query<Entity, (Added<RetailCountedPicture>, Without<CountedPictureText>)>,
    fonts: Res<RetailFonts>,
    assets: Res<RetailAssetsResource>,
) {
    let Ok((font, layout, line_height)) = counted_picture_style(&fonts) else {
        return;
    };
    let text_color = palette_color(&assets, COUNT_PALETTE);
    let shadow_color = palette_color(&assets, COUNT_SHADOW_PALETTE);
    for entity in &placards {
        let text = commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    right: Val::Px(0.0),
                    bottom: Val::Px(2.0),
                    width: Val::Px(42.0),
                    height: Val::Px(16.0),
                    ..default()
                },
                Text::new(""),
                font.clone(),
                layout,
                line_height,
                TextColor(text_color),
                TextShadow {
                    offset: Vec2::new(-1.0, -1.0),
                    color: shadow_color,
                },
                Pickable::IGNORE,
                ChildOf(entity),
            ))
            .id();
        commands.entity(entity).insert(CountedPictureText(text));
    }
}

#[allow(clippy::type_complexity)]
fn draw_counted_pictures(
    placards: Query<
        (&RetailCountedPicture, &CountedPictureText),
        Or<(Changed<RetailCountedPicture>, Added<CountedPictureText>)>,
    >,
    mut texts: Query<&mut Text>,
) {
    for (placard, CountedPictureText(text)) in &placards {
        if let Ok(mut label) = texts.get_mut(*text) {
            label.0 = placard
                .value
                .map(|count| count.to_string())
                .unwrap_or_default();
        }
    }
}

fn palette_color(assets: &RetailAssetsResource, index: u8) -> Color {
    let [red, green, blue] = assets.assets().default_dib_palette()[index].to_array();
    Color::srgb_u8(red, green, blue)
}

fn counted_picture_style(
    fonts: &RetailFonts,
) -> Result<(TextFont, TextLayout, LineHeight), RetailTextStyleError> {
    let style = resolve_retail_text_style(RetailTextStylePreset {
        font_family: 0,
        face_flags: 0,
        point_size: 10,
        alignment: -1,
    })?;
    let (font, layout, line_height, _) = retail_text_components(style, fonts.get(style.face));
    Ok((font, layout, line_height))
}
