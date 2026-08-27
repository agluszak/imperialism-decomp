//! Recovered `TNumberedArrowButton` as composition of two Bevy `Button`s.
//!
//! Bevy owns press/click on the transparent halves. This widget owns atlas
//! presentation from child `Pressed` state and the count overlay.

use super::retail::retail_text_components;
use crate::{RetailAssetsResource, RetailFonts};
use bevy::prelude::*;
use bevy::reflect::Is;
use bevy::text::LineHeight;
use bevy::ui::Pressed;
use bevy::ui_widgets::{Activate, ActivateOnPress, Button};
use imperialism_formats::{
    PictureId, RetailTextStyleError, RetailTextStylePreset, resolve_retail_text_style,
};

const ARROW_ATLAS: i16 = 804;
const TRANSPARENT_INDEX: u8 = 0x10;
const COUNT_PALETTE: u8 = 0x28;
const COUNT_SHADOW_PALETTE: u8 = 0xd2;
const HALF_HEIGHT: f32 = 16.0;
const LOWER_TOP: f32 = 25.0;
const WIDTH: f32 = 11.0;
const HEIGHT: f32 = 41.0;

/// Top half idle/pressed and bottom half idle/pressed atlas crops (atlas 804).
const TOP_IDLE: Rect = Rect {
    min: Vec2::new(10.0, 0.0),
    max: Vec2::new(21.0, 16.0),
};
const TOP_PRESSED: Rect = Rect {
    min: Vec2::new(0.0, 0.0),
    max: Vec2::new(11.0, 16.0),
};
const BOTTOM_IDLE: Rect = Rect {
    min: Vec2::new(33.0, 0.0),
    max: Vec2::new(44.0, 16.0),
};
const BOTTOM_PRESSED: Rect = Rect {
    min: Vec2::new(22.0, 0.0),
    max: Vec2::new(33.0, 16.0),
};

/// Presentation state for the numbered arrow count.
#[derive(Component, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetailNumberedArrow {
    pub value: i32,
}

/// Which half of a numbered arrow was activated.
#[derive(EntityEvent, Clone, Copy, Debug, Eq, PartialEq)]
pub struct NumberedArrowClick {
    #[event_target]
    pub entity: Entity,
    pub action: NumberedArrowAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NumberedArrowAction {
    Upper,
    Lower,
}

#[derive(Component, Clone, Copy)]
struct NumberedArrowHalf {
    root: Entity,
    upper: bool,
}

#[derive(Component, Clone, Copy)]
struct NumberedArrowParts {
    upper_image: Entity,
    lower_image: Entity,
    count: Entity,
}

pub(super) fn register_numbered_arrow(app: &mut App) {
    app.add_systems(
        PostUpdate,
        (spawn_numbered_arrow_parts, draw_numbered_arrow_counts).chain(),
    )
    .add_observer(on_numbered_arrow_half_activate)
    .add_observer(on_numbered_arrow_half_pressed::<Add>)
    .add_observer(on_numbered_arrow_half_pressed::<Remove>);
}

/// Install atlas art and widget state on a recovered numbered-arrow node.
pub fn install_numbered_arrow(
    commands: &mut Commands,
    entity: Entity,
    assets: &mut super::retail::RetailUiAssets,
) {
    let atlas = assets
        .transparent_picture(PictureId::new(ARROW_ATLAS), TRANSPARENT_INDEX)
        .expect("retail numbered-arrow atlas 804 must load");
    commands.entity(entity).insert((
        RetailNumberedArrow { value: 0 },
        ImageNode {
            image: atlas,
            // Root image is unused; halves own the glyphs. Keep IGNORE pick so
            // transparent half buttons receive hits.
            ..default()
        },
        Pickable::IGNORE,
    ));
}

#[allow(clippy::type_complexity)]
fn spawn_numbered_arrow_parts(
    mut commands: Commands,
    arrows: Query<(Entity, &ImageNode), (Added<RetailNumberedArrow>, Without<NumberedArrowParts>)>,
    fonts: Res<RetailFonts>,
    assets: Res<RetailAssetsResource>,
) {
    let Ok((font, layout, line_height)) = arrow_count_style(&fonts) else {
        return;
    };
    let text_color = palette_color(&assets, COUNT_PALETTE);
    let shadow_color = palette_color(&assets, COUNT_SHADOW_PALETTE);
    for (root, image) in &arrows {
        let atlas = image.image.clone();
        let upper_image = commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(0.0),
                    top: Val::Px(0.0),
                    width: Val::Px(WIDTH),
                    height: Val::Px(HALF_HEIGHT),
                    ..default()
                },
                ImageNode {
                    image: atlas.clone(),
                    rect: Some(TOP_IDLE),
                    ..default()
                },
                Pickable::IGNORE,
                ChildOf(root),
            ))
            .id();
        let lower_image = commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(0.0),
                    top: Val::Px(LOWER_TOP),
                    width: Val::Px(WIDTH),
                    height: Val::Px(HALF_HEIGHT),
                    ..default()
                },
                ImageNode {
                    image: atlas,
                    rect: Some(BOTTOM_IDLE),
                    ..default()
                },
                Pickable::IGNORE,
                ChildOf(root),
            ))
            .id();
        let upper_button = commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(0.0),
                    top: Val::Px(0.0),
                    width: Val::Px(WIDTH),
                    height: Val::Px(HEIGHT / 2.0),
                    ..default()
                },
                Button,
                ActivateOnPress,
                NumberedArrowHalf { root, upper: true },
                ChildOf(root),
            ))
            .id();
        let lower_button = commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(0.0),
                    top: Val::Px(HEIGHT / 2.0),
                    width: Val::Px(WIDTH),
                    height: Val::Px(HEIGHT / 2.0),
                    ..default()
                },
                Button,
                ActivateOnPress,
                NumberedArrowHalf { root, upper: false },
                ChildOf(root),
            ))
            .id();
        let _ = (upper_button, lower_button);
        let count = commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(7.0),
                    top: Val::Px(0.0),
                    width: Val::Px(11.0),
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
                ChildOf(root),
            ))
            .id();
        commands.entity(root).insert(NumberedArrowParts {
            upper_image,
            lower_image,
            count,
        });
    }
}

#[allow(clippy::type_complexity)]
fn draw_numbered_arrow_counts(
    arrows: Query<
        (&RetailNumberedArrow, &NumberedArrowParts),
        Or<(Changed<RetailNumberedArrow>, Added<NumberedArrowParts>)>,
    >,
    mut texts: Query<&mut Text>,
) {
    for (arrow, parts) in &arrows {
        if let Ok(mut text) = texts.get_mut(parts.count) {
            text.0 = if arrow.value == 0 {
                String::new()
            } else {
                arrow.value.to_string()
            };
        }
    }
}

#[allow(clippy::type_complexity)]
fn on_numbered_arrow_half_pressed<E: EntityEvent>(
    event: On<E, Pressed>,
    halves: Query<&NumberedArrowHalf>,
    parts: Query<&NumberedArrowParts>,
    mut images: Query<&mut ImageNode>,
) {
    let Ok(half) = halves.get(event.event_target()) else {
        return;
    };
    let Ok(parts) = parts.get(half.root) else {
        return;
    };
    let entity = if half.upper {
        parts.upper_image
    } else {
        parts.lower_image
    };
    let Ok(mut image) = images.get_mut(entity) else {
        return;
    };
    let pressed = !E::is::<Remove>();
    image.rect = Some(match (half.upper, pressed) {
        (true, false) => TOP_IDLE,
        (true, true) => TOP_PRESSED,
        (false, false) => BOTTOM_IDLE,
        (false, true) => BOTTOM_PRESSED,
    });
}

fn on_numbered_arrow_half_activate(
    activate: On<Activate>,
    halves: Query<&NumberedArrowHalf>,
    mut commands: Commands,
) {
    let Ok(half) = halves.get(activate.entity) else {
        return;
    };
    let action = if half.upper {
        NumberedArrowAction::Upper
    } else {
        NumberedArrowAction::Lower
    };
    commands.trigger(NumberedArrowClick {
        entity: half.root,
        action,
    });
}

fn palette_color(assets: &RetailAssetsResource, index: u8) -> Color {
    let [red, green, blue] = assets.assets().default_dib_palette()[index].to_array();
    Color::srgb_u8(red, green, blue)
}

fn arrow_count_style(
    fonts: &RetailFonts,
) -> Result<(TextFont, TextLayout, LineHeight), RetailTextStyleError> {
    let style = resolve_retail_text_style(RetailTextStylePreset {
        font_family: 0,
        face_flags: 0,
        point_size: 10,
        alignment: 1,
    })?;
    let (font, layout, line_height, _) = retail_text_components(style, fonts.get(style.face));
    Ok((font, layout, line_height))
}
