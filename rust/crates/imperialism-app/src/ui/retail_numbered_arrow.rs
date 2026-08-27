//! Recovered `TNumberedArrowButton`: two Bevy `Button`s with atlas skins.
//!
//! Screens write the count caption and observe `Activate` on upper/lower.
//! This module only swaps glyph crops from child `Pressed` state.
//!
//! Hit testing matches retail `TrackMouse` (41px: dead at y==0 and y==20).
//! Count caption paints outside the 11px frame (`Overflow::visible`).

use super::retail::{
    load_template_transparent_picture, retail_text_color, retail_text_shadow, retail_text_style,
};
use bevy::prelude::*;
use bevy::reflect::Is;
use bevy::ui::{Overflow, Pressed};
use bevy::ui_widgets::Button;
use imperialism_formats::PictureId;

const ARROW_ATLAS: i16 = 804;
const TRANSPARENT_INDEX: u8 = 0x10;
const WIDTH: f32 = 11.0;
const HEIGHT: f32 = 41.0;
const MIDPOINT: f32 = 20.0;
const UPPER_HIT_TOP: f32 = 1.0;
const UPPER_HIT_HEIGHT: f32 = MIDPOINT - UPPER_HIT_TOP;
const LOWER_HIT_TOP: f32 = MIDPOINT + 1.0;
const LOWER_HIT_HEIGHT: f32 = HEIGHT - LOWER_HIT_TOP;

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

#[derive(Component, FromTemplate, Clone, Copy, Default)]
struct NumberedArrowGlyph {
    idle: Rect,
    pressed: Rect,
}

/// Private structure for the numbered-arrow hierarchy.
#[derive(Component, FromTemplate, Clone, Copy)]
pub struct NumberedArrowParts {
    pub upper: Entity,
    pub lower: Entity,
    pub count: Entity,
}

pub fn retail_numbered_arrow() -> impl Scene {
    bsn! {
        Pickable::IGNORE
        Node { overflow: Overflow::visible() }
        NumberedArrowParts {
            upper: #Upper,
            lower: #Lower,
            count: #Count,
        }
        Children [
            (
                #Upper
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0), top: px(UPPER_HIT_TOP),
                    width: px(WIDTH), height: px(UPPER_HIT_HEIGHT),
                }
                Button
                NumberedArrowGlyph { idle: TOP_IDLE, pressed: TOP_PRESSED }
                template(|context| {
                    Ok(ImageNode {
                        image: load_template_transparent_picture(
                            context, PictureId::new(ARROW_ATLAS), TRANSPARENT_INDEX,
                        )?,
                        rect: Some(TOP_IDLE),
                        ..default()
                    })
                })
            ),
            (
                #Lower
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0), top: px(LOWER_HIT_TOP),
                    width: px(WIDTH), height: px(LOWER_HIT_HEIGHT),
                }
                Button
                NumberedArrowGlyph { idle: BOTTOM_IDLE, pressed: BOTTOM_PRESSED }
                template(|context| {
                    Ok(ImageNode {
                        image: load_template_transparent_picture(
                            context, PictureId::new(ARROW_ATLAS), TRANSPARENT_INDEX,
                        )?,
                        rect: Some(BOTTOM_IDLE),
                        ..default()
                    })
                })
            ),
            (
                #Count
                Node {
                    position_type: PositionType::Absolute,
                    left: px(7), top: px(0), width: px(20), height: px(16),
                }
                Text("")
                retail_text_style(0, 0, 10, 1)
                retail_text_color(0x28)
                retail_text_shadow(0, 1, 1)
                Pickable::IGNORE
            ),
        ]
    }
}

pub(super) fn register_numbered_arrow(app: &mut App) {
    app.add_observer(on_numbered_arrow_glyph_pressed::<Add>)
        .add_observer(on_numbered_arrow_glyph_pressed::<Remove>);
}

fn on_numbered_arrow_glyph_pressed<E: EntityEvent>(
    event: On<E, Pressed>,
    mut glyphs: Query<(&NumberedArrowGlyph, &mut ImageNode)>,
) {
    let Ok((glyph, mut image)) = glyphs.get_mut(event.event_target()) else {
        return;
    };
    image.rect = Some(if !E::is::<Remove>() {
        glyph.pressed
    } else {
        glyph.idle
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_rects_leave_retail_dead_pixels() {
        assert_eq!(UPPER_HIT_TOP, 1.0);
        assert_eq!(UPPER_HIT_HEIGHT, 19.0);
        assert_eq!(LOWER_HIT_TOP, 21.0);
        assert_eq!(LOWER_HIT_HEIGHT, 20.0);
        assert_eq!(UPPER_HIT_TOP + UPPER_HIT_HEIGHT, MIDPOINT);
        assert_eq!(LOWER_HIT_TOP + LOWER_HIT_HEIGHT, HEIGHT);
    }
}
