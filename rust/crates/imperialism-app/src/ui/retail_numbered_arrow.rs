//! Recovered `TNumberedArrowButton`: separate glyph images and Bevy `Button` hit boxes.
//!
//! Screens write the count caption and observe `Activate` on upper/lower.
//! This module only swaps glyph crops from button `Pressed` state onto the image entities.
//!
//! Hit testing matches retail `TrackMouse` (41px: dead at y==0 and y==20).
//! Glyphs draw at y=0..16 and y=25..41; count paints outside the 11px frame
//! (`Overflow::visible`).

use super::retail::{
    load_template_transparent_picture, retail_built_text_style, retail_text_color,
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
const GLYPH_HEIGHT: f32 = 16.0;
const UPPER_GLYPH_TOP: f32 = 0.0;
const LOWER_GLYPH_TOP: f32 = 25.0;
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

/// Links a hit-box button to the glyph image whose atlas crop it drives.
#[derive(Component, FromTemplate, Clone, Copy)]
struct ArrowGlyph {
    image: Entity,
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

#[rustfmt::skip]
pub fn retail_numbered_arrow() -> impl Scene {
    bsn! {
        Pickable::IGNORE
        Node { overflow: Overflow::visible() }
        NumberedArrowParts { upper: #Upper, lower: #Lower, count: #Count }
        Children [
            (
                #UpperImage
                Node { position_type: PositionType::Absolute, left: px(0), top: px(UPPER_GLYPH_TOP), width: px(WIDTH), height: px(GLYPH_HEIGHT) }
                template(|context| Ok(ImageNode {
                    image: load_template_transparent_picture(context, PictureId::new(ARROW_ATLAS), TRANSPARENT_INDEX)?,
                    rect: Some(TOP_IDLE), ..default()
                }))
                Pickable::IGNORE
            ),
            (
                #LowerImage
                Node { position_type: PositionType::Absolute, left: px(0), top: px(LOWER_GLYPH_TOP), width: px(WIDTH), height: px(GLYPH_HEIGHT) }
                template(|context| Ok(ImageNode {
                    image: load_template_transparent_picture(context, PictureId::new(ARROW_ATLAS), TRANSPARENT_INDEX)?,
                    rect: Some(BOTTOM_IDLE), ..default()
                }))
                Pickable::IGNORE
            ),
            (
                #Upper
                Node { position_type: PositionType::Absolute, left: px(0), top: px(UPPER_HIT_TOP), width: px(WIDTH), height: px(UPPER_HIT_HEIGHT) }
                Button
                ArrowGlyph { image: #UpperImage, idle: TOP_IDLE, pressed: TOP_PRESSED }
            ),
            (
                #Lower
                Node { position_type: PositionType::Absolute, left: px(0), top: px(LOWER_HIT_TOP), width: px(WIDTH), height: px(LOWER_HIT_HEIGHT) }
                Button
                ArrowGlyph { image: #LowerImage, idle: BOTTOM_IDLE, pressed: BOTTOM_PRESSED }
            ),
            (
                #Count
                Node { position_type: PositionType::Absolute, left: px(7), top: px(0) }
                Text("")
                retail_built_text_style(10, 0)
                retail_text_color(0)
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
    glyphs: Query<&ArrowGlyph>,
    mut images: Query<&mut ImageNode>,
) {
    let Ok(glyph) = glyphs.get(event.event_target()) else {
        return;
    };
    let Ok(mut image) = images.get_mut(glyph.image) else {
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
    #[test]
    fn count_caption_uses_built_10pt_book_antiqua() {
        use imperialism_formats::{
            RetailFontFace, RetailTextStylePreset, resolve_retail_text_style,
        };
        let style = resolve_retail_text_style(RetailTextStylePreset::built(10, 1)).unwrap();
        assert_eq!(style.face, RetailFontFace::BookAntiquaRegular);
    }
}
