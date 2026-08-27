//! Recovered `TNumberedArrowButton` as a BSN SceneComponent of two Bevy `Button`s.
//!
//! Bevy owns press/click on the transparent halves. This widget owns atlas
//! presentation from child `Pressed` state and the count overlay. Atlas 804 is
//! loaded inside the scene (keyed transparency), not passed as a binder prop.
//!
//! Hit testing matches retail `TrackMouse`: for a 41px control, integer
//! `height/2 == 20` leaves `y == 0` and `y == 20` dead. Activation is release-
//! based (stock `Button`), not `ActivateOnPress`. The count caption is drawn
//! outside the 11px frame, so the root opts out of the generated clip.

use super::retail::{
    load_template_transparent_picture, retail_text_color, retail_text_shadow, retail_text_style,
};
use bevy::prelude::*;
use bevy::reflect::Is;
use bevy::ui::{Overflow, Pressed, UiSystems};
use bevy::ui_widgets::{Activate, Button};
use imperialism_formats::PictureId;

const ARROW_ATLAS: i16 = 804;
const TRANSPARENT_INDEX: u8 = 0x10;
const HALF_HEIGHT: f32 = 16.0;
const LOWER_TOP: f32 = 25.0;
const WIDTH: f32 = 11.0;
const HEIGHT: f32 = 41.0;
/// Integer `frameHeight / 2` as recovered in `TNumberedArrowButton::TrackMouse`.
const MIDPOINT: f32 = 20.0;
/// Upper hit: `y > 0 && y < height/2` → `[1, 20)`.
const UPPER_HIT_TOP: f32 = 1.0;
const UPPER_HIT_HEIGHT: f32 = MIDPOINT - UPPER_HIT_TOP;
/// Lower hit: `y > height/2 && y < height` → `[21, 41)`.
const LOWER_HIT_TOP: f32 = MIDPOINT + 1.0;
const LOWER_HIT_HEIGHT: f32 = HEIGHT - LOWER_HIT_TOP;

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

/// Private structure for the numbered-arrow hierarchy.
#[derive(SceneComponent, FromTemplate, Clone)]
pub struct RetailNumberedArrow {
    pub upper_image: Entity,
    pub lower_image: Entity,
    pub count: Entity,
}

/// Externally projected arrow count. `None` clears the caption; `Some(0)` shows `0`.
#[derive(Component, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NumberedArrowValue(pub Option<i32>);

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

#[derive(Component, FromTemplate, Clone)]
struct NumberedArrowHalf {
    root: Entity,
    upper: bool,
}

impl RetailNumberedArrow {
    fn scene() -> impl Scene {
        bsn! {
            #Root
            Pickable::IGNORE
            // Caption at x=7 extends past the 11px hit frame; retail paints outside.
            Node {
                overflow: Overflow::visible(),
            }
            NumberedArrowValue(None)
            RetailNumberedArrow {
                upper_image: #UpperImage,
                lower_image: #LowerImage,
                count: #Count,
            }
            Children [
                (
                    #UpperImage
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(0),
                        top: px(0),
                        width: px(WIDTH),
                        height: px(HALF_HEIGHT),
                    }
                    template(|context| {
                        Ok(ImageNode {
                            image: load_template_transparent_picture(
                                context,
                                PictureId::new(ARROW_ATLAS),
                                TRANSPARENT_INDEX,
                            )?,
                            rect: Some(TOP_IDLE),
                            ..default()
                        })
                    })
                    Pickable::IGNORE
                ),
                (
                    #LowerImage
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(0),
                        top: px(LOWER_TOP),
                        width: px(WIDTH),
                        height: px(HALF_HEIGHT),
                    }
                    template(|context| {
                        Ok(ImageNode {
                            image: load_template_transparent_picture(
                                context,
                                PictureId::new(ARROW_ATLAS),
                                TRANSPARENT_INDEX,
                            )?,
                            rect: Some(BOTTOM_IDLE),
                            ..default()
                        })
                    })
                    Pickable::IGNORE
                ),
                (
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(0),
                        top: px(UPPER_HIT_TOP),
                        width: px(WIDTH),
                        height: px(UPPER_HIT_HEIGHT),
                    }
                    Button
                    NumberedArrowHalf {
                        root: #Root,
                        upper: true,
                    }
                    on(on_numbered_arrow_half_activate)
                ),
                (
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(0),
                        top: px(LOWER_HIT_TOP),
                        width: px(WIDTH),
                        height: px(LOWER_HIT_HEIGHT),
                    }
                    Button
                    NumberedArrowHalf {
                        root: #Root,
                        upper: false,
                    }
                    on(on_numbered_arrow_half_activate)
                ),
                (
                    #Count
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(7),
                        top: px(0),
                        width: px(20),
                        height: px(16),
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
}

/// BSN helper used by generated screens.
pub fn retail_numbered_arrow() -> impl Scene {
    bsn! {
        @RetailNumberedArrow
    }
}

pub(super) fn register_numbered_arrow(app: &mut App) {
    app.add_systems(
        PostUpdate,
        draw_numbered_arrow_counts.before(UiSystems::Prepare),
    )
    .add_observer(on_numbered_arrow_half_pressed::<Add>)
    .add_observer(on_numbered_arrow_half_pressed::<Remove>);
}

fn draw_numbered_arrow_counts(
    arrows: Query<(&NumberedArrowValue, &RetailNumberedArrow), Changed<NumberedArrowValue>>,
    mut texts: Query<&mut Text>,
) {
    for (value, arrow) in &arrows {
        texts
            .get_mut(arrow.count)
            .expect("RetailNumberedArrow count child")
            .0 = match value.0 {
            None => String::new(),
            Some(count) => count.to_string(),
        };
    }
}

fn on_numbered_arrow_half_pressed<E: EntityEvent>(
    event: On<E, Pressed>,
    halves: Query<&NumberedArrowHalf>,
    arrows: Query<&RetailNumberedArrow>,
    mut images: Query<&mut ImageNode>,
) {
    let Ok(half) = halves.get(event.event_target()) else {
        return;
    };
    let Ok(arrow) = arrows.get(half.root) else {
        return;
    };
    let entity = if half.upper {
        arrow.upper_image
    } else {
        arrow.lower_image
    };
    let mut image = images
        .get_mut(entity)
        .expect("RetailNumberedArrow half image");
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
