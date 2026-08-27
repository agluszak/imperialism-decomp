//! Recovered `TNumberedArrowButton` as a BSN SceneComponent of two Bevy `Button`s.
//!
//! Bevy owns press/click on the transparent halves. This widget owns atlas
//! presentation from child `Pressed` state and the count overlay.

use super::retail::{retail_text_color, retail_text_shadow, retail_text_style};
use bevy::prelude::*;
use bevy::reflect::Is;
use bevy::ui::{Pressed, UiSystems};
use bevy::ui_widgets::{Activate, ActivateOnPress, Button};
use imperialism_formats::PictureId;

const ARROW_ATLAS: i16 = 804;
const TRANSPARENT_INDEX: u8 = 0x10;
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

/// Private structure for the numbered-arrow hierarchy.
#[derive(SceneComponent, FromTemplate, Clone)]
#[scene(RetailNumberedArrowProps)]
pub struct RetailNumberedArrow {
    pub upper_image: Entity,
    pub lower_image: Entity,
    pub count: Entity,
}

/// Construction props: atlas handle loaded by the installer.
#[derive(Clone, Default)]
pub struct RetailNumberedArrowProps {
    pub atlas: Handle<Image>,
}

/// Externally projected arrow count.
#[derive(Component, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NumberedArrowValue(pub i32);

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
    fn scene(props: RetailNumberedArrowProps) -> impl Scene {
        let atlas = props.atlas;
        bsn! {
            #Root
            Pickable::IGNORE
            NumberedArrowValue(0)
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
                    ImageNode {
                        image: {atlas.clone()},
                        rect: {Some(TOP_IDLE)},
                    }
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
                    ImageNode {
                        image: {atlas},
                        rect: {Some(BOTTOM_IDLE)},
                    }
                    Pickable::IGNORE
                ),
                (
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(0),
                        top: px(0),
                        width: px(WIDTH),
                        height: px(HEIGHT / 2.0),
                    }
                    Button
                    ActivateOnPress
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
                        top: px(HEIGHT / 2.0),
                        width: px(WIDTH),
                        height: px(HEIGHT / 2.0),
                    }
                    Button
                    ActivateOnPress
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
                        width: px(11),
                        height: px(16),
                    }
                    Text("")
                    retail_text_style(0, 0, 10, 1)
                    retail_text_color(0x28)
                    retail_text_shadow(0xd2, -1, -1)
                    Pickable::IGNORE
                ),
            ]
        }
    }
}

/// Install atlas art and the numbered-arrow SceneComponent on a recovered node.
pub fn install_numbered_arrow(
    commands: &mut Commands,
    entity: Entity,
    assets: &mut super::retail::RetailUiAssets,
) {
    let atlas = assets
        .transparent_picture(PictureId::new(ARROW_ATLAS), TRANSPARENT_INDEX)
        .expect("retail numbered-arrow atlas 804 must load");
    commands
        .entity(entity)
        .remove::<Button>()
        .apply_scene(bsn! {
            @RetailNumberedArrow {
                @atlas: atlas,
            }
        });
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
            .0 = if value.0 == 0 {
            String::new()
        } else {
            value.0.to_string()
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
