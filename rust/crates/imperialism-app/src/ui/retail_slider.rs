//! Recovered `TTwoPicSlider` presentation with retail pointer→value mapping.
//!
//! Stock Bevy `Slider` track math spans the full control height. Retail instead uses
//! `splitPosition = height - y` and `value = max(split - 12, 0) * scale / (height - 12)`,
//! so the bottom 12px are a zero plateau. Input is therefore handwritten; `SliderValue`
//! still stores the preference scale value that screens observe.

use super::retail::{
    load_template_picture, retail_text_color, retail_text_shadow, retail_text_style,
};
use crate::RetailAssetsResource;
use bevy::ecs::template::TemplateContext;
use bevy::prelude::*;
use bevy::ui::{InteractionDisabled, RelativeCursorPosition, UiSystems};
use bevy::ui_widgets::{SliderPrecision, SliderRange, SliderValue, ValueChange};
use imperialism_formats::{PictureId, StringGroup};

pub const TWO_PIC_SLIDER_SPLIT_PAD: i16 = 0x0c;

/// Private child refs for the two-picture slider hierarchy.
#[derive(Component, FromTemplate, Clone, Copy)]
pub struct RetailTwoPicSliderParts {
    pub lower: Entity,
    pub off: Entity,
}

/// Generated construction for recovered `TTwoPicSlider` instances.
pub fn retail_two_pic_slider(
    picture_base: i16,
    scale: i16,
    off_group: i16,
    off_index: i16,
) -> impl Scene {
    bsn! {
        SliderValue(0.0)
        SliderRange::new(0.0, scale as f32)
        SliderPrecision(0)
        RelativeCursorPosition::default()
        Pickable::default()
        RetailTwoPicSliderParts {
            lower: #Lower,
            off: #Off,
        }
        template(move |context| {
            Ok(ImageNode::new(load_template_picture(
                context,
                PictureId::new(picture_base),
            )?))
        })
        Children [
            (
                #Lower
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0),
                    bottom: px(0),
                    width: percent(100),
                    height: px(0),
                    overflow: Overflow::clip(),
                }
                template(move |context| {
                    Ok(ImageNode::new(load_template_picture(
                        context,
                        PictureId::new(picture_base + 1),
                    )?))
                })
                Pickable::IGNORE
            ),
            (
                #Off
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0),
                    top: px(0),
                    width: percent(100),
                    height: percent(100),
                    justify_content: JustifyContent::Center,
                    align_items: AlignItems::Center,
                }
                template(move |context| Ok(Text(load_off_string(context, off_group, off_index))))
                retail_text_style(1, 0, 14, 1)
                retail_text_color(0x28)
                retail_text_shadow(0, 1, 1)
                Visibility::Visible
                Pickable::IGNORE
            ),
        ]
    }
}

fn load_off_string(context: &TemplateContext, off_group: i16, off_index: i16) -> String {
    context
        .resource::<RetailAssetsResource>()
        .assets()
        .string(StringGroup::new(off_group as u16).entry(off_index as u16))
        .unwrap_or_else(|_| "Off".to_string())
}

pub(super) fn register_slider(app: &mut App) {
    app.add_observer(on_two_pic_slider_press)
        .add_observer(on_two_pic_slider_drag)
        .add_observer(on_two_pic_slider_drag_end)
        .add_systems(
            PostUpdate,
            sync_two_pic_slider_visuals.before(UiSystems::Prepare),
        );
}

type TwoPicSliderQuery = (
    &'static SliderValue,
    &'static SliderRange,
    &'static RetailTwoPicSliderParts,
    &'static Node,
);

/// Value→bitmap split for draw (`split + 12` when non-zero; pad collapses to empty fill).
pub fn two_pic_slider_split(value: i16, height: i16, scale: i16) -> i16 {
    let span = height - TWO_PIC_SLIDER_SPLIT_PAD;
    if span <= 0 || scale == 0 {
        return 0;
    }
    let split = value * span / scale;
    if split == 0 {
        0
    } else {
        split + TWO_PIC_SLIDER_SPLIT_PAD
    }
}

/// `TTwoPicSlider::TrackMouse` / `SliderScaledValue`: pointer y (from top) → preference value.
///
/// Retail: `split = height - clamp(y)`, then `max(split - 12, 0) * scale / (height - 12)`.
/// The bottom 12px all map to zero.
pub fn two_pic_slider_value_at_y(y: i16, height: i16, scale: i16) -> i16 {
    let span = height - TWO_PIC_SLIDER_SPLIT_PAD;
    if span <= 0 || scale == 0 {
        return 0;
    }
    let mut requested = y;
    if height <= requested {
        requested = height;
    }
    if requested < 1 {
        requested = 0;
    }
    let split = height - requested;
    let adjusted = if split >= TWO_PIC_SLIDER_SPLIT_PAD {
        split - TWO_PIC_SLIDER_SPLIT_PAD
    } else {
        0
    };
    adjusted * scale / span
}

fn pointer_y_from_hit(hit: Option<Vec3>, height: f32) -> Option<i16> {
    let position = hit?;
    Some((((position.y + 0.5) * height).floor() as i32).clamp(0, i32::from(i16::MAX)) as i16)
}

fn pointer_y_from_cursor(cursor: &RelativeCursorPosition, height: f32) -> Option<i16> {
    let normalized = cursor.normalized.filter(|_| cursor.cursor_over())?;
    Some((normalized.y * height).floor() as i16)
}

fn emit_two_pic_slider_value_at_y(
    commands: &mut Commands,
    entity: Entity,
    range: &SliderRange,
    height: i16,
    y: i16,
    is_final: bool,
) {
    let value = two_pic_slider_value_at_y(y, height, range.end() as i16);
    commands.trigger(ValueChange {
        source: entity,
        value: f32::from(value),
        is_final,
    });
}

fn emit_two_pic_slider_value(
    commands: &mut Commands,
    entity: Entity,
    range: &SliderRange,
    node: &Node,
    hit: Option<Vec3>,
    is_final: bool,
) {
    let Val::Px(height) = node.height else {
        return;
    };
    let Some(y) = pointer_y_from_hit(hit, height) else {
        return;
    };
    emit_two_pic_slider_value_at_y(commands, entity, range, height as i16, y, is_final);
}

fn on_two_pic_slider_press(
    mut press: On<Pointer<Press>>,
    sliders: Query<(&SliderRange, &Node, Has<InteractionDisabled>), With<RetailTwoPicSliderParts>>,
    mut commands: Commands,
) {
    let Ok((range, node, disabled)) = sliders.get(press.entity) else {
        return;
    };
    press.propagate(false);
    if disabled {
        return;
    }
    emit_two_pic_slider_value(
        &mut commands,
        press.entity,
        range,
        node,
        press.hit.position,
        false,
    );
}

fn on_two_pic_slider_drag(
    mut drag: On<Pointer<Drag>>,
    sliders: Query<
        (
            &SliderRange,
            &Node,
            Has<InteractionDisabled>,
            &RelativeCursorPosition,
        ),
        With<RetailTwoPicSliderParts>,
    >,
    mut commands: Commands,
) {
    let Ok((range, node, disabled, cursor)) = sliders.get(drag.entity) else {
        return;
    };
    drag.propagate(false);
    if disabled {
        return;
    }
    let Val::Px(height) = node.height else {
        return;
    };
    let Some(y) = pointer_y_from_cursor(cursor, height) else {
        return;
    };
    emit_two_pic_slider_value_at_y(&mut commands, drag.entity, range, height as i16, y, false);
}

fn on_two_pic_slider_drag_end(
    mut drag_end: On<Pointer<DragEnd>>,
    sliders: Query<
        (
            &SliderRange,
            &Node,
            Has<InteractionDisabled>,
            &RelativeCursorPosition,
        ),
        With<RetailTwoPicSliderParts>,
    >,
    mut commands: Commands,
) {
    let Ok((range, node, disabled, cursor)) = sliders.get(drag_end.entity) else {
        return;
    };
    drag_end.propagate(false);
    if disabled {
        return;
    }
    let Val::Px(height) = node.height else {
        return;
    };
    let Some(y) = pointer_y_from_cursor(cursor, height) else {
        return;
    };
    emit_two_pic_slider_value_at_y(
        &mut commands,
        drag_end.entity,
        range,
        height as i16,
        y,
        true,
    );
}

fn sync_two_pic_slider_visuals(
    sliders: Query<TwoPicSliderQuery, (With<RetailTwoPicSliderParts>, Changed<SliderValue>)>,
    mut nodes: Query<&mut Node, Without<RetailTwoPicSliderParts>>,
    mut images: Query<&mut ImageNode, Without<RetailTwoPicSliderParts>>,
    mut visibilities: Query<&mut Visibility>,
) {
    for (value, range, parts, root) in &sliders {
        let (Val::Px(height), Val::Px(width)) = (root.height, root.width) else {
            continue;
        };
        let height = height as i16;
        let split = two_pic_slider_split(value.0 as i16, height, range.end() as i16);
        let fill = if split < TWO_PIC_SLIDER_SPLIT_PAD {
            0
        } else {
            split
        };
        if let Ok(mut lower_node) = nodes.get_mut(parts.lower) {
            lower_node.height = Val::Px(f32::from(fill));
        }
        if let Ok(mut lower_image) = images.get_mut(parts.lower) {
            let top = f32::from(height - fill);
            lower_image.rect = Some(Rect {
                min: Vec2::new(0.0, top),
                max: Vec2::new(width.max(1.0), f32::from(height).max(top)),
            });
        }
        if let Ok(mut off) = visibilities.get_mut(parts.off) {
            *off = if split < TWO_PIC_SLIDER_SPLIT_PAD {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        }
    }
}
