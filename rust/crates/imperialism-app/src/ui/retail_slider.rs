//! Recovered `TTwoPicSlider` presentation and retail pointer→value mapping.
//!
//! Stock Bevy `Slider` maps the full control height linearly. Retail keeps a 12px zero
//! plateau at the bottom (`splitPosition - 0x0c`), so input uses the recovered equation
//! instead. `SliderValue` / `SliderRange` still store the preference scale value that
//! binders and the visual sync read.

use super::retail::{
    load_template_picture, retail_text_color, retail_text_shadow, retail_text_style,
};
use crate::RetailAssetsResource;
use bevy::ecs::template::TemplateContext;
use bevy::picking::events::{Cancel, Drag, DragEnd, DragStart, Pointer, Press, Release};
use bevy::prelude::*;
use bevy::ui::{ComputedUiRenderTargetInfo, InteractionDisabled, Pressed, UiSystems};
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
        .add_observer(on_two_pic_slider_drag_start)
        .add_observer(on_two_pic_slider_drag)
        .add_observer(on_two_pic_slider_drag_end)
        .add_observer(on_two_pic_slider_release)
        .add_observer(on_two_pic_slider_cancel)
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

type TwoPicSliderInput = (
    &'static SliderRange,
    &'static ComputedNode,
    &'static ComputedUiRenderTargetInfo,
    &'static UiGlobalTransform,
    Has<InteractionDisabled>,
);

type TwoPicSliderPressedInput = (
    &'static SliderRange,
    &'static ComputedNode,
    &'static ComputedUiRenderTargetInfo,
    &'static UiGlobalTransform,
    Has<InteractionDisabled>,
    Has<Pressed>,
);

/// `TTwoPicSlider` draw split from preference/scale value.
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

/// Retail `ClampSliderInputToHeight` + `SliderScaledValue`: pointer y from top → scale value.
///
/// The bottom [`TWO_PIC_SLIDER_SPLIT_PAD`] pixels all map to zero; the linear track is
/// `height - 12`.
pub fn two_pic_slider_value_from_y(y: i16, height: i16, scale: i16) -> i16 {
    let requested = if y >= height {
        height
    } else if y < 1 {
        0
    } else {
        y
    };
    let split = height - requested;
    two_pic_slider_value_from_split(split, height, scale)
}

fn two_pic_slider_value_from_split(split: i16, height: i16, scale: i16) -> i16 {
    let span = height - TWO_PIC_SLIDER_SPLIT_PAD;
    if span <= 0 || scale == 0 {
        return 0;
    }
    let adjusted = (split - TWO_PIC_SLIDER_SPLIT_PAD).max(0);
    (i32::from(adjusted) * i32::from(scale) / i32::from(span)) as i16
}

fn pointer_y_from_top(
    node: &ComputedNode,
    transform: &UiGlobalTransform,
    target: &ComputedUiRenderTargetInfo,
    location: &bevy::picking::pointer::Location,
    ui_scale: f32,
) -> Option<f32> {
    let normalized = node.normalize_point(
        *transform,
        location.position * target.scale_factor() / ui_scale,
    )?;
    Some((normalized.y + 0.5) * node.size().y)
}

fn emit_two_pic_slider_value(
    commands: &mut Commands,
    entity: Entity,
    range: &SliderRange,
    node: &ComputedNode,
    transform: &UiGlobalTransform,
    target: &ComputedUiRenderTargetInfo,
    location: &bevy::picking::pointer::Location,
    ui_scale: f32,
    is_final: bool,
) {
    let Some(y) = pointer_y_from_top(node, transform, target, location, ui_scale) else {
        return;
    };
    let height = node.size().y.round() as i16;
    let value = two_pic_slider_value_from_y(y.floor() as i16, height, range.end() as i16);
    commands.trigger(ValueChange {
        source: entity,
        value: f32::from(value),
        is_final,
    });
}

fn on_two_pic_slider_press(
    mut press: On<Pointer<Press>>,
    sliders: Query<TwoPicSliderInput, With<RetailTwoPicSliderParts>>,
    mut commands: Commands,
    ui_scale: Res<UiScale>,
) {
    let Ok((range, node, target, transform, disabled)) = sliders.get(press.event_target()) else {
        return;
    };
    press.propagate(false);
    if disabled {
        return;
    }
    let entity = press.event_target();
    commands.entity(entity).insert(Pressed);
    emit_two_pic_slider_value(
        &mut commands,
        entity,
        range,
        node,
        transform,
        target,
        &press.pointer_location,
        ui_scale.0,
        false,
    );
}

fn on_two_pic_slider_drag_start(
    mut drag_start: On<Pointer<DragStart>>,
    sliders: Query<(), With<RetailTwoPicSliderParts>>,
) {
    if sliders.contains(drag_start.event_target()) {
        drag_start.propagate(false);
    }
}

fn on_two_pic_slider_drag(
    mut drag: On<Pointer<Drag>>,
    sliders: Query<TwoPicSliderPressedInput, With<RetailTwoPicSliderParts>>,
    mut commands: Commands,
    ui_scale: Res<UiScale>,
) {
    let Ok((range, node, target, transform, disabled, pressed)) = sliders.get(drag.event_target())
    else {
        return;
    };
    drag.propagate(false);
    if disabled || !pressed {
        return;
    }
    emit_two_pic_slider_value(
        &mut commands,
        drag.event_target(),
        range,
        node,
        transform,
        target,
        &drag.pointer_location,
        ui_scale.0,
        false,
    );
}

fn finish_two_pic_slider(
    commands: &mut Commands,
    entity: Entity,
    range: &SliderRange,
    node: &ComputedNode,
    transform: &UiGlobalTransform,
    target: &ComputedUiRenderTargetInfo,
    location: &bevy::picking::pointer::Location,
    ui_scale: f32,
    disabled: bool,
    pressed: bool,
) {
    if pressed {
        commands.entity(entity).remove::<Pressed>();
    }
    if disabled || !pressed {
        return;
    }
    emit_two_pic_slider_value(
        commands, entity, range, node, transform, target, location, ui_scale, true,
    );
}

fn on_two_pic_slider_drag_end(
    mut drag_end: On<Pointer<DragEnd>>,
    sliders: Query<TwoPicSliderPressedInput, With<RetailTwoPicSliderParts>>,
    mut commands: Commands,
    ui_scale: Res<UiScale>,
) {
    let Ok((range, node, target, transform, disabled, pressed)) =
        sliders.get(drag_end.event_target())
    else {
        return;
    };
    drag_end.propagate(false);
    finish_two_pic_slider(
        &mut commands,
        drag_end.event_target(),
        range,
        node,
        transform,
        target,
        &drag_end.pointer_location,
        ui_scale.0,
        disabled,
        pressed,
    );
}

fn on_two_pic_slider_release(
    mut release: On<Pointer<Release>>,
    sliders: Query<TwoPicSliderPressedInput, With<RetailTwoPicSliderParts>>,
    mut commands: Commands,
    ui_scale: Res<UiScale>,
) {
    let Ok((range, node, target, transform, disabled, pressed)) =
        sliders.get(release.event_target())
    else {
        return;
    };
    release.propagate(false);
    // Click without drag: still commit on release (`TrackPhaseEnd`).
    finish_two_pic_slider(
        &mut commands,
        release.event_target(),
        range,
        node,
        transform,
        target,
        &release.pointer_location,
        ui_scale.0,
        disabled,
        pressed,
    );
}

fn on_two_pic_slider_cancel(
    mut cancel: On<Pointer<Cancel>>,
    sliders: Query<(Entity, Has<Pressed>), With<RetailTwoPicSliderParts>>,
    mut commands: Commands,
) {
    let Ok((entity, pressed)) = sliders.get(cancel.event_target()) else {
        return;
    };
    cancel.propagate(false);
    if pressed {
        commands.entity(entity).remove::<Pressed>();
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slider_split_matches_retail_padding() {
        assert_eq!(two_pic_slider_split(0, 91, 100), 0);
        assert_eq!(two_pic_slider_split(100, 91, 100), 91);
        assert_eq!(two_pic_slider_split(0xff, 91, 0xff), 91);
    }

    #[test]
    fn slider_pointer_y_matches_retail_zero_plateau() {
        let height = 91;
        let scale = 100;
        assert_eq!(two_pic_slider_value_from_y(0, height, scale), scale);
        assert_eq!(
            two_pic_slider_value_from_y(height - TWO_PIC_SLIDER_SPLIT_PAD, height, scale),
            0
        );
        assert_eq!(two_pic_slider_value_from_y(height - 6, height, scale), 0);
        assert_eq!(two_pic_slider_value_from_y(height, height, scale), 0);
    }

    #[test]
    fn slider_pointer_mid_track_is_linear_over_height_minus_pad() {
        let height = 91;
        let scale = 100;
        let span = height - TWO_PIC_SLIDER_SPLIT_PAD;
        // y such that split = pad + span/2 → value = (span/2) * scale / span (integer trunc).
        let y = height - (TWO_PIC_SLIDER_SPLIT_PAD + span / 2);
        let expected = (span / 2) * scale / span;
        assert_eq!(two_pic_slider_value_from_y(y, height, scale), expected);
        assert!(expected > 0 && expected < scale);
    }
}
