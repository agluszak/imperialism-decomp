//! Recovered `TTwoPicSlider` presentation over Bevy's stock `Slider`.
//!
//! Interaction uses a stock vertical `Slider` whose track is the top
//! `height - 12` of the control (bottom inset = [`TWO_PIC_SLIDER_SPLIT_PAD`]).
//! That makes the bottom 12px a zero plateau without forking Bevy's pointer
//! lifecycle. A thin zero-strip child handles direct clicks in that plateau.
//! Syncs the clipped lower bitmap and Off caption from the input `SliderValue`.

use super::retail::{
    load_template_picture, retail_text_color, retail_text_shadow, retail_text_style,
};
use crate::RetailAssetsResource;
use bevy::ecs::template::TemplateContext;
use bevy::picking::events::{Pointer, Press};
use bevy::prelude::*;
use bevy::ui::UiSystems;
use bevy::ui_widgets::{
    Slider, SliderOrientation, SliderPrecision, SliderRange, SliderValue, TrackClick, ValueChange,
};
use imperialism_formats::{PictureId, StringGroup};

pub const TWO_PIC_SLIDER_SPLIT_PAD: i16 = 0x0c;

/// Private child refs for the two-picture slider hierarchy.
#[derive(Component, FromTemplate, Clone, Copy)]
pub struct RetailTwoPicSliderParts {
    /// Stock `Slider` track (`height - 12`); binders read/write [`SliderValue`] here.
    pub input: Entity,
    pub lower: Entity,
    pub off: Entity,
}

/// Marks the bottom 12px plateau that forces value zero on press.
#[derive(Component, FromTemplate, Clone, Copy)]
struct TwoPicSliderZeroStrip {
    input: Entity,
}

/// Generated construction for recovered `TTwoPicSlider` instances.
pub fn retail_two_pic_slider(
    picture_base: i16,
    scale: i16,
    off_group: i16,
    off_index: i16,
) -> impl Scene {
    bsn! {
        Pickable::IGNORE
        RetailTwoPicSliderParts {
            input: #Input,
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
                #Input
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0),
                    top: px(0),
                    right: px(0),
                    bottom: px(TWO_PIC_SLIDER_SPLIT_PAD as f32),
                }
                Slider {
                    track_click: TrackClick::Snap,
                    orientation: SliderOrientation::Vertical,
                }
                SliderValue(0.0)
                SliderRange::new(0.0, scale as f32)
                SliderPrecision(0)
            ),
            (
                #Zero
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0),
                    right: px(0),
                    bottom: px(0),
                    height: px(TWO_PIC_SLIDER_SPLIT_PAD as f32),
                }
                TwoPicSliderZeroStrip { input: #Input }
            ),
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
    app.add_observer(on_two_pic_zero_strip_press).add_systems(
        PostUpdate,
        sync_two_pic_slider_visuals.before(UiSystems::Prepare),
    );
}

fn on_two_pic_zero_strip_press(
    mut press: On<Pointer<Press>>,
    strips: Query<&TwoPicSliderZeroStrip>,
    mut commands: Commands,
) {
    let Ok(strip) = strips.get(press.event_target()) else {
        return;
    };
    press.propagate(false);
    commands.trigger(ValueChange {
        source: strip.input,
        value: 0.0,
        is_final: true,
    });
}

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
#[cfg_attr(not(test), allow(dead_code))]
pub fn two_pic_slider_value_from_y(y: i16, height: i16, scale: i16) -> i16 {
    let requested = if y >= height {
        height
    } else if y < 1 {
        0
    } else {
        y
    };
    let split = height - requested;
    let span = height - TWO_PIC_SLIDER_SPLIT_PAD;
    if span <= 0 || scale == 0 {
        return 0;
    }
    let adjusted = (split - TWO_PIC_SLIDER_SPLIT_PAD).max(0);
    (i32::from(adjusted) * i32::from(scale) / i32::from(span)) as i16
}

fn sync_two_pic_slider_visuals(
    roots: Query<(&RetailTwoPicSliderParts, &Node)>,
    changed_inputs: Query<(), Changed<SliderValue>>,
    values: Query<(&SliderValue, &SliderRange)>,
    mut nodes: Query<&mut Node, Without<RetailTwoPicSliderParts>>,
    mut images: Query<&mut ImageNode, Without<RetailTwoPicSliderParts>>,
    mut visibilities: Query<&mut Visibility>,
) {
    for (parts, root) in &roots {
        if !changed_inputs.contains(parts.input) {
            continue;
        }
        let Ok((value, range)) = values.get(parts.input) else {
            continue;
        };
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
}
