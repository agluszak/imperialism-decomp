//! Recovered `TTwoPicSlider` presentation over Bevy's stock `Slider`.
//!
//! Input semantics stay on `Slider` / `SliderValue` / `ValueChange<f32>`.
//! This module syncs the lower clipped bitmap and Off caption from `SliderValue`.

use super::retail::{
    load_template_picture, retail_text_color, retail_text_shadow, retail_text_style,
};
use crate::RetailAssetsResource;
use bevy::ecs::template::TemplateContext;
use bevy::prelude::*;
use bevy::ui_widgets::{
    Slider, SliderOrientation, SliderPrecision, SliderRange, SliderValue, TrackClick,
};
use imperialism_formats::PictureId;

pub const TWO_PIC_SLIDER_SPLIT_PAD: i16 = 0x0c;

/// Private child refs for the two-picture slider hierarchy.
#[derive(Component, FromTemplate, Clone)]
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
        Slider {
            track_click: TrackClick::Snap,
            orientation: SliderOrientation::Vertical,
        }
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
    match context
        .resource::<RetailAssetsResource>()
        .assets()
        .string(off_group, off_index)
    {
        Ok(text) => text,
        Err(_) => "Off".to_string(),
    }
}

pub(super) fn register_slider(app: &mut App) {
    app.add_systems(PostUpdate, sync_two_pic_slider_visuals);
}

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

fn two_pic_slider_fill_height(split: i16) -> i16 {
    if split < TWO_PIC_SLIDER_SPLIT_PAD {
        0
    } else {
        split
    }
}

fn sync_two_pic_slider_visuals(
    sliders: Query<
        (&SliderValue, &SliderRange, &RetailTwoPicSliderParts, &Node),
        (With<RetailTwoPicSliderParts>, Changed<SliderValue>),
    >,
    mut nodes: Query<&mut Node, Without<RetailTwoPicSliderParts>>,
    mut images: Query<&mut ImageNode, Without<RetailTwoPicSliderParts>>,
    mut visibilities: Query<&mut Visibility>,
) {
    for (value, range, parts, root) in &sliders {
        let height = match root.height {
            Val::Px(height) => height as i16,
            _ => continue,
        };
        let width = match root.width {
            Val::Px(width) => width,
            _ => continue,
        };
        let split = two_pic_slider_split(value.0 as i16, height, range.end() as i16);
        let fill = two_pic_slider_fill_height(split);
        if let Ok(mut lower_node) = nodes.get_mut(parts.lower) {
            lower_node.height = Val::Px(f32::from(fill));
        }
        if let Ok(mut lower_image) = images.get_mut(parts.lower) {
            // Bottom `fill` rows of the lower picture (matches retail blit).
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
}
