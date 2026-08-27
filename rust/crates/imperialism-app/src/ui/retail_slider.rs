//! Recovered `TTwoPicSlider` presentation over Bevy's stock `Slider`.
//!
//! Input semantics stay on `Slider` / `SliderValue` / `ValueChange<f32>`.
//! This module only redraws the upper/lower bitmap composition.

use super::retail_raster::IndexedRasterExt;
use super::retail_raster_text::RetailRasterTextPainter;
use crate::{RetailAssetsResource, RetailFonts};
use bevy::ecs::template::TemplateContext;
use bevy::prelude::*;
use bevy::ui_widgets::{
    Slider, SliderOrientation, SliderPrecision, SliderRange, SliderValue, TrackClick,
};
use imperialism_formats::{IndexedPicture, PictureId, RetailTextStylePreset};

pub const TWO_PIC_SLIDER_SPLIT_PAD: i16 = 0x0c;

/// Retail two-picture slider skin (`TTwoPicSlider::Draw`).
#[derive(Component)]
pub struct RetailTwoPicSliderVisual {
    pub upper: IndexedPicture,
    pub lower: IndexedPicture,
    pub off_text: String,
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
        template(move |context| {
            let (upper, lower, off_text, image) =
                load_two_pic_slider(context, picture_base, off_group, off_index)?;
            context.entity.insert(RetailTwoPicSliderVisual {
                upper,
                lower,
                off_text,
            });
            Ok(ImageNode::new(image))
        })
    }
}

fn load_two_pic_slider(
    context: &mut TemplateContext,
    picture_base: i16,
    off_group: i16,
    off_index: i16,
) -> bevy::ecs::error::Result<(IndexedPicture, IndexedPicture, String, Handle<Image>)> {
    Ok(context.entity.world_scope(|world| {
        let assets = world.resource::<RetailAssetsResource>().assets();
        let upper = assets.indexed_picture(PictureId::new(picture_base))?;
        let lower = assets.indexed_picture(PictureId::new(picture_base + 1))?;
        let off_text = match assets.string(off_group, off_index) {
            Ok(text) => text,
            Err(_) => "Off".to_string(),
        };
        let image = upper.to_image(assets.default_dib_palette());
        let handle = world.resource_mut::<Assets<Image>>().add(image);
        Ok::<_, imperialism_formats::RetailAssetError>((upper, lower, off_text, handle))
    })?)
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

#[allow(clippy::type_complexity)]
fn sync_two_pic_slider_visuals(
    retail: Res<RetailAssetsResource>,
    fonts: Res<RetailFonts>,
    font_assets: Res<Assets<Font>>,
    mut image_assets: ResMut<Assets<Image>>,
    sliders: Query<
        (
            &SliderValue,
            &SliderRange,
            &RetailTwoPicSliderVisual,
            &ImageNode,
            &Node,
        ),
        (With<RetailTwoPicSliderVisual>, Changed<SliderValue>),
    >,
) {
    let Ok(mut text) = RetailRasterTextPainter::from_preset(
        &fonts,
        &font_assets,
        RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 14,
            alignment: 1,
        },
    ) else {
        return;
    };
    for (value, range, visual, image_node, node) in &sliders {
        let height = match node.height {
            Val::Px(height) => height as i16,
            _ => visual.upper.height as i16,
        };
        let split = two_pic_slider_split(value.0 as i16, height, range.end() as i16);
        let fill = two_pic_slider_fill_height(split);
        let mut picture = visual.upper.clone();
        let top = i32::from(height - fill);
        picture.copy_rect(
            &visual.lower,
            IRect::new(0, top, visual.lower.width as i32, i32::from(height)),
            IVec2::new(0, top),
        );
        if split < TWO_PIC_SLIDER_SPLIT_PAD {
            let center = visual.upper.width as i32 / 2;
            let baseline = i32::from(height / 2 + 4);
            text.draw_center(&mut picture, center, baseline, &visual.off_text, 0x28);
            text.draw_center(&mut picture, center + 1, baseline + 1, &visual.off_text, 0);
        }
        if let Some(mut image) = image_assets.get_mut(&image_node.image) {
            *image = picture.to_image(retail.assets().default_dib_palette());
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
