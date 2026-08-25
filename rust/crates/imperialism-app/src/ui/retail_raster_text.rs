//! Compatibility painter for retail GDI text rasterized into an indexed picture.
//!
//! Swash alpha-thresholding at 0x80 is an approximation of retail GDI, not a pixel
//! match. Keeping font resolution, metrics, and `ScaleContext` here makes an
//! oracle-driven replacement a single-object swap later.

use super::retail_raster::IndexedRasterExt;
use bevy::prelude::*;
use imperialism_formats::{
    IndexedPicture, RetailAssets, RetailTextStyleError, RetailTextStylePreset,
    decode_retail_font_cell_metrics, resolve_retail_text_style,
};
use swash::{
    FontRef,
    scale::{Render, ScaleContext, Source},
    zeno::Format,
};

pub struct RetailRasterTextPainter<'a> {
    font: FontRef<'a>,
    size: f32,
    scale_context: ScaleContext,
}

impl<'a> RetailRasterTextPainter<'a> {
    pub fn new(font_data: &'a [u8], size: f32) -> Self {
        Self {
            font: FontRef::from_index(font_data, 0).expect("retail font bytes are valid"),
            size,
            scale_context: ScaleContext::new(),
        }
    }

    pub fn from_preset(
        assets: &'a RetailAssets,
        preset: RetailTextStylePreset,
    ) -> Result<Self, RetailTextStyleError> {
        let style = resolve_retail_text_style(preset)?;
        let font_data = assets.font_bytes(style.face);
        let size = decode_retail_font_cell_metrics(style.face, font_data)
            .expect("retail font metrics")
            .em_pixel_size(style.logical_pixel_height) as f32;
        Ok(Self::new(font_data, size))
    }

    pub fn measure(&self, text: &str) -> i32 {
        let charmap = self.font.charmap();
        let metrics = self.font.glyph_metrics(&[]).scale(self.size);
        text.chars()
            .map(|character| metrics.advance_width(charmap.map(character)))
            .sum::<f32>()
            .round() as i32
    }

    pub fn draw(&mut self, picture: &mut IndexedPicture, baseline: IVec2, text: &str, color: u8) {
        let charmap = self.font.charmap();
        let metrics = self.font.glyph_metrics(&[]).scale(self.size);
        let mut scaler = self
            .scale_context
            .builder(self.font)
            .size(self.size)
            .hint(true)
            .build();
        let mut x = baseline.x as f32;
        for character in text.chars() {
            let glyph = charmap.map(character);
            if let Some(image) = Render::new(&[Source::Outline])
                .format(Format::Alpha)
                .render(&mut scaler, glyph)
            {
                let left = x.round() as i32 + image.placement.left;
                let top = baseline.y - image.placement.top;
                for row in 0..image.placement.height as i32 {
                    for column in 0..image.placement.width as i32 {
                        let alpha =
                            image.data[(row * image.placement.width as i32 + column) as usize];
                        if alpha >= 0x80 {
                            picture.put(IVec2::new(left + column, top + row), color);
                        }
                    }
                }
            }
            x += metrics.advance_width(glyph);
        }
    }

    pub fn draw_right(
        &mut self,
        picture: &mut IndexedPicture,
        right: i32,
        baseline_y: i32,
        text: &str,
        color: u8,
    ) {
        let width = self.measure(text);
        self.draw(picture, IVec2::new(right - width, baseline_y), text, color);
    }

    pub fn draw_center(
        &mut self,
        picture: &mut IndexedPicture,
        center: i32,
        baseline_y: i32,
        text: &str,
        color: u8,
    ) {
        let width = self.measure(text);
        self.draw(
            picture,
            IVec2::new(center - width / 2, baseline_y),
            text,
            color,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::retail_raster::indexed_picture;
    use std::fs;

    fn test_font() -> Vec<u8> {
        const CANDIDATES: &[&str] = &[
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/wine/fonts/courier.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        ];
        for path in CANDIDATES {
            if let Ok(bytes) = fs::read(path) {
                return bytes;
            }
        }
        panic!("raster text tests require a TrueType font");
    }

    fn ink_bounds(picture: &IndexedPicture) -> Option<IRect> {
        let width = picture.width as i32;
        let mut min = IVec2::new(i32::MAX, i32::MAX);
        let mut max = IVec2::new(i32::MIN, i32::MIN);
        for (index, &pixel) in picture.pixels.iter().enumerate() {
            if pixel == 0 {
                continue;
            }
            let x = index as i32 % width;
            let y = index as i32 / width;
            min = min.min(IVec2::new(x, y));
            max = max.max(IVec2::new(x + 1, y + 1));
        }
        (min.x < max.x).then_some(IRect::from_corners(min, max))
    }

    #[test]
    fn measured_width_matches_rendered_advancement() {
        let font = test_font();
        let mut painter = RetailRasterTextPainter::new(&font, 16.0);
        let text = "1848";
        let width = painter.measure(text);
        let mut picture = indexed_picture(80, 24, 0);
        painter.draw(&mut picture, IVec2::new(4, 16), text, 7);
        let bounds = ink_bounds(&picture).expect("number string inks pixels");
        assert!(width > 0);
        assert!(
            bounds.width() <= width + 2,
            "ink width {} should not exceed measured advance {width} by more than a side bearing",
            bounds.width()
        );
        assert!(
            bounds.min.x >= 4 - 4,
            "left-aligned ink starts near the baseline x, found {}",
            bounds.min.x
        );
    }

    #[test]
    fn left_right_and_center_share_one_measured_width() {
        let font = test_font();
        let mut painter = RetailRasterTextPainter::new(&font, 16.0);
        let text = "Agp";
        let width = painter.measure(text);

        let mut left = indexed_picture(80, 24, 0);
        painter.draw(&mut left, IVec2::new(10, 16), text, 7);
        let left_bounds = ink_bounds(&left).unwrap();

        let mut right = indexed_picture(80, 24, 0);
        painter.draw_right(&mut right, 70, 16, text, 7);
        let right_bounds = ink_bounds(&right).unwrap();

        let mut center = indexed_picture(80, 24, 0);
        painter.draw_center(&mut center, 40, 16, text, 7);
        let center_bounds = ink_bounds(&center).unwrap();

        assert!((right_bounds.max.x - 70).abs() <= 4);
        let center_mid = (center_bounds.min.x + center_bounds.max.x) / 2;
        assert!((center_mid - 40).abs() <= width / 4 + 2);
        assert!(left_bounds.min.x <= 10);
        assert!(
            left_bounds.max.y > 16,
            "descenders in Agp must ink below the baseline"
        );
        assert!(
            left_bounds.min.y < 16,
            "capitals in Agp must ink above the baseline"
        );
    }

    #[test]
    fn negative_side_bearings_may_ink_left_of_the_pen() {
        let font = test_font();
        let mut painter = RetailRasterTextPainter::new(&font, 24.0);
        let mut picture = indexed_picture(48, 32, 0);
        painter.draw(&mut picture, IVec2::new(8, 22), "j", 7);
        let bounds = ink_bounds(&picture).expect("j inks pixels");
        assert!(
            bounds.min.x <= 8,
            "glyph j often has a left/negative bearing; ink started at {}",
            bounds.min.x
        );
        assert!(bounds.max.y > 22, "j has a descender below the baseline");
    }

    #[test]
    fn same_string_is_stable_across_painter_reuse() {
        let font = test_font();
        let mut painter = RetailRasterTextPainter::new(&font, 14.0);
        let mut first = indexed_picture(64, 20, 0);
        painter.draw(&mut first, IVec2::new(2, 14), "100", 3);
        let mut second = indexed_picture(64, 20, 0);
        painter.draw(&mut second, IVec2::new(2, 14), "100", 3);
        assert_eq!(first.pixels, second.pixels);
        assert!(first.pixels.contains(&3));
    }
}
