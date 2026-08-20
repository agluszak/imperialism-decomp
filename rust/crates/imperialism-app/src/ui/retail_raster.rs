//! Palette-indexed drawing primitives shared by recovered retail UI algorithms.

use bevy::asset::RenderAssetUsages;
use bevy::image::ImageSampler;
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use imperialism_formats::{DibPalette, IndexedPicture};
use swash::{
    FontRef,
    scale::{Render, ScaleContext, Source},
    zeno::Format,
};

pub(in crate::ui) fn indexed_picture(width: i32, height: i32, fill: u8) -> IndexedPicture {
    assert!(width >= 0 && height >= 0);
    IndexedPicture {
        width: width as u32,
        height: height as u32,
        pixels: vec![fill; (width * height) as usize],
    }
}

pub(in crate::ui) trait IndexedRasterExt {
    fn put(&mut self, point: IVec2, color: u8);
    fn fill_rect(&mut self, rect: IRect, color: u8);
    fn copy_rect(&mut self, source: &IndexedPicture, source_rect: IRect, destination: IVec2);
    fn copy_at(&mut self, source: &IndexedPicture, destination: IVec2) {
        self.copy_rect(
            source,
            IRect::new(0, 0, source.width as i32, source.height as i32),
            destination,
        );
    }
    fn blit_keyed(
        &mut self,
        source: &IndexedPicture,
        source_rect: IRect,
        destination: IVec2,
        transparent: u8,
    );
    fn blit_keyed_at(&mut self, source: &IndexedPicture, destination: IVec2, transparent: u8) {
        self.blit_keyed(
            source,
            IRect::new(0, 0, source.width as i32, source.height as i32),
            destination,
            transparent,
        );
    }
    fn line_to_gdi(&mut self, start: IVec2, end: IVec2, color: u8, pen_width: i32);
    fn stroke_polyline_gdi(
        &mut self,
        points: impl IntoIterator<Item = IVec2>,
        color: u8,
        pen_width: i32,
    ) {
        let mut points = points.into_iter();
        let Some(mut start) = points.next() else {
            return;
        };
        for end in points {
            self.line_to_gdi(start, end, color, pen_width);
            start = end;
        }
    }
    fn line_bresenham_inclusive(&mut self, start: IVec2, end: IVec2, color: u8);
    fn frame_rect(&mut self, rect: IRect, color: u8);
    fn draw_text(&mut self, font_data: &[u8], size: f32, baseline: IVec2, text: &str, color: u8);
    fn draw_text_right(
        &mut self,
        font_data: &[u8],
        size: f32,
        right: i32,
        baseline_y: i32,
        text: &str,
        color: u8,
    );
    fn draw_text_center(
        &mut self,
        font_data: &[u8],
        size: f32,
        center: i32,
        baseline_y: i32,
        text: &str,
        color: u8,
    );
    fn crop(&self, rect: IRect) -> IndexedPicture;
    fn to_image(&self, palette: &DibPalette) -> Image;
    fn to_keyed_image(&self, palette: &DibPalette, transparent: u8) -> Image;
}

impl IndexedRasterExt for IndexedPicture {
    fn put(&mut self, point: IVec2, color: u8) {
        if (0..self.width as i32).contains(&point.x) && (0..self.height as i32).contains(&point.y) {
            self.pixels[(point.y * self.width as i32 + point.x) as usize] = color;
        }
    }

    fn fill_rect(&mut self, rect: IRect, color: u8) {
        let left = rect.min.x.max(0);
        let top = rect.min.y.max(0);
        let right = rect.max.x.min(self.width as i32);
        let bottom = rect.max.y.min(self.height as i32);
        if left >= right || top >= bottom {
            return;
        }
        for y in top..bottom {
            self.pixels
                [(y * self.width as i32 + left) as usize..(y * self.width as i32 + right) as usize]
                .fill(color);
        }
    }

    fn copy_rect(&mut self, source: &IndexedPicture, source_rect: IRect, destination: IVec2) {
        let Some(blit) = clipped_blit(self, source, source_rect, destination) else {
            return;
        };
        for row in 0..blit.height {
            let source_start =
                ((blit.source.y + row) * source.width as i32 + blit.source.x) as usize;
            let destination_start =
                ((blit.destination.y + row) * self.width as i32 + blit.destination.x) as usize;
            self.pixels[destination_start..destination_start + blit.width as usize]
                .copy_from_slice(&source.pixels[source_start..source_start + blit.width as usize]);
        }
    }

    fn blit_keyed(
        &mut self,
        source: &IndexedPicture,
        source_rect: IRect,
        destination: IVec2,
        transparent: u8,
    ) {
        let Some(blit) = clipped_blit(self, source, source_rect, destination) else {
            return;
        };
        for row in 0..blit.height {
            let source_start =
                ((blit.source.y + row) * source.width as i32 + blit.source.x) as usize;
            let destination_start =
                ((blit.destination.y + row) * self.width as i32 + blit.destination.x) as usize;
            let width = blit.width as usize;
            let source_row = &source.pixels[source_start..source_start + width];
            let destination_row = &mut self.pixels[destination_start..destination_start + width];
            for (&source_pixel, destination_pixel) in source_row.iter().zip(destination_row) {
                if source_pixel != transparent {
                    *destination_pixel = source_pixel;
                }
            }
        }
    }

    /// Integer Bresenham stroke with Win32 `LineTo`'s excluded endpoint.
    fn line_to_gdi(&mut self, start: IVec2, end: IVec2, color: u8, pen_width: i32) {
        assert!(pen_width > 0);
        let offset = pen_width / 2;
        let end = end + IVec2::splat(offset);
        let mut point = start + IVec2::splat(offset);
        let delta = (end - point).abs();
        let step = (end - point).signum();
        let mut error = delta.x - delta.y;
        while point != end {
            self.fill_rect(
                IRect::from_corners(point, point + IVec2::splat(pen_width)),
                color,
            );
            let twice_error = error * 2;
            if twice_error > -delta.y {
                error -= delta.y;
                point.x += step.x;
            }
            if twice_error < delta.x {
                error += delta.x;
                point.y += step.y;
            }
        }
    }

    fn line_bresenham_inclusive(&mut self, mut point: IVec2, end: IVec2, color: u8) {
        let delta_x = (end.x - point.x).abs();
        let step_x = if point.x < end.x { 1 } else { -1 };
        let delta_y = -(end.y - point.y).abs();
        let step_y = if point.y < end.y { 1 } else { -1 };
        let mut error = delta_x + delta_y;
        loop {
            self.put(point, color);
            if point == end {
                break;
            }
            let doubled = error * 2;
            if doubled >= delta_y {
                error += delta_y;
                point.x += step_x;
            }
            if doubled <= delta_x {
                error += delta_x;
                point.y += step_y;
            }
        }
    }

    fn frame_rect(&mut self, rect: IRect, color: u8) {
        if rect.is_empty() {
            return;
        }
        self.fill_rect(
            IRect::new(rect.min.x, rect.min.y, rect.max.x, rect.min.y + 1),
            color,
        );
        self.fill_rect(
            IRect::new(rect.min.x, rect.max.y - 1, rect.max.x, rect.max.y),
            color,
        );
        self.fill_rect(
            IRect::new(rect.min.x, rect.min.y, rect.min.x + 1, rect.max.y),
            color,
        );
        self.fill_rect(
            IRect::new(rect.max.x - 1, rect.min.y, rect.max.x, rect.max.y),
            color,
        );
    }

    fn draw_text(&mut self, font_data: &[u8], size: f32, baseline: IVec2, text: &str, color: u8) {
        let font = FontRef::from_index(font_data, 0).expect("retail font bytes are valid");
        let charmap = font.charmap();
        let metrics = font.glyph_metrics(&[]).scale(size);
        let mut scale_context = ScaleContext::new();
        let mut scaler = scale_context.builder(font).size(size).hint(true).build();
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
                            self.put(IVec2::new(left + column, top + row), color);
                        }
                    }
                }
            }
            x += metrics.advance_width(glyph);
        }
    }

    fn draw_text_right(
        &mut self,
        font_data: &[u8],
        size: f32,
        right: i32,
        baseline_y: i32,
        text: &str,
        color: u8,
    ) {
        let font = FontRef::from_index(font_data, 0).expect("retail font bytes are valid");
        let charmap = font.charmap();
        let metrics = font.glyph_metrics(&[]).scale(size);
        let width = text
            .chars()
            .map(|character| metrics.advance_width(charmap.map(character)))
            .sum::<f32>()
            .round() as i32;
        self.draw_text(
            font_data,
            size,
            IVec2::new(right - width, baseline_y),
            text,
            color,
        );
    }

    fn draw_text_center(
        &mut self,
        font_data: &[u8],
        size: f32,
        center: i32,
        baseline_y: i32,
        text: &str,
        color: u8,
    ) {
        let font = FontRef::from_index(font_data, 0).expect("retail font bytes are valid");
        let charmap = font.charmap();
        let metrics = font.glyph_metrics(&[]).scale(size);
        let width = text
            .chars()
            .map(|character| metrics.advance_width(charmap.map(character)))
            .sum::<f32>()
            .round() as i32;
        self.draw_text(
            font_data,
            size,
            IVec2::new(center - width / 2, baseline_y),
            text,
            color,
        );
    }

    fn crop(&self, rect: IRect) -> IndexedPicture {
        assert!(
            rect.min.x >= 0
                && rect.min.y >= 0
                && rect.max.x <= self.width as i32
                && rect.max.y <= self.height as i32
        );
        let mut picture = indexed_picture(rect.width(), rect.height(), 0);
        picture.copy_rect(self, rect, IVec2::ZERO);
        picture
    }

    fn to_image(&self, palette: &DibPalette) -> Image {
        indexed_pixels_to_image(self.width, self.height, &self.pixels, palette, None)
    }

    fn to_keyed_image(&self, palette: &DibPalette, transparent: u8) -> Image {
        indexed_pixels_to_image(
            self.width,
            self.height,
            &self.pixels,
            palette,
            Some(transparent),
        )
    }
}

struct ClippedBlit {
    source: IVec2,
    destination: IVec2,
    width: i32,
    height: i32,
}

fn clipped_blit(
    destination: &IndexedPicture,
    source: &IndexedPicture,
    source_rect: IRect,
    destination_origin: IVec2,
) -> Option<ClippedBlit> {
    let mut source_x = source_rect.min.x;
    let mut source_y = source_rect.min.y;
    let mut destination_x = destination_origin.x;
    let mut destination_y = destination_origin.y;
    let mut width = source_rect.width();
    let mut height = source_rect.height();

    if source_x < 0 {
        let clipped = -source_x;
        source_x = 0;
        destination_x += clipped;
        width -= clipped;
    }
    if source_y < 0 {
        let clipped = -source_y;
        source_y = 0;
        destination_y += clipped;
        height -= clipped;
    }
    if destination_x < 0 {
        let clipped = -destination_x;
        destination_x = 0;
        source_x += clipped;
        width -= clipped;
    }
    if destination_y < 0 {
        let clipped = -destination_y;
        destination_y = 0;
        source_y += clipped;
        height -= clipped;
    }
    width = width
        .min(source.width as i32 - source_x)
        .min(destination.width as i32 - destination_x);
    height = height
        .min(source.height as i32 - source_y)
        .min(destination.height as i32 - destination_y);
    (width > 0 && height > 0).then_some(ClippedBlit {
        source: IVec2::new(source_x, source_y),
        destination: IVec2::new(destination_x, destination_y),
        width,
        height,
    })
}

fn indexed_pixels_to_image(
    width: u32,
    height: u32,
    pixels: &[u8],
    palette: &DibPalette,
    transparent: Option<u8>,
) -> Image {
    assert_eq!(pixels.len(), width as usize * height as usize);
    let mut rgba = Vec::with_capacity(pixels.len() * 4);
    for &palette_index in pixels {
        let alpha = if transparent == Some(palette_index) {
            0
        } else {
            0xff
        };
        palette[palette_index].write_rgba(alpha, &mut rgba);
    }
    let mut image = Image::new(
        Extent3d {
            width,
            height,
            depth_or_array_layers: 1,
        },
        TextureDimension::D2,
        rgba,
        TextureFormat::Rgba8UnormSrgb,
        RenderAssetUsages::default(),
    );
    image.sampler = ImageSampler::nearest();
    image
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyed_blit_clips_both_pictures() {
        let source = IndexedPicture {
            width: 3,
            height: 2,
            pixels: vec![1, 2, 3, 4, 0x10, 6],
        };
        let mut destination = indexed_picture(3, 2, 9);
        destination.blit_keyed(&source, IRect::new(0, 0, 3, 2), IVec2::new(-1, 0), 0x10);
        assert_eq!(destination.pixels, [2, 3, 9, 9, 6, 9]);
    }

    #[test]
    fn opaque_copy_clips_once_then_copies_rows() {
        let source = IndexedPicture {
            width: 4,
            height: 2,
            pixels: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let mut destination = indexed_picture(3, 2, 9);
        destination.copy_rect(&source, IRect::new(1, 0, 4, 2), IVec2::new(-1, 0));
        assert_eq!(destination.pixels, [3, 4, 9, 7, 8, 9]);
    }

    #[test]
    fn crop_copies_the_requested_rows_into_a_new_picture() {
        let source = IndexedPicture {
            width: 4,
            height: 3,
            pixels: (0..12).collect(),
        };
        let cropped = source.crop(IRect::new(1, 1, 4, 3));
        assert_eq!((cropped.width, cropped.height), (3, 2));
        assert_eq!(cropped.pixels, [5, 6, 7, 9, 10, 11]);
    }

    #[test]
    fn gdi_line_excludes_endpoint() {
        let mut picture = indexed_picture(4, 2, 0);
        picture.line_to_gdi(IVec2::new(0, 0), IVec2::new(3, 0), 7, 1);
        assert_eq!(picture.pixels, [7, 7, 7, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn diagonal_gdi_line_excludes_endpoint() {
        let mut picture = indexed_picture(4, 4, 0);
        picture.line_to_gdi(IVec2::ZERO, IVec2::new(3, 3), 7, 1);
        assert_eq!(
            picture.pixels,
            [7, 0, 0, 0, 0, 7, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn wide_gdi_line_stamps_two_by_two_pixels_and_excludes_endpoint() {
        let mut picture = indexed_picture(6, 4, 0);
        picture.line_to_gdi(IVec2::ZERO, IVec2::new(3, 0), 7, 2);
        assert_eq!(
            picture.pixels,
            [
                0, 0, 0, 0, 0, 0, 0, 7, 7, 7, 7, 0, 0, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn inclusive_bresenham_has_its_own_endpoint_and_tie_breaking() {
        let mut picture = indexed_picture(4, 3, 0);
        picture.line_bresenham_inclusive(IVec2::ZERO, IVec2::new(3, 2), 7);
        assert_eq!(picture.pixels, [7, 0, 0, 0, 0, 7, 7, 0, 0, 0, 0, 7]);
    }
}
