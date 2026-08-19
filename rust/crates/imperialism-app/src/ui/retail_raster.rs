//! Palette-indexed drawing primitives shared by recovered retail UI algorithms.

use bevy::asset::RenderAssetUsages;
use bevy::image::ImageSampler;
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use imperialism_formats::{DibPalette, IndexedPicture};

pub(in crate::ui) struct IndexedSurface {
    width: i32,
    height: i32,
    pixels: Vec<u8>,
}

impl IndexedSurface {
    pub(in crate::ui) fn new(width: i32, height: i32, fill: u8) -> Self {
        assert!(width >= 0 && height >= 0);
        Self {
            width,
            height,
            pixels: vec![fill; (width * height) as usize],
        }
    }

    pub(in crate::ui) fn from_pixels(width: i32, height: i32, pixels: Vec<u8>) -> Self {
        assert!(width >= 0 && height >= 0);
        assert_eq!(pixels.len(), (width * height) as usize);
        Self {
            width,
            height,
            pixels,
        }
    }

    pub(in crate::ui) fn pixels_mut(&mut self) -> &mut [u8] {
        &mut self.pixels
    }

    pub(in crate::ui) fn into_pixels(self) -> Vec<u8> {
        self.pixels
    }

    pub(in crate::ui) fn into_picture(self) -> IndexedPicture {
        IndexedPicture {
            width: self.width as u32,
            height: self.height as u32,
            pixels: self.pixels,
        }
    }

    pub(in crate::ui) fn fill_rect(&mut self, rect: IRect, color: u8) {
        let left = rect.min.x.max(0);
        let top = rect.min.y.max(0);
        let right = rect.max.x.min(self.width);
        let bottom = rect.max.y.min(self.height);
        if left >= right || top >= bottom {
            return;
        }
        for y in top..bottom {
            self.pixels[(y * self.width + left) as usize..(y * self.width + right) as usize]
                .fill(color);
        }
    }

    pub(in crate::ui) fn copy_rect(
        &mut self,
        source: &IndexedPicture,
        source_rect: IRect,
        destination: IVec2,
    ) {
        self.blit(source, source_rect, destination, None);
    }

    pub(in crate::ui) fn blit_keyed(
        &mut self,
        source: &IndexedPicture,
        source_rect: IRect,
        destination: IVec2,
        transparent: u8,
    ) {
        self.blit(source, source_rect, destination, Some(transparent));
    }

    fn blit(
        &mut self,
        source: &IndexedPicture,
        source_rect: IRect,
        destination: IVec2,
        transparent: Option<u8>,
    ) {
        let source_width = source.width as i32;
        let source_height = source.height as i32;
        for y in 0..source_rect.height() {
            let source_y = source_rect.min.y + y;
            let destination_y = destination.y + y;
            if !(0..source_height).contains(&source_y) || !(0..self.height).contains(&destination_y)
            {
                continue;
            }
            for x in 0..source_rect.width() {
                let source_x = source_rect.min.x + x;
                let destination_x = destination.x + x;
                if !(0..source_width).contains(&source_x)
                    || !(0..self.width).contains(&destination_x)
                {
                    continue;
                }
                let pixel = source.pixels[(source_y * source_width + source_x) as usize];
                if transparent != Some(pixel) {
                    self.pixels[(destination_y * self.width + destination_x) as usize] = pixel;
                }
            }
        }
    }

    /// Integer Bresenham stroke with Win32 `LineTo`'s excluded endpoint.
    pub(in crate::ui) fn line_to_gdi(
        &mut self,
        start: IVec2,
        end: IVec2,
        color: u8,
        pen_width: i32,
    ) {
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

    pub(in crate::ui) fn frame_rect(&mut self, rect: IRect, color: u8) {
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

    pub(in crate::ui) fn to_image(&self, palette: &DibPalette) -> Image {
        indexed_image(self.width, self.height, &self.pixels, palette, None)
    }

    pub(in crate::ui) fn to_keyed_image(&self, palette: &DibPalette, transparent: u8) -> Image {
        indexed_image(
            self.width,
            self.height,
            &self.pixels,
            palette,
            Some(transparent),
        )
    }
}

fn indexed_image(
    width: i32,
    height: i32,
    pixels: &[u8],
    palette: &DibPalette,
    transparent: Option<u8>,
) -> Image {
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
            width: width as u32,
            height: height as u32,
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
    fn keyed_blit_clips_both_surfaces() {
        let source = IndexedPicture {
            width: 3,
            height: 2,
            pixels: vec![1, 2, 3, 4, 0x10, 6],
        };
        let mut destination = IndexedSurface::new(3, 2, 9);
        destination.blit_keyed(&source, IRect::new(0, 0, 3, 2), IVec2::new(-1, 0), 0x10);
        assert_eq!(destination.pixels, [2, 3, 9, 9, 6, 9]);
    }

    #[test]
    fn gdi_line_excludes_endpoint() {
        let mut surface = IndexedSurface::new(4, 2, 0);
        surface.line_to_gdi(IVec2::new(0, 0), IVec2::new(3, 0), 7, 1);
        assert_eq!(surface.pixels, [7, 7, 7, 0, 0, 0, 0, 0]);
    }
}
