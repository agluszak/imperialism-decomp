//! Small color and indexed-palette types used by retail bitmap decoding.

use std::ops::{Index, IndexMut};

/// 8-bit RGB triplet in display order (red, green, blue).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Builds RGB from a Windows `RGBQUAD` / `RGBTRIPLE` BGR byte order.
    pub const fn from_bgr(b: u8, g: u8, r: u8) -> Self {
        Self { r, g, b }
    }

    pub const fn to_array(self) -> [u8; 3] {
        [self.r, self.g, self.b]
    }

    pub fn write_rgba(self, alpha: u8, out: &mut Vec<u8>) {
        out.extend_from_slice(&[self.r, self.g, self.b, alpha]);
    }
}

/// Index into an 8-bit retail DIB palette (`0..=255`).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PaletteIndex(u8);

impl PaletteIndex {
    pub const fn new(index: u8) -> Self {
        Self(index)
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl From<PaletteIndex> for usize {
    fn from(value: PaletteIndex) -> Self {
        value.as_usize()
    }
}

/// The 256-entry RGB palette carried by the retail default indexed DIB.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DibPalette([Rgb; 256]);

impl DibPalette {
    pub const fn new(colors: [Rgb; 256]) -> Self {
        Self(colors)
    }

    pub const fn colors(&self) -> &[Rgb; 256] {
        &self.0
    }

    pub fn colors_mut(&mut self) -> &mut [Rgb; 256] {
        &mut self.0
    }
}

impl Default for DibPalette {
    fn default() -> Self {
        Self([Rgb::default(); 256])
    }
}

impl Index<PaletteIndex> for DibPalette {
    type Output = Rgb;

    fn index(&self, index: PaletteIndex) -> &Self::Output {
        &self.0[index.as_usize()]
    }
}

impl IndexMut<PaletteIndex> for DibPalette {
    fn index_mut(&mut self, index: PaletteIndex) -> &mut Self::Output {
        &mut self.0[index.as_usize()]
    }
}

impl Index<usize> for DibPalette {
    type Output = Rgb;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for DibPalette {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}
