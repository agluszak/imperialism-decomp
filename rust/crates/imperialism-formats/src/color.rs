//! Small color and indexed-palette types used by retail bitmap decoding.

use std::ops::{Index, IndexMut};

/// 8-bit RGB triplet in display order (red, green, blue).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Rgb {
    r: u8,
    g: u8,
    b: u8,
}

impl Rgb {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Builds RGB from a Windows `RGBQUAD` / `RGBTRIPLE` BGR byte order.
    pub(crate) const fn from_bgr(b: u8, g: u8, r: u8) -> Self {
        Self { r, g, b }
    }

    pub const fn to_array(self) -> [u8; 3] {
        [self.r, self.g, self.b]
    }

    pub fn write_rgba(self, alpha: u8, out: &mut Vec<u8>) {
        out.extend_from_slice(&[self.r, self.g, self.b, alpha]);
    }
}

/// The 256-entry RGB palette carried by the retail default indexed DIB.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DibPalette([Rgb; 256]);

impl DibPalette {
    pub(crate) const fn new(colors: [Rgb; 256]) -> Self {
        Self(colors)
    }
}

impl Default for DibPalette {
    fn default() -> Self {
        Self([Rgb::default(); 256])
    }
}

impl Index<u8> for DibPalette {
    type Output = Rgb;

    fn index(&self, index: u8) -> &Self::Output {
        &self.0[usize::from(index)]
    }
}

impl IndexMut<u8> for DibPalette {
    fn index_mut(&mut self, index: u8) -> &mut Self::Output {
        &mut self.0[usize::from(index)]
    }
}
