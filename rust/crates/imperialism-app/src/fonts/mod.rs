//! Application font registration for retail faces.
//!
//! `RetailAssets` owns the shipped `Data/*.ttf` files. This module registers those
//! bytes, plus the vendored Windows System compatibility face, as Bevy `Font`
//! assets and keeps only handles and GDI cell metrics.

use bevy::prelude::*;
use imperialism_formats::{
    RetailAssets, RetailFontCellMetrics, RetailFontFace, RetailFontMetricsError,
    decode_retail_font_cell_metrics,
};

const SYSTEM_FONT: &[u8] = include_bytes!("system.ttf");

pub struct RetailFont {
    handle: Handle<Font>,
    metrics: RetailFontCellMetrics,
}

impl RetailFont {
    fn register(
        face: RetailFontFace,
        data: Vec<u8>,
        fonts: &mut Assets<Font>,
    ) -> Result<Self, RetailFontMetricsError> {
        let metrics = decode_retail_font_cell_metrics(face, &data)?;
        Ok(Self {
            handle: fonts.add(Font::from_bytes(data)),
            metrics,
        })
    }

    pub fn metrics(&self) -> RetailFontCellMetrics {
        self.metrics
    }

    pub fn handle(&self) -> Handle<Font> {
        self.handle.clone()
    }
}

#[derive(Resource)]
pub struct RetailFonts {
    system: RetailFont,
    belwe_bold: RetailFont,
    book_antiqua: RetailFont,
    book_antiqua_bold: RetailFont,
}

impl RetailFonts {
    pub fn load(
        assets: &RetailAssets,
        fonts: &mut Assets<Font>,
    ) -> Result<Self, RetailFontMetricsError> {
        Self::from_shipped_bytes(
            assets.font_bytes(RetailFontFace::BelweBold),
            assets.font_bytes(RetailFontFace::BookAntiquaRegular),
            assets.font_bytes(RetailFontFace::BookAntiquaBold),
            fonts,
        )
    }

    fn from_shipped_bytes(
        belwe_bold: &[u8],
        book_antiqua: &[u8],
        book_antiqua_bold: &[u8],
        fonts: &mut Assets<Font>,
    ) -> Result<Self, RetailFontMetricsError> {
        Ok(Self {
            system: RetailFont::register(RetailFontFace::System, SYSTEM_FONT.to_vec(), fonts)?,
            belwe_bold: RetailFont::register(
                RetailFontFace::BelweBold,
                belwe_bold.to_vec(),
                fonts,
            )?,
            book_antiqua: RetailFont::register(
                RetailFontFace::BookAntiquaRegular,
                book_antiqua.to_vec(),
                fonts,
            )?,
            book_antiqua_bold: RetailFont::register(
                RetailFontFace::BookAntiquaBold,
                book_antiqua_bold.to_vec(),
                fonts,
            )?,
        })
    }

    pub fn get(&self, face: RetailFontFace) -> &RetailFont {
        match face {
            RetailFontFace::System => &self.system,
            RetailFontFace::BelweBold => &self.belwe_bold,
            RetailFontFace::BookAntiquaRegular => &self.book_antiqua,
            RetailFontFace::BookAntiquaBold => &self.book_antiqua_bold,
        }
    }
}

#[cfg(test)]
pub(crate) fn load_test_fonts(fonts: &mut Assets<Font>) -> RetailFonts {
    const OUTLINE: &[u8] = include_bytes!("test_outline.ttf");
    RetailFonts::from_shipped_bytes(OUTLINE, OUTLINE, OUTLINE, fonts).expect("test font metrics")
}
