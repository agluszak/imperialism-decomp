//! Application font registration for retail faces.
//!
//! `RetailAssets` knows where GOG `Data/*.ttf` files live and reads them once.
//! This module moves those bytes, plus the vendored Windows System face, into
//! Bevy `Font` assets and keeps only handles and GDI cell-height conversion.

use anyhow::Context;
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

    pub fn size_for_cell_height(&self, cell_height: i32) -> i32 {
        self.metrics.em_pixel_size(cell_height)
    }

    pub fn handle(&self) -> &Handle<Font> {
        &self.handle
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
    pub fn load(assets: &RetailAssets, fonts: &mut Assets<Font>) -> anyhow::Result<Self> {
        Ok(Self::from_shipped_bytes(
            shipped_font(assets, RetailFontFace::BelweBold)?,
            shipped_font(assets, RetailFontFace::BookAntiquaRegular)?,
            shipped_font(assets, RetailFontFace::BookAntiquaBold)?,
            fonts,
        )?)
    }

    fn from_shipped_bytes(
        belwe_bold: Vec<u8>,
        book_antiqua: Vec<u8>,
        book_antiqua_bold: Vec<u8>,
        fonts: &mut Assets<Font>,
    ) -> Result<Self, RetailFontMetricsError> {
        Ok(Self {
            system: RetailFont::register(RetailFontFace::System, SYSTEM_FONT.to_vec(), fonts)?,
            belwe_bold: RetailFont::register(RetailFontFace::BelweBold, belwe_bold, fonts)?,
            book_antiqua: RetailFont::register(
                RetailFontFace::BookAntiquaRegular,
                book_antiqua,
                fonts,
            )?,
            book_antiqua_bold: RetailFont::register(
                RetailFontFace::BookAntiquaBold,
                book_antiqua_bold,
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

fn shipped_font(assets: &RetailAssets, face: RetailFontFace) -> anyhow::Result<Vec<u8>> {
    assets
        .read_font(face)?
        .with_context(|| format!("{face:?} is a shipped Data/*.ttf file"))
}

#[cfg(test)]
pub(crate) fn load_test_fonts(fonts: &mut Assets<Font>) -> RetailFonts {
    const OUTLINE: &[u8] = include_bytes!("test_outline.ttf");
    RetailFonts::from_shipped_bytes(OUTLINE.to_vec(), OUTLINE.to_vec(), OUTLINE.to_vec(), fonts)
        .expect("test font metrics")
}
