//! One owner for every retail face: TTF bytes, GDI cell metrics, and the Bevy handle.
//!
//! `RetailAssets` only knows the retail directory. System bytes are injected at
//! application bootstrap; UI code asks for a `RetailFont` and never opens a font file.

use bevy::prelude::*;
use imperialism_formats::{
    RetailFontCellMetrics, RetailFontFace, RetailFontMetricsError, decode_retail_font_cell_metrics,
};
use std::fs;
use std::path::{Path, PathBuf};
use swash::FontRef;

#[derive(Debug, thiserror::Error)]
pub enum RetailFontError {
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Metrics(#[from] RetailFontMetricsError),
}

pub struct RetailFont {
    data: Vec<u8>,
    metrics: RetailFontCellMetrics,
    bevy: Handle<Font>,
}

impl RetailFont {
    fn from_bytes(
        face: RetailFontFace,
        data: Vec<u8>,
        fonts: &mut Assets<Font>,
    ) -> Result<Self, RetailFontMetricsError> {
        let metrics = decode_retail_font_cell_metrics(face, &data)?;
        let bevy = fonts.add(Font::from_bytes(data.clone()));
        Ok(Self {
            data,
            metrics,
            bevy,
        })
    }

    pub fn metrics(&self) -> RetailFontCellMetrics {
        self.metrics
    }

    pub fn handle(&self) -> Handle<Font> {
        self.bevy.clone()
    }

    pub fn swash(&self) -> FontRef<'_> {
        FontRef::from_index(&self.data, 0).expect("retail font bytes are valid")
    }
}

#[cfg(test)]
impl RetailFont {
    pub(crate) fn from_test_bytes(face: RetailFontFace, data: &'static [u8]) -> Self {
        let metrics = decode_retail_font_cell_metrics(face, data).expect("test font metrics");
        Self {
            data: data.to_vec(),
            metrics,
            bevy: Handle::default(),
        }
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
        retail_root: &Path,
        system: Vec<u8>,
        fonts: &mut Assets<Font>,
    ) -> Result<Self, RetailFontError> {
        Ok(Self {
            system: RetailFont::from_bytes(RetailFontFace::System, system, fonts)?,
            belwe_bold: load_shipped(RetailFontFace::BelweBold, retail_root, fonts)?,
            book_antiqua: load_shipped(RetailFontFace::BookAntiquaRegular, retail_root, fonts)?,
            book_antiqua_bold: load_shipped(RetailFontFace::BookAntiquaBold, retail_root, fonts)?,
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

fn load_shipped(
    face: RetailFontFace,
    retail_root: &Path,
    fonts: &mut Assets<Font>,
) -> Result<RetailFont, RetailFontError> {
    let Some(relative) = face.shipped_relative_path() else {
        unreachable!("System is injected at load, not read from Data/");
    };
    let path = retail_root.join(relative);
    let data = fs::read(&path).map_err(|source| RetailFontError::Io {
        path: path.clone(),
        source,
    })?;
    Ok(RetailFont::from_bytes(face, data, fonts)?)
}
