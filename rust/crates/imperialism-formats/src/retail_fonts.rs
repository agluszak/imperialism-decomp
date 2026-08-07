use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const BOOK_ANTIQUA_HEIGHTS: [i32; 25] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 14, 15, 16, 17, 20, 20, 20, 20, 20, 20, 25, 25, 25, 25, 30,
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetailFontFace {
    BelweBold,
    BookAntiquaRegular,
    BookAntiquaBold,
}

impl RetailFontFace {
    pub const fn relative_path(self) -> &'static str {
        match self {
            Self::BelweBold => "Data/WeBeBd__.ttf",
            Self::BookAntiquaRegular => "Data/Antqua.ttf",
            Self::BookAntiquaBold => "Data/Antquab.ttf",
        }
    }

    pub const fn expected_family_name(self) -> &'static str {
        match self {
            Self::BelweBold => "Belwe Bd BT",
            Self::BookAntiquaRegular | Self::BookAntiquaBold => "Book Antiqua",
        }
    }

    pub const fn expected_postscript_name(self) -> &'static str {
        match self {
            Self::BelweBold => "BelweBT-Bold",
            Self::BookAntiquaRegular => "BookAntiqua",
            Self::BookAntiquaBold => "BookAntiqua-Bold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetailTextAlignment {
    Left,
    Center,
    Right,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetailTextStylePreset {
    pub font_family: i32,
    pub face_flags: i32,
    pub point_size: i32,
    pub alignment: i32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResolvedRetailTextStyle {
    pub face: RetailFontFace,
    pub requested_font_family: i32,
    pub effective_font_family: i32,
    pub point_size: i32,
    pub logical_pixel_height: i32,
    pub alignment: RetailTextAlignment,
    pub italic: bool,
    pub underline: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RetailTextStyleError {
    #[error(
        "retail font family {effective_family} is not backed by a shipped font (requested family {requested_family})"
    )]
    UnresolvedFontFamily {
        requested_family: i32,
        effective_family: i32,
    },
    #[error("retail point size {0} is invalid")]
    InvalidPointSize(i32),
    #[error("retail logical font height overflows for point size {0}")]
    HeightOverflow(i32),
}

pub fn resolve_retail_text_style(
    preset: RetailTextStylePreset,
) -> Result<ResolvedRetailTextStyle, RetailTextStyleError> {
    let effective_family = if (1..=4).contains(&preset.font_family) {
        preset.font_family
    } else {
        0
    };
    let point_size = if preset.point_size == 0 {
        12
    } else {
        preset.point_size
    };
    let logical_pixel_height = retail_logical_font_height(preset.font_family, preset.point_size)?;
    let face = match effective_family {
        1 => RetailFontFace::BelweBold,
        2 | 3 if preset.face_flags & 1 != 0 => RetailFontFace::BookAntiquaBold,
        2 | 3 => RetailFontFace::BookAntiquaRegular,
        0 | 4 => {
            return Err(RetailTextStyleError::UnresolvedFontFamily {
                requested_family: preset.font_family,
                effective_family,
            });
        }
        _ => unreachable!("font family was normalized above"),
    };
    let alignment = match preset.alignment {
        -1 => RetailTextAlignment::Right,
        1 => RetailTextAlignment::Center,
        _ => RetailTextAlignment::Left,
    };
    Ok(ResolvedRetailTextStyle {
        face,
        requested_font_family: preset.font_family,
        effective_font_family: effective_family,
        point_size,
        logical_pixel_height,
        alignment,
        italic: preset.face_flags & 2 != 0,
        underline: preset.face_flags & 4 != 0,
    })
}

pub fn retail_logical_font_height(
    font_family: i32,
    requested_point_size: i32,
) -> Result<i32, RetailTextStyleError> {
    let effective_family = if (1..=4).contains(&font_family) {
        font_family
    } else {
        0
    };
    let point_size = if requested_point_size == 0 {
        12
    } else {
        requested_point_size
    };
    if point_size < 0 {
        return Err(RetailTextStyleError::InvalidPointSize(point_size));
    }
    if matches!(effective_family, 2 | 3)
        && (1..BOOK_ANTIQUA_HEIGHTS.len() as i32).contains(&point_size)
    {
        return Ok(BOOK_ANTIQUA_HEIGHTS[point_size as usize]);
    }
    i32::try_from((i64::from(point_size) * 10 + 3) / 8)
        .map_err(|_| RetailTextStyleError::HeightOverflow(point_size))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetailGlyphBounds {
    pub x_min: i16,
    pub y_min: i16,
    pub x_max: i16,
    pub y_max: i16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetailGlyphMetrics {
    pub character: char,
    pub glyph_id: u16,
    pub horizontal_advance: u16,
    pub horizontal_side_bearing: i16,
    pub bounds: Option<RetailGlyphBounds>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetailFontMetrics {
    pub face: RetailFontFace,
    pub family_names: Vec<String>,
    pub full_names: Vec<String>,
    pub postscript_names: Vec<String>,
    pub units_per_em: u16,
    pub ascender: i16,
    pub descender: i16,
    pub line_gap: i16,
    pub glyph_count: u16,
    pub glyphs: Vec<RetailGlyphMetrics>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RetailFontDecodeError {
    #[error("retail font data is not a supported TrueType/OpenType face")]
    InvalidFont,
    #[error("retail font {face:?} reports family names {actual:?}, expected {expected:?}")]
    UnexpectedFamily {
        face: RetailFontFace,
        expected: String,
        actual: Vec<String>,
    },
    #[error("retail font {face:?} reports PostScript names {actual:?}, expected {expected:?}")]
    UnexpectedPostscriptName {
        face: RetailFontFace,
        expected: String,
        actual: Vec<String>,
    },
    #[error("retail font {face:?} has no glyph for {character:?} (U+{code_point:04X})")]
    MissingGlyph {
        face: RetailFontFace,
        character: char,
        code_point: u32,
    },
    #[error("retail font {face:?} has incomplete horizontal metrics for glyph {glyph_id}")]
    MissingHorizontalMetrics { face: RetailFontFace, glyph_id: u16 },
}

pub fn decode_retail_font_metrics(
    face_kind: RetailFontFace,
    bytes: &[u8],
    text: &str,
) -> Result<RetailFontMetrics, RetailFontDecodeError> {
    let face = ttf_parser::Face::parse(bytes, 0).map_err(|_| RetailFontDecodeError::InvalidFont)?;
    let family_names = font_names(&face, ttf_parser::name_id::FAMILY);
    let full_names = font_names(&face, ttf_parser::name_id::FULL_NAME);
    let postscript_names = font_names(&face, ttf_parser::name_id::POST_SCRIPT_NAME);
    if !family_names
        .iter()
        .any(|name| name == face_kind.expected_family_name())
    {
        return Err(RetailFontDecodeError::UnexpectedFamily {
            face: face_kind,
            expected: face_kind.expected_family_name().to_owned(),
            actual: family_names,
        });
    }
    if !postscript_names
        .iter()
        .any(|name| name == face_kind.expected_postscript_name())
    {
        return Err(RetailFontDecodeError::UnexpectedPostscriptName {
            face: face_kind,
            expected: face_kind.expected_postscript_name().to_owned(),
            actual: postscript_names,
        });
    }
    let characters = text
        .chars()
        .filter(|character| !matches!(character, '\n' | '\r'))
        .collect::<BTreeSet<_>>();
    let mut glyphs = Vec::with_capacity(characters.len());
    for character in characters {
        let glyph = face
            .glyph_index(character)
            .ok_or(RetailFontDecodeError::MissingGlyph {
                face: face_kind,
                character,
                code_point: u32::from(character),
            })?;
        let horizontal_advance = face.glyph_hor_advance(glyph).ok_or(
            RetailFontDecodeError::MissingHorizontalMetrics {
                face: face_kind,
                glyph_id: glyph.0,
            },
        )?;
        let horizontal_side_bearing = face.glyph_hor_side_bearing(glyph).ok_or(
            RetailFontDecodeError::MissingHorizontalMetrics {
                face: face_kind,
                glyph_id: glyph.0,
            },
        )?;
        let bounds = face
            .glyph_bounding_box(glyph)
            .map(|rect| RetailGlyphBounds {
                x_min: rect.x_min,
                y_min: rect.y_min,
                x_max: rect.x_max,
                y_max: rect.y_max,
            });
        glyphs.push(RetailGlyphMetrics {
            character,
            glyph_id: glyph.0,
            horizontal_advance,
            horizontal_side_bearing,
            bounds,
        });
    }
    Ok(RetailFontMetrics {
        face: face_kind,
        family_names,
        full_names,
        postscript_names,
        units_per_em: face.units_per_em(),
        ascender: face.ascender(),
        descender: face.descender(),
        line_gap: face.line_gap(),
        glyph_count: face.number_of_glyphs(),
        glyphs,
    })
}

fn font_names(face: &ttf_parser::Face<'_>, name_id: u16) -> Vec<String> {
    face.names()
        .into_iter()
        .filter(|name| name.name_id == name_id)
        .filter_map(|name| name.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preset(family: i32, flags: i32, size: i32, alignment: i32) -> RetailTextStylePreset {
        RetailTextStylePreset {
            font_family: family,
            face_flags: flags,
            point_size: size,
            alignment,
        }
    }

    #[test]
    fn resolves_recovered_windows_family_face_and_height_rules() {
        let belwe = resolve_retail_text_style(preset(1, 0, 12, 1)).unwrap();
        assert_eq!(belwe.face, RetailFontFace::BelweBold);
        assert_eq!(belwe.logical_pixel_height, 15);
        assert_eq!(belwe.alignment, RetailTextAlignment::Center);

        let antiquated = resolve_retail_text_style(preset(3, 0, 9, -1)).unwrap();
        assert_eq!(antiquated.face, RetailFontFace::BookAntiquaRegular);
        assert_eq!(antiquated.logical_pixel_height, 14);
        assert_eq!(antiquated.alignment, RetailTextAlignment::Right);

        let bold = resolve_retail_text_style(preset(2, 1 | 2 | 4, 24, -2)).unwrap();
        assert_eq!(bold.face, RetailFontFace::BookAntiquaBold);
        assert_eq!(bold.logical_pixel_height, 30);
        assert!(bold.italic);
        assert!(bold.underline);
        assert_eq!(bold.alignment, RetailTextAlignment::Left);
    }

    #[test]
    fn defaults_zero_size_and_coerces_out_of_range_family_to_unresolved_system() {
        assert_eq!(retail_logical_font_height(0, 0).unwrap(), 15);
        assert_eq!(retail_logical_font_height(4, 12).unwrap(), 15);
        assert_eq!(retail_logical_font_height(21, 12).unwrap(), 15);
        let error = resolve_retail_text_style(preset(21, 0, 0, 0)).unwrap_err();
        assert_eq!(
            error,
            RetailTextStyleError::UnresolvedFontFamily {
                requested_family: 21,
                effective_family: 0,
            }
        );
        assert_eq!(
            resolve_retail_text_style(preset(3, 0, 25, 0))
                .unwrap()
                .logical_pixel_height,
            31
        );
    }
}
