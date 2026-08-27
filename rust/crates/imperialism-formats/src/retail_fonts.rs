const BOOK_ANTIQUA_HEIGHTS: [i32; 25] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 14, 15, 16, 17, 20, 20, 20, 20, 20, 20, 25, 25, 25, 25, 30,
];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RetailFontFace {
    System,
    BelweBold,
    BookAntiquaRegular,
    BookAntiquaBold,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetailTextAlignment {
    Left,
    Center,
    Right,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetailTextStylePreset {
    font_family: i32,
    face_flags: i32,
    point_size: i32,
    alignment: i32,
}

impl RetailTextStylePreset {
    /// `BuildUiTextStyleDescriptor`: its family argument is dead. Retail derives the
    /// family from the point size alone — family 3 (Book Antiqua) below 12pt,
    /// family 1 (Belwe) from 12pt upward — and clears the face flags.
    pub const fn built(point_size: i32, alignment: i32) -> Self {
        Self {
            font_family: if point_size >= 12 { 1 } else { 3 },
            face_flags: 0,
            point_size,
            alignment,
        }
    }

    /// `InitializeUiTextStyleDescriptor`: an explicitly selected font family.
    pub const fn explicit(
        font_family: i32,
        face_flags: i32,
        point_size: i32,
        alignment: i32,
    ) -> Self {
        Self {
            font_family,
            face_flags,
            point_size,
            alignment,
        }
    }

    pub(crate) fn family(self) -> i32 {
        self.font_family
    }

    pub(crate) fn face_flags(self) -> i32 {
        self.face_flags
    }

    pub(crate) fn point_size(self) -> i32 {
        self.point_size
    }

    pub(crate) fn alignment(self) -> i32 {
        self.alignment
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedRetailTextStyle {
    pub face: RetailFontFace,
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
    let effective_family = if (1..=4).contains(&preset.family()) {
        preset.family()
    } else {
        0
    };
    let logical_pixel_height = retail_logical_font_height(preset.family(), preset.point_size())?;
    let face = match effective_family {
        0 => RetailFontFace::System,
        1 => RetailFontFace::BelweBold,
        2 | 3 if preset.face_flags() & 1 != 0 => RetailFontFace::BookAntiquaBold,
        2 | 3 => RetailFontFace::BookAntiquaRegular,
        4 => {
            return Err(RetailTextStyleError::UnresolvedFontFamily {
                requested_family: preset.family(),
                effective_family,
            });
        }
        _ => unreachable!("font family was normalized above"),
    };
    let alignment = match preset.alignment() {
        -1 => RetailTextAlignment::Right,
        1 => RetailTextAlignment::Center,
        _ => RetailTextAlignment::Left,
    };
    Ok(ResolvedRetailTextStyle {
        face,
        logical_pixel_height,
        alignment,
        italic: preset.face_flags() & 2 != 0,
        underline: preset.face_flags() & 4 != 0,
    })
}

fn retail_logical_font_height(
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

/// OS/2 Windows cell metrics used by GDI `CreateFontIndirectA` with a positive `lfHeight`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetailFontCellMetrics {
    pub units_per_em: u16,
    pub win_ascent: u16,
    pub win_descent: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RetailFontMetricsError {
    #[error("retail font {face:?} is not a supported TrueType face")]
    InvalidFont { face: RetailFontFace },
}

impl RetailFontCellMetrics {
    /// Maps a positive GDI cell height onto the em size Bevy/parley consume.
    ///
    /// Retail `CreateFontFromPresetAndAttachRegionHandle` stores `lfHeight` as a cell
    /// height (`tmHeight`). Bevy `TextFont::font_size` is the em square, which GDI
    /// derives as `MulDiv(lfHeight, unitsPerEm, usWinAscent + usWinDescent)`.
    pub fn em_pixel_size(self, cell_height: i32) -> i32 {
        let cell_units = i32::from(self.win_ascent) + i32::from(self.win_descent);
        if cell_height <= 0 || self.units_per_em == 0 || cell_units <= 0 {
            return cell_height.max(1);
        }
        let product = i64::from(cell_height) * i64::from(self.units_per_em);
        let divisor = i64::from(cell_units);
        let rounded = if product >= 0 {
            product + divisor / 2
        } else {
            product - divisor / 2
        };
        i32::try_from(rounded / divisor)
            .ok()
            .filter(|size| *size > 0)
            .unwrap_or(1)
    }
}

pub fn decode_retail_font_cell_metrics(
    face: RetailFontFace,
    bytes: &[u8],
) -> Result<RetailFontCellMetrics, RetailFontMetricsError> {
    let parsed = ttf_parser::Face::parse(bytes, 0)
        .map_err(|_| RetailFontMetricsError::InvalidFont { face })?;
    let (win_ascent, win_descent) = if let Some(os2) = parsed.tables().os2 {
        (
            positive_font_metric(os2.windows_ascender()),
            os2.windows_descender().unsigned_abs(),
        )
    } else {
        let hhea = parsed.tables().hhea;
        (
            positive_font_metric(hhea.ascender),
            hhea.descender.unsigned_abs(),
        )
    };
    Ok(RetailFontCellMetrics {
        units_per_em: parsed.units_per_em(),
        win_ascent,
        win_descent,
    })
}

fn positive_font_metric(value: i16) -> u16 {
    u16::try_from(value.max(0)).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preset(family: i32, flags: i32, size: i32, alignment: i32) -> RetailTextStylePreset {
        RetailTextStylePreset::explicit(family, flags, size, alignment)
    }

    #[test]
    fn explicit_family_counterexamples_stay_distinct_from_built() {
        // Trade price/stock cells: InitializeUiTextStyleDescriptor(..., 0xe, ..., 2).
        assert_eq!(
            resolve_retail_text_style(RetailTextStylePreset::explicit(2, 0, 14, -1))
                .unwrap()
                .face,
            RetailFontFace::BookAntiquaRegular
        );
        // Help body: explicit family 3 at 12pt must NOT become Belwe.
        assert_eq!(
            resolve_retail_text_style(RetailTextStylePreset::explicit(3, 0, 12, 0))
                .unwrap()
                .face,
            RetailFontFace::BookAntiquaRegular
        );
        // Newspaper headline/body: explicit family 2 at 12/14pt.
        assert_eq!(
            resolve_retail_text_style(RetailTextStylePreset::explicit(2, 0, 12, 2))
                .unwrap()
                .face,
            RetailFontFace::BookAntiquaRegular
        );
        assert_eq!(
            resolve_retail_text_style(RetailTextStylePreset::explicit(2, 1, 14, 2))
                .unwrap()
                .face,
            RetailFontFace::BookAntiquaBold
        );
        // Built styles at the 12pt threshold pick Belwe vs Book Antiqua.
        assert_eq!(
            resolve_retail_text_style(RetailTextStylePreset::built(10, -1))
                .unwrap()
                .face,
            RetailFontFace::BookAntiquaRegular
        );
        assert_eq!(
            resolve_retail_text_style(RetailTextStylePreset::built(12, 1))
                .unwrap()
                .face,
            RetailFontFace::BelweBold
        );
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
    fn resolves_system_family_and_rejects_unavailable_small_fonts() {
        assert_eq!(retail_logical_font_height(0, 0).unwrap(), 15);
        assert_eq!(retail_logical_font_height(4, 12).unwrap(), 15);
        assert_eq!(retail_logical_font_height(21, 12).unwrap(), 15);
        assert_eq!(
            resolve_retail_text_style(preset(21, 0, 0, 0)).unwrap().face,
            RetailFontFace::System
        );
        assert_eq!(
            resolve_retail_text_style(preset(4, 0, 12, 0)).unwrap_err(),
            RetailTextStyleError::UnresolvedFontFamily {
                requested_family: 4,
                effective_family: 4,
            }
        );
        assert_eq!(
            resolve_retail_text_style(preset(3, 0, 25, 0))
                .unwrap()
                .logical_pixel_height,
            31
        );
    }

    #[test]
    fn maps_positive_gdi_cell_height_to_em_size() {
        let metrics = RetailFontCellMetrics {
            units_per_em: 2048,
            win_ascent: 1892,
            win_descent: 430,
        };
        assert_eq!(metrics.em_pixel_size(16), 14);
        assert_eq!(metrics.em_pixel_size(15), 13);
        assert_eq!(metrics.em_pixel_size(14), 12);
        assert_eq!(
            RetailFontCellMetrics {
                units_per_em: 2048,
                win_ascent: 2048,
                win_descent: 0,
            }
            .em_pixel_size(15),
            15
        );
        assert_eq!(
            RetailFontCellMetrics {
                units_per_em: 2048,
                win_ascent: 0,
                win_descent: 0,
            }
            .em_pixel_size(15),
            15
        );
    }

    #[test]
    fn rejects_bytes_that_are_not_a_font() {
        assert_eq!(
            decode_retail_font_cell_metrics(RetailFontFace::BelweBold, b"not a font"),
            Err(RetailFontMetricsError::InvalidFont {
                face: RetailFontFace::BelweBold,
            })
        );
    }
}
