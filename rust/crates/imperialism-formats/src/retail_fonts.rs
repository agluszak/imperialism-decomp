use serde::{Deserialize, Serialize};

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
