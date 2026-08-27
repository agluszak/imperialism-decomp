//! Placard caption layout helpers. Scene structure is generated.

use bevy::prelude::*;

const SYSTEM_10PT_HEIGHT: f32 = 12.0;

/// Text child of any recovered placard variant.
#[derive(Component, FromTemplate, Clone, Copy)]
pub struct PlacardParts {
    pub text: Entity,
}

/// `TPlacard::Draw` digit-aware X origin relative to placard left.
pub fn placard_text_x(width: f32, value: i16) -> f32 {
    let half = width / 2.0;
    if value < 10 {
        half - 2.0
    } else if value < 100 {
        half - 6.0
    } else {
        half - 10.0
    }
}

/// QuickDraw baseline `frameHeight - 2` with system 10pt cell height 12.
pub fn placard_text_layout(root_width: f32, root_height: f32, value: i16) -> (f32, f32) {
    let top = (root_height - 2.0 - SYSTEM_10PT_HEIGHT).max(0.0);
    (placard_text_x(root_width, value), top)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digit_aware_x_matches_retail_thresholds() {
        assert_eq!(placard_text_x(39.0, 9), 39.0 / 2.0 - 2.0);
        assert_eq!(placard_text_x(39.0, 10), 39.0 / 2.0 - 6.0);
        assert_eq!(placard_text_x(39.0, 100), 39.0 / 2.0 - 10.0);
    }
}
