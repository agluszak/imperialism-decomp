//! Recovered `TPlacard` as a structure-only BSN SceneComponent.
//!
//! Screens write the caption [`Text`], layout, and root [`Visibility`].

use super::retail::{retail_picture, retail_text_color, retail_text_shadow, retail_text_style};
use bevy::prelude::*;

/// System 10pt logical cell height (`(10*10+3)/8`).
const SYSTEM_10PT_HEIGHT: f32 = 12.0;

/// Private structure for the recovered placard hierarchy.
#[derive(SceneComponent, FromTemplate, Clone)]
#[scene(PlacardProps)]
pub struct PlacardParts {
    pub text: Entity,
}

/// Static construction props for [`PlacardParts`].
#[derive(Default, Clone, Copy)]
pub struct PlacardProps {
    pub picture_id: i16,
}

impl PlacardParts {
    fn scene(props: PlacardProps) -> impl Scene {
        bsn! {
            retail_picture(props.picture_id)
            PlacardParts {
                text: #Value,
            }
            Visibility::Hidden
            Children [(
                #Value
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0),
                    top: px(0),
                    width: px(20),
                    height: px(14),
                }
                Text("")
                retail_text_style(3, 0, 10, 0)
                retail_text_color(0x28)
                retail_text_shadow(0, 1, 1)
                Pickable::IGNORE
            )]
        }
    }
}

/// BSN helper used by generated screens.
pub fn retail_placard(picture_id: i16) -> impl Scene {
    bsn! {
        @PlacardParts {
            @picture_id: picture_id,
        }
    }
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

    #[test]
    fn layout_uses_baseline_minus_cell_height() {
        assert_eq!(placard_text_layout(39.0, 40.0, 9), (39.0 / 2.0 - 2.0, 26.0));
    }
}
