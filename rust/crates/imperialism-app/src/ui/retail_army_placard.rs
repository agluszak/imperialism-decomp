//! Recovered `TArmyPlacard` as a structure-only BSN SceneComponent.
//!
//! Screens write the count caption. Retail draws black theme `0x2b67` at
//! `(width - text_width, height - 2)`, then palette `0x28` at
//! `(width - text_width - 1, height - 3)`. Bevy: foreground `0x28` with black
//! `(+1,+1)` shadow. Fixed layout for the recovered 42×53 placard.

use super::retail::{retail_picture, retail_text_color, retail_text_shadow, retail_text_style};
use bevy::prelude::*;

/// System 10pt logical cell height (`(10*10+3)/8`).
const SYSTEM_10PT_HEIGHT: f32 = 12.0;
/// Placard frame from recovery (`pic0`… are 42×53).
const PLACARD_HEIGHT: f32 = 53.0;
/// Main (0x28) QuickDraw baseline is `frameHeight - 3`.
const TEXT_TOP: f32 = PLACARD_HEIGHT - 3.0 - SYSTEM_10PT_HEIGHT;

/// Private structure for the army-placard hierarchy.
#[derive(SceneComponent, FromTemplate, Clone)]
#[scene(ArmyPlacardProps)]
pub struct ArmyPlacardParts {
    pub text: Entity,
}

/// Static construction props for [`ArmyPlacardParts`].
#[derive(Default, Clone, Copy)]
pub struct ArmyPlacardProps {
    pub picture_id: i16,
}

impl ArmyPlacardParts {
    fn scene(props: ArmyPlacardProps) -> impl Scene {
        bsn! {
            retail_picture(props.picture_id)
            ArmyPlacardParts {
                text: #Count,
            }
            Children [(
                #Count
                Node {
                    position_type: PositionType::Absolute,
                    right: px(0),
                    top: px(TEXT_TOP),
                    width: px(42),
                    height: px(SYSTEM_10PT_HEIGHT),
                }
                Text("")
                retail_text_style(0, 0, 10, -1)
                retail_text_color(0x28)
                retail_text_shadow(0, 1, 1)
                Pickable::IGNORE
            )]
        }
    }
}

/// BSN helper used by generated screens.
pub fn retail_army_placard(picture_id: i16) -> impl Scene {
    bsn! {
        @ArmyPlacardParts {
            @picture_id: picture_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_box_uses_baseline_not_cpp_origin_as_top() {
        // Main baseline is height-3; Bevy top is baseline minus system 10pt cell.
        assert_eq!(TEXT_TOP, 38.0);
    }
}
