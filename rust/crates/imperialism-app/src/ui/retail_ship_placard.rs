//! Recovered `TShipPlacard` as a structure-only BSN SceneComponent.
//!
//! Screens write the available-count caption. Retail centers around (0x50, 0x2e)
//! with theme `0x2b6c` / shadow `0x2b67` (+1,+1). `(0x50 - width/2, 0x2e)` is the
//! QuickDraw baseline origin, not a Bevy text-box top-left.

use super::retail::{retail_picture, retail_text_color, retail_text_shadow, retail_text_style};
use bevy::prelude::*;

/// System 10pt logical cell height (`(10*10+3)/8`).
const SYSTEM_10PT_HEIGHT: f32 = 12.0;
/// Main (0x28) QuickDraw baseline Y from `TShipPlacard::Draw`.
const BASELINE_Y: f32 = 0x2e as f32;
const TEXT_TOP: f32 = BASELINE_Y - SYSTEM_10PT_HEIGHT;
/// Center X of the caption (`0x50`); box is wide enough for multi-digit counts.
const CENTER_X: f32 = 0x50 as f32;
const TEXT_WIDTH: f32 = 40.0;
const TEXT_LEFT: f32 = CENTER_X - TEXT_WIDTH / 2.0;

/// Private structure for the ship-placard hierarchy.
#[derive(SceneComponent, FromTemplate, Clone)]
#[scene(ShipPlacardProps)]
pub struct ShipPlacardParts {
    pub text: Entity,
}

/// Static construction props for [`ShipPlacardParts`].
#[derive(Default, Clone, Copy)]
pub struct ShipPlacardProps {
    pub picture_id: i16,
}

impl ShipPlacardParts {
    fn scene(props: ShipPlacardProps) -> impl Scene {
        bsn! {
            retail_picture(props.picture_id)
            ShipPlacardParts {
                text: #Count,
            }
            Children [(
                #Count
                Node {
                    position_type: PositionType::Absolute,
                    left: px(TEXT_LEFT),
                    top: px(TEXT_TOP),
                    width: px(TEXT_WIDTH),
                    height: px(SYSTEM_10PT_HEIGHT),
                }
                Text("")
                retail_text_style(0, 0, 10, 1)
                retail_text_color(0x28)
                retail_text_shadow(0, 1, 1)
                Pickable::IGNORE
            )]
        }
    }
}

/// BSN helper used by generated screens.
pub fn retail_ship_placard(picture_id: i16) -> impl Scene {
    bsn! {
        @ShipPlacardParts {
            @picture_id: picture_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_box_stays_inside_100x57_placard() {
        assert_eq!(TEXT_TOP, 34.0);
        assert!(TEXT_TOP + SYSTEM_10PT_HEIGHT <= 57.0);
        assert!(TEXT_LEFT + TEXT_WIDTH <= 100.0);
    }
}
