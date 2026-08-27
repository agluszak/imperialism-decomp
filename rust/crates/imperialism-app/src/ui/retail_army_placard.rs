//! Recovered `TArmyPlacard` as a BSN SceneComponent.
//!
//! Root `ImageNode` comes from the recovered picture; this widget owns the count overlay.
//! Screens may replace the image for technology/empty art while projecting [`ArmyPlacardValue`].
//!
//! Retail draws black theme `0x2b67` at `(width - text_width, height - 2)`, then palette
//! `0x28` (`0x2b6c`) at `(width - text_width - 1, height - 3)`. Bevy: foreground `0x28` with
//! black `(+1,+1)` shadow. The Bevy text box top is derived from the main baseline.

use super::retail::{retail_picture, retail_text_color, retail_text_shadow, retail_text_style};
use bevy::prelude::*;
use bevy::ui::UiSystems;

/// System 10pt logical cell height (`(10*10+3)/8`).
const SYSTEM_10PT_HEIGHT: f32 = 12.0;
/// Placard frame from recovery (`pic0`… are 42×53).
const PLACARD_HEIGHT: f32 = 53.0;
/// Main (0x28) QuickDraw baseline is `frameHeight - 3`.
const TEXT_TOP: f32 = PLACARD_HEIGHT - 3.0 - SYSTEM_10PT_HEIGHT;

/// Private structure for the army-placard hierarchy.
#[derive(SceneComponent, FromTemplate, Clone)]
#[scene(RetailArmyPlacardProps)]
pub struct RetailArmyPlacard {
    pub text: Entity,
}

/// Static construction props for [`RetailArmyPlacard`].
#[derive(Default, Clone, Copy)]
pub struct RetailArmyPlacardProps {
    pub picture_id: i16,
}

/// Externally projected army placard count. `None` clears the label.
#[derive(Component, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArmyPlacardValue(pub Option<i32>);

impl RetailArmyPlacard {
    fn scene(props: RetailArmyPlacardProps) -> impl Scene {
        bsn! {
            retail_picture(props.picture_id)
            RetailArmyPlacard {
                text: #Count,
            }
            ArmyPlacardValue(None)
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
        @RetailArmyPlacard {
            @picture_id: picture_id,
        }
    }
}

pub(super) fn register_army_placard(app: &mut App) {
    app.add_systems(PostUpdate, draw_army_placards.before(UiSystems::Prepare));
}

fn draw_army_placards(
    pictures: Query<(&ArmyPlacardValue, &RetailArmyPlacard), Changed<ArmyPlacardValue>>,
    mut texts: Query<&mut Text>,
) {
    for (value, picture) in &pictures {
        texts
            .get_mut(picture.text)
            .expect("RetailArmyPlacard text child")
            .0 = value.0.map(|count| count.to_string()).unwrap_or_default();
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
