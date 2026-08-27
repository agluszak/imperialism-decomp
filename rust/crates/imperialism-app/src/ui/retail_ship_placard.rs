//! Recovered `TShipPlacard` as a BSN SceneComponent.
//!
//! Visually distinct from [`super::retail_army_placard::RetailArmyPlacard`]: retail centers the
//! available-count caption around (0x50, 0x2e) with theme `0x2b6c` / shadow `0x2b67` (+1,+1).

use super::retail::{retail_picture, retail_text_color, retail_text_shadow, retail_text_style};
use bevy::prelude::*;
use bevy::ui::UiSystems;

/// Private structure for the ship-placard hierarchy.
#[derive(SceneComponent, FromTemplate, Clone)]
#[scene(RetailShipPlacardProps)]
pub struct RetailShipPlacard {
    pub text: Entity,
}

/// Static construction props for [`RetailShipPlacard`].
#[derive(Default, Clone, Copy)]
pub struct RetailShipPlacardProps {
    pub picture_id: i16,
}

/// Externally projected available ship count. `None` or non-positive clears the label.
#[derive(Component, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShipPlacardValue(pub Option<i32>);

impl RetailShipPlacard {
    fn scene(props: RetailShipPlacardProps) -> impl Scene {
        // Caption centered at x≈80 within the 100px-wide placard (retail 0x50 ± extent/2).
        bsn! {
            retail_picture(props.picture_id)
            RetailShipPlacard {
                text: #Count,
            }
            ShipPlacardValue(None)
            Children [(
                #Count
                Node {
                    position_type: PositionType::Absolute,
                    left: px(40),
                    top: px(0x2e),
                    width: px(80),
                    height: px(16),
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
        @RetailShipPlacard {
            @picture_id: picture_id,
        }
    }
}

pub(super) fn register_ship_placard(app: &mut App) {
    app.add_systems(PostUpdate, draw_ship_placards.before(UiSystems::Prepare));
}

fn draw_ship_placards(
    pictures: Query<(&ShipPlacardValue, &RetailShipPlacard), Changed<ShipPlacardValue>>,
    mut texts: Query<&mut Text>,
) {
    for (value, picture) in &pictures {
        texts
            .get_mut(picture.text)
            .expect("RetailShipPlacard text child")
            .0 = value
            .0
            .filter(|&count| count > 0)
            .map(|count| count.to_string())
            .unwrap_or_default();
    }
}
