//! Recovered `TArmyPlacard` as a BSN SceneComponent.
//!
//! Root `ImageNode` comes from the recovered picture; this widget owns the count overlay.
//! Screens may replace the image for technology/empty art while projecting [`ArmyPlacardValue`].

use super::retail::{retail_picture, retail_text_color, retail_text_shadow, retail_text_style};
use bevy::prelude::*;
use bevy::ui::UiSystems;

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
                    bottom: px(2),
                    width: px(42),
                    height: px(16),
                }
                Text("")
                retail_text_style(0, 0, 10, -1)
                retail_text_color(0x28)
                retail_text_shadow(0xd2, -1, -1)
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
