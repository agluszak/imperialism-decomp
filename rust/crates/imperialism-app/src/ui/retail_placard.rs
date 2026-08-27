//! Recovered `TPlacard` as a BSN SceneComponent.
//!
//! Structure (`RetailPlacard` + text child) is spawned atomically with the scene.
//! Screens project `PlacardValue`; this module redraws text and digit-aware layout.

use super::retail::{retail_picture, retail_text_color, retail_text_shadow, retail_text_style};
use bevy::prelude::*;
use bevy::ui::UiSystems;

/// Private structure for the recovered placard hierarchy.
#[derive(SceneComponent, FromTemplate, Clone)]
#[scene(RetailPlacardProps)]
pub struct RetailPlacard {
    pub text: Entity,
}

/// Static construction props for [`RetailPlacard`].
#[derive(Default, Clone, Copy)]
pub struct RetailPlacardProps {
    pub picture_id: i16,
}

/// Externally projected placard value (`TPlacard::glyph90`).
#[derive(Component, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlacardValue(pub i16);

impl RetailPlacard {
    fn scene(props: RetailPlacardProps) -> impl Scene {
        bsn! {
            retail_picture(props.picture_id)
            RetailPlacard {
                text: #Value,
            }
            PlacardValue(0)
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
        @RetailPlacard {
            @picture_id: picture_id,
        }
    }
}

pub(super) fn register_placard(app: &mut App) {
    app.add_systems(PostUpdate, draw_placards.before(UiSystems::Prepare));
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

fn draw_placards(
    mut placards: Query<
        (&PlacardValue, &RetailPlacard, &Node, &mut Visibility),
        Changed<PlacardValue>,
    >,
    mut texts: Query<&mut Text>,
    mut nodes: Query<&mut Node, Without<RetailPlacard>>,
) {
    for (value, placard, root, mut visibility) in &mut placards {
        let shown = value.0 != 0;
        *visibility = if shown {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        if !shown {
            continue;
        }
        let (Val::Px(width), Val::Px(height)) = (root.width, root.height) else {
            continue;
        };
        // QuickDraw baseline is `frameHeight - 2`; Book Antiqua 10pt cell is 14px.
        let top = (height - 2.0 - 12.0).max(0.0);
        let mut text = texts
            .get_mut(placard.text)
            .expect("RetailPlacard text child");
        text.0 = value.0.to_string();
        let mut text_node = nodes
            .get_mut(placard.text)
            .expect("RetailPlacard text node");
        text_node.left = Val::Px(placard_text_x(width, value.0));
        text_node.top = Val::Px(top);
    }
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
