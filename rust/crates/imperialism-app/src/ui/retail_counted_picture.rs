//! Recovered `TArmyPlacard`-style picture with a right-aligned count overlay.
//!
//! Screen code owns the root `ImageNode`; this SceneComponent owns the count child.

use super::retail::{retail_text_color, retail_text_shadow, retail_text_style};
use bevy::prelude::*;
use bevy::ui::UiSystems;

/// Private structure for the counted-picture hierarchy.
#[derive(SceneComponent, FromTemplate, Clone)]
pub struct RetailCountedPicture {
    pub text: Entity,
}

/// Externally projected count overlay. `None` clears the label.
#[derive(Component, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CountedPictureValue(pub Option<i32>);

impl RetailCountedPicture {
    fn scene() -> impl Scene {
        bsn! {
            RetailCountedPicture {
                text: #Count,
            }
            CountedPictureValue(None)
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

/// Apply the counted-picture widget onto an existing picture node.
pub fn install_counted_picture(commands: &mut Commands, entity: Entity) {
    commands.entity(entity).apply_scene(bsn! {
        @RetailCountedPicture
    });
}

pub(super) fn register_counted_picture(app: &mut App) {
    app.add_systems(PostUpdate, draw_counted_pictures.before(UiSystems::Prepare));
}

fn draw_counted_pictures(
    pictures: Query<(&CountedPictureValue, &RetailCountedPicture), Changed<CountedPictureValue>>,
    mut texts: Query<&mut Text>,
) {
    for (value, picture) in &pictures {
        texts
            .get_mut(picture.text)
            .expect("RetailCountedPicture text child")
            .0 = value.0.map(|count| count.to_string()).unwrap_or_default();
    }
}
