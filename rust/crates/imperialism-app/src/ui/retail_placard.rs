//! Recovered placard scene helpers (`TPlacard`, `TArmyPlacard`, `TShipPlacard`).
//!
//! Structure only: screens write caption via bind-time child handles.

use super::retail::{retail_picture, retail_text_color, retail_text_shadow, retail_text_style};
use bevy::prelude::*;

const SYSTEM_10PT_HEIGHT: f32 = 12.0;

/// Text child of any recovered placard variant.
#[derive(Component, FromTemplate, Clone, Copy)]
pub struct PlacardParts {
    pub text: Entity,
}

pub fn retail_placard(picture_id: i16) -> impl Scene {
    placard_scene(picture_id, 3, 0, Val::Px(0.), Val::Px(0.), Val::Px(20.), Val::Px(14.), Val::Auto, true)
}

pub fn retail_army_placard(picture_id: i16) -> impl Scene {
    placard_scene(
        picture_id, 0, -1, Val::Auto, Val::Px(53. - 3. - SYSTEM_10PT_HEIGHT),
        Val::Px(42.), Val::Px(SYSTEM_10PT_HEIGHT), Val::Px(0.), false,
    )
}

pub fn retail_ship_placard(picture_id: i16) -> impl Scene {
    placard_scene(
        picture_id, 0, 1, Val::Px(0x50 as f32 - 20.), Val::Px(0x2e as f32 - SYSTEM_10PT_HEIGHT),
        Val::Px(40.), Val::Px(SYSTEM_10PT_HEIGHT), Val::Auto, false,
    )
}

#[rustfmt::skip]
fn placard_scene(
    picture_id: i16, family: i32, align: i32,
    left: Val, top: Val, width: Val, height: Val, right: Val, hidden: bool,
) -> impl Scene {
    let root_hidden = hidden.then(|| bsn! { Visibility::Hidden });
    bsn! {
        retail_picture(picture_id)
        PlacardParts { text: #Caption }
        {root_hidden}
        Children [(
            #Caption
            Node { position_type: PositionType::Absolute, left: {left}, right: {right}, top: {top}, width: {width}, height: {height} }
            Text("")
            retail_text_style(family, 0, 10, align)
            retail_text_color(0x28)
            retail_text_shadow(0, 1, 1)
            Pickable::IGNORE
        )]
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
}
