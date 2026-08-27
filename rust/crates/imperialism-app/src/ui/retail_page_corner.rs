//! Recovered `TPageCorner` triangular hit testing.
//!
//! Only the corner triangle accepts input; other clicks fall through to the page underneath.
//! Valid presses trigger [`Activate`] for handwritten binders.

use bevy::picking::events::{Pointer, Press};
use bevy::picking::pointer::PointerButton;
use bevy::prelude::*;
use bevy::ui::{ComputedNode, InteractionDisabled};
use bevy::ui_widgets::Activate;

/// Which half of a page-corner control accepts clicks.
#[derive(Component, Clone, Copy, Debug, Eq, PartialEq, Reflect)]
#[reflect(Component)]
pub enum RetailPageCorner {
    /// `lcor`: accept when local `x < y`.
    Left,
    /// `rcor`: accept when `height - y < x`.
    Right,
}

pub(super) fn register_page_corner(app: &mut App) {
    app.add_observer(on_page_corner_press);
}

/// Retail `TPageCorner::HandleMouseDown` triangle test in pixel coordinates.
pub fn page_corner_hit(corner: RetailPageCorner, width: f32, height: f32, x: f32, y: f32) -> bool {
    if !(0.0..=width).contains(&x) || !(0.0..=height).contains(&y) {
        return false;
    }
    match corner {
        RetailPageCorner::Left => x < y,
        RetailPageCorner::Right => height - y < x,
    }
}

fn local_pixels(hit: Vec3, size: Vec2) -> Option<(f32, f32)> {
    if size.x <= 0.0 || size.y <= 0.0 {
        return None;
    }
    let x = (hit.x + 0.5) * size.x;
    let y = (hit.y + 0.5) * size.y;
    Some((x, y))
}

fn on_page_corner_press(
    mut press: On<Pointer<Press>>,
    disabled: Query<Has<InteractionDisabled>>,
    corners: Query<(&RetailPageCorner, &ComputedNode)>,
    mut commands: Commands,
) {
    if press.event.button != PointerButton::Primary {
        return;
    }
    let entity = press.entity;
    if disabled.get(entity).unwrap_or(false) {
        return;
    }
    let Ok((corner, node)) = corners.get(entity) else {
        return;
    };
    let Some(hit) = press.hit.position else {
        return;
    };
    let Some((x, y)) = local_pixels(hit, node.size) else {
        return;
    };
    if !page_corner_hit(*corner, node.size.x, node.size.y, x, y) {
        return;
    }
    press.propagate(false);
    commands.trigger(Activate { entity });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn left_corner_accepts_upper_triangle() {
        assert!(page_corner_hit(
            RetailPageCorner::Left,
            41.0,
            36.0,
            10.0,
            20.0
        ));
        assert!(!page_corner_hit(
            RetailPageCorner::Left,
            41.0,
            36.0,
            20.0,
            10.0
        ));
    }

    #[test]
    fn right_corner_accepts_lower_triangle() {
        assert!(page_corner_hit(
            RetailPageCorner::Right,
            40.0,
            35.0,
            30.0,
            30.0
        ));
        assert!(!page_corner_hit(
            RetailPageCorner::Right,
            40.0,
            35.0,
            5.0,
            5.0
        ));
    }
}
