//! Recovered `TPageCorner` triangular hit testing.
//!
//! Triangular acceptance happens in the picking pipeline so rejected clicks fall through.
//! Valid corners use stock [`Button`] release activation like other controls.

use bevy::picking::PickingSystems;
use bevy::picking::backend::{HitData, PointerHits};
use bevy::prelude::*;
use bevy::ui::ComputedNode;
use bevy::ui::InteractionDisabled;
use bevy::ui::picking_backend::ui_picking;

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
    app.add_systems(
        PreUpdate,
        filter_page_corner_pointer_hits
            .after(ui_picking)
            .in_set(PickingSystems::Backend),
    );
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

fn corner_hit_valid(
    entity: Entity,
    hit: &HitData,
    corners: &Query<(&RetailPageCorner, &ComputedNode)>,
    disabled: &Query<(), With<InteractionDisabled>>,
) -> bool {
    let Ok((corner, node)) = corners.get(entity) else {
        return true;
    };
    if disabled.get(entity).is_ok() {
        return false;
    }
    let Some(hit) = hit.position else {
        return false;
    };
    let Some((x, y)) = local_pixels(hit, node.size) else {
        return false;
    };
    page_corner_hit(*corner, node.size.x, node.size.y, x, y)
}

/// Drop rejected triangle/disabled hits; truncate after the first retained corner.
pub fn filter_page_corner_picks(
    picks: &mut Vec<(Entity, HitData)>,
    corners: &Query<(&RetailPageCorner, &ComputedNode)>,
    disabled: &Query<(), With<InteractionDisabled>>,
) {
    picks.retain(|(entity, hit)| corner_hit_valid(*entity, hit, corners, disabled));
    if let Some(index) = picks
        .iter()
        .position(|(entity, _)| corners.get(*entity).is_ok())
    {
        picks.truncate(index + 1);
    }
}

fn filter_page_corner_pointer_hits(
    pointer_hits: Option<MessageMutator<PointerHits>>,
    corners: Query<(&RetailPageCorner, &ComputedNode)>,
    disabled: Query<(), With<InteractionDisabled>>,
) {
    let Some(mut pointer_hits) = pointer_hits else {
        return;
    };
    for hits in pointer_hits.read() {
        filter_page_corner_picks(&mut hits.picks, &corners, &disabled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevy::camera::Camera;
    use bevy::ecs::system::SystemState;
    use bevy::picking::backend::HitData;
    use bevy::picking::events::{Click, Pointer, Press};
    use bevy::picking::pointer::{PointerButton, PointerId};
    use bevy::ui::Pressed;
    use bevy::ui_widgets::{Activate, Button, ButtonPlugin};
    use std::time::Duration;

    #[derive(Resource, Default)]
    struct ActivateCount(u32);

    fn hit_at(entity: Entity, x: f32, y: f32) -> (Entity, HitData) {
        let camera = Entity::from_bits(1);
        (
            entity,
            HitData::new(camera, 0.0, Some(Vec3::new(x, y, 0.0)), None),
        )
    }

    fn filter_picks(app: &mut App, picks: &mut Vec<(Entity, HitData)>) {
        let mut state = SystemState::<(
            Query<(&RetailPageCorner, &ComputedNode)>,
            Query<(), With<InteractionDisabled>>,
        )>::new(app.world_mut());
        let (corners, disabled) = state.get_mut(app.world_mut()).unwrap();
        filter_page_corner_picks(picks, &corners, &disabled);
    }

    fn pointer_location() -> bevy::picking::pointer::Location {
        bevy::picking::pointer::Location {
            target: bevy::camera::NormalizedRenderTarget::None {
                width: 1,
                height: 1,
            },
            position: Vec2::ZERO,
        }
    }

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
    fn rejected_triangle_lets_lower_target_remain_in_picks() {
        let mut app = App::new();
        app.world_mut().spawn(Camera::default());
        let corner = app
            .world_mut()
            .spawn((
                RetailPageCorner::Left,
                ComputedNode {
                    size: Vec2::new(40.0, 36.0),
                    ..default()
                },
            ))
            .id();
        let lower = app.world_mut().spawn_empty().id();
        let mut picks = vec![hit_at(corner, 0.2, -0.2), hit_at(lower, 0.0, 0.0)];
        filter_picks(&mut app, &mut picks);

        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].0, lower);
    }

    #[test]
    fn valid_triangle_keeps_only_corner_pick() {
        let mut app = App::new();
        app.world_mut().spawn(Camera::default());
        let corner = app
            .world_mut()
            .spawn((
                RetailPageCorner::Left,
                ComputedNode {
                    size: Vec2::new(40.0, 36.0),
                    ..default()
                },
            ))
            .id();
        let lower = app.world_mut().spawn_empty().id();
        let mut picks = vec![hit_at(corner, -0.2, 0.2), hit_at(lower, 0.0, 0.0)];
        filter_picks(&mut app, &mut picks);

        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].0, corner);
    }

    #[test]
    fn disabled_valid_corner_falls_through_to_lower_target() {
        let mut app = App::new();
        let corner = app
            .world_mut()
            .spawn((
                RetailPageCorner::Left,
                InteractionDisabled,
                ComputedNode {
                    size: Vec2::new(40.0, 36.0),
                    ..default()
                },
            ))
            .id();
        let lower = app.world_mut().spawn_empty().id();
        let mut picks = vec![hit_at(corner, -0.2, 0.2), hit_at(lower, 0.0, 0.0)];
        filter_picks(&mut app, &mut picks);

        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].0, lower);
    }

    #[test]
    fn overlay_before_corner_truncates_after_corner_not_before() {
        let mut app = App::new();
        let overlay = app.world_mut().spawn_empty().id();
        let corner = app
            .world_mut()
            .spawn((
                RetailPageCorner::Left,
                ComputedNode {
                    size: Vec2::new(40.0, 36.0),
                    ..default()
                },
            ))
            .id();
        let lower = app.world_mut().spawn_empty().id();
        let mut picks = vec![
            hit_at(overlay, 0.0, 0.0),
            hit_at(corner, -0.2, 0.2),
            hit_at(lower, 0.0, 0.0),
        ];
        filter_picks(&mut app, &mut picks);

        assert_eq!(picks.len(), 2);
        assert_eq!(picks[0].0, overlay);
        assert_eq!(picks[1].0, corner);
    }

    #[test]
    fn button_press_alone_does_not_activate() {
        let mut app = App::new();
        app.add_plugins((MinimalPlugins, ButtonPlugin))
            .init_resource::<ActivateCount>();
        let entity = app.world_mut().spawn(Button).id();
        app.world_mut().add_observer(
            move |activate: On<Activate>, mut count: ResMut<ActivateCount>| {
                if activate.entity == entity {
                    count.0 += 1;
                }
            },
        );

        app.world_mut().trigger(Pointer::new(
            PointerId::Mouse,
            pointer_location(),
            Press {
                button: PointerButton::Primary,
                hit: HitData::new(Entity::from_bits(1), 0.0, None, None),
                count: 1,
            },
            entity,
        ));
        app.update();
        assert_eq!(app.world().resource::<ActivateCount>().0, 0);
    }

    #[test]
    fn button_click_after_press_activates() {
        let mut app = App::new();
        app.add_plugins((MinimalPlugins, ButtonPlugin))
            .init_resource::<ActivateCount>();
        let entity = app.world_mut().spawn((Button, Pressed)).id();
        app.world_mut().add_observer(
            move |activate: On<Activate>, mut count: ResMut<ActivateCount>| {
                if activate.entity == entity {
                    count.0 += 1;
                }
            },
        );

        app.world_mut().trigger(Pointer::new(
            PointerId::Mouse,
            pointer_location(),
            Click {
                button: PointerButton::Primary,
                hit: HitData::new(Entity::from_bits(1), 0.0, None, None),
                duration: Duration::ZERO,
                count: 1,
            },
            entity,
        ));
        app.update();
        assert_eq!(app.world().resource::<ActivateCount>().0, 1);
    }
}
