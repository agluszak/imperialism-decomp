//! Shared press-and-repeat timing for recovered quantity arrows.
//!
//! [`RetailSidewaysArrow`] and runtime `TRightLeftView` share the same repeat-deadline
//! algorithm. Only [`TSidewaysArrow`] also hilites via `TUpDownPictureButton`; mark that
//! path with [`RetailSidewaysArrowHilite`].

use accesskit::Role;
use bevy::a11y::AccessibilityNode;
use bevy::picking::PickingSystems;
use bevy::picking::events::{Cancel, DragEnd, Pointer, Press, Release};
use bevy::picking::hover::HoverMap;
use bevy::picking::pointer::{PointerButton, PointerId};
use bevy::prelude::*;
use bevy::ui::{InteractionDisabled, Pressed};

/// Marker for controls that use retail sideways repeat-step input.
#[derive(Component, Clone, Copy, Debug, Default)]
#[component(immutable)]
#[require(
    Pickable,
    RetailSidewaysArrowRepeat,
    AccessibilityNode(accesskit::Node::new(Role::Button))
)]
pub struct RetailSidewaysArrow;

/// `TSidewaysArrow` hilite while held; omit on [`TRightLeftView`] replacements.
#[derive(Component, Clone, Copy, Debug, Default)]
#[component(immutable)]
pub struct RetailSidewaysArrowHilite;

/// Retail `repeatDeadlineTick` survives mouse releases on the control.
#[derive(Component, Clone, Copy, Debug, Default)]
struct RetailSidewaysArrowRepeat {
    repeat_deadline_tick: u32,
}

/// Semantic quantity step from a sideways arrow (not release-activated).
#[derive(Copy, Clone, Debug, PartialEq, EntityEvent)]
pub struct Step {
    pub entity: Entity,
}

#[derive(Component, Clone, Copy, Debug)]
struct RetailSidewaysArrowTracking {
    pointer_id: PointerId,
}

const TICKS_PER_REPEAT: u32 = 5;
const INITIAL_REPEAT_DELAY: u32 = 10;

pub(super) fn register_sideways_arrow(app: &mut App) {
    app.add_observer(on_sideways_arrow_press)
        .add_observer(on_sideways_arrow_release)
        .add_observer(on_sideways_arrow_cancel)
        .add_observer(on_sideways_arrow_drag_end)
        .add_systems(
            PreUpdate,
            (sync_sideways_arrow_pressed, repeat_sideways_arrows)
                .chain()
                .after(PickingSystems::Hover),
        );
}

fn retail_tick(time: &Time<Real>) -> u32 {
    (time.elapsed().as_millis() / 16) as u32
}

fn pointer_inside(entity: Entity, pointer_id: PointerId, hover_map: &HoverMap) -> bool {
    hover_map
        .0
        .get(&pointer_id)
        .is_some_and(|hits| hits.contains_key(&entity))
}

/// Mirrors retail `TrackMouse` gating: five-tick hold-off, ten-tick begin deferral.
pub fn poll_repeat_deadline(deadline: &mut u32, now: u32, begin: bool) -> bool {
    if now < deadline.saturating_add(TICKS_PER_REPEAT) {
        return false;
    }
    *deadline = if begin {
        now.saturating_add(INITIAL_REPEAT_DELAY)
    } else {
        now
    };
    true
}

fn on_sideways_arrow_press(
    mut press: On<Pointer<Press>>,
    time: Res<Time<Real>>,
    disabled: Query<Has<InteractionDisabled>>,
    tracking: Query<(), With<RetailSidewaysArrowTracking>>,
    hilite: Query<(), With<RetailSidewaysArrowHilite>>,
    mut repeats: Query<&mut RetailSidewaysArrowRepeat, With<RetailSidewaysArrow>>,
    mut commands: Commands,
) {
    if press.event.button != PointerButton::Primary {
        return;
    }
    let entity = press.entity;
    let Ok(mut repeat) = repeats.get_mut(entity) else {
        return;
    };
    if disabled.get(entity).unwrap_or(false) || tracking.get(entity).is_ok() {
        return;
    }
    press.propagate(false);
    if hilite.get(entity).is_ok() {
        commands.entity(entity).insert(Pressed);
    }
    commands.entity(entity).insert(RetailSidewaysArrowTracking {
        pointer_id: press.pointer_id,
    });
    let tick = retail_tick(time.as_ref());
    if poll_repeat_deadline(&mut repeat.repeat_deadline_tick, tick, true) {
        commands.trigger(Step { entity });
    }
}

fn clear_sideways_arrow_hold(
    entity: Entity,
    pointer_id: PointerId,
    hilite: &Query<(), With<RetailSidewaysArrowHilite>>,
    tracking: &Query<&RetailSidewaysArrowTracking, With<RetailSidewaysArrow>>,
    commands: &mut Commands,
) -> bool {
    let Ok(state) = tracking.get(entity) else {
        return false;
    };
    if state.pointer_id != pointer_id {
        return false;
    }
    commands
        .entity(entity)
        .remove::<RetailSidewaysArrowTracking>();
    if hilite.get(entity).is_ok() {
        commands.entity(entity).remove::<Pressed>();
    }
    true
}

fn on_sideways_arrow_release(
    mut release: On<Pointer<Release>>,
    hilite: Query<(), With<RetailSidewaysArrowHilite>>,
    tracking: Query<&RetailSidewaysArrowTracking, With<RetailSidewaysArrow>>,
    mut commands: Commands,
) {
    if clear_sideways_arrow_hold(
        release.entity,
        release.pointer_id,
        &hilite,
        &tracking,
        &mut commands,
    ) {
        release.propagate(false);
    }
}

fn on_sideways_arrow_cancel(
    mut cancel: On<Pointer<Cancel>>,
    hilite: Query<(), With<RetailSidewaysArrowHilite>>,
    tracking: Query<&RetailSidewaysArrowTracking, With<RetailSidewaysArrow>>,
    mut commands: Commands,
) {
    if clear_sideways_arrow_hold(
        cancel.entity,
        cancel.pointer_id,
        &hilite,
        &tracking,
        &mut commands,
    ) {
        cancel.propagate(false);
    }
}

fn on_sideways_arrow_drag_end(
    mut drag_end: On<Pointer<DragEnd>>,
    hilite: Query<(), With<RetailSidewaysArrowHilite>>,
    tracking: Query<&RetailSidewaysArrowTracking, With<RetailSidewaysArrow>>,
    mut commands: Commands,
) {
    if clear_sideways_arrow_hold(
        drag_end.entity,
        drag_end.pointer_id,
        &hilite,
        &tracking,
        &mut commands,
    ) {
        drag_end.propagate(false);
    }
}

fn sync_sideways_arrow_pressed(
    hover_map: Option<Res<HoverMap>>,
    tracking: Query<(Entity, &RetailSidewaysArrowTracking), With<RetailSidewaysArrowHilite>>,
    disabled: Query<Has<InteractionDisabled>>,
    pressed: Query<Has<Pressed>>,
    mut commands: Commands,
) {
    let Some(hover_map) = hover_map else {
        return;
    };
    for (entity, state) in tracking.iter() {
        if disabled.get(entity).unwrap_or(false) {
            continue;
        }
        let inside = pointer_inside(entity, state.pointer_id, hover_map.as_ref());
        let has_pressed = pressed.get(entity).unwrap_or(false);
        if inside && !has_pressed {
            commands.entity(entity).insert(Pressed);
        } else if !inside && has_pressed {
            commands.entity(entity).remove::<Pressed>();
        }
    }
}

fn repeat_sideways_arrows(
    time: Res<Time<Real>>,
    hover_map: Option<Res<HoverMap>>,
    disabled: Query<Has<InteractionDisabled>>,
    mut tracking: Query<
        (
            Entity,
            &RetailSidewaysArrowTracking,
            &mut RetailSidewaysArrowRepeat,
        ),
        With<RetailSidewaysArrow>,
    >,
    mut commands: Commands,
) {
    let Some(hover_map) = hover_map else {
        return;
    };
    let tick = retail_tick(time.as_ref());
    for (entity, state, mut repeat) in tracking.iter_mut() {
        if disabled.get(entity).unwrap_or(false) {
            commands
                .entity(entity)
                .remove::<RetailSidewaysArrowTracking>();
            commands.entity(entity).remove::<Pressed>();
            continue;
        }
        if !poll_repeat_deadline(&mut repeat.repeat_deadline_tick, tick, false) {
            continue;
        }
        if !pointer_inside(entity, state.pointer_id, hover_map.as_ref()) {
            continue;
        }
        commands.trigger(Step { entity });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevy::camera::Camera;
    use bevy::ecs::entity::EntityHashMap;
    use bevy::picking::backend::HitData;
    use bevy::picking::events::{Pointer, Press, Release};
    use bevy::picking::hover::HoverMap;
    use bevy::picking::pointer::{PointerButton, PointerId};
    use bevy::ui_widgets::{Button, ButtonPlugin};
    use std::time::Duration;

    #[derive(Resource, Default)]
    struct StepCount(u32);

    fn test_app() -> App {
        let mut app = App::new();
        app.add_plugins((MinimalPlugins, ButtonPlugin))
            .init_resource::<HoverMap>();
        register_sideways_arrow(&mut app);
        app
    }

    fn dummy_hit() -> HitData {
        HitData::new(Entity::from_bits(1), 0.0, None, None)
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

    fn press(entity: Entity, app: &mut App) {
        app.world_mut().trigger(Pointer::new(
            PointerId::Mouse,
            pointer_location(),
            Press {
                button: PointerButton::Primary,
                hit: dummy_hit(),
                count: 1,
            },
            entity,
        ));
    }

    fn release(entity: Entity, app: &mut App) {
        app.world_mut().trigger(Pointer::new(
            PointerId::Mouse,
            pointer_location(),
            Release {
                button: PointerButton::Primary,
                hit: dummy_hit(),
            },
            entity,
        ));
    }

    fn set_hovered(app: &mut App, entity: Entity) {
        let camera = app.world_mut().spawn(Camera::default()).id();
        let mut hover = EntityHashMap::default();
        hover.insert(entity, HitData::new(camera, 0.0, Some(Vec3::ZERO), None));
        app.world_mut()
            .resource_mut::<HoverMap>()
            .0
            .insert(PointerId::Mouse, hover);
    }

    fn advance_time(app: &mut App, ms: u64) {
        app.world_mut()
            .resource_mut::<Time<Real>>()
            .advance_by(Duration::from_millis(ms));
    }

    #[test]
    fn poll_matches_retail_begin_and_repeat_gates() {
        let mut deadline = 0;
        assert!(poll_repeat_deadline(&mut deadline, 100, true));
        assert_eq!(deadline, 110);
        assert!(!poll_repeat_deadline(&mut deadline, 114, false));
        assert!(poll_repeat_deadline(&mut deadline, 115, false));
        assert_eq!(deadline, 115);
    }

    #[test]
    fn ordinary_button_is_untouched_by_global_sideways_observers() {
        let mut app = test_app();
        let button = app.world_mut().spawn(Button).id();
        app.init_resource::<StepCount>();
        app.world_mut()
            .add_observer(|_: On<Step>, mut count: ResMut<StepCount>| count.0 += 1);

        press(button, &mut app);
        app.update();

        assert_eq!(app.world().resource::<StepCount>().0, 0);
        assert!(
            app.world()
                .get::<RetailSidewaysArrowTracking>(button)
                .is_none()
        );
    }

    #[test]
    fn gated_repress_tracks_and_repeats_while_held() {
        let mut app = test_app();
        let entity = app
            .world_mut()
            .spawn((
                RetailSidewaysArrow,
                RetailSidewaysArrowRepeat::default(),
                RetailSidewaysArrowHilite,
                Pickable::default(),
            ))
            .id();
        app.update();
        app.init_resource::<StepCount>();
        app.world_mut()
            .add_observer(move |step: On<Step>, mut count: ResMut<StepCount>| {
                if step.entity == entity {
                    count.0 += 1;
                }
            });
        set_hovered(&mut app, entity);
        advance_time(&mut app, 100 * 16);
        app.update();

        press(entity, &mut app);
        app.update();
        assert_eq!(app.world().resource::<StepCount>().0, 1);

        release(entity, &mut app);
        app.update();

        advance_time(&mut app, 2 * 16);
        press(entity, &mut app);
        app.update();
        assert_eq!(app.world().resource::<StepCount>().0, 1);
        assert!(
            app.world()
                .get::<RetailSidewaysArrowTracking>(entity)
                .is_some()
        );
        assert!(app.world().get::<Pressed>(entity).is_some());

        advance_time(&mut app, 13 * 16);
        app.update();
        assert_eq!(app.world().resource::<StepCount>().0, 2);
    }

    #[test]
    fn rapid_second_press_respects_persisted_deadline() {
        let mut app = test_app();
        let entity = app
            .world_mut()
            .spawn((
                RetailSidewaysArrow,
                RetailSidewaysArrowRepeat::default(),
                RetailSidewaysArrowHilite,
                Pickable::default(),
            ))
            .id();
        app.update();
        app.init_resource::<StepCount>();
        app.world_mut()
            .add_observer(move |step: On<Step>, mut count: ResMut<StepCount>| {
                if step.entity == entity {
                    count.0 += 1;
                }
            });
        set_hovered(&mut app, entity);
        advance_time(&mut app, 100 * 16);
        app.update();

        press(entity, &mut app);
        app.update();
        assert_eq!(app.world().resource::<StepCount>().0, 1);

        release(entity, &mut app);
        app.update();

        advance_time(&mut app, 2 * 16);
        press(entity, &mut app);
        app.update();
        assert_eq!(app.world().resource::<StepCount>().0, 1);

        advance_time(&mut app, 4 * 16);
        press(entity, &mut app);
        app.update();
        assert_eq!(app.world().resource::<StepCount>().0, 1);

        advance_time(&mut app, 12 * 16);
        press(entity, &mut app);
        app.update();
        assert_eq!(app.world().resource::<StepCount>().0, 2);
    }

    #[test]
    fn held_outside_advances_deadline_without_stepping() {
        let mut app = test_app();
        let entity = app
            .world_mut()
            .spawn((
                RetailSidewaysArrow,
                RetailSidewaysArrowRepeat::default(),
                RetailSidewaysArrowHilite,
                Pickable::default(),
            ))
            .id();
        app.update();
        app.init_resource::<StepCount>();
        app.world_mut()
            .add_observer(move |step: On<Step>, mut count: ResMut<StepCount>| {
                if step.entity == entity {
                    count.0 += 1;
                }
            });
        set_hovered(&mut app, entity);
        advance_time(&mut app, 100 * 16);
        app.update();

        press(entity, &mut app);
        app.update();
        assert_eq!(app.world().resource::<StepCount>().0, 1);

        app.world_mut().resource_mut::<HoverMap>().0.clear();
        advance_time(&mut app, 20 * 16);
        app.update();
        assert_eq!(app.world().resource::<StepCount>().0, 1);

        set_hovered(&mut app, entity);
        app.update();
        assert_eq!(app.world().resource::<StepCount>().0, 1);

        advance_time(&mut app, 5 * 16);
        app.update();
        assert_eq!(app.world().resource::<StepCount>().0, 2);
    }

    #[test]
    fn right_left_view_repeats_without_pressed_hilite() {
        let mut app = test_app();
        let entity = app
            .world_mut()
            .spawn((
                RetailSidewaysArrow,
                RetailSidewaysArrowRepeat::default(),
                Pickable::default(),
            ))
            .id();
        app.update();
        app.init_resource::<StepCount>();
        app.world_mut()
            .add_observer(move |step: On<Step>, mut count: ResMut<StepCount>| {
                if step.entity == entity {
                    count.0 += 1;
                }
            });
        set_hovered(&mut app, entity);
        advance_time(&mut app, 100 * 16);
        app.update();

        press(entity, &mut app);
        app.update();

        assert_eq!(app.world().resource::<StepCount>().0, 1);
        assert!(app.world().get::<Pressed>(entity).is_none());
        assert!(
            app.world()
                .get::<RetailSidewaysArrowTracking>(entity)
                .is_some()
        );
    }

    #[test]
    fn press_emits_step_and_release_does_not_emit_another() {
        let mut app = test_app();
        let entity = app
            .world_mut()
            .spawn((
                RetailSidewaysArrow,
                RetailSidewaysArrowRepeat::default(),
                RetailSidewaysArrowHilite,
                Pickable::default(),
            ))
            .id();
        app.update();
        app.init_resource::<StepCount>();
        app.world_mut()
            .add_observer(move |step: On<Step>, mut count: ResMut<StepCount>| {
                if step.entity == entity {
                    count.0 += 1;
                }
            });
        set_hovered(&mut app, entity);
        advance_time(&mut app, 100 * 16);
        app.update();

        press(entity, &mut app);
        app.update();
        assert_eq!(app.world().resource::<StepCount>().0, 1);
        assert!(app.world().get::<Pressed>(entity).is_some());

        release(entity, &mut app);
        app.update();
        assert_eq!(app.world().resource::<StepCount>().0, 1);
        assert!(app.world().get::<Pressed>(entity).is_none());
        assert!(
            app.world()
                .get::<RetailSidewaysArrowRepeat>(entity)
                .is_some()
        );
    }
}
