//! Recovered `TSidewaysArrow` / `TRightLeftView` press-and-repeat input.
//!
//! Screens observe [`Step`]; this module owns retail timing and [`Pressed`] visuals.

use bevy::picking::PickingSystems;
use bevy::picking::events::{Cancel, DragEnd, Pointer, Press, Release};
use bevy::picking::hover::HoverMap;
use bevy::picking::pointer::{PointerButton, PointerId};
use bevy::prelude::*;
use bevy::ui::{InteractionDisabled, Pressed};

/// Marker for quantity arrows that act on press and repeat while held.
#[derive(Component, Clone, Copy, Debug, Default, Reflect)]
#[reflect(Component)]
pub struct RetailSidewaysArrow;

/// Retail `repeatDeadlineTick` survives mouse releases on the control.
#[derive(Component, Clone, Copy, Debug, Default)]
struct RetailSidewaysArrowRepeat {
    repeat_deadline_tick: u32,
}

/// Semantic quantity step from a sideways arrow (not release-activated).
#[derive(Copy, Clone, Debug, PartialEq, EntityEvent, Reflect)]
#[reflect(Event)]
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
    app.add_observer(on_sideways_arrow_added)
        .add_observer(on_sideways_arrow_press)
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

fn on_sideways_arrow_added(add: On<Add, RetailSidewaysArrow>, mut commands: Commands) {
    commands
        .entity(add.entity)
        .insert(RetailSidewaysArrowRepeat::default());
}

fn retail_tick(time: &Time) -> u32 {
    (time.elapsed().as_millis() / 16) as u32
}

fn pointer_inside(entity: Entity, pointer_id: PointerId, hover_map: &HoverMap) -> bool {
    hover_map
        .0
        .get(&pointer_id)
        .is_some_and(|hits| hits.contains_key(&entity))
}

fn advance_repeat_deadline(deadline: &mut u32, tick: u32, initial_hold: bool) -> bool {
    if tick < deadline.saturating_add(TICKS_PER_REPEAT) {
        return false;
    }
    *deadline = tick;
    if initial_hold {
        *deadline = tick.saturating_add(INITIAL_REPEAT_DELAY);
    }
    true
}

fn on_sideways_arrow_press(
    mut press: On<Pointer<Press>>,
    time: Res<Time>,
    disabled: Query<Has<InteractionDisabled>>,
    tracking: Query<(), With<RetailSidewaysArrowTracking>>,
    mut repeats: Query<&mut RetailSidewaysArrowRepeat>,
    mut commands: Commands,
) {
    if press.event.button != PointerButton::Primary {
        return;
    }
    let entity = press.entity;
    if disabled.get(entity).unwrap_or(false) || tracking.get(entity).is_ok() {
        return;
    }
    press.propagate(false);
    let tick = retail_tick(time.as_ref());
    if let Ok(mut repeat) = repeats.get_mut(entity) {
        repeat.repeat_deadline_tick = tick.saturating_add(INITIAL_REPEAT_DELAY);
    }
    commands.entity(entity).insert((
        Pressed,
        RetailSidewaysArrowTracking {
            pointer_id: press.pointer_id,
        },
    ));
    commands.trigger(Step { entity });
}

fn clear_sideways_arrow_hold(
    entity: Entity,
    pointer_id: PointerId,
    tracking: &Query<&RetailSidewaysArrowTracking>,
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
        .remove::<(Pressed, RetailSidewaysArrowTracking)>();
    true
}

fn on_sideways_arrow_release(
    mut release: On<Pointer<Release>>,
    tracking: Query<&RetailSidewaysArrowTracking>,
    mut commands: Commands,
) {
    if clear_sideways_arrow_hold(release.entity, release.pointer_id, &tracking, &mut commands) {
        release.propagate(false);
    }
}

fn on_sideways_arrow_cancel(
    mut cancel: On<Pointer<Cancel>>,
    tracking: Query<&RetailSidewaysArrowTracking>,
    mut commands: Commands,
) {
    if clear_sideways_arrow_hold(cancel.entity, cancel.pointer_id, &tracking, &mut commands) {
        cancel.propagate(false);
    }
}

fn on_sideways_arrow_drag_end(
    mut drag_end: On<Pointer<DragEnd>>,
    tracking: Query<&RetailSidewaysArrowTracking>,
    mut commands: Commands,
) {
    if clear_sideways_arrow_hold(
        drag_end.entity,
        drag_end.pointer_id,
        &tracking,
        &mut commands,
    ) {
        drag_end.propagate(false);
    }
}

fn sync_sideways_arrow_pressed(
    hover_map: Option<Res<HoverMap>>,
    tracking: Query<(Entity, &RetailSidewaysArrowTracking)>,
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
    time: Res<Time>,
    hover_map: Option<Res<HoverMap>>,
    disabled: Query<Has<InteractionDisabled>>,
    mut tracking: Query<(
        Entity,
        &RetailSidewaysArrowTracking,
        &mut RetailSidewaysArrowRepeat,
    )>,
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
                .remove::<(Pressed, RetailSidewaysArrowTracking)>();
            continue;
        }
        if !pointer_inside(entity, state.pointer_id, hover_map.as_ref()) {
            continue;
        }
        if advance_repeat_deadline(&mut repeat.repeat_deadline_tick, tick, false) {
            commands.trigger(Step { entity });
        }
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
    use bevy::ui_widgets::ButtonPlugin;

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

    fn press(entity: Entity, app: &mut App) {
        app.world_mut().trigger(Pointer::new(
            PointerId::Mouse,
            bevy::picking::pointer::Location {
                target: bevy::camera::NormalizedRenderTarget::None {
                    width: 1,
                    height: 1,
                },
                position: Vec2::ZERO,
            },
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
            bevy::picking::pointer::Location {
                target: bevy::camera::NormalizedRenderTarget::None {
                    width: 1,
                    height: 1,
                },
                position: Vec2::ZERO,
            },
            Release {
                button: PointerButton::Primary,
                hit: dummy_hit(),
            },
            entity,
        ));
    }

    #[test]
    fn repeat_timing_matches_retail_gate() {
        let mut deadline = 0;
        let tick = 20;
        assert!(advance_repeat_deadline(&mut deadline, tick, true));
        assert_eq!(deadline, tick + INITIAL_REPEAT_DELAY);
        assert!(!advance_repeat_deadline(
            &mut deadline,
            tick + INITIAL_REPEAT_DELAY + TICKS_PER_REPEAT - 1,
            false
        ));
        assert!(advance_repeat_deadline(
            &mut deadline,
            tick + INITIAL_REPEAT_DELAY + TICKS_PER_REPEAT,
            false
        ));
        assert_eq!(deadline, tick + INITIAL_REPEAT_DELAY + TICKS_PER_REPEAT);
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

    #[test]
    fn press_emits_step_and_release_does_not_emit_another() {
        let mut app = test_app();
        let entity = app
            .world_mut()
            .spawn((RetailSidewaysArrow, Pickable::default()))
            .id();
        app.init_resource::<StepCount>();
        app.world_mut()
            .add_observer(move |step: On<Step>, mut count: ResMut<StepCount>| {
                if step.entity == entity {
                    count.0 += 1;
                }
            });
        set_hovered(&mut app, entity);
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

    #[test]
    fn held_outside_unhighlights_and_stops_repeat_until_reenter() {
        let mut app = test_app();
        let entity = app
            .world_mut()
            .spawn((RetailSidewaysArrow, Pickable::default()))
            .id();
        app.update();
        set_hovered(&mut app, entity);

        press(entity, &mut app);
        app.update();
        assert!(app.world().get::<Pressed>(entity).is_some());

        app.world_mut().resource_mut::<HoverMap>().0.clear();
        app.update();
        assert!(app.world().get::<Pressed>(entity).is_none());
        assert!(
            app.world()
                .get::<RetailSidewaysArrowTracking>(entity)
                .is_some()
        );

        let camera = app.world_mut().spawn(Camera::default()).id();
        let mut hover = EntityHashMap::default();
        hover.insert(entity, HitData::new(camera, 0.0, Some(Vec3::ZERO), None));
        app.world_mut()
            .resource_mut::<HoverMap>()
            .0
            .insert(PointerId::Mouse, hover);
        app.update();
        assert!(app.world().get::<Pressed>(entity).is_some());
    }
}
