//! Recovered `TSidewaysArrow` / `TRightLeftView` press-and-repeat input.
//!
//! Screens observe [`Step`]; this module owns retail timing and [`Pressed`] visuals.

use bevy::picking::events::{Cancel, DragEnd, Pointer, Press, Release};
use bevy::picking::hover::HoverMap;
use bevy::picking::pointer::{PointerButton, PointerId};
use bevy::prelude::*;
use bevy::ui::{InteractionDisabled, Pressed};

/// Marker for quantity arrows that act on press and repeat while held.
#[derive(Component, Clone, Copy, Debug, Default, Reflect)]
#[reflect(Component)]
pub struct RetailSidewaysArrow;

/// Semantic quantity step from a sideways arrow (not release-activated).
#[derive(Copy, Clone, Debug, PartialEq, EntityEvent, Reflect)]
#[reflect(Event)]
pub struct Step {
    pub entity: Entity,
}

#[derive(Component, Clone, Copy, Debug)]
struct RetailSidewaysArrowTracking {
    pointer_id: PointerId,
    repeat_deadline_tick: u32,
}

const TICKS_PER_REPEAT: u32 = 5;
const INITIAL_REPEAT_DELAY: u32 = 10;

pub(super) fn register_sideways_arrow(app: &mut App) {
    app.add_observer(on_sideways_arrow_press)
        .add_observer(on_sideways_arrow_release)
        .add_observer(on_sideways_arrow_cancel)
        .add_observer(on_sideways_arrow_drag_end)
        .add_systems(PreUpdate, repeat_sideways_arrows);
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
    commands.entity(entity).insert((
        Pressed,
        RetailSidewaysArrowTracking {
            pointer_id: press.pointer_id,
            repeat_deadline_tick: tick.saturating_add(INITIAL_REPEAT_DELAY),
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

fn repeat_sideways_arrows(
    time: Res<Time>,
    hover_map: Option<Res<HoverMap>>,
    disabled: Query<Has<InteractionDisabled>>,
    mut tracking: Query<(Entity, &mut RetailSidewaysArrowTracking)>,
    mut commands: Commands,
) {
    let Some(hover_map) = hover_map else {
        return;
    };
    let tick = retail_tick(time.as_ref());
    for (entity, mut state) in tracking.iter_mut() {
        if disabled.get(entity).unwrap_or(false) {
            commands
                .entity(entity)
                .remove::<(Pressed, RetailSidewaysArrowTracking)>();
            continue;
        }
        if !pointer_inside(entity, state.pointer_id, hover_map.as_ref()) {
            continue;
        }
        if advance_repeat_deadline(&mut state.repeat_deadline_tick, tick, false) {
            commands.trigger(Step { entity });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn subsequent_repeats_use_five_tick_gate() {
        let mut deadline = 50;
        assert!(!advance_repeat_deadline(&mut deadline, 54, false));
        assert!(advance_repeat_deadline(&mut deadline, 55, false));
        assert_eq!(deadline, 55);
    }
}
