//! Recovered `TAmtBarCluster` family: wire existing left/right/value/bar children.
//!
//! Generator names those children and attaches this component. Industry/Rail
//! relocate the value control with the bar fill; Trader leaves Sell fixed.
//! Industry/Rail `+/-` halves emit [`ValueChange<i16>`] on the cluster root.
//! Trader keeps domain-owned left/right observers in the trade binder.

use super::retail_amount_bar::{
    INDUSTRY_AMOUNT_BAR, RetailAmountBarState, amount_bar_counter_offset,
};
use bevy::prelude::*;
use bevy::ui::UiSystems;
use bevy::ui_widgets::{Activate, ValueChange};

/// Recovered cluster specialization.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RetailAmountSelectorKind {
    #[default]
    Industry,
    Rail,
    Trader,
}

/// Structural links to recovered cluster children.
#[derive(Component, FromTemplate, Clone)]
pub struct RetailAmountSelector {
    pub kind: RetailAmountSelectorKind,
    pub decrease: Entity,
    pub increase: Entity,
    pub value: Entity,
    pub bar: Entity,
}

/// BSN helper: attach selector links resolved against `#Left`/`#Right`/`#Value`/`#Bar`.
pub fn retail_amount_selector(kind: RetailAmountSelectorKind) -> impl Scene {
    bsn! {
        RetailAmountSelector {
            kind: {kind},
            decrease: #Left,
            increase: #Right,
            value: #Value,
            bar: #Bar,
        }
    }
}

pub(super) fn register_amount_selector(app: &mut App) {
    app.add_observer(on_amount_selector_added).add_systems(
        PostUpdate,
        draw_amount_selector_counters.before(UiSystems::Prepare),
    );
}

fn on_amount_selector_added(
    event: On<Add, RetailAmountSelector>,
    selectors: Query<&RetailAmountSelector>,
    mut commands: Commands,
) {
    let Ok(selector) = selectors.get(event.entity) else {
        return;
    };
    // Trade binder still owns commodity-aware left/right stepping.
    if matches!(selector.kind, RetailAmountSelectorKind::Trader) {
        return;
    }
    let root = event.entity;
    let bar = selector.bar;
    let step = |delta: i16| {
        move |_: On<Activate>, bars: Query<&RetailAmountBarState>, mut commands: Commands| {
            let Ok(state) = bars.get(bar) else {
                return;
            };
            let next = (state.value + delta).clamp(0, state.range.max(0));
            if next == state.value {
                return;
            }
            commands.trigger(ValueChange {
                source: root,
                value: next,
                is_final: true,
            });
        }
    };
    commands.entity(selector.decrease).observe(step(-1));
    commands.entity(selector.increase).observe(step(1));
}

fn draw_amount_selector_counters(
    selectors: Query<&RetailAmountSelector>,
    bars: Query<Ref<RetailAmountBarState>>,
    bar_nodes: Query<&Node, With<RetailAmountBarState>>,
    mut counter_nodes: Query<&mut Node, Without<RetailAmountBarState>>,
) {
    for selector in &selectors {
        if matches!(selector.kind, RetailAmountSelectorKind::Trader) {
            continue;
        }
        let Ok(state) = bars.get(selector.bar) else {
            continue;
        };
        if !state.is_changed() {
            continue;
        }
        let geometry = INDUSTRY_AMOUNT_BAR.with_segments(state.range);
        let offset = amount_bar_counter_offset(geometry, state.value);
        let Ok(track) = bar_nodes.get(selector.bar) else {
            continue;
        };
        let (Val::Px(bar_left), Val::Px(bar_top)) = (track.left, track.top) else {
            continue;
        };
        let Ok(mut counter) = counter_nodes.get_mut(selector.value) else {
            continue;
        };
        counter.left = Val::Px(bar_left + offset.x);
        counter.top = Val::Px(bar_top + offset.y);
    }
}
