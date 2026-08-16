use bevy::prelude::*;
use imperialism_core::CivilianUnitId;

/// Transient civilian selection on the strategic map.
#[derive(Component, Default)]
pub(crate) struct StrategicSelection(pub(crate) Option<CivilianUnitId>);

pub(crate) fn register(_app: &mut App) {}
