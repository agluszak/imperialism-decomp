//! Presentation-layer movie playback. GStreamer stays behind this module.

use bevy::prelude::*;

mod movie;

pub(crate) struct ImperialismMediaPlugin;

impl Plugin for ImperialismMediaPlugin {
    fn build(&self, _app: &mut App) {
        movie::ensure_initialized();
    }
}
