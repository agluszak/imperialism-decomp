//! Presentation-layer media. GStreamer stays behind `movie`; WAVE playback is Bevy audio.

use bevy::prelude::*;

mod movie;
mod music;
mod sfx;

pub(crate) use sfx::{RetailAudioHandles, play_cached_or_retail_sound};

pub(crate) struct ImperialismMediaPlugin;

impl Plugin for ImperialismMediaPlugin {
    fn build(&self, app: &mut App) {
        movie::ensure_initialized();
        app.init_resource::<sfx::RetailAudioHandles>()
            .add_observer(sfx::on_picture_button_activate);
        music::register(app);
    }
}
