//! Presentation-layer media. GStreamer stays behind `movie`; WAVE playback is Bevy audio.

use crate::AppState;
use bevy::prelude::*;

mod movie;
mod music;
mod sfx;

pub(crate) use movie::{MovieBackend, rgba_frame_to_image};
pub(crate) use music::MusicDirector;
pub(crate) use sfx::RetailAudioAssets;

pub(crate) struct ImperialismMediaPlugin;

impl Plugin for ImperialismMediaPlugin {
    fn build(&self, app: &mut App) {
        movie::ensure_initialized();
        app.init_resource::<sfx::RetailAudioHandles>()
            .add_observer(sfx::on_picture_button_activate)
            .add_systems(OnEnter(AppState::OpeningCinematic), sfx::stop_sfx_for_movie);
        music::register(app);
    }
}
