//! Presentation-layer media. GStreamer stays behind `movie`; WAVE playback is Bevy audio.

use bevy::prelude::*;

mod movie;
mod music;
mod sfx;

pub(crate) use movie::{MovieBackend, rgba_frame_to_image};
pub(crate) use music::{
    MusicDirector, play_credits_music, play_host_screen_music, play_load_save_music,
};
pub(crate) use sfx::RetailAudioAssets;

pub(crate) struct ImperialismMediaPlugin;

impl Plugin for ImperialismMediaPlugin {
    fn build(&self, app: &mut App) {
        movie::ensure_initialized();
        sfx::register(app);
        music::register(app);
    }
}
