//! Presentation-only playback for direct retail audio assets.
//!
//! The retail main-menu cue is known exactly: `TViewMgr::HandleTurnEventDialogFactorySlotF8`
//! installs cue 6, and `TSoundPlayer` forwards that value unchanged to the CD track index.
//! The generic UI click sound is likewise recovered as WAVE resource `0x1b58` (7000) in
//! `TClickZone` and the random-map setup controls. No random-setup music transition or
//! playback policy is encoded here without equivalent source evidence.

use crate::launcher::RetailAssetsResource;
use bevy::asset::Assets;
use bevy::audio::{AudioPlayer, AudioSource, PlaybackSettings};
use bevy::ecs::system::SystemParam;
use bevy::log::warn;
use bevy::prelude::*;
use imperialism_formats::RetailAssetError;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RetailWaveId(u16);

impl RetailWaveId {
    pub const fn new(resource_id: u16) -> Self {
        Self(resource_id)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for RetailWaveId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "WAVE {}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RetailMusicTrack(u8);

impl RetailMusicTrack {
    pub const fn new(track: u8) -> Result<Self, RetailMusicTrackError> {
        if track >= 2 && track <= 12 {
            Ok(Self(track))
        } else {
            Err(RetailMusicTrackError { track })
        }
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

impl fmt::Display for RetailMusicTrack {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Track{:02}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("retail music track {track} is outside the supported Track02-Track12 range")]
pub struct RetailMusicTrackError {
    pub track: u8,
}

/// The recovered click sound used by ordinary retail UI controls.
pub const RETAIL_UI_CLICK_WAVE: RetailWaveId = RetailWaveId(0x1b58);

/// The sole music cue installed by the recovered retail main-menu setup path.
pub const RETAIL_MAIN_MENU_MUSIC: RetailMusicTrack = RetailMusicTrack(6);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RetailAudioAsset {
    Wave(RetailWaveId),
    Music(RetailMusicTrack),
}

impl fmt::Display for RetailAudioAsset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wave(wave) => wave.fmt(formatter),
            Self::Music(track) => track.fmt(formatter),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioCuePlayback {
    Once,
    Loop,
}

#[derive(Message, Clone, Copy, Debug, Eq, PartialEq)]
pub struct AudioCue {
    pub asset: RetailAudioAsset,
    pub playback: AudioCuePlayback,
}

impl AudioCue {
    pub const fn sound_effect(wave: RetailWaveId) -> Self {
        Self {
            asset: RetailAudioAsset::Wave(wave),
            playback: AudioCuePlayback::Once,
        }
    }

    pub const fn music(track: RetailMusicTrack, playback: AudioCuePlayback) -> Self {
        Self {
            asset: RetailAudioAsset::Music(track),
            playback,
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum RetailAudioError {
    #[error("could not load retail {asset}: {source}")]
    RetailAsset {
        asset: RetailAudioAsset,
        #[source]
        source: RetailAssetError,
    },
    #[error("could not read retail music {track} from {}: {source}", path.display())]
    ReadMusic {
        track: RetailMusicTrack,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Resource, Default)]
struct RetailAudioHandles(HashMap<RetailAudioAsset, Handle<AudioSource>>);

pub struct RetailAudioPlugin;

impl Plugin for RetailAudioPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<Assets<AudioSource>>()
            .init_resource::<RetailAudioHandles>()
            .add_message::<AudioCue>()
            .add_systems(Update, play_audio_cues);
    }
}

#[derive(SystemParam)]
struct RetailAudioResources<'w> {
    retail_assets: Res<'w, RetailAssetsResource>,
    handles: ResMut<'w, RetailAudioHandles>,
    sources: ResMut<'w, Assets<AudioSource>>,
}

fn load_retail_audio_handle(
    retail_assets: &RetailAssetsResource,
    asset: RetailAudioAsset,
    handles: &mut RetailAudioHandles,
    sources: &mut Assets<AudioSource>,
) -> Result<Handle<AudioSource>, RetailAudioError> {
    if let Some(handle) = handles.0.get(&asset) {
        return Ok(handle.clone());
    }
    let bytes = match asset {
        RetailAudioAsset::Wave(wave) => retail_assets
            .assets()
            .wave_bytes(wave.get())
            .map_err(|source| RetailAudioError::RetailAsset { asset, source })?
            .to_vec(),
        RetailAudioAsset::Music(track) => {
            let path = retail_assets
                .assets()
                .music_path(track.get())
                .map_err(|source| RetailAudioError::RetailAsset { asset, source })?;
            fs::read(&path).map_err(|source| RetailAudioError::ReadMusic {
                track,
                path,
                source,
            })?
        }
    };
    let handle = sources.add(AudioSource {
        bytes: bytes.into(),
    });
    handles.0.insert(asset, handle.clone());
    Ok(handle)
}

fn play_audio_cues(
    mut commands: Commands,
    mut cues: MessageReader<AudioCue>,
    mut resources: RetailAudioResources,
) {
    for cue in cues.read().copied() {
        match load_retail_audio_handle(
            &resources.retail_assets,
            cue.asset,
            &mut resources.handles,
            &mut resources.sources,
        ) {
            Ok(handle) => {
                let settings = match cue.playback {
                    AudioCuePlayback::Once => PlaybackSettings::DESPAWN,
                    AudioCuePlayback::Loop => PlaybackSettings::LOOP,
                };
                commands.spawn((AudioPlayer::new(handle), settings));
            }
            Err(error) => {
                warn!("could not play retail {}: {error}", cue.asset);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_the_supported_music_track_range() {
        assert_eq!(RetailMusicTrack::new(2).unwrap().get(), 2);
        assert_eq!(RetailMusicTrack::new(12).unwrap().get(), 12);
        assert_eq!(
            RetailMusicTrack::new(1).unwrap_err(),
            RetailMusicTrackError { track: 1 }
        );
        assert_eq!(
            RetailMusicTrack::new(13).unwrap_err(),
            RetailMusicTrackError { track: 13 }
        );
    }
}
