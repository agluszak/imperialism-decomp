//! Presentation-only playback for the locally imported retail audio pack.
//!
//! The retail main-menu cue is known exactly: `TViewMgr::HandleTurnEventDialogFactorySlotF8`
//! installs cue 6, and `TSoundPlayer` forwards that value unchanged to the CD track index.
//! The generic UI click sound is likewise recovered as WAVE resource `0x1b58` (7000) in
//! `TClickZone` and the random-map setup controls. No random-setup music transition or
//! playback policy is encoded here without equivalent source evidence.

use crate::launcher::RetailAssetPackResource;
use bevy::asset::Assets;
use bevy::audio::{AudioPlayer, AudioSource, PlaybackSettings};
use bevy::ecs::system::SystemParam;
use bevy::prelude::*;
use imperialism_formats::{CachedRetailObject, ResourceIdentifier};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::PathBuf;

const ENGLISH_LANGUAGE: u32 = 1033;

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

    fn relative_path(self) -> String {
        format!("MUSIC/Track{:02}.ogg", self.0)
    }
}

impl fmt::Display for RetailMusicTrack {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Track{:02}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("retail music track {track} is outside the imported Track02-Track12 range")]
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

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetailAudioPlayback {
    pub sequence: u64,
    pub cue: AudioCue,
}

#[derive(Message, Clone, Copy, Debug, Eq, PartialEq)]
pub struct AudioCueQueued {
    pub sequence: u64,
    pub cue: AudioCue,
    pub entity: Entity,
}

#[derive(Message, Debug)]
pub struct AudioCueFailed {
    pub sequence: u64,
    pub cue: AudioCue,
    pub error: RetailAudioError,
}

#[derive(Debug, thiserror::Error)]
pub enum RetailAudioError {
    #[error("retail asset pack has no English {0}")]
    MissingWave(RetailWaveId),
    #[error("retail asset pack has no {0}")]
    MissingMusic(RetailMusicTrack),
    #[error("{asset} resolved to .{actual_extension}, expected .{expected_extension}")]
    UnexpectedObjectExtension {
        asset: RetailAudioAsset,
        actual_extension: String,
        expected_extension: &'static str,
    },
    #[error("could not read imported {asset} object {}: {source}", path.display())]
    ReadObject {
        asset: RetailAudioAsset,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Resource, Default)]
struct RetailAudioHandles(HashMap<RetailAudioAsset, Handle<AudioSource>>);

#[derive(Resource, Default)]
struct NextAudioSequence(u64);

pub struct RetailAudioPlugin;

impl Plugin for RetailAudioPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<Assets<AudioSource>>()
            .init_resource::<RetailAudioHandles>()
            .init_resource::<NextAudioSequence>()
            .add_message::<AudioCue>()
            .add_message::<AudioCueQueued>()
            .add_message::<AudioCueFailed>()
            .add_systems(Update, play_audio_cues);
    }
}

#[derive(SystemParam)]
struct RetailAudioResources<'w> {
    pack: Res<'w, RetailAssetPackResource>,
    handles: ResMut<'w, RetailAudioHandles>,
    sources: ResMut<'w, Assets<AudioSource>>,
    next_sequence: ResMut<'w, NextAudioSequence>,
}

pub fn resolve_retail_audio_path(
    pack: &RetailAssetPackResource,
    asset: RetailAudioAsset,
) -> Result<PathBuf, RetailAudioError> {
    let object = resolve_retail_audio_object(pack, asset)?;
    Ok(pack.cache_root().join(object.relative_path()))
}

fn resolve_retail_audio_object(
    pack: &RetailAssetPackResource,
    asset: RetailAudioAsset,
) -> Result<&CachedRetailObject, RetailAudioError> {
    let (object, expected_extension) = match asset {
        RetailAudioAsset::Wave(wave) => {
            let resource = pack
                .manifest()
                .resources
                .iter()
                .find(|resource| {
                    resource.source_path == "Data/wave.gob"
                        && matches!(
                            &resource.resource_type,
                            ResourceIdentifier::Named(name) if name == "WAVE"
                        )
                        && resource.resource_name
                            == ResourceIdentifier::Numeric(u32::from(wave.get()))
                        && resource.language == ENGLISH_LANGUAGE
                })
                .ok_or(RetailAudioError::MissingWave(wave))?;
            (&resource.object, "wav")
        }
        RetailAudioAsset::Music(track) => {
            let expected_path = track.relative_path();
            let standalone = pack
                .manifest()
                .music
                .iter()
                .find(|standalone| standalone.relative_path == expected_path)
                .ok_or(RetailAudioError::MissingMusic(track))?;
            (&standalone.object, "ogg")
        }
    };
    if object.extension != expected_extension {
        return Err(RetailAudioError::UnexpectedObjectExtension {
            asset,
            actual_extension: object.extension.clone(),
            expected_extension,
        });
    }
    Ok(object)
}

fn load_retail_audio_handle(
    pack: &RetailAssetPackResource,
    asset: RetailAudioAsset,
    handles: &mut RetailAudioHandles,
    sources: &mut Assets<AudioSource>,
) -> Result<Handle<AudioSource>, RetailAudioError> {
    if let Some(handle) = handles.0.get(&asset) {
        return Ok(handle.clone());
    }
    let path = resolve_retail_audio_path(pack, asset)?;
    let bytes = fs::read(&path).map_err(|source| RetailAudioError::ReadObject {
        asset,
        path: path.clone(),
        source,
    })?;
    let handle = sources.add(AudioSource {
        bytes: bytes.into(),
    });
    handles.0.insert(asset, handle.clone());
    Ok(handle)
}

fn play_audio_cues(
    mut commands: Commands,
    mut cues: MessageReader<AudioCue>,
    mut queued: MessageWriter<AudioCueQueued>,
    mut failed: MessageWriter<AudioCueFailed>,
    mut resources: RetailAudioResources,
) {
    for cue in cues.read().copied() {
        let sequence = resources.next_sequence.0;
        resources.next_sequence.0 = resources.next_sequence.0.wrapping_add(1);
        match load_retail_audio_handle(
            &resources.pack,
            cue.asset,
            &mut resources.handles,
            &mut resources.sources,
        ) {
            Ok(handle) => {
                let settings = match cue.playback {
                    AudioCuePlayback::Once => PlaybackSettings::DESPAWN,
                    AudioCuePlayback::Loop => PlaybackSettings::LOOP,
                };
                let entity = commands
                    .spawn((
                        AudioPlayer::new(handle),
                        settings,
                        RetailAudioPlayback { sequence, cue },
                    ))
                    .id();
                queued.write(AudioCueQueued {
                    sequence,
                    cue,
                    entity,
                });
            }
            Err(error) => {
                failed.write(AudioCueFailed {
                    sequence,
                    cue,
                    error,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_formats::{
        ImportedRetailAssets, RetailAssetPackManifest, RetailResourceAsset, RetailStandaloneAsset,
    };
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_cache() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("imperialism-audio-{}-{nonce}", std::process::id()))
    }

    fn object(root: &Path, digest_byte: char, extension: &str, bytes: &[u8]) -> CachedRetailObject {
        let object = CachedRetailObject {
            sha256: digest_byte.to_string().repeat(64),
            byte_length: bytes.len() as u64,
            extension: extension.to_owned(),
        };
        let path = root.join(object.relative_path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
        object
    }

    fn pack(include_wave: bool, include_music: bool) -> (RetailAssetPackResource, PathBuf) {
        let root = temporary_cache();
        fs::create_dir_all(&root).unwrap();
        let mut resources = Vec::new();
        if include_wave {
            let wave = object(&root, 'a', "wav", b"synthetic wave bytes");
            resources.push(RetailResourceAsset {
                source_path: "Data/wave.gob".to_owned(),
                picture_library: None,
                resource_type: ResourceIdentifier::Named("WAVE".to_owned()),
                resource_name: ResourceIdentifier::Numeric(u32::from(RETAIL_UI_CLICK_WAVE.get())),
                language: ENGLISH_LANGUAGE,
                retail_byte_length: wave.byte_length,
                retail_sha256: "c".repeat(64),
                object: wave,
            });
        }
        let mut music = Vec::new();
        if include_music {
            music.push(RetailStandaloneAsset {
                relative_path: "MUSIC/Track02.ogg".to_owned(),
                object: object(&root, 'b', "ogg", b"synthetic ogg bytes"),
            });
        }
        let imported = ImportedRetailAssets {
            cache_root: root.clone(),
            pack_dir: root.join("packs/test"),
            manifest: RetailAssetPackManifest {
                cache_key: "d".repeat(64),
                logical_resolution: [640, 480],
                bitmap_lookup_is_name_then_numeric: true,
                sources: Vec::new(),
                resources,
                strings: Vec::new(),
                fonts: Vec::new(),
                music,
            },
        };
        (RetailAssetPackResource::new(imported), root)
    }

    fn audio_app(pack: RetailAssetPackResource) -> App {
        let mut app = App::new();
        app.insert_resource(pack).add_plugins(RetailAudioPlugin);
        app
    }

    #[test]
    fn validates_the_imported_music_track_range() {
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

    #[test]
    fn resolves_wave_and_music_objects_by_typed_retail_identity() {
        let (pack, root) = pack(true, true);
        let wave =
            resolve_retail_audio_path(&pack, RetailAudioAsset::Wave(RETAIL_UI_CLICK_WAVE)).unwrap();
        let track = resolve_retail_audio_path(
            &pack,
            RetailAudioAsset::Music(RetailMusicTrack::new(2).unwrap()),
        )
        .unwrap();

        assert_eq!(wave.extension().unwrap(), "wav");
        assert_eq!(track.extension().unwrap(), "ogg");
        assert!(wave.is_file());
        assert!(track.is_file());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn playback_entities_and_notifications_preserve_message_order() {
        let (pack, root) = pack(true, true);
        let mut app = audio_app(pack);
        let wave = AudioCue::sound_effect(RETAIL_UI_CLICK_WAVE);
        let music = AudioCue::music(RetailMusicTrack::new(2).unwrap(), AudioCuePlayback::Loop);
        app.world_mut().write_message(wave).unwrap();
        app.world_mut().write_message(music).unwrap();

        app.update();

        let world = app.world_mut();
        let mut played = world
            .query::<(&RetailAudioPlayback, &AudioPlayer<AudioSource>)>()
            .iter(world)
            .map(|(played, player)| (played.sequence, played.cue, player.0.clone()))
            .collect::<Vec<_>>();
        played.sort_by_key(|row| row.0);
        assert_eq!(
            played.iter().map(|row| row.1).collect::<Vec<_>>(),
            vec![wave, music]
        );
        let sources = world.resource::<Assets<AudioSource>>();
        assert!(played.iter().all(|row| sources.get(&row.2).is_some()));
        assert_eq!(world.resource::<Messages<AudioCueQueued>>().len(), 2);

        drop(app);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_cue_reports_a_typed_error_without_spawning_a_playback_entity() {
        let (pack, root) = pack(false, false);
        let mut app = audio_app(pack);
        app.world_mut()
            .write_message(AudioCue::sound_effect(RETAIL_UI_CLICK_WAVE))
            .unwrap();

        app.update();

        assert_eq!(app.world().resource::<Messages<AudioCueFailed>>().len(), 1);
        let world = app.world_mut();
        let mut playbacks = world.query_filtered::<Entity, With<RetailAudioPlayback>>();
        assert_eq!(playbacks.iter(world).count(), 0);

        drop(app);
        fs::remove_dir_all(root).unwrap();
    }
}
