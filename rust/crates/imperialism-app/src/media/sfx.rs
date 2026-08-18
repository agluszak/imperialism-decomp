//! One-shot retail WAVE playback through Bevy audio.
//!
//! `TSoundPlayer::PlaySoundEffect` is a volume gate plus a WAVE id, not a device graph.
//! Missing archives or ids are skipped, matching a failed `FindResourceA`. Slot 2 at 0
//! is silence (`preferenceValues[kSoundEffectsVolumePreference] == 0`).

use crate::AppState;
use crate::RetailAssetsResource;
use crate::ui::GamePreferences;
use bevy::audio::{AudioPlayer, AudioSource, PlaybackSettings, Volume};
use bevy::ecs::system::SystemParam;
use bevy::prelude::*;
use bevy::ui_widgets::{Activate, Button};
use imperialism_formats::{RetailAssets, SoundId};
use std::collections::HashMap;

const SOUND_VOLUME_SCALE: f32 = 100.0;

#[derive(Component)]
struct SoundEffect;

#[derive(Resource, Default)]
pub(crate) struct RetailAudioHandles(HashMap<SoundId, Handle<AudioSource>>);

#[derive(SystemParam)]
pub(crate) struct RetailAudioAssets<'w> {
    retail_assets: Res<'w, RetailAssetsResource>,
    sources: ResMut<'w, Assets<AudioSource>>,
    handles: ResMut<'w, RetailAudioHandles>,
    prefs: Res<'w, GamePreferences>,
    app_state: Option<Res<'w, State<AppState>>>,
}

impl RetailAudioAssets<'_> {
    pub(crate) fn play(&mut self, commands: &mut Commands, sound: SoundId) {
        if movie_blocks_sfx(self.app_state.as_ref().map(|state| *state.get())) {
            return;
        }
        play_cached_or_retail_sound(
            commands,
            Some(self.retail_assets.assets()),
            &mut self.sources,
            &mut self.handles,
            self.prefs.sound_volume_percent(),
            sound,
        );
    }
}

/// Retail tears DirectSound down for AVI audio. Keep game WAVE silent while a movie plays.
fn movie_blocks_sfx(state: Option<AppState>) -> bool {
    state == Some(AppState::OpeningCinematic)
}

fn stop_sfx_for_movie(mut commands: Commands, playback: Query<Entity, With<SoundEffect>>) {
    for entity in &playback {
        commands.entity(entity).despawn();
    }
}

pub(super) fn register(app: &mut App) {
    app.init_resource::<RetailAudioHandles>()
        .add_observer(on_picture_button_activate)
        .add_systems(OnEnter(AppState::OpeningCinematic), stop_sfx_for_movie);
}

fn play_cached_or_retail_sound(
    commands: &mut Commands,
    retail: Option<&RetailAssets>,
    sources: &mut Assets<AudioSource>,
    handles: &mut RetailAudioHandles,
    volume_percent: i16,
    sound: SoundId,
) {
    let Some(volume) = linear_volume(volume_percent) else {
        return;
    };
    let Some(source) = audio_source(retail, sources, handles, sound) else {
        return;
    };
    commands.spawn((
        SoundEffect,
        AudioPlayer::new(source),
        PlaybackSettings::DESPAWN.with_volume(Volume::Linear(volume)),
    ));
}

pub(crate) fn on_picture_button_activate(
    activate: On<Activate>,
    buttons: Query<(), With<Button>>,
    mut commands: Commands,
    mut audio: RetailAudioAssets,
) {
    if !buttons.contains(activate.entity) {
        return;
    }
    audio.play(&mut commands, SoundId::UI_CLICK);
}

fn audio_source(
    retail: Option<&RetailAssets>,
    sources: &mut Assets<AudioSource>,
    handles: &mut RetailAudioHandles,
    sound: SoundId,
) -> Option<Handle<AudioSource>> {
    if let Some(handle) = handles.0.get(&sound) {
        return Some(handle.clone());
    }
    let bytes = retail?.sound(sound).ok()?;
    let handle = sources.add(AudioSource {
        bytes: bytes.into(),
    });
    handles.0.insert(sound, handle.clone());
    Some(handle)
}

fn linear_volume(percent: i16) -> Option<f32> {
    if percent <= 0 {
        return None;
    }
    Some((f32::from(percent) / SOUND_VOLUME_SCALE).clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevy::asset::AssetPlugin;

    fn pcm_wav() -> Vec<u8> {
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&36u32.to_le_bytes());
        wav.extend_from_slice(b"WAVE");
        wav.extend_from_slice(b"fmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&8000u32.to_le_bytes());
        wav.extend_from_slice(&16000u32.to_le_bytes());
        wav.extend_from_slice(&2u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&4u32.to_le_bytes());
        wav.extend_from_slice(&[0, 0, 0, 0]);
        wav
    }

    fn seed_click(world: &mut World) {
        let source = world
            .resource_mut::<Assets<AudioSource>>()
            .add(AudioSource {
                bytes: pcm_wav().into(),
            });
        world
            .resource_mut::<RetailAudioHandles>()
            .0
            .insert(SoundId::UI_CLICK, source);
    }

    fn audio_app() -> App {
        let mut app = App::new();
        app.add_plugins((MinimalPlugins, AssetPlugin::default()))
            .init_asset::<AudioSource>()
            .init_resource::<RetailAudioHandles>()
            .init_resource::<GamePreferences>();
        app
    }

    fn play_click(app: &mut App, volume_percent: i16) {
        let mut sources = app
            .world_mut()
            .remove_resource::<Assets<AudioSource>>()
            .unwrap();
        let mut handles = app
            .world_mut()
            .remove_resource::<RetailAudioHandles>()
            .unwrap();
        play_cached_or_retail_sound(
            &mut app.world_mut().commands(),
            None,
            &mut sources,
            &mut handles,
            volume_percent,
            SoundId::UI_CLICK,
        );
        app.world_mut().insert_resource(sources);
        app.world_mut().insert_resource(handles);
        app.world_mut().flush();
    }

    fn spawned_volumes(world: &mut World) -> Vec<f32> {
        world
            .query::<(&PlaybackSettings, &SoundEffect)>()
            .iter(world)
            .map(|(settings, _)| settings.volume.to_linear())
            .collect()
    }

    #[test]
    fn muted_slot_2_does_not_spawn_a_player() {
        let mut app = audio_app();
        seed_click(app.world_mut());
        play_click(&mut app, 0);
        assert!(spawned_volumes(app.world_mut()).is_empty());
    }

    #[test]
    fn slot_2_percent_scales_the_one_shot_player() {
        let mut app = audio_app();
        seed_click(app.world_mut());
        play_click(&mut app, 50);
        assert_eq!(spawned_volumes(app.world_mut()), [0.5]);
    }

    #[test]
    fn missing_wave_does_not_strand() {
        let mut app = audio_app();
        play_click(&mut app, 100);
        assert!(spawned_volumes(app.world_mut()).is_empty());
    }

    #[test]
    fn opening_cinematic_blocks_new_sfx() {
        assert!(movie_blocks_sfx(Some(AppState::OpeningCinematic)));
        assert!(!movie_blocks_sfx(Some(AppState::MainMenu)));
        assert!(!movie_blocks_sfx(None));
    }

    #[test]
    fn movie_enter_despawns_existing_one_shots() {
        let mut app = audio_app();
        seed_click(app.world_mut());
        play_click(&mut app, 100);
        assert_eq!(spawned_volumes(app.world_mut()).len(), 1);
        app.add_systems(Update, stop_sfx_for_movie);
        app.update();
        assert!(spawned_volumes(app.world_mut()).is_empty());
    }
}
