//! Retail CD-cue policy above one Bevy sink.
//!
//! `TSoundPlayer` is game policy: active/pending cues, fade-before-switch, a pool, and a
//! remaining list sampled without replacement. Core turn boundaries consume retail's shared
//! gameplay CRT draw; this director keeps only the presentation-side cue selection state.

use crate::AppState;
use crate::RetailAssetsResource;
use crate::ui::GamePreferences;
use bevy::audio::{
    AudioPlayer, AudioSink, AudioSinkPlayback, AudioSource, PlaybackSettings, Volume,
};
use bevy::prelude::*;
use imperialism_formats::{MusicTrack, RetailAssets};
use std::collections::HashMap;
use std::fs;

const MUSIC_VOLUME_SCALE: f32 = 255.0;
const TICK16_MS: u128 = 16;

#[derive(Component)]
struct MusicPlayback {
    track: MusicTrack,
}

#[derive(Resource, Default)]
struct MusicTrackHandles(HashMap<MusicTrack, Handle<AudioSource>>);

#[derive(Clone, Copy, Debug)]
struct MusicFade {
    start_tick16: u32,
}

#[derive(Resource, Debug)]
pub(crate) struct MusicDirector {
    active: Option<MusicTrack>,
    pending: Option<MusicTrack>,
    pool: Vec<MusicTrack>,
    remaining: Vec<MusicTrack>,
    fade: Option<MusicFade>,
    /// Presentation-side cue selection after core has consumed retail's gameplay draw.
    rng: u32,
}

impl Default for MusicDirector {
    fn default() -> Self {
        Self {
            active: None,
            pending: None,
            pool: Vec::new(),
            remaining: Vec::new(),
            fade: None,
            rng: 1,
        }
    }
}

impl MusicDirector {
    pub(crate) fn output_volume(&self, now_tick16: u32, preference: i16) -> i16 {
        if preference <= 0 {
            return 0;
        }
        match self.fade {
            Some(fade) => fade_remaining(fade.start_tick16, now_tick16, preference),
            None => preference,
        }
    }

    /// `ResetDualAudioCuePools` then `PushCueToDualAudioCuePools` for each cue.
    pub(crate) fn set_pool(&mut self, cues: &[MusicTrack]) {
        self.pool.clear();
        self.remaining.clear();
        self.pool.extend_from_slice(cues);
        self.remaining.extend_from_slice(cues);
    }

    /// `SetActiveAudioCueAndResetQueue`.
    pub(crate) fn set_active_cue(&mut self, cue: MusicTrack, fade: bool, now_tick16: u32) {
        if self.active == Some(cue) {
            return;
        }
        self.set_pool(&[cue]);
        self.queue_cue(cue, fade, now_tick16);
    }

    /// `RequestAudioPresetChangeWithDeferredApply` — does not replace the pool.
    pub(crate) fn request_preset(&mut self, cue: MusicTrack, fade: bool, now_tick16: u32) {
        if self.active == Some(cue) {
            return;
        }
        self.queue_cue(cue, fade, now_tick16);
    }

    /// Load/save and the player-orders map use the same 2+3 pool. Re-entering the map
    /// while that pool is already playing must not reshuffle (city/trade overlays).
    pub(crate) fn start_turn_flow_pool(&mut self, now_tick16: u32) {
        const POOL: [MusicTrack; 2] = [MusicTrack::TURN_FLOW_2, MusicTrack::TURN_FLOW_3];
        if self.pool.as_slice() == POOL.as_slice() && self.active.is_some() {
            return;
        }
        self.set_pool(&POOL);
        self.schedule_random(now_tick16);
    }

    /// `SelectAndScheduleRandomAudioCue`.
    pub(crate) fn schedule_random(&mut self, now_tick16: u32) {
        if self.remaining.is_empty() {
            if self.pool.is_empty() {
                return;
            }
            self.remaining.clone_from(&self.pool);
            self.active = None;
        }
        let pick = presentation_rand(&mut self.rng) as usize % self.remaining.len();
        let chosen = self.remaining.remove(pick);
        if self.active == Some(chosen) {
            return;
        }
        self.queue_cue(chosen, self.active.is_some(), now_tick16);
    }

    /// Retail movies call the immediate CD-audio stop path before opening the AVI.
    pub(crate) fn stop_all(&mut self) {
        self.active = None;
        self.pending = None;
        self.pool.clear();
        self.remaining.clear();
        self.fade = None;
    }

    fn queue_cue(&mut self, cue: MusicTrack, fade: bool, now_tick16: u32) {
        if fade && self.active.is_some() {
            self.pending = Some(cue);
            if self.fade.is_none() {
                self.fade = Some(MusicFade {
                    start_tick16: now_tick16,
                });
            }
            return;
        }
        self.pending = None;
        self.fade = None;
        self.active = Some(cue);
    }

    fn advance_fade(&mut self, now_tick16: u32, preference: i16) {
        let Some(fade) = self.fade else {
            return;
        };
        if fade_remaining(fade.start_tick16, now_tick16, preference) > 0 {
            return;
        }
        self.fade = None;
        if self.pending.is_none() {
            self.active = None;
        }
    }

    fn apply_pending(&mut self) {
        if self.fade.is_some() {
            return;
        }
        if let Some(cue) = self.pending.take() {
            self.active = Some(cue);
        }
    }
}

fn fade_remaining(start_tick16: u32, now_tick16: u32, preference: i16) -> i16 {
    let remaining = i32::from(preference) - now_tick16 as i32 + start_tick16 as i32;
    remaining.clamp(0, i32::from(preference)) as i16
}

fn tick16(time: &Time) -> u32 {
    u32::try_from(time.elapsed().as_millis() / TICK16_MS).unwrap_or(u32::MAX)
}

fn linear_volume(scalar: i16) -> f32 {
    (f32::from(scalar.max(0)) / MUSIC_VOLUME_SCALE).clamp(0.0, 1.0)
}

/// Presentation-side selection; gameplay-stream consumption happens at core turn boundaries.
fn presentation_rand(state: &mut u32) -> u32 {
    *state = state.wrapping_mul(1664525).wrapping_add(1013904223);
    *state >> 16
}

fn start_main_menu_music(mut music: ResMut<MusicDirector>, time: Option<Res<Time>>) {
    let now = time.as_ref().map_or(0, |time| tick16(time));
    music.set_pool(&[MusicTrack::MAIN_MENU]);
    music.schedule_random(now);
}

fn start_diplomacy_music(mut music: ResMut<MusicDirector>, time: Option<Res<Time>>) {
    let now = time.as_ref().map_or(0, |time| tick16(time));
    music.set_active_cue(MusicTrack::DIPLOMACY, true, now);
}

fn start_offer_sheet_music(mut music: ResMut<MusicDirector>, time: Option<Res<Time>>) {
    let now = time.as_ref().map_or(0, |time| tick16(time));
    music.request_preset(MusicTrack::DIPLOMACY, true, now);
}

fn start_load_save_music(mut music: ResMut<MusicDirector>, time: Option<Res<Time>>) {
    let now = time.as_ref().map_or(0, |time| tick16(time));
    music.set_pool(&[MusicTrack::TURN_FLOW_2, MusicTrack::TURN_FLOW_3]);
    music.schedule_random(now);
}

fn start_turn_flow_music(mut music: ResMut<MusicDirector>, time: Option<Res<Time>>) {
    let now = time.as_ref().map_or(0, |time| tick16(time));
    music.start_turn_flow_pool(now);
}

fn start_battle_report_music(mut music: ResMut<MusicDirector>, time: Option<Res<Time>>) {
    let now = time.as_ref().map_or(0, |time| tick16(time));
    music.set_pool(&[MusicTrack::BATTLE_REPORT]);
    music.schedule_random(now);
}

fn start_score_music(mut music: ResMut<MusicDirector>, time: Option<Res<Time>>) {
    let now = time.as_ref().map_or(0, |time| tick16(time));
    music.set_pool(&[MusicTrack::HIGH_SCORE]);
    music.schedule_random(now);
}

fn start_credits_music(mut music: ResMut<MusicDirector>, time: Option<Res<Time>>) {
    let now = time.as_ref().map_or(0, |time| tick16(time));
    music.set_pool(&[MusicTrack::CREDITS]);
    music.schedule_random(now);
}

pub(crate) fn register(app: &mut App) {
    app.init_resource::<MusicDirector>()
        .init_resource::<MusicTrackHandles>()
        .add_systems(OnEnter(AppState::MainMenu), start_main_menu_music)
        .add_systems(OnEnter(AppState::Diplomacy), start_diplomacy_music)
        .add_systems(OnEnter(AppState::DealBook), start_diplomacy_music)
        .add_systems(OnEnter(AppState::OfferSheet), start_offer_sheet_music)
        .add_systems(OnEnter(AppState::LoadSave), start_load_save_music)
        .add_systems(OnEnter(AppState::StrategicMap), start_turn_flow_music)
        .add_systems(OnEnter(AppState::BattleReport), start_battle_report_music)
        .add_systems(OnEnter(AppState::GameScore), start_score_music)
        .add_systems(OnEnter(AppState::HighScore), start_score_music)
        .add_systems(OnEnter(AppState::Credits), start_credits_music)
        .add_systems(Update, (sync_music, apply_music_volume).chain());
}

#[allow(clippy::too_many_arguments)]
fn sync_music(
    mut commands: Commands,
    mut music: ResMut<MusicDirector>,
    time: Option<Res<Time>>,
    prefs: Res<GamePreferences>,
    retail: Option<Res<RetailAssetsResource>>,
    sources: Option<ResMut<Assets<AudioSource>>>,
    handles: Option<ResMut<MusicTrackHandles>>,
    playback: Query<(Entity, &MusicPlayback, Option<&AudioSink>)>,
) {
    let now = time.as_ref().map_or(0, |time| tick16(time));
    let preference = prefs.music_volume();
    if preference > 0 {
        music.advance_fade(now, preference);
        music.apply_pending();
    }

    let playing = playback.iter().next().map(|(entity, current, sink)| {
        (entity, current.track, sink.is_some_and(|sink| sink.empty()))
    });
    let finished = playing.as_ref().is_some_and(|(_, _, empty)| *empty);
    if preference > 0
        && (playing.is_none() || finished)
        && music.pending.is_none()
        && music.fade.is_none()
    {
        if music.active.is_some() && finished {
            music.active = None;
        }
        if music.active.is_none() && !music.pool.is_empty() {
            music.schedule_random(now);
        }
    }

    let desired = if preference <= 0 { None } else { music.active };
    let volume = music.output_volume(now, preference);

    match (playing, desired) {
        (Some((_, current, _)), Some(track)) if current == track => {}
        (playing, desired) => {
            if let Some((entity, _, _)) = playing {
                commands.entity(entity).despawn();
            }
            if let (Some(track), Some(retail), Some(mut sources), Some(mut handles)) =
                (desired, retail, sources, handles)
                && let Some(source) =
                    music_source(retail.assets(), &mut sources, &mut handles, track)
            {
                commands.spawn((
                    MusicPlayback { track },
                    AudioPlayer::new(source),
                    PlaybackSettings::ONCE.with_volume(Volume::Linear(linear_volume(volume))),
                ));
            }
        }
    }
}

fn apply_music_volume(
    music: Res<MusicDirector>,
    time: Option<Res<Time>>,
    prefs: Res<GamePreferences>,
    mut sinks: Query<&mut AudioSink, With<MusicPlayback>>,
) {
    let now = time.as_ref().map_or(0, |time| tick16(time));
    let volume = Volume::Linear(linear_volume(
        music.output_volume(now, prefs.music_volume()),
    ));
    for mut sink in &mut sinks {
        sink.set_volume(volume);
    }
}

fn music_source(
    retail: &RetailAssets,
    sources: &mut Assets<AudioSource>,
    handles: &mut MusicTrackHandles,
    track: MusicTrack,
) -> Option<Handle<AudioSource>> {
    if let Some(handle) = handles.0.get(&track) {
        return Some(handle.clone());
    }
    let path = retail.music_track_path(track).ok()?;
    let bytes = fs::read(path).ok()?;
    let handle = sources.add(AudioSource {
        bytes: bytes.into(),
    });
    handles.0.insert(track, handle.clone());
    Some(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn director_with_rng(seed: u32) -> MusicDirector {
        MusicDirector {
            rng: seed,
            ..Default::default()
        }
    }

    #[test]
    fn set_active_cue_fades_before_switching() {
        let mut music = MusicDirector::default();
        music.set_active_cue(MusicTrack::MAIN_MENU, false, 0);
        music.set_active_cue(MusicTrack::DIPLOMACY, true, 10);
        assert_eq!(music.active, Some(MusicTrack::MAIN_MENU));
        assert_eq!(music.pending, Some(MusicTrack::DIPLOMACY));
        assert!(music.fade.is_some());
        assert_eq!(music.output_volume(10, 255), 255);
        assert_eq!(music.output_volume(10 + 128, 255), 127);

        music.advance_fade(10 + 255, 255);
        music.apply_pending();
        assert!(music.fade.is_none());
        assert_eq!(music.active, Some(MusicTrack::DIPLOMACY));
        assert!(music.pending.is_none());
    }

    #[test]
    fn random_pool_samples_without_replacement_then_replenishes() {
        let mut music = director_with_rng(1);
        music.set_pool(&[MusicTrack::TURN_FLOW_2, MusicTrack::TURN_FLOW_3]);
        music.schedule_random(0);
        let first = music.active.unwrap();
        assert!(music.remaining.len() == 1);
        assert_ne!(music.remaining[0], first);

        music.active = None;
        music.schedule_random(0);
        let second = music.active.unwrap();
        assert_ne!(first, second);
        assert!(music.remaining.is_empty());

        music.active = None;
        music.schedule_random(0);
        assert!(music.active.is_some());
        assert_eq!(music.remaining.len(), 1);
        assert_eq!(
            music.pool,
            [MusicTrack::TURN_FLOW_2, MusicTrack::TURN_FLOW_3]
        );
    }

    #[test]
    fn movie_stop_clears_active_and_queued_music() {
        let mut music = MusicDirector::default();
        music.set_pool(&[MusicTrack::MAIN_MENU, MusicTrack::TURN_FLOW_2]);
        music.schedule_random(0);
        music.request_preset(MusicTrack::DIPLOMACY, true, 1);
        music.stop_all();
        assert!(music.active.is_none());
        assert!(music.pending.is_none());
        assert!(music.pool.is_empty());
        assert!(music.remaining.is_empty());
        assert!(music.fade.is_none());
    }
}
