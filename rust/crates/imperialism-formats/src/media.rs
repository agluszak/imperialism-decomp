//! Retail media identifiers recovered from the C++ host, not Win32 device types.

use std::fmt;

/// Stem of `Movies/<name>.avi` as assembled by `PlayMovieClipAndDispatchTurnStateFollowup`.
///
/// `TViewMgr::HandleTurnEventDialogFactorySlotF4` picks the clip from `TSimMgr::mode`
/// (`kTurnEventOpeningCinematic` is the shared dispatcher, not an opening-only event):
/// mode 1 → `open`, mode `0x0e` (decade / quarter-gate) → `vote`, mode `0x16` → `win`,
/// mode `0x17` → `lose`, mode `0x19` → `win` or `lose` from nation eligibility.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MovieId {
    Open,
    Vote,
    Win,
    Lose,
}

impl MovieId {
    pub const fn file_stem(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Vote => "vote",
            Self::Win => "win",
            Self::Lose => "lose",
        }
    }
}

/// CD-audio track index passed to `TCdAudioDevice::ApplyMciPlaybackRangeFromAudioManager`.
///
/// Retail plays TMSF range `[track, track+1)`. GOG replaces that with ripped files named
/// `MUSIC/TrackNN.ogg` (and occasionally another extension) using the same 1-based track
/// numbers. Cue 6 is the main-menu pool entry that already appears as `MUSIC/Track06.ogg`
/// in the synthetic-install negative test.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MusicTrack(u8);

impl MusicTrack {
    pub const DIPLOMACY: Self = Self(4);
    pub const MAIN_MENU: Self = Self(6);
    pub const BATTLE_VICTORY: Self = Self(9);
    pub const BATTLE_DEFEAT: Self = Self(10);
    pub const HIGH_SCORE: Self = Self(11);
    pub const CREDITS: Self = Self(12);

    pub const fn new(track: u8) -> Self {
        Self(track)
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub fn file_stem(self) -> String {
        format!("Track{:02}", self.0)
    }
}

/// Numeric `WAVE` resource id loaded by `TSoundResourceManager::LoadWaveResourceByNumericIdAndBuildBuffer`.
///
/// Retail first tries `<id>.wav` on disk, then the wave-pack module (`Data/wave.gob`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SoundId(u16);

impl SoundId {
    /// Shared UI click used as literal `7000` and as `0x1b58`.
    pub const UI_CLICK: Self = Self(7000);

    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for MovieId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.file_stem())
    }
}

impl fmt::Display for MusicTrack {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.file_stem())
    }
}

impl fmt::Display for SoundId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}
