#include "game/ui_widgets/TSoundPlayer.h"

#include "game/gfx/TAmbitApplication.h"
#include "game/mfc.h"
#include "game/globals/global_types.h"
#include "game/globals/assets_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TApplication.h"
#include "game/city_ui/TLongintList.h"
#include "game/gfx/TSoundResourceManager.h"
#include "game/assets/TAssetMgr.h"
#include "game/assets/TCdAudioDevice.h"
#include "game/assets/timer_slots.h"
#include "game/ui_screens/turn_flow_cooldown.h"

#include <math.h>
#include <new>
#include <stdlib.h>

namespace {
enum {
  kSoundEffectsVolumePreference = 2,
  kCdAudioVolumePreference = 3,
  kDirectSoundChannelCount = 6,
  kRandomCuePollInterval = 4,
  kCdAudioFadeTimerInterval = 6
};
}

// FUNCTION: IMPERIALISM 0x00593210
bool UpdateDeferredCdAudioFade() {
  TSoundPlayer* soundPlayer = g_pSfxPlaybackSystem;
  if (soundPlayer != 0) {
    unsigned int fadeStartTick = soundPlayer->fadeStartTick;
    bool keepTimer = true;
    if (fadeStartTick > 0) {
      unsigned int now = GetTickCountDiv16();
      int remaining = static_cast<int>(g_pSimMgr->preferenceValues[kCdAudioVolumePreference]) -
                      static_cast<int>(now) + static_cast<int>(soundPlayer->fadeStartTick);
      if (!(remaining > 0 && soundPlayer->fadeStartTick <= now)) {
        remaining = 0;
        keepTimer = false;
        soundPlayer->fadeStartTick = 0;
        if (static_cast<short>(soundPlayer->pendingAudioCueId) == static_cast<short>(remaining)) {
          g_cdAudioDevice.StopPlayback();
        }
      }
      g_cdAudioDevice.ApplyAuxOutputVolumeFromScalar(static_cast<short>(remaining) << 8);
      return keepTimer;
    }
    keepTimer = false;
    return keepTimer;
  }
  return false;
}

IMPLEMENT_DYNCREATE(TSoundPlayer, TEventHandler)

// FUNCTION: IMPERIALISM 0x00593370
TSoundPlayer::TSoundPlayer()
    : TEventHandler(), audioCuePool(0), remainingRandomAudioCues(0), cdAudioPlaybackActive(0),
      unused79(0), unused7A(0), fadeStartTick(0) {}

// Slot 0x13 override — pump the audio playback state machine / schedule random cues.

// FUNCTION: IMPERIALISM 0x00593400
bool TSoundPlayer::DoIdle(int action) {
  if (g_pSimMgr->preferenceValues[kCdAudioVolumePreference] == 0) {
    if (this->cdAudioPlaybackActive) {
      if (g_cdAudioDevice.IsPlaybackActive()) {
        g_cdAudioDevice.StopPlayback();
      }
      this->cdAudioPlaybackActive = false;
    }
    return false;
  }

  if (this->clearCuePoolsAfterFade && this->fadeStartTick == 0) {
    int n = this->audioCuePool->GetSize();
    if (n > 0) {
      this->audioCuePool->RemoveAll();
      this->remainingRandomAudioCues->RemoveAll();
    }
    if (this->cdAudioPlaybackActive) {
      g_cdAudioDevice.StopPlayback();
      this->cdAudioPlaybackActive = false;
      this->activeAudioCueId = 0;
    }
    this->clearCuePoolsAfterFade = false;
    return false;
  }

  if (this->pendingAudioCueId != 0 && this->fadeStartTick == 0) {
    this->RequestAudioPresetChangeWithDeferredApply(this->pendingAudioCueId, false);
    this->pendingAudioCueId = 0;
    return false;
  }

  int n = this->audioCuePool->GetSize();
  if (n > 0) {
    g_randomAudioCuePollCounter = static_cast<short>(g_randomAudioCuePollCounter + 1);
    if (g_randomAudioCuePollCounter > kRandomCuePollInterval) {
      g_randomAudioCuePollCounter = 0;
      if (!g_cdAudioDevice.IsPlaybackActive()) {
        this->SelectAndScheduleRandomAudioCue();
      }
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x00593530
bool TSoundPlayer::FadeCD() {
  bool keepTimer = true;
  if (fadeStartTick > 0) {
    unsigned int now = GetTickCountDiv16();
    int remaining = static_cast<int>(g_pSimMgr->preferenceValues[kCdAudioVolumePreference]) -
                    static_cast<int>(now) + static_cast<int>(fadeStartTick);
    if (!(remaining > 0 && fadeStartTick <= now)) {
      remaining = 0;
      keepTimer = false;
      fadeStartTick = 0;
      if (static_cast<short>(pendingAudioCueId) == static_cast<short>(remaining)) {
        g_cdAudioDevice.StopPlayback();
      }
    }
    g_cdAudioDevice.ApplyAuxOutputVolumeFromScalar(static_cast<short>(remaining) << 8);
    return keepTimer;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005935c0
void TSoundPlayer::UpdateAudioPlaybackStateAndScheduleRandomCue() {
  if (clearCuePoolsAfterFade && fadeStartTick == 0) {
    int n = audioCuePool->GetSize();
    if (n > 0) {
      audioCuePool->RemoveAll();
      remainingRandomAudioCues->RemoveAll();
    }
    if (cdAudioPlaybackActive) {
      g_cdAudioDevice.StopPlayback();
      cdAudioPlaybackActive = false;
      activeAudioCueId = 0;
    }
    clearCuePoolsAfterFade = false;
    return;
  }

  short pending = static_cast<short>(pendingAudioCueId);
  if (pending != 0 && fadeStartTick == 0) {
    if (static_cast<short>(g_pSimMgr->preferenceValues[kCdAudioVolumePreference]) != 0) {
      if (!IsTurnFlowCooldownActiveAndResetExpiredState()) {
        if (ReturnTrueStub() == 0) {
          g_pSimMgr->preferenceValues[kCdAudioVolumePreference] = 0;
          pendingAudioCueId = 0;
          return;
        }
        if (pending != static_cast<short>(activeAudioCueId)) {
          activeAudioCueId = pending;
          g_cdAudioDevice.ApplyMciPlaybackRangeFromAudioManager(pending);
          g_cdAudioDevice.ApplyAuxOutputVolumeFromScalar(
              static_cast<short>(g_pSimMgr->preferenceValues[kCdAudioVolumePreference]) << 8);
          cdAudioPlaybackActive = true;
        }
      }
    }
    pendingAudioCueId = 0;
    return;
  }

  int n = audioCuePool->GetSize();
  if (n > 0) {
    g_randomAudioCuePollCounter = static_cast<short>(g_randomAudioCuePollCounter + 1);
    if (g_randomAudioCuePollCounter > kRandomCuePollInterval) {
      g_randomAudioCuePollCounter = 0;
      if (!g_cdAudioDevice.IsPlaybackActive()) {
        SelectAndScheduleRandomAudioCue();
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00593730
void TSoundPlayer::ResetDualAudioCuePools() {
  audioCuePool->RemoveAll();
  remainingRandomAudioCues->RemoveAll();
}

// FUNCTION: IMPERIALISM 0x00593760
void TSoundPlayer::AddToPlayList(int cueId) {
  audioCuePool->InsertLast(cueId);
  remainingRandomAudioCues->InsertLast(cueId);
}

// FUNCTION: IMPERIALISM 0x00593790
void TSoundPlayer::SelectAndScheduleRandomAudioCue() {
  if (g_pSimMgr->preferenceValues[kCdAudioVolumePreference] == 0 ||
      IsTurnFlowCooldownActiveAndResetExpiredState()) {
    return;
  }

  if (this->remainingRandomAudioCues->GetSize() == 0) {
    int available = this->audioCuePool->GetSize();
    if (available == 0) {
      return;
    }
    for (int i = 1; i <= available; ++i) {
      this->remainingRandomAudioCues->InsertLast(this->audioCuePool->At(i));
    }
    this->activeAudioCueId = 0;
  }

  int total = this->remainingRandomAudioCues->GetSize();
  int pick = static_cast<int>(rand()) % total + 1;
  int chosen = this->remainingRandomAudioCues->At(pick);
  this->remainingRandomAudioCues->AtDelete(pick);

  if (g_pSimMgr->preferenceValues[kCdAudioVolumePreference] == 0 ||
      IsTurnFlowCooldownActiveAndResetExpiredState()) {
    return;
  }
  if (ReturnTrueStub() == 0) {
    g_pSimMgr->preferenceValues[kCdAudioVolumePreference] = 0;
    return;
  }

  if (chosen == static_cast<short>(this->activeAudioCueId)) {
    return;
  }
  if (static_cast<short>(this->activeAudioCueId) > 0) {
    this->pendingAudioCueId = static_cast<unsigned short>(chosen);
    if (this->fadeStartTick == 0) {
      this->fadeStartTick = GetTickCountDiv16();
      g_pAssetMgr->ScheduleTimerSlotCallbackWithInterval(&UpdateDeferredCdAudioFade,
                                                         kCdAudioFadeTimerInterval, 0);
    }
  } else {
    this->activeAudioCueId = static_cast<unsigned short>(chosen);
    g_cdAudioDevice.ApplyMciPlaybackRangeFromAudioManager(chosen);
    g_cdAudioDevice.ApplyAuxOutputVolumeFromScalar(
        static_cast<int>(g_pSimMgr->preferenceValues[kCdAudioVolumePreference]) << 8);
    this->cdAudioPlaybackActive = true;
  }
}

// FUNCTION: IMPERIALISM 0x00593920
void TSoundPlayer::RequestAudioPresetChangeWithDeferredApply(int presetId, bool flag) {
  if (g_pSimMgr->preferenceValues[kCdAudioVolumePreference] == 0) {
    return;
  }
  if (IsTurnFlowCooldownActiveAndResetExpiredState()) {
    return;
  }
  if (ReturnTrueStub() == 0) {
    g_pSimMgr->preferenceValues[kCdAudioVolumePreference] = 0;
    return;
  }
  if (presetId == static_cast<short>(this->activeAudioCueId)) {
    return;
  }

  if (flag && static_cast<short>(this->activeAudioCueId) > 0) {
    // Deferred apply: stash the preset and arm the one-shot timer callback.
    this->pendingAudioCueId = static_cast<unsigned short>(presetId);
    if (this->fadeStartTick != 0) {
      return;
    }
    this->fadeStartTick = GetTickCountDiv16();
    g_pAssetMgr->ScheduleTimerSlotCallbackWithInterval(&UpdateDeferredCdAudioFade,
                                                       kCdAudioFadeTimerInterval, 0);
    return;
  }

  // Immediate apply: start the CD track and set the aux volume from the preference.
  this->activeAudioCueId = static_cast<unsigned short>(presetId);
  g_cdAudioDevice.ApplyMciPlaybackRangeFromAudioManager(static_cast<short>(presetId));
  g_cdAudioDevice.ApplyAuxOutputVolumeFromScalar(
      static_cast<int>(g_pSimMgr->preferenceValues[kCdAudioVolumePreference]) << 8);
  this->cdAudioPlaybackActive = true;
}

// FUNCTION: IMPERIALISM 0x00593a10
void TSoundPlayer::SetActiveAudioCueAndResetQueue(int cueId, bool flag) {
  if (cueId == static_cast<short>(this->activeAudioCueId)) {
    return;
  }

  if (this->clearCuePoolsAfterFade && this->fadeStartTick == 0) {
    int pending = this->audioCuePool->GetSize();
    if (pending > 0) {
      this->ResetDualAudioCuePools();
    }
    if (this->cdAudioPlaybackActive) {
      g_cdAudioDevice.StopPlayback();
      this->cdAudioPlaybackActive = false;
      this->activeAudioCueId = 0;
    }
    this->clearCuePoolsAfterFade = false;
  } else if (this->pendingAudioCueId != 0 && this->fadeStartTick == 0) {
    this->RequestAudioPresetChangeWithDeferredApply(this->pendingAudioCueId, false);
    this->pendingAudioCueId = 0;
  } else {
    int rotating = this->audioCuePool->GetSize();
    if (rotating > 0) {
      g_randomAudioCuePollCounter = static_cast<short>(g_randomAudioCuePollCounter + 1);
      if (g_randomAudioCuePollCounter > kRandomCuePollInterval) {
        g_randomAudioCuePollCounter = 0;
        if (!g_cdAudioDevice.IsPlaybackActive()) {
          this->SelectAndScheduleRandomAudioCue();
        }
      }
    }
  }

  this->audioCuePool->RemoveAll();
  this->remainingRandomAudioCues->RemoveAll();
  this->audioCuePool->InsertLast(cueId);
  this->remainingRandomAudioCues->InsertLast(cueId);

  if (g_pSimMgr->preferenceValues[kCdAudioVolumePreference] == 0) {
    return;
  }
  if (IsTurnFlowCooldownActiveAndResetExpiredState()) {
    return;
  }
  if (ReturnTrueStub() == 0) {
    g_pSimMgr->preferenceValues[kCdAudioVolumePreference] = 0;
    return;
  }
  if (cueId == static_cast<short>(this->activeAudioCueId)) {
    return;
  }

  if (flag && static_cast<short>(this->activeAudioCueId) > 0) {
    this->pendingAudioCueId = static_cast<unsigned short>(cueId);
    if (this->fadeStartTick != 0) {
      return;
    }
    this->fadeStartTick = GetTickCountDiv16();
    g_pAssetMgr->ScheduleTimerSlotCallbackWithInterval(&UpdateDeferredCdAudioFade,
                                                       kCdAudioFadeTimerInterval, 0);
    return;
  }

  this->activeAudioCueId = static_cast<unsigned short>(cueId);
  g_cdAudioDevice.ApplyMciPlaybackRangeFromAudioManager(static_cast<short>(cueId));
  g_cdAudioDevice.ApplyAuxOutputVolumeFromScalar(
      static_cast<int>(g_pSimMgr->preferenceValues[kCdAudioVolumePreference]) << 8);
  this->cdAudioPlaybackActive = true;
}

// FUNCTION: IMPERIALISM 0x00593c10
void TSoundPlayer::StopMusic(bool fadeOut) {
  int pendingCount = audioCuePool->GetSize();
  if (pendingCount > 0) {
    audioCuePool->RemoveAll();
    remainingRandomAudioCues->RemoveAll();
  }

  if (!cdAudioPlaybackActive) {
    return;
  }
  if (fadeOut) {
    if (fadeStartTick == 0) {
      fadeStartTick = GetTickCountDiv16();
      g_pAssetMgr->ScheduleTimerSlotCallbackWithInterval(&UpdateDeferredCdAudioFade,
                                                         kCdAudioFadeTimerInterval, 0);
    }
    clearCuePoolsAfterFade = true;
    return;
  }

  g_cdAudioDevice.StopPlayback();
  cdAudioPlaybackActive = false;
  activeAudioCueId = 0;
}

// FUNCTION: IMPERIALISM 0x00593cb0
void TSoundPlayer::ScaleAndApplyAuxOutputVolume(short scalar) {
  g_cdAudioDevice.ApplyAuxOutputVolumeFromScalar(scalar << 8);
}

// FUNCTION: IMPERIALISM 0x00593ce0
void TSoundPlayer::StartDeferredAudioFadeTimerIfIdle() {
  if (fadeStartTick == 0) {
    fadeStartTick = GetTickCountDiv16();
    g_pAssetMgr->ScheduleTimerSlotCallbackWithInterval(&UpdateDeferredCdAudioFade,
                                                       kCdAudioFadeTimerInterval, 0);
  }
}

// Slot 0x25 — allocate the two sound-channel peer objects and bring up DirectSound.

// FUNCTION: IMPERIALISM 0x005e4e70
void TSoundPlayer::ISoundPlayer(int idleFrequency) {
  this->IEventHandler(nullptr);
  char ok = static_cast<char>(g_soundResourceManager.InitializeDirectSoundDeviceAndChannels());
  this->directSoundInitOk = static_cast<unsigned char>(ok);
  if (ok == 0) {
    this->ClearDirectSoundInitPendingAndResetState();
  } else {
    this->RequestDirectSoundInitIfAllowed();
  }

  this->audioCuePool = new TLongintList();
  this->remainingRandomAudioCues = new TLongintList();

  this->activeAudioCueId = 0;
  g_cdAudioDevice.EnsureCdAudioDeviceHandleInitialized();
  this->idleFrequencyTicks = idleFrequency;
  // Register for idle ticks on the global UI root controller (virtual slot 0x29).
  g_pAmbitApplication->InstallCohandler(this, true);
}

// FUNCTION: IMPERIALISM 0x005e4f60
bool TSoundPlayer::DefaultSoundCapabilityPredicate() {
  return true;
}

// Slot 0x28 — kick off DirectSound init if the device is available.

// FUNCTION: IMPERIALISM 0x005e4f80
void TSoundPlayer::RequestDirectSoundInitIfAllowed() {
  if (this->directSoundInitOk != 0) {
    this->directSoundInitPending = true;
    g_soundResourceManager.InitializeDirectSoundDeviceAndChannels();
  }
}

// FUNCTION: IMPERIALISM 0x005e4fb0
bool TSoundPlayer::DefaultSoundCompatibilityPredicate(int unusedArg1, int unusedArg2) {
  return false;
}

// Slot 0x29 — clear the pending flag and tear down the partial init.

// FUNCTION: IMPERIALISM 0x005e4fd0
void TSoundPlayer::ClearDirectSoundInitPendingAndResetState() {
  this->directSoundInitPending = false;
  g_soundResourceManager.ReleaseDirectSoundDeviceAndChannels();
}

// Slot 0x2a — stop playback on all six global DirectSound channels.

// FUNCTION: IMPERIALISM 0x005e4ff0
void TSoundPlayer::StopAllSoundChannels() {
  for (int i = 0; i < kDirectSoundChannelCount; ++i) {
    g_soundResourceManager.m_channels[i]->Stop();
  }
}

// FUNCTION: IMPERIALISM 0x005e5020
void TSoundPlayer::SetMasterVolumeFromPercent(short percent) {
  if (this->directSoundInitPending) {
    double val = -pow(2.0, (100 - percent) * g_dMasterVolumeExponentScale);
    int volume = static_cast<int>(val);
    if (volume > 0) {
      volume = 0;
    }
    if (volume < -9999) {
      volume = -9999;
    }
    g_soundResourceManager.SetChannelVolumesUntilAccepted(volume);
  }
}

// FUNCTION: IMPERIALISM 0x005e50a0
void TSoundPlayer::PriorityOverride(short currentPriority, short requestedPriority) {}

// Slot 0x07 override — release the two channel peers, then run the base teardown.

// FUNCTION: IMPERIALISM 0x005e50c0
int TSoundPlayer::UpdateLocalizationAudioSlotAndMaybeRefreshVoiceState(short sfxToken,
                                                                       int unusedArg2,
                                                                       int unusedArg3,
                                                                       int unusedArg4) {
  if (g_pSimMgr->preferenceValues[kSoundEffectsVolumePreference] == 0) {
    return 0;
  }
  short slot = static_cast<short>(g_localizationAudioSlotCursor);
  if (++g_localizationAudioSlotCursor >= kDirectSoundChannelCount) {
    g_localizationAudioSlotCursor = 0;
  }
  if (g_soundResourceManager.LoadWaveResourceByNumericIdAndBuildBuffer(sfxToken, slot) != 0) {
    g_soundResourceManager.UpdateLocalizationAudioSlot(slot);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005e5140
int TSoundPlayer::PlaySoundEffect(short sfxToken, int forwardedArg2, int forwardedArg3) {
  this->UpdateLocalizationAudioSlotAndMaybeRefreshVoiceState(sfxToken, forwardedArg2, forwardedArg3,
                                                             1);
  return 0;
}

// FUNCTION: IMPERIALISM 0x005e5170
int TSoundPlayer::PlaySoundAsynchronously(short soundId, short channel, short priority) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005e5190
int TSoundPlayer::PlaySoundSynchronously(short soundId, short channel, short priority) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005e51b0
int TSoundPlayer::PlayAiffFile(CString fileName, short channel, short priority) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005e51d0
void TSoundPlayer::Free() {
  if (this->remainingRandomAudioCues != 0) {
    this->remainingRandomAudioCues->Free();
  }
  this->remainingRandomAudioCues = 0;
  if (this->audioCuePool != 0) {
    this->audioCuePool->Free();
  }
  this->audioCuePool = 0;
  g_soundResourceManager.ReleaseDirectSoundDeviceAndChannels();
  g_cdAudioDevice.StopPlayback();
  TEventHandler::Free();
}
