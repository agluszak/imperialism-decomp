#include "game/TSoundPlayer.h"

#include "game/mfc.h"
#include "game/wave_helpers.h"
#include "game/global_data_tables.h"
#include "game/TSimMgr.h"
#include "game/TApplication.h"
#include "game/TSoundChannelNode.h"
#include "game/TSoundResourceManager.h"
#include "game/startup_helpers.h"
#include "game/cd_audio.h"
#include "game/timer_slots.h"
#include "game/turn_flow_cooldown.h"

#include <new>
#include <math.h>

extern char PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;
// Random-cue rotation counter at 0x006a4520 (raw audio-state global, not yet in
// symbols.csv). Provisional definition until the owning data block is recovered.
short DAT_006a4520 = 0;

undefined4 ForwardMciCommand808ToDevice(void);
undefined4 ReleaseRuntimeSelectionPeersAndResetOwner_Impl(void);

extern "C" int __cdecl rand(void);
// The deferred-apply timer callback (0x593210); registered by ScheduleTimerSlotCallbackWithInterval
// as a real function pointer (its return keeps/clears the slot).
extern undefined4 Helper_Uses_ForwardMciCommand808ToDevice_At00593210(void);

void __fastcall DestructTSoundPlayerBaseState(TSoundPlayer* player);

static int DAT_006a60f8 = 0;

// SYNTHETIC: IMPERIALISM 0x005932b0
// TSoundPlayer::CreateObject

// SYNTHETIC: IMPERIALISM 0x00593350
// TSoundPlayer::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSoundPlayer, TEventHandler)

TSoundPlayer::TSoundPlayer()
    : TEventHandler(), runtimePeerAt6c(0), runtimePeerAt70(0), stateByte78(0), stateByte79(0),
      stateByte7a(0), stateDword7c(0) {}

// FUNCTION: IMPERIALISM 0x00593370
TSoundPlayer* TSoundPlayer::ConstructTSoundPlayerBaseState() {
  ::new (static_cast<void*>(this)) TSoundPlayer();
  return this;
}

// SYNTHETIC: IMPERIALISM 0x005933b0
// TSoundPlayer::`scalar deleting destructor'

// Partial teardown writes the runtime-object base vptr, symmetric with TEventHandler
// construction via the normal base ctor chain.

extern char PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;

// FUNCTION: IMPERIALISM 0x005933e0
void __fastcall DestructTSoundPlayerBaseState(TSoundPlayer* player) {
  *reinterpret_cast<void**>(player) = &PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;
}

void TSoundPlayer::EnsureCdAudioDeviceHandleInitialized() {
  g_cdAudioDevice.EnsureCdAudioDeviceHandleInitialized();
}

void TSoundPlayer::ForwardMciCommand808ToDevice() {
  ::ForwardMciCommand808ToDevice();
}

BOOL TSoundPlayer::ForwardMciStatusCommand814IgnoreFailure() {
  return static_cast<BOOL>(g_cdAudioDevice.ForwardMciStatusCommand814IgnoreFailure());
}

// Slot 0x13 override — pump the audio playback state machine / schedule random cues.

// FUNCTION: IMPERIALISM 0x00593400
char TSoundPlayer::DoIdle(int action) {
  (void)action;
  if (g_pSimMgr->preferenceValues[3] == 0) {
    if (this->stateByte78 != 0) {
      if (static_cast<char>(this->ForwardMciStatusCommand814IgnoreFailure()) != 0) {
        this->ForwardMciCommand808ToDevice();
      }
      this->stateByte78 = 0;
    }
    return 0;
  }

  if (this->stateByte80 != 0 && this->stateDword7c == 0) {
    int n = this->runtimePeerAt6c->QueryPendingPlaybackCountSlot28();
    if (n > 0) {
      this->runtimePeerAt6c->StopOrResetActivePlaybackSlot30();
      this->runtimePeerAt70->StopOrResetActivePlaybackSlot30();
    }
    if (this->stateByte78 != 0) {
      this->ForwardMciCommand808ToDevice();
      this->stateByte78 = 0;
      this->fieldShort74 = 0;
    }
    this->stateByte80 = 0;
    return 0;
  }

  if (this->fieldShort76 != 0 && this->stateDword7c == 0) {
    this->RequestAudioPresetChangeWithDeferredApply(this->fieldShort76, 0);
    this->fieldShort76 = 0;
    return 0;
  }

  int n = this->runtimePeerAt6c->QueryPendingPlaybackCountSlot28();
  if (n > 0) {
    DAT_006a4520 = static_cast<short>(DAT_006a4520 + 1);
    if (DAT_006a4520 > 4) {
      DAT_006a4520 = 0;
      if (static_cast<char>(this->ForwardMciStatusCommand814IgnoreFailure()) == 0) {
        this->SelectAndScheduleRandomAudioCue();
      }
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00593730
void TSoundPlayer::ResetDualAudioCuePools() {
  runtimePeerAt6c->StopOrResetActivePlaybackSlot30();
  runtimePeerAt70->StopOrResetActivePlaybackSlot30();
}

// FUNCTION: IMPERIALISM 0x00593760
void TSoundPlayer::PushCueToDualAudioCuePools(int cueId) {
  runtimePeerAt6c->SoundChannelNodeDummy00(cueId);
  runtimePeerAt70->SoundChannelNodeDummy00(cueId);
}

// FUNCTION: IMPERIALISM 0x00593790
void TSoundPlayer::SelectAndScheduleRandomAudioCue() {
  if (g_pSimMgr->preferenceValues[3] == 0 || IsTurnCooldownCounterActiveOrResetFlag() != 0) {
    return;
  }

  if (this->runtimePeerAt70->QueryPendingPlaybackCountSlot28() == 0) {
    int available = this->runtimePeerAt6c->QueryPendingPlaybackCountSlot28();
    if (available == 0) {
      return;
    }
    for (int i = 1; i <= available; ++i) {
      TSoundChannelNode* peer70 = this->runtimePeerAt70;
      int cue = this->runtimePeerAt6c->SoundChannelNodeDummy04(i);
      peer70->SoundChannelNodeDummy00(cue);
    }
    this->fieldShort74 = 0;
  }

  int total = this->runtimePeerAt70->QueryPendingPlaybackCountSlot28();
  int pick = static_cast<int>(rand()) % total + 1;
  int chosen = this->runtimePeerAt70->SoundChannelNodeDummy04(pick);
  this->runtimePeerAt70->SoundChannelNodeDummy2C(pick);

  if (g_pSimMgr->preferenceValues[3] == 0 || IsTurnCooldownCounterActiveOrResetFlag() != 0) {
    return;
  }
  if (ReturnTrueStub() == 0) {
    g_pSimMgr->preferenceValues[3] = 0;
    return;
  }

  if (chosen == static_cast<short>(this->fieldShort74)) {
    return;
  }
  if (static_cast<short>(this->fieldShort74) > 0) {
    this->fieldShort76 = static_cast<unsigned short>(chosen);
    if (this->stateDword7c == 0) {
      this->stateDword7c = GetTickCountDiv16();
      ScheduleTimerSlotCallbackWithInterval(&Helper_Uses_ForwardMciCommand808ToDevice_At00593210, 6,
                                            0);
    }
  } else {
    this->fieldShort74 = static_cast<unsigned short>(chosen);
    g_cdAudioDevice.ApplyMciPlaybackRangeFromAudioManager(chosen);
    ApplyAuxOutputVolumeFromScalar(static_cast<int>(g_pSimMgr->preferenceValues[3]) << 8);
    this->stateByte78 = 1;
  }
}

// FUNCTION: IMPERIALISM 0x00593920
void TSoundPlayer::RequestAudioPresetChangeWithDeferredApply(int presetId, int flag) {
  // TODO(verify): the asm tests only the low byte of `flag` -- original param was
  // likely char/BOOL.
  if (g_pSimMgr->preferenceValues[3] == 0) {
    return;
  }
  if (IsTurnCooldownCounterActiveOrResetFlag() != 0) {
    return;
  }
  if (ReturnTrueStub() == 0) {
    g_pSimMgr->preferenceValues[3] = 0;
    return;
  }
  if (presetId == static_cast<short>(this->fieldShort74)) {
    return;
  }

  if (flag != 0 && static_cast<short>(this->fieldShort74) > 0) {
    // Deferred apply: stash the preset and arm the one-shot timer callback.
    this->fieldShort76 = static_cast<unsigned short>(presetId);
    if (this->stateDword7c != 0) {
      return;
    }
    this->stateDword7c = GetTickCountDiv16();
    ScheduleTimerSlotCallbackWithInterval(&Helper_Uses_ForwardMciCommand808ToDevice_At00593210, 6,
                                          0);
    return;
  }

  // Immediate apply: start the CD track and set the aux volume from the preference.
  this->fieldShort74 = static_cast<unsigned short>(presetId);
  g_cdAudioDevice.ApplyMciPlaybackRangeFromAudioManager(static_cast<short>(presetId));
  ApplyAuxOutputVolumeFromScalar(static_cast<int>(g_pSimMgr->preferenceValues[3]) << 8);
  this->stateByte78 = 1;
}

// FUNCTION: IMPERIALISM 0x00593c10
void TSoundPlayer::HandleBlinkStateAndScheduleTimerTick(char enabled) {
  int pendingCount = runtimePeerAt6c->QueryPendingPlaybackCountSlot28();
  if (pendingCount > 0) {
    runtimePeerAt6c->StopOrResetActivePlaybackSlot30();
    runtimePeerAt70->StopOrResetActivePlaybackSlot30();
  }

  if (stateByte78 == 0) {
    return;
  }
  if (enabled != 0) {
    if (stateDword7c == 0) {
      stateDword7c = GetTickCountDiv16();
    }
    stateByte80 = 1;
    return;
  }

  ForwardMciCommand808ToDevice();
  stateByte78 = 0;
  fieldShort74 = 0;
}

// FUNCTION: IMPERIALISM 0x00593cb0
void TSoundPlayer::ScaleAndApplyAuxOutputVolume(short scalar) {
  // Original forwards through 0x47cdd0 with ECX pointed at the CD-audio device singleton
  // (g_cdAudioDevice, 0x6a60bc) that the callee never reads; modeled as the free helper.
  ApplyAuxOutputVolumeFromScalar(scalar << 8);
}

// Slot 0x25 — allocate the two sound-channel peer objects and bring up DirectSound.

// FUNCTION: IMPERIALISM 0x005e4e70
void TSoundPlayer::InitializeSoundSubsystemAndAllocateChannelLists(int param_1) {
  this->InitializePacketHeaderFields_Tag20202020(0);
  char ok = static_cast<char>(g_soundResourceManager.InitializeDirectSoundDeviceAndChannels());
  this->directSoundInitOkAt20 = static_cast<unsigned char>(ok);
  if (ok == 0) {
    this->ClearDirectSoundInitPendingAndResetState();
  } else {
    this->RequestDirectSoundInitIfAllowed();
  }

  this->runtimePeerAt6c = new TSoundChannelNode();
  this->runtimePeerAt70 = new TSoundChannelNode();

  this->fieldShort74 = 0;
  EnsureCdAudioDeviceHandleInitialized();
  this->field10 = param_1;
  // Notify the global UI root controller via its slot 0x29 (peer class unrecovered).
  g_pGlobalUiRootController->InstallCohandler(this, 1);
}

// FUNCTION: IMPERIALISM 0x005e4f60
unsigned char TSoundPlayer::ReturnConstantTrue_SoundPredicate() {
  return 1;
}

// Slot 0x28 — kick off DirectSound init if the device is available.

// FUNCTION: IMPERIALISM 0x005e4f80
void TSoundPlayer::RequestDirectSoundInitIfAllowed() {
  if (this->directSoundInitOkAt20 != 0) {
    this->directSoundInitPendingAt21 = 1;
    g_soundResourceManager.InitializeDirectSoundDeviceAndChannels();
  }
}

// FUNCTION: IMPERIALISM 0x005e4fb0
unsigned char TSoundPlayer::ReturnConstantFalse_SoundPredicate(int a, int b) {
  (void)a;
  (void)b;
  return 0;
}

// Slot 0x29 — clear the pending flag and tear down the partial init.

// FUNCTION: IMPERIALISM 0x005e4fd0
void TSoundPlayer::ClearDirectSoundInitPendingAndResetState() {
  this->directSoundInitPendingAt21 = 0;
  g_soundResourceManager.ReleaseDirectSoundDeviceAndChannels();
}

// Slot 0x2a — stop playback on all six global DirectSound channels.

// FUNCTION: IMPERIALISM 0x005e4ff0
void TSoundPlayer::StopAllSoundChannels() {
  for (int i = 0; i < 6; ++i) {
    g_soundResourceManager.m_channels[i]->Stop();
  }
}

// FUNCTION: IMPERIALISM 0x005e5020
void TSoundPlayer::SetMasterVolumeFromPercent(short percent) {
  if (this->directSoundInitPendingAt21 != 0) {
    double val = -pow(2.0, (100 - percent) * DAT_0066fad0);
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
void TSoundPlayer::NoOpAudioTickCallback_005e50a0() {}

// Slot 0x07 override — release the two channel peers, then run the base teardown.

// FUNCTION: IMPERIALISM 0x005e50c0
int TSoundPlayer::UpdateLocalizationAudioSlotAndMaybeRefreshVoiceState(int sfxToken, int param_2,
                                                                       int param_3, int param_4) {
  if (g_pSimMgr->preferenceValues[2] == 0) {
    return 0;
  }
  int slot = DAT_006a60f8++;
  if (DAT_006a60f8 > 5) {
    DAT_006a60f8 = 0;
  }
  if (g_soundResourceManager.LoadWaveResourceByNumericIdAndBuildBuffer(sfxToken, slot) != 0) {
    g_soundResourceManager.UpdateLocalizationAudioSlot(slot);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005e5140
int TSoundPlayer::PlaySoundEffect(int sfxToken, int param_2, int param_3) {
  this->UpdateLocalizationAudioSlotAndMaybeRefreshVoiceState(sfxToken, param_2, param_3, 1);
  return 0;
}

// FUNCTION: IMPERIALISM 0x005e51d0
void TSoundPlayer::Free() {
  if (this->runtimePeerAt70 != 0) {
    this->runtimePeerAt70->ReleaseChannelNodeSlot38();
  }
  this->runtimePeerAt70 = 0;
  if (this->runtimePeerAt6c != 0) {
    this->runtimePeerAt6c->ReleaseChannelNodeSlot38();
  }
  this->runtimePeerAt6c = 0;
  ReleaseRuntimeSelectionPeersAndResetOwner_Impl();
  this->ForwardMciCommand808ToDevice();
  TEventHandler::Free();
}
