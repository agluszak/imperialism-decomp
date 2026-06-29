#include "game/TSoundPlayer.h"

#include "game/mfc.h"
#include "game/global_data_tables.h"
#include "game/TSimMgr.h"
#include "game/TApplication.h"
#include "game/TSoundChannelNode.h"
#include "game/TSoundResourceManager.h"

#include <new>
#include <math.h>


extern char PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;
// Random-cue rotation counter at 0x006a4520 (raw audio-state global, not yet in
// symbols.csv). Provisional definition until the owning data block is recovered.
short DAT_006a4520 = 0;

undefined4 thunk_InitializeDirectSoundDeviceAndChannels(void);
undefined4 EnsureCdAudioDeviceHandleInitialized(void);
undefined4 ForwardMciCommand808ToDevice(void);
undefined4 ForwardMciStatusCommand814IgnoreFailure(void);
undefined4 ClearDirectSoundInitPendingAndResetState_Impl(void);
undefined4 ReleaseRuntimeSelectionPeersAndResetOwner_Impl(void);
undefined4 RequestAudioPresetChangeWithDeferredApply(void);
undefined4 SelectAndScheduleRandomAudioCue(void);

void __fastcall DestructTSoundPlayerBaseState(TSoundPlayer* player);

static int DAT_006a60f8 = 0;

// FUNCTION: IMPERIALISM 0x005932b0
TSoundPlayer* CreateTSoundPlayerInstance(void) {
  return new TSoundPlayer();
}
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
  ::EnsureCdAudioDeviceHandleInitialized();
}

void TSoundPlayer::ForwardMciCommand808ToDevice() {
  ::ForwardMciCommand808ToDevice();
}

BOOL TSoundPlayer::ForwardMciStatusCommand814IgnoreFailure() {
  return static_cast<BOOL>(::ForwardMciStatusCommand814IgnoreFailure());
}

// Slot 0x13 override — pump the audio playback state machine / schedule random cues.

// FUNCTION: IMPERIALISM 0x00593400
char TSoundPlayer::CanHandleCityDialogActionFalse(int action) {
  (void)action;
  if (g_pLocalizationTable->preferenceValues[5] == 0) {
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
    RequestAudioPresetChangeWithDeferredApply();
    this->fieldShort76 = 0;
    return 0;
  }

  int n = this->runtimePeerAt6c->QueryPendingPlaybackCountSlot28();
  if (n > 0) {
    DAT_006a4520 = static_cast<short>(DAT_006a4520 + 1);
    if (DAT_006a4520 > 4) {
      DAT_006a4520 = 0;
      if (static_cast<char>(this->ForwardMciStatusCommand814IgnoreFailure()) == 0) {
        SelectAndScheduleRandomAudioCue();
      }
    }
  }
  return 0;
}

// Slot 0x25 — allocate the two sound-channel peer objects and bring up DirectSound.

// FUNCTION: IMPERIALISM 0x005e4e70
void TSoundPlayer::InitializeSoundSubsystemAndAllocateChannelLists(int param_1) {
  this->InitializePacketHeaderFields_Tag20202020(0);
  char ok = static_cast<char>(thunk_InitializeDirectSoundDeviceAndChannels());
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
  g_pGlobalUiRootController->InsertOrRemoveTrackedEntry(reinterpret_cast<int>(this), 1);
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
    thunk_InitializeDirectSoundDeviceAndChannels();
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
  ClearDirectSoundInitPendingAndResetState_Impl();
}

// FUNCTION: IMPERIALISM 0x005e4ff0
void TSoundPlayer::NotifyGlobalAudioObjectsViaVslot48() {
  for (int offset = 4; offset < 28; offset += 4) {
    TAudioChannel* obj = *reinterpret_cast<TAudioChannel**>(
        reinterpret_cast<char*>(&g_soundResourceManager) + offset);
    obj->NotifyAudioObjectSlot48();
  }
}

// FUNCTION: IMPERIALISM 0x005e5020
void TSoundPlayer::WrapperFor_ftol_At005e5020(short param_1) {
  if (this->directSoundInitPendingAt21 != 0) {
    double val = -pow(2.0, (100 - param_1) * DAT_0066fad0);
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
  if (g_pLocalizationTable->preferenceValues[4] == 0) {
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
void TSoundPlayer::PlaySoundEffect(int sfxToken, int param_2, int param_3) {
  this->UpdateLocalizationAudioSlotAndMaybeRefreshVoiceState(sfxToken, param_2, param_3, 1);
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
