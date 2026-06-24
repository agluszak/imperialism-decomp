#include "game/TSoundPlayer.h"

#include "game/mfc.h"
#include "game/diplomacy_globals.h"
#include "game/TApplication.h"
#include "game/TSoundChannelNode.h"

#include <new>
#include <math.h>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
// GLOBAL: IMPERIALISM 0x00668a18
CRuntimeClass g_pClassDescTSoundPlayer = {nullptr, 0, 0, nullptr, nullptr};
extern double DAT_0066fad0;
}

extern char PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;

// Random-cue rotation counter at 0x006a4520 (raw audio-state global, not yet in
// symbols.csv). Provisional definition until the owning data block is recovered.
short DAT_006a4520 = 0;

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 InitializeUiResourceEntryBaseHeaderDefaults(void);
undefined4 InitializePacketHeaderFields_Tag20202020(void);
undefined4 thunk_InitializeDirectSoundDeviceAndChannels(void);
undefined4 EnsureCdAudioDeviceHandleInitialized(void);
undefined4 ClearDirectSoundInitPendingAndResetState_Impl(void);
undefined4 ReleaseRuntimeSelectionPeersAndResetOwner_Impl(void);
undefined4 ForwardMciCommand808ToDevice(void);
undefined4 ForwardMciStatusCommand814IgnoreFailure(void);
undefined4 RequestAudioPresetChangeWithDeferredApply(void);
undefined4 SelectAndScheduleRandomAudioCue(void);
void __fastcall DestructTSoundPlayerBaseState(TSoundPlayer* player);

static int DAT_006a60f8 = 0;

undefined4 LoadWaveResourceByNumericIdAndBuildBuffer(void);
undefined4 UpdateLocalizationAudioSlotAndMaybeRefreshVoiceState_Impl(void);
undefined4 WrapperFor_ftol_At005e5020_Impl(void);

namespace {
int CallLoadWaveResource(int sfxToken, int slot) {
  typedef int (__fastcall *LoadWaveFunc)(void*, int, int, int);
  return reinterpret_cast<LoadWaveFunc>(LoadWaveResourceByNumericIdAndBuildBuffer)(reinterpret_cast<void*>(0x6a60c0), 0, sfxToken, slot);
}

void CallUpdateLocalizationAudio(int slot) {
  typedef void (__fastcall *UpdateLocFunc)(void*, int, int);
  reinterpret_cast<UpdateLocFunc>(UpdateLocalizationAudioSlotAndMaybeRefreshVoiceState_Impl)(reinterpret_cast<void*>(0x6a60c0), 0, slot);
}

void CallWrapperForFtolImpl(int volume) {
  typedef void (__fastcall *FtolImplFunc)(void*, int, int);
  reinterpret_cast<FtolImplFunc>(WrapperFor_ftol_At005e5020_Impl)(reinterpret_cast<void*>(0x6a60c0), 0, volume);
}
} // namespace



// FUNCTION: IMPERIALISM 0x005932b0
TSoundPlayer* CreateTSoundPlayerInstance(void) {
  void* storage = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x84));
  if (storage == 0) {
    return 0;
  }
  return new (storage) TSoundPlayer();
}



// FUNCTION: IMPERIALISM 0x00593350
CRuntimeClass* TSoundPlayer::GetRuntimeClass() const {
  return &g_pClassDescTSoundPlayer;
}

// Fork-class construction: the binary calls InitializeUiResourceEntryBaseHeaderDefaults
// (TEventHandler field defaults) then installs the TSoundPlayer vptr — same pattern as
// TApplication @ 0x00486760, not TControl::TControl().
TSoundPlayer::TSoundPlayer() {
  typedef void(__fastcall * InitHeader)(undefined4 * self);
  reinterpret_cast<InitHeader>(InitializeUiResourceEntryBaseHeaderDefaults)(
      reinterpret_cast<undefined4*>(this));
  this->runtimePeerAt6c = 0;
  this->runtimePeerAt70 = 0;
  this->stateByte78 = 0;
  this->stateByte79 = 0;
  this->stateByte7a = 0;
  this->stateDword7c = 0;
}



// FUNCTION: IMPERIALISM 0x00593370
TSoundPlayer* __fastcall ConstructTSoundPlayerBaseState(TSoundPlayer* storage) {
  return new (storage) TSoundPlayer();
}

// SYNTHETIC: IMPERIALISM 0x005933b0
// TSoundPlayer::`scalar deleting destructor'

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// Partial teardown writes the runtime-object base vptr, symmetric with header-only
// construction (InitializeUiResourceEntryBaseHeaderDefaults, not ~TEventHandler()).


// FUNCTION: IMPERIALISM 0x005933e0
void __fastcall DestructTSoundPlayerBaseState(TSoundPlayer* player) {
  *reinterpret_cast<void**>(player) = &PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;
}

// Slot 0x13 override — pump the audio playback state machine / schedule random cues.


// FUNCTION: IMPERIALISM 0x00593400
char TSoundPlayer::CanHandleCityDialogActionFalse(int action) {
  (void)action;
  if (*reinterpret_cast<short*>(reinterpret_cast<char*>(g_pLocalizationTable) + 0x4e) == 0) {
    if (this->stateByte78 != 0) {
      if (static_cast<char>(ForwardMciStatusCommand814IgnoreFailure()) != 0) {
        ForwardMciCommand808ToDevice();
      }
      this->stateByte78 = 0;
    }
    return 0;
  }

  if (this->stateByte80 != 0 && this->stateDword7c == 0) {
    int n = static_cast<TSoundChannelNode*>(this->runtimePeerAt6c)->QueryPendingPlaybackCountSlot28();
    if (n > 0) {
      static_cast<TSoundChannelNode*>(this->runtimePeerAt6c)->StopOrResetActivePlaybackSlot30();
      static_cast<TSoundChannelNode*>(this->runtimePeerAt70)->StopOrResetActivePlaybackSlot30();
    }
    if (this->stateByte78 != 0) {
      ForwardMciCommand808ToDevice();
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

  int n = static_cast<TSoundChannelNode*>(this->runtimePeerAt6c)->QueryPendingPlaybackCountSlot28();
  if (n > 0) {
    DAT_006a4520 = static_cast<short>(DAT_006a4520 + 1);
    if (DAT_006a4520 > 4) {
      DAT_006a4520 = 0;
      if (static_cast<char>(ForwardMciStatusCommand814IgnoreFailure()) == 0) {
        SelectAndScheduleRandomAudioCue();
      }
    }
  }
  return 0;
}

// Slot 0x25 — allocate the two sound-channel peer objects and bring up DirectSound.


// FUNCTION: IMPERIALISM 0x005e4e70
void TSoundPlayer::InitializeSoundSubsystemAndAllocateChannelLists(int param_1) {
  InitializePacketHeaderFields_Tag20202020();
  char ok = static_cast<char>(thunk_InitializeDirectSoundDeviceAndChannels());
  this->directSoundInitOkAt20 = static_cast<unsigned char>(ok);
  if (ok == 0) {
    this->ClearDirectSoundInitPendingAndResetState();
  } else {
    this->RequestDirectSoundInitIfAllowed();
  }

  int* node = reinterpret_cast<int*>(AllocateWithFallbackHandler(0x1c));
  if (node != 0) {
    node[3] = 0;
    node[4] = 0;
    node[2] = 0;
    node[1] = 0;
    node[5] = 0;
    node[6] = 10;
    node[0] = 0; // channel-node vtable &PTR_GetCObjectRuntimeClass_00650a08 (unrecovered)
  }
  this->runtimePeerAt6c = node;

  node = reinterpret_cast<int*>(AllocateWithFallbackHandler(0x1c));
  if (node != 0) {
    node[3] = 0;
    node[4] = 0;
    node[2] = 0;
    node[1] = 0;
    node[5] = 0;
    node[6] = 10;
    node[0] = 0; // channel-node vtable &PTR_GetCObjectRuntimeClass_00650a08 (unrecovered)
  }
  this->runtimePeerAt70 = node;

  this->fieldShort74 = 0;
  EnsureCdAudioDeviceHandleInitialized();
  this->field10 = param_1;
  // Notify the global UI root controller via its slot 0x29 (peer class unrecovered).
  reinterpret_cast<TApplication*>(g_pGlobalUiRootController)
      ->InsertOrRemoveTrackedEntry(reinterpret_cast<int>(this), 1);
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
  for (int offset = 4; offset < 0x1c; offset += 4) {
    void* obj = *reinterpret_cast<void**>(0x006a60c0 + offset);
    typedef void (__stdcall *VirtualFunc)(void*);
    VirtualFunc* vtable = *reinterpret_cast<VirtualFunc**>(obj);
    vtable[18](obj);
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
    CallWrapperForFtolImpl(volume);
  }
}

// FUNCTION: IMPERIALISM 0x005e50a0
void TSoundPlayer::NoOpAudioTickCallback_005e50a0() {
}

// Slot 0x07 override — release the two channel peers, then run the base teardown.


// FUNCTION: IMPERIALISM 0x005e50c0
int TSoundPlayer::UpdateLocalizationAudioSlotAndMaybeRefreshVoiceState(int sfxToken, int param_2, int param_3, int param_4) {
  if (*reinterpret_cast<short*>(reinterpret_cast<char*>(g_pLocalizationTable) + 0x4c) == 0) {
    return 0;
  }
  int slot = DAT_006a60f8++;
  if (DAT_006a60f8 > 5) {
    DAT_006a60f8 = 0;
  }
  if (CallLoadWaveResource(sfxToken, slot) != 0) {
    CallUpdateLocalizationAudio(slot);
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
    // Peer class (vtable 0x650a08) unrecovered — slot 0x38 release.
    static_cast<TSoundChannelNode*>(this->runtimePeerAt70)->ReleaseChannelNodeSlot38();
  }
  this->runtimePeerAt70 = 0;
  if (this->runtimePeerAt6c != 0) {
    static_cast<TSoundChannelNode*>(this->runtimePeerAt6c)->ReleaseChannelNodeSlot38();
  }
  this->runtimePeerAt6c = 0;
  ReleaseRuntimeSelectionPeersAndResetOwner_Impl();
  ForwardMciCommand808ToDevice();
  TEventHandler::Free();
}

