#include "game/TSoundPlayer.h"

#include "game/CRuntimeClass.h"
#include "game/diplomacy_globals.h"
#include "game/vcall_runtime.h"

#include <new>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
// GLOBAL: IMPERIALISM 0x00668a18
CRuntimeClass g_pClassDescTSoundPlayer = {nullptr, 0, 0, nullptr, nullptr};
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
// ApplicationUiRootController @ 0x00486760, not TControl::TControl().
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
    int n = vcall_runtime::fastcall0<int>(this->runtimePeerAt6c, 0x0a);
    if (n > 0) {
      vcall_runtime::fastcall0<int>(this->runtimePeerAt6c, 0x0c);
      vcall_runtime::fastcall0<int>(this->runtimePeerAt70, 0x0c);
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

  int n = vcall_runtime::fastcall0<int>(this->runtimePeerAt6c, 0x0a);
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
  vcall_runtime::fastcall0<int>(g_pGlobalUiRootController, 0x29);
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

// Slot 0x07 override — release the two channel peers, then run the base teardown.
// FUNCTION: IMPERIALISM 0x005e51d0
void TSoundPlayer::ReleaseRuntimeSelectionOwnerAndDestroyObject() {
  if (this->runtimePeerAt70 != 0) {
    // Peer class (vtable 0x650a08) unrecovered — slot 0x38 release.
    vcall_runtime::fastcall0<int>(this->runtimePeerAt70, 0x0e);
  }
  this->runtimePeerAt70 = 0;
  if (this->runtimePeerAt6c != 0) {
    vcall_runtime::fastcall0<int>(this->runtimePeerAt6c, 0x0e);
  }
  this->runtimePeerAt6c = 0;
  ReleaseRuntimeSelectionPeersAndResetOwner_Impl();
  ForwardMciCommand808ToDevice();
  TEventHandler::ReleaseRuntimeSelectionOwnerAndDestroyObject();
}
