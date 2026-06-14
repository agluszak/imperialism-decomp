#include "game/TSoundPlayer.h"

#include "game/CRuntimeClass.h"

#include <new>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
// GLOBAL: IMPERIALISM 0x00668a18
CRuntimeClass g_pClassDescTSoundPlayer = {0};
}

extern char PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 InitializeUiResourceEntryBaseHeaderDefaults(void);

// FUNCTION: IMPERIALISM 0x00593370
TSoundPlayer* __fastcall ConstructTSoundPlayerBaseState(TSoundPlayer* storage) {
  return new (storage) TSoundPlayer();
}

// FUNCTION: IMPERIALISM 0x005932b0
TSoundPlayer* CreateTSoundPlayerInstance(void) {
  void* storage = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x84));
  if (storage == 0) {
    return 0;
  }
  return new (storage) TSoundPlayer();
}

// FUNCTION: IMPERIALISM 0x00593350
CRuntimeClass* TSoundPlayer::GetRuntimeClass() {
  return &g_pClassDescTSoundPlayer;
}

// Fork-class construction: the binary calls InitializeUiResourceEntryBaseHeaderDefaults
// (TEventHandler field defaults) then installs the TSoundPlayer vptr — same pattern as
// ApplicationUiRootController @ 0x00486760, not TControl::TControl().
TSoundPlayer::TSoundPlayer() {
  typedef void(__fastcall * InitHeader)(undefined4* self);
  reinterpret_cast<InitHeader>(InitializeUiResourceEntryBaseHeaderDefaults)(
      reinterpret_cast<undefined4*>(this));
  this->runtimePeerAt6c = 0;
  this->runtimePeerAt70 = 0;
  this->stateByte78 = 0;
  this->stateByte79 = 0;
  this->stateByte7a = 0;
  this->stateDword7c = 0;
}

void TSoundPlayer::SoundPlayerSlot25_Provisional() {}
void TSoundPlayer::SoundPlayerSlot26_Provisional() {}
void TSoundPlayer::SoundPlayerSlot27_Provisional() {}
void TSoundPlayer::SoundPlayerSlot28_Provisional() {}
void TSoundPlayer::SoundPlayerSlot29_Provisional() {}

// Partial teardown writes the runtime-object base vptr, symmetric with header-only
// construction (InitializeUiResourceEntryBaseHeaderDefaults, not ~TEventHandler()).
// FUNCTION: IMPERIALISM 0x005933e0
void __fastcall DestructTSoundPlayerBaseState(TSoundPlayer* player) {
  *reinterpret_cast<void**>(player) = &PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;
}

// FUNCTION: IMPERIALISM 0x005933b0
TSoundPlayer* __fastcall DestructTSoundPlayerAndMaybeFree(TSoundPlayer* player, int unusedEdx,
                                                           unsigned char freeSelfFlag) {
  (void)unusedEdx;
  DestructTSoundPlayerBaseState(player);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)player);
  }
  return player;
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
