// TSoundPlayer wrapper block extracted from Ghidra autogen.

#include "decomp_types.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 thunk_InitializeUiResourceEntryBaseHeaderDefaults(void);

namespace {

char g_vtblTSoundPlayer;
char g_pClassDescTSoundPlayer;
char PTR_GetCObjectRuntimeClass_0066fec4;

struct SoundPlayerState {
  void *vftable;
  char pad_04[0x68];
  void *runtimePeerAt6c;
  void *runtimePeerAt70;
  char pad_74[4];
  unsigned char stateByte78;
  unsigned char stateByte79;
  unsigned char stateByte7a;
  unsigned char pad_7b;
  int stateDword7c;
  char pad_80[4];
};

class RuntimeBridge {
public:
  static __inline void ConstructUiResourceEntryBaseHeaderDefaults(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(
        ::thunk_InitializeUiResourceEntryBaseHeaderDefaults)(self);
  }
};

}  // namespace

void __fastcall DestructTSoundPlayerBaseState(SoundPlayerState *player);


// FUNCTION: IMPERIALISM 0x005932B0
SoundPlayerState *__cdecl CreateTSoundPlayerInstance(void)
{
  SoundPlayerState *player = reinterpret_cast<SoundPlayerState *>(
      AllocateWithFallbackHandler(0x84));
  if (player != 0) {
    RuntimeBridge::ConstructUiResourceEntryBaseHeaderDefaults(player);
    player->vftable = reinterpret_cast<void *>(&g_vtblTSoundPlayer);
    player->runtimePeerAt6c = 0;
    player->runtimePeerAt70 = 0;
    player->stateByte78 = 0;
    player->stateByte79 = 0;
    player->stateByte7a = 0;
    player->stateDword7c = 0;
  }
  return player;
}



// FUNCTION: IMPERIALISM 0x00593350
void *__cdecl GetTSoundPlayerClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTSoundPlayer);
}



// FUNCTION: IMPERIALISM 0x00593370
SoundPlayerState *__fastcall ConstructTSoundPlayerBaseState(SoundPlayerState *player)
{
  RuntimeBridge::ConstructUiResourceEntryBaseHeaderDefaults(player);
  player->vftable = reinterpret_cast<void *>(&g_vtblTSoundPlayer);
  player->runtimePeerAt6c = 0;
  player->runtimePeerAt70 = 0;
  player->stateByte78 = 0;
  player->stateByte79 = 0;
  player->stateByte7a = 0;
  player->stateDword7c = 0;
  return player;
}



// FUNCTION: IMPERIALISM 0x005933B0
SoundPlayerState *__fastcall DestructTSoundPlayerAndMaybeFree(
    SoundPlayerState *player, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  DestructTSoundPlayerBaseState(player);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)player);
  }
  return player;
}



// FUNCTION: IMPERIALISM 0x005933E0
void __fastcall DestructTSoundPlayerBaseState(SoundPlayerState *player)
{
  player->vftable = reinterpret_cast<void *>(&PTR_GetCObjectRuntimeClass_0066fec4);
}


// GHIDRA_FUNCTION IMPERIALISM 0x005E51D0
// GHIDRA_NAME TSoundPlayer::ReleaseRuntimeSelectionPeersAndResetOwner
// GHIDRA_PROTO void __thiscall ReleaseRuntimeSelectionPeersAndResetOwner(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Releases peer/session pointers at +0x6C/+0x70, performs runtime cleanup callbacks, then clears runtime selection owner context.
// GHIDRA_COMMENT_END

/* Releases peer/session pointers at +0x6C/+0x70, performs runtime cleanup callbacks, then clears
   runtime selection owner context. */

void __thiscall TSoundPlayer::ReleaseRuntimeSelectionPeersAndResetOwner(TSoundPlayer *this)

{
  if (*(int **)(this + 0x70) != (int *)0x0) {
    (**(code **)(**(int **)(this + 0x70) + 0x38))();
  }
  *(undefined4 *)(this + 0x70) = 0;
  if (*(int **)(this + 0x6c) != (int *)0x0) {
    (**(code **)(**(int **)(this + 0x6c) + 0x38))();
  }
  *(undefined4 *)(this + 0x6c) = 0;
  ReleaseRuntimeSelectionPeersAndResetOwner_Impl();
  ForwardMciCommand808ToDevice();
  thunk_ReleaseRuntimeSelectionOwnerAndDestroyObject();
  return;
}

