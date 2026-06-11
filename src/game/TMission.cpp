#include "game/TMission.h"

#include "decomp_types.h"

undefined4 thunk_CreateMissionObjectByKindAndNodeContext(void);

void* TMission::CreateByKindAndNodeContext(int sourceNation, int missionKind, int arg2, int arg3,
                                           int arg4) {
  return reinterpret_cast<void*(__cdecl*)(int, int, int, int, int)>(
      thunk_CreateMissionObjectByKindAndNodeContext)(sourceNation, missionKind, arg2, arg3, arg4);
}
