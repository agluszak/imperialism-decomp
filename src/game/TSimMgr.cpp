#include "game/TSimMgr.h"

#include "decomp_types.h"

undefined4 GetTSimMgrClassNamePointer(void);
undefined4 PostMainWindowCommand100ForTurnFlow(void);
undefined4 LoadUiStringByCodeGroupAndOffset(void);

// FUNCTION: IMPERIALISM 0x004021ee
short TSimMgr::GetTurnTickSlot3C() {
  return quarterGateTick2c;
}

// FUNCTION: IMPERIALISM 0x00402d1a
void TSimMgr::IncrementQuarterGateTick2C() {
  ++quarterGateTick2c;
}

// FUNCTION: IMPERIALISM 0x004053d5
void TSimMgr::CallSlot44() {
  reinterpret_cast<void(__cdecl*)(void)>(PostMainWindowCommand100ForTurnFlow)();
}

// FUNCTION: IMPERIALISM 0x00407c1b
void TSimMgr::GetString(short codeGroup, short offset, void* destString) {
  reinterpret_cast<void(__cdecl*)(short, short, void*)>(LoadUiStringByCodeGroupAndOffset)(
      codeGroup, offset, destString);
}

// FUNCTION: IMPERIALISM 0x0040853f
void* TSimMgr::GetClassDescDynamic() {
  return reinterpret_cast<void*(__cdecl*)(void)>(GetTSimMgrClassNamePointer)();
}

// FUNCTION: IMPERIALISM 0x005811e0
int TSimMgr::GetField30(void) {
  return field30;
}

// FUNCTION: IMPERIALISM 0x00581200
#pragma optimize("y", on)
void TSimMgr::DecrementField30Value() {
  --field30;
}
#pragma optimize("", on)

#pragma optimize("", on)
