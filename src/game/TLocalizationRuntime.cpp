#include "game/TLocalizationRuntime.h"

#include "decomp_types.h"

undefined4 GetTSimMgrClassNamePointer(void);
undefined4 PostMainWindowCommand100ForTurnFlow(void);
undefined4 LoadUiStringByCodeGroupAndOffset(void);

// FUNCTION: IMPERIALISM 0x0040853f
void* TLocalizationRuntime::GetClassDescDynamic() {
  return reinterpret_cast<void*(__cdecl*)(void)>(GetTSimMgrClassNamePointer)();
}

// FUNCTION: IMPERIALISM 0x004021ee
short TLocalizationRuntime::GetTurnTickSlot3C() {
  return quarterGateTick2c;
}

// FUNCTION: IMPERIALISM 0x00402d1a
void TLocalizationRuntime::IncrementQuarterGateTick2C() {
  ++quarterGateTick2c;
}

// FUNCTION: IMPERIALISM 0x004053d5
void TLocalizationRuntime::CallSlot44() {
  reinterpret_cast<void(__cdecl*)(void)>(PostMainWindowCommand100ForTurnFlow)();
}

// FUNCTION: IMPERIALISM 0x00407c1b
void TLocalizationRuntime::GetString(short codeGroup, short offset, void* destString) {
  reinterpret_cast<void(__cdecl*)(short, short, void*)>(LoadUiStringByCodeGroupAndOffset)(
      codeGroup, offset, destString);
}

// FUNCTION: IMPERIALISM 0x00581200
#pragma optimize("y", on)
void TLocalizationRuntime::DecrementField30Value() {
  --field30;
}
#pragma optimize("", on)

#pragma optimize("", on)
