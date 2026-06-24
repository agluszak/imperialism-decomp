#include "game/TSimMgr.h"

#include "decomp_types.h"
#include "game/TCountry.h"
#include "game/diplomacy_globals.h"

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
void TSimMgr::GetString(short codeGroup, short offset, CString* destString) {
  reinterpret_cast<void(__cdecl*)(short, short, void*)>(LoadUiStringByCodeGroupAndOffset)(
      codeGroup, offset, destString);
}

// FUNCTION: IMPERIALISM 0x0040853f
void* TSimMgr::GetClassDescDynamic() {
  return reinterpret_cast<void*(__cdecl*)(void)>(GetTSimMgrClassNamePointer)();
}

// FUNCTION: IMPERIALISM 0x0057d990
void TSimMgr::SetGlobalTurnStateCodeIfAllowed(int turnStateCode) {
  short nationSlot = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x2e);
  bool allowStateChange = false;
  if (nationSlot == -1) {
    allowStateChange = false;
  } else {
    TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[nationSlot];
    if (terrainDescriptor == 0) {
      allowStateChange = false;
    } else {
      if (nationSlot < 7) {
        short field0e = *reinterpret_cast<short*>(reinterpret_cast<char*>(terrainDescriptor) + 0xe);
        if (terrainDescriptor == 0 || field0e < 100 || field0e > 199) {
          allowStateChange = false;
        } else {
          allowStateChange = true;
        }
        if (allowStateChange) {
          allowStateChange = false;
          goto check_turn_state_code;
        }
      }
      allowStateChange = true;
    }
  }
check_turn_state_code:
  if (!allowStateChange) {
    switch (turnStateCode) {
    case 100:
    case 0x67:
    case 0x68:
    case 0x69:
    case 0x6a:
    case 0x6d:
      return;
    }
  }
  int previousMode = *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x4);
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x4) = turnStateCode;
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x10) = mode;
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0xc) = previousMode;
  PostTurnFlowUiRefresh();
}

void TSimMgr::PostTurnFlowUiRefresh() {}

#pragma optimize("", on)

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
