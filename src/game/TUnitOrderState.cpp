#include "game/TUnitOrderState.h"
#include <windows.h>
#include "decomp_types.h"
#include "game/GameAssert.h"

extern "C" void* g_apNationStates[];
extern "C" void* g_apTerrainTypeDescriptorTable[];
extern "C" void* g_pLocalizationTable;
undefined4 thunk_TemporarilyClearAndRestoreUiInvalidationFlag(void);

struct TUnitOrderOwnerManagerView {
  virtual void s00() = 0;
  virtual void s01() = 0;
  virtual void s02() = 0;
  virtual void s03() = 0;
  virtual void s04() = 0;
  virtual void s05() = 0;
  virtual void s06() = 0;
  virtual void s07() = 0;
  virtual void s08() = 0;
  virtual void s09() = 0;
  virtual void s10() = 0;
  virtual void s11() = 0;
  virtual void VTableSlot12(TUnitOrderState* order) = 0; // slot 12 at 0x30
};

// FUNCTION: IMPERIALISM 0x00402eeb
void TUnitOrderState::thunk_RegisterUnitOrderWithOwnerManager(short nOrderType, int pOwnerContext,
                                                              short nOrderOwnerNationId,
                                                              short arg3) {
  this->RegisterUnitOrderWithOwnerManager(nOrderType, pOwnerContext, nOrderOwnerNationId, arg3);
}

// Original is FPO (frame-pointer omitted); force /Oy to match the esp-relative
// argument loads (heuristic 88).
#pragma optimize("y", on)
// FUNCTION: IMPERIALISM 0x005c2530
void TUnitOrderState::RegisterUnitOrderWithOwnerManager(short nOrderType, int pOwnerContext,
                                                        short nOrderOwnerNationId, short arg3) {
  this->orderType = nOrderType;
  this->field_8 = 0;
  this->VTableSlot10(pOwnerContext);

  TUnitOrderOwnerManagerView* ownerManager = 0;
  if (this->field_1C != 0) {
    void* terrain = g_apTerrainTypeDescriptorTable[nOrderOwnerNationId];
    ownerManager =
        *reinterpret_cast<TUnitOrderOwnerManagerView**>(reinterpret_cast<char*>(terrain) + 0x44);
  } else {
    void* nation = g_apNationStates[nOrderOwnerNationId];
    ownerManager =
        *reinterpret_cast<TUnitOrderOwnerManagerView**>(reinterpret_cast<char*>(nation) + 0x89c);
  }

  if (ownerManager == 0) {
    GAME_FAIL_NIL_POINTER();
    reinterpret_cast<void(__cdecl*)(const char*, int)>(
        thunk_TemporarilyClearAndRestoreUiInvalidationFlag)("D:\\Ambit\\Cross\\UUnit.cpp", 287);
  }

  ownerManager->VTableSlot12(this);

  this->field_18 = nOrderOwnerNationId;
  this->field_1A = arg3;
  this->field_C = static_cast<short>(-1);

  void* const locTable = g_pLocalizationTable;
  int* pLoc = reinterpret_cast<int*>(locTable);
  int uniqueId = pLoc[25] + 1;
  pLoc[25] = uniqueId;
  this->field_20 = uniqueId;
}
#pragma optimize("", on)
