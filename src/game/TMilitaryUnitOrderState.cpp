#include "game/TMilitaryUnitOrderState.h"

#include "game/TAdmiral.h"
#include "game/TStream.h"

extern "C" char g_pClassDescTMilitaryUnitOrderState = 0;

// FUNCTION: IMPERIALISM 0x005c2dd0
CRuntimeClass* TMilitaryUnitOrderState::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(&g_pClassDescTMilitaryUnitOrderState);
}

// FUNCTION: IMPERIALISM 0x005c2df0
TMilitaryUnitOrderState::TMilitaryUnitOrderState()
    : name24(), field_38(0), field_3A(0), field_3C(0), field_40(0) {
  field_1C = 1;
  field_34 = 0x1f4;
  field_36 = 0;
  CString empty(g_szEmptyString); // temp -> 0x00605950, ~ -> 0x006058e2
  name24 = empty;                 // -> 0x00605a29 CString::operator=
}

// SYNTHETIC: IMPERIALISM 0x005c2ed0
// TMilitaryUnitOrderState::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005c2f00
TMilitaryUnitOrderState::~TMilitaryUnitOrderState() {}

// FUNCTION: IMPERIALISM 0x005c2f50
void TMilitaryUnitOrderState::InitializeRecruitOrderState(short capValue, int nodeContext,
                                                          short nationSlot) {
  field_1C = 1;
  field_6 = static_cast<short>(-1);
  RegisterUnitOrderWithOwnerManager(capValue, nodeContext, nationSlot, 0);
  field_36 = static_cast<short>(
      (static_cast<int>(capValue) + (static_cast<int>(capValue) >> 31 & 7)) >> 3);
  if (capValue > 0x1b) {
    TAdmiral::GenerateMappedFlavorTextByNationSlotField0C(
        static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[nationSlot]), &name24);
  }
  CopyUnitCurrentTileIntoOrderTargets();
}

// FUNCTION: IMPERIALISM 0x005c2fd0
void TMilitaryUnitOrderState::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x005c30a0
void TMilitaryUnitOrderState::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x005c3190
void TMilitaryUnitOrderState::CopyUnitCurrentTileIntoOrderTargets() {
  short tile = field_6;
  short* cursor = reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x2e);
  int remaining = 3;
  do {
    cursor[-3] = tile;
    *cursor = tile;
    ++cursor;
    --remaining;
  } while (remaining != 0);
}

// FUNCTION: IMPERIALISM 0x005c31c0
void TMilitaryUnitOrderState::DetachUnitOrderFromOwnerAndReset() {}

// FUNCTION: IMPERIALISM 0x005c3200
void TMilitaryUnitOrderState::VTableSlot10(int pOwnerContext) {
  (void)pOwnerContext;
}
