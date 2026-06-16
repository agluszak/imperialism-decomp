#include "game/TMilitaryUnitOrderState.h"

#include "game/TAdmiral.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// Military land-unit recruit-order ctor. The inlined TUnitOrderState base ctor writes
// the base vptr (0x0066ee18) + base fields (incl. field_1C=0); the derived scalar fields
// and the CString member name24 are member-initializers so they emit in declaration order
// before the body, with MSVC writing the derived vptr (0x0066eea8) around them. The body
// overrides field_1C=1 and assigns the empty string into name24. The non-trivial ~CString
// on the member + the temporary are what make MSVC emit the EH unwind frame + uStack
// partial-construction state markers.
// FUNCTION: IMPERIALISM 0x005c2df0
TMilitaryUnitOrderState::TMilitaryUnitOrderState()
    : name24(), field_38(0), field_3A(0), field_3C(0), field_40(0) {
  field_1C = 1;
  field_34 = 0x1f4;
  field_36 = 0;
  CString empty(g_szEmptyString); // temp -> 0x00605950, ~ -> 0x006058e2
  name24 = empty;                 // -> 0x00605a29 CString::operator=
}

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
        g_apTerrainTypeDescriptorTable[nationSlot], &name24);
  }
  CopyUnitCurrentTileIntoOrderTargets();
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

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
