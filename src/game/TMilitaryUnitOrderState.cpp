#include "game/TMilitaryUnitOrderState.h"

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
  name24.AssignFromPtr(empty);    // -> 0x00605a29
}
