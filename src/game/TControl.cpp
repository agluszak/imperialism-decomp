// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#include "game/TControl.h"

namespace {

const unsigned int kAddrVtblTControl = 0x0064A098;
const unsigned int kAddrUiResourceEntryDefaultParam0 = 0x006A1D90;
const unsigned int kAddrUiResourceEntryDefaultParam1 = 0x006A1D94;
const unsigned int kAddrUiResourceEntryDefaultParam2 = 0x006A1D98;

} // namespace

// FUNCTION: IMPERIALISM 0x004087fb
void TControl::thunk_ConstructUiCommandTagResourceEntryBase() {
  ConstructUiCommandTagResourceEntryBase();
}

// FUNCTION: IMPERIALISM 0x0048e520
void TControl::ConstructUiCommandTagResourceEntryBase() {
  TView::thunk_ConstructUiResourceEntryBase();
  hasCommandTagResource = 1;
  commandTagResourceByte = 0;
  field68 = 0;
  field6C = 0;
  field70 = 0;
  field74 = 0;
  commandTagDefaultParam0 = *reinterpret_cast<int*>(kAddrUiResourceEntryDefaultParam0);
  commandTagDefaultParam1 = *reinterpret_cast<int*>(kAddrUiResourceEntryDefaultParam1);
  vftable = reinterpret_cast<void*>(kAddrVtblTControl);
  commandTagDefaultParam2 = *reinterpret_cast<unsigned short*>(kAddrUiResourceEntryDefaultParam2);
}
