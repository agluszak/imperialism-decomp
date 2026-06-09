// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#include "game/TControl.h"

extern "C" {
extern int g_nUiResourceEntryDefaultParam0;
extern int g_nUiResourceEntryDefaultParam1;
extern unsigned short g_wUiResourceEntryDefaultParam2;
}

// Real ctor: the TView base ctor runs first (constructs the TView subobject +
// its CString member), then MSVC writes this class's vptr (0x0064a098). Fields
// are member-initializers so they emit in declaration order. No manual vtable
// writes — the // VTABLE: annotation owns 0x0064a098.
// FUNCTION: IMPERIALISM 0x0048e520
TControl::TControl()
    : hasCommandTagResource(1), commandTagResourceByte(0), field68(0), field6C(0), field70(0),
      field74(0), commandTagDefaultParam0(g_nUiResourceEntryDefaultParam0),
      commandTagDefaultParam1(g_nUiResourceEntryDefaultParam1),
      commandTagDefaultParam2(g_wUiResourceEntryDefaultParam2) {}

undefined4 thunk_InvalidateCityDialogRectRegion(void);

void TControl::InvalidateCityDialogRectRegion(struct RECT* rect, int flag) {
  reinterpret_cast<void(__stdcall*)(struct RECT*, int)>(thunk_InvalidateCityDialogRectRegion)(rect,
                                                                                              flag);
}

// Dummy methods
void TControl::vmethod_0104() {}
void TControl::SwitchTab(int arg1, int arg2, int arg3) {}
void TControl::InvokeSlot1A8() {}
void TControl::vmethod_0107() {}
void TControl::vmethod_0108() {}
void TControl::vmethod_0109() {}
void TControl::vmethod_0110() {}
char TControl::GetBoolSlot1BC() {
  return 0;
}
void TControl::vmethod_0112() {}
