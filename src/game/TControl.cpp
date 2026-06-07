// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#include "game/TControl.h"

extern "C" {
extern int g_nUiResourceEntryDefaultParam0;
extern int g_nUiResourceEntryDefaultParam1;
extern unsigned short g_wUiResourceEntryDefaultParam2;
}

#include <new>

// KNOWN LINKER ARTIFACT (heuristic 93): 0x004087fb is a 5-byte incremental-link
// `jmp TControl::TControl` thunk with no clean C++ source equivalent here — not expected
// to match, and the same-TU placement-new inlines the (light, non-EH) ctor so the
// standalone TControl::TControl is not emitted. Both are fixed by converting TControl's
// derived classes to real inheritance (symbolic base-ctor ref). Do NOT chase this thunk.
// FUNCTION: IMPERIALISM 0x004087fb
void TControl::thunk_ConstructUiCommandTagResourceEntryBase() {
  new (this) TControl();
}

// Real ctor: the TView base ctor runs first (constructs the TView subobject +
// its CString member), then MSVC writes this class's vptr (0x0064a098). Fields
// are member-initializers so they emit in declaration order. No manual vtable
// writes — the // VTABLE: annotation owns 0x0064a098.
// FUNCTION: IMPERIALISM 0x0048e520
TControl::TControl()
    : hasCommandTagResource(1),
      commandTagResourceByte(0),
      field68(0),
      field6C(0),
      field70(0),
      field74(0),
      commandTagDefaultParam0(g_nUiResourceEntryDefaultParam0),
      commandTagDefaultParam1(g_nUiResourceEntryDefaultParam1),
      commandTagDefaultParam2(g_wUiResourceEntryDefaultParam2) {}

undefined4 thunk_InvalidateCityDialogRectRegion(void);

void TControl::InvalidateCityDialogRectRegion(struct RECT* rect, int flag) {
  reinterpret_cast<void(__stdcall*)(struct RECT*, int)>(thunk_InvalidateCityDialogRectRegion)(rect, flag);
}
