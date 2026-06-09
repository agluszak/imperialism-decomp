// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#include "game/TControl.h"
#include "game/ui_widget_thunks.h"

#include <new>

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

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0048e590
// TControl::`scalar deleting destructor'

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

// FUNCTION: IMPERIALISM 0x0058e440
void TControl::OrphanTiny_SetDwordEcxOffset_60_0058e440(int value) {
  hasCommandTagResource = value;
}

// FUNCTION: IMPERIALISM 0x0058c7c0
void TControl::WrapperFor_thunk_HandleCursorHoverSelectionByChildHitTestAndFallback_At0058c7c0(
    int* cursorPoint, int hitArg) {
  if (IsActionable() != '\0') {
    if (cursorPoint[1] < field38 / 2) {
      field4e = 0x100;
      reinterpret_cast<void(__fastcall*)(TControl*, int, int*, int)>(
          thunk_HandleCursorHoverSelectionByChildHitTestAndFallback)(this, 0, cursorPoint, hitArg);
      return;
    }
    field4e = (short)0xffff;
  }
  reinterpret_cast<void(__fastcall*)(TControl*, int, int*, int)>(
      thunk_HandleCursorHoverSelectionByChildHitTestAndFallback)(this, 0, cursorPoint, hitArg);
}

// KNOWN LINKER ARTIFACT: 0x004087fb is `jmp TControl::TControl`.
// FUNCTION: IMPERIALISM 0x004087fb
void __fastcall ConstructTControlBaseStateThunk(TControl* self) {
  new (self) TControl();
}
