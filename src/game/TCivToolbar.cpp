// TCivToolbar wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 thunk_ConstructUiResourceEntryType4B0C0(void);
undefined4 thunk_DestructEngineerDialogBaseState(void);

namespace {

// GLOBAL: IMPERIALISM 0x667f00
char g_vtblTCivToolbar;
// GLOBAL: IMPERIALISM 0x663100
char g_pClassDescTCivToolbar;

struct CivToolbarState {
  void* vftable;
  char pad_04[0x88];
};

class RuntimeBridge {
public:
  static __inline void ConstructUiResourceEntryType4B0C0(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructUiResourceEntryType4B0C0)(self);
  }
};

} // namespace

// FUNCTION: IMPERIALISM 0x0058ea00
CivToolbarState* __cdecl CreateTCivToolbarInstance(void) {
  CivToolbarState* toolbar = reinterpret_cast<CivToolbarState*>(AllocateWithFallbackHandler(0x8c));
  if (toolbar != 0) {
    RuntimeBridge::ConstructUiResourceEntryType4B0C0(toolbar);
    toolbar->vftable = reinterpret_cast<void*>(&g_vtblTCivToolbar);
  }
  return toolbar;
}

// FUNCTION: IMPERIALISM 0x0058ea80
void* __cdecl GetTCivToolbarClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTCivToolbar);
}

// FUNCTION: IMPERIALISM 0x0058eaa0
CivToolbarState* __fastcall ConstructTCivToolbarBaseState(CivToolbarState* toolbar) {
  RuntimeBridge::ConstructUiResourceEntryType4B0C0(toolbar);
  toolbar->vftable = reinterpret_cast<void*>(&g_vtblTCivToolbar);
  return toolbar;
}

// FUNCTION: IMPERIALISM 0x0058ead0
CivToolbarState* __fastcall DestructTCivToolbarAndMaybeFree(CivToolbarState* toolbar, int unusedEdx,
                                                            unsigned char freeSelfFlag) {
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)toolbar);
  }
  return toolbar;
}
