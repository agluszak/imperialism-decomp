// TWarningView wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 thunk_ConstructPictureResourceEntryBase(void);
undefined4 thunk_DestructCityDialogSharedBaseState(void);

namespace {

char g_vtblTWarningView;
char g_pClassDescTWarningView;

struct WarningViewState {
  void* vftable;
  char pad_04[0x90];
};

class RuntimeBridge {
public:
  static __inline void ConstructPictureResourceEntryBase(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructPictureResourceEntryBase)(self);
  }

  static __inline void DestructCityDialogSharedBaseState(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_DestructCityDialogSharedBaseState)(self);
  }
};

} // namespace

// FUNCTION: IMPERIALISM 0x00592860
WarningViewState* __cdecl CreateTWarningViewInstance(void) {
  WarningViewState* view = reinterpret_cast<WarningViewState*>(AllocateWithFallbackHandler(0x94));
  if (view != 0) {
    RuntimeBridge::ConstructPictureResourceEntryBase(view);
    view->vftable = reinterpret_cast<void*>(&g_vtblTWarningView);
  }
  return view;
}

// FUNCTION: IMPERIALISM 0x005928E0
void* __cdecl GetTWarningViewClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTWarningView);
}

// FUNCTION: IMPERIALISM 0x00592900
WarningViewState* __fastcall ConstructTWarningViewBaseState(WarningViewState* view) {
  RuntimeBridge::ConstructPictureResourceEntryBase(view);
  view->vftable = reinterpret_cast<void*>(&g_vtblTWarningView);
  return view;
}

// FUNCTION: IMPERIALISM 0x00592930
WarningViewState* __fastcall DestructTWarningViewAndMaybeFree(WarningViewState* view, int unusedEdx,
                                                              unsigned char freeSelfFlag) {
  (void)unusedEdx;
  RuntimeBridge::DestructCityDialogSharedBaseState(view);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)view);
  }
  return view;
}
