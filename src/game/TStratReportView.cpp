// TStratReportView wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 thunk_ConstructUiResourceEntryBase(void);
undefined4 thunk_DestructEngineerDialogBaseState(void);

namespace {

char g_vtblTStratReportView;
char g_pClassDescTStratReportView;

struct StratReportViewState {
  void* vftable;
  char pad_04[0x60];
};

class RuntimeBridge {
public:
  static __inline void ConstructUiResourceEntryBase(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructUiResourceEntryBase)(self);
  }
};

} // namespace

// FUNCTION: IMPERIALISM 0x0058E330
StratReportViewState* __cdecl CreateTStratReportViewInstance(void) {
  StratReportViewState* view =
      reinterpret_cast<StratReportViewState*>(AllocateWithFallbackHandler(100));
  if (view != 0) {
    RuntimeBridge::ConstructUiResourceEntryBase(view);
    view->vftable = reinterpret_cast<void*>(&g_vtblTStratReportView);
  }
  return view;
}

// FUNCTION: IMPERIALISM 0x0058E3A0
void* __cdecl GetTStratReportViewClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTStratReportView);
}

// FUNCTION: IMPERIALISM 0x0058E3C0
StratReportViewState* __fastcall ConstructTStratReportViewBaseState(StratReportViewState* view) {
  RuntimeBridge::ConstructUiResourceEntryBase(view);
  view->vftable = reinterpret_cast<void*>(&g_vtblTStratReportView);
  return view;
}

// FUNCTION: IMPERIALISM 0x0058E3F0
StratReportViewState* __fastcall DestructTStratReportViewAndMaybeFree(StratReportViewState* view,
                                                                      int unusedEdx,
                                                                      unsigned char freeSelfFlag) {
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)view);
  }
  return view;
}
