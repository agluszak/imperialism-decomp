// TStratReportView wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"
#include "game/TView.h"

#include <new>

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 thunk_DestructEngineerDialogBaseState(void);

namespace {

// GLOBAL: IMPERIALISM 0x6630e8
char g_pClassDescTStratReportView;

// VTABLE: IMPERIALISM 0x667d08
class TStratReportView : public TView {
public:
  char pad_60_to_63[0x04];

  TStratReportView();

  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }
};

} // namespace

// FUNCTION: IMPERIALISM 0x0058e330
TStratReportView* __cdecl CreateTStratReportViewInstance(void) {
  TStratReportView* view =
      reinterpret_cast<TStratReportView*>(AllocateWithFallbackHandler(sizeof(TStratReportView)));
  if (view != 0) {
    ::new (view) TStratReportView();
  }
  return view;
}

// FUNCTION: IMPERIALISM 0x0058e3a0
void* __cdecl GetTStratReportViewClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTStratReportView);
}

// FUNCTION: IMPERIALISM 0x0058e3c0
TStratReportView::TStratReportView() : TView() {}

// FUNCTION: IMPERIALISM 0x0058e3f0
TStratReportView* __fastcall DestructTStratReportViewAndMaybeFree(TStratReportView* view,
                                                                  int unusedEdx,
                                                                  unsigned char freeSelfFlag) {
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)view);
  }
  return view;
}
