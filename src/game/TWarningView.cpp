#include "game/TWarningView.h"

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

namespace {

// GLOBAL: IMPERIALISM 0x663178
char g_pClassDescTWarningView;

} // namespace

// FUNCTION: IMPERIALISM 0x00592860
TWarningView* __cdecl CreateTWarningViewInstance(void) {
  return new TWarningView();
}

// FUNCTION: IMPERIALISM 0x005928e0
void* __cdecl GetTWarningViewClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTWarningView);
}

// FUNCTION: IMPERIALISM 0x00592900
TWarningView::TWarningView() : TPictureResourceEntryBase() {}

// FUNCTION: IMPERIALISM 0x00592930
TWarningView* __fastcall DestructTWarningViewAndMaybeFree(TWarningView* view, int unusedEdx,
                                                          unsigned char freeSelfFlag) {
  (void)unusedEdx;
  view->~TWarningView();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)view);
  }
  return view;
}

TWarningView::~TWarningView() {}
