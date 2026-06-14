#include "game/TWarningView.h"
#include "game/CRuntimeClass.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x00663178
CRuntimeClass g_pClassDescTWarningView = {0};
}

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

// FUNCTION: IMPERIALISM 0x00592860
TWarningView* __cdecl CreateTWarningViewInstance(void) {
  return new TWarningView();
}

// FUNCTION: IMPERIALISM 0x005928e0
CRuntimeClass* TWarningView::GetRuntimeClass() {
  return &g_pClassDescTWarningView;
}

// FUNCTION: IMPERIALISM 0x00592900
TWarningView::TWarningView() : TPictureResourceEntryBase() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00592930
// TWarningView::`scalar deleting destructor'
