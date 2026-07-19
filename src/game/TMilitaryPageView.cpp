#include "game/TMilitaryPageView.h"

#include "game/CString.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x00564860
// TMilitaryPageView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00564900
// TMilitaryPageView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMilitaryPageView, TPageView)

// FUNCTION: IMPERIALISM 0x00564920
TMilitaryPageView::TMilitaryPageView() {}

// SYNTHETIC: IMPERIALISM 0x00564950
// TMilitaryPageView::`scalar deleting destructor'
TMilitaryPageView::~TMilitaryPageView() {}

// FUNCTION: IMPERIALISM 0x005649a0
void TMilitaryPageView::NoOpUiLifecycleHook(int arg) {
  TPageView::NoOpUiLifecycleHook(arg);
  TView* okControl = ownerContext->ResolveControlByTag(kControlTagOkay);
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 0x22, okControl);
  CString empty(g_szEmptyString);
  SetControlHoverHelpText(empty, this);
}

// FUNCTION: IMPERIALISM 0x00564bf0
char TMilitaryPageView::CallVoidSlotA0() {
  return 0;
}
