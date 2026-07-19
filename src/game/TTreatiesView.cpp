#include "game/TTreatiesView.h"

#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x00430350
// TTreatiesView::`scalar deleting destructor'
TTreatiesView::~TTreatiesView() {}
// SYNTHETIC: IMPERIALISM 0x004f7a10
// TTreatiesView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f7aa0
// TTreatiesView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTreatiesView, TPanelView)

TTreatiesView::TTreatiesView() {}

// FUNCTION: IMPERIALISM 0x004f7ac0
void TTreatiesView::NoOpUiLifecycleHook(int arg) {
  TPanelView::NoOpUiLifecycleHook(arg);
  CString text;
  for (int i = 0; i < 7; ++i) {
    TView* control = ResolveControlByTag(kControlTagScr0 + i);
    g_pSimMgr->GetString(0x2733, static_cast<short>(0x37 + i), &text);
    SetControlHoverHelpText(text, control);
  }
  text = CString(g_szEmptyString);
  SetControlHoverHelpText(text, this);
}

// FUNCTION: IMPERIALISM 0x004f7c00
void TTreatiesView::ApplyRectSlot110(RECT* rectBuffer) {
}

// FUNCTION: IMPERIALISM 0x004f7f10
undefined TTreatiesView::OrphanRetStub_00430550() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004f7f80
void TTreatiesView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) { }
