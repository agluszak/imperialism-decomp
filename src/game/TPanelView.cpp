#include "game/TPanelView.h"

// FUNCTION: IMPERIALISM 0x00430550
undefined TPanelView::OrphanRetStub_00430550() {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x004f7970
// TPanelView::`scalar deleting destructor'
TPanelView::~TPanelView() {}
// SYNTHETIC: IMPERIALISM 0x004f78e0
// TPanelView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f79c0
// TPanelView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPanelView, TView)

TPanelView::TPanelView() : m_panelData(0) {}

// FUNCTION: IMPERIALISM 0x004f79e0
void TPanelView::NoOpUiLifecycleHook(int arg) {
}
