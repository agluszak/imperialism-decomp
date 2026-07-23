#include "game/app/TPanelView.h"

#include "game/diplomacy_ui/TDiplomacyMapView.h"

// FUNCTION: IMPERIALISM 0x00430550
void TPanelView::Setup() {}

// SYNTHETIC: IMPERIALISM 0x004f7970
// TPanelView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004f79a0
TPanelView::~TPanelView() {}
// SYNTHETIC: IMPERIALISM 0x004f78e0
// TPanelView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f79c0
// TPanelView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPanelView, TView)

// Always inlined by the compiler (no standalone out-of-line address), so no // FUNCTION
// marker: TView base construction then diplomacyMapView60 = 0.
TPanelView::TPanelView() : TView(), diplomacyMapView60(0) {}

// FUNCTION: IMPERIALISM 0x004f79e0
void TPanelView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  diplomacyMapView60 = static_cast<TDiplomacyMapView*>(ownerContext);
}
