#include "game/app/TPanelView.h"

#include "game/diplomacy_ui/TDiplomacyMapView.h"

// FUNCTION: IMPERIALISM 0x00430550
void TPanelView::Setup() {}

// FUNCTION: IMPERIALISM 0x004f79a0
TPanelView::~TPanelView() {}

IMPLEMENT_DYNCREATE(TPanelView, TView)

// FUNCTION: IMPERIALISM 0x004f79e0
void TPanelView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  diplomacyMapView = static_cast<TDiplomacyMapView*>(ownerContext);
}
