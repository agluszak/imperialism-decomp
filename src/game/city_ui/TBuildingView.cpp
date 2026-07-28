#include "game/city_ui/TBuildingView.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TWindow.h"
#include "game/city/TCity.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
// SYNTHETIC: IMPERIALISM 0x004c6df0
// TBuildingView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c6e90
// TBuildingView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBuildingView, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x004c6eb0
TBuildingView::TBuildingView() : TNoHilitePicture() {
  city94 = 0;
}

// SYNTHETIC: IMPERIALISM 0x004c6ee0
// TBuildingView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004c6f10
TBuildingView::~TBuildingView() {}

// FUNCTION: IMPERIALISM 0x004c6f30
void TBuildingView::ApplyCityViewSelectionPayloadAndRefreshControls(
    TCity* city, bool isEmbeddedPage, TCityProductionView* productionView,
    short embeddedPageIndex) {
  city94 = city;
  isEmbeddedPage9C = isEmbeddedPage;
  productionView98 = productionView;
  embeddedPageIndex9E = embeddedPageIndex;
  GetWindow()->controlValue3c = 0x65;
  DoStartup();
  UpdateFields();
}

// FUNCTION: IMPERIALISM 0x004c6fb0
void TBuildingView::UpdateFields() {}

// FUNCTION: IMPERIALISM 0x004c6fd0
void TBuildingView::DoStartup() {}

// FUNCTION: IMPERIALISM 0x004c6ff0
void TBuildingView::SetUniversityDialogTextAndRefresh(TStaticText* label, CString text) {
  label->SetTextAndMaybeRefresh(&text, 0);
  CRect labelBounds;
  label->QueryBounds(&labelBounds);
  RECT invalidateRect;
  CopyRect(&invalidateRect, &labelBounds);
  InvalidateCityDialogRectRegion(&invalidateRect, 1);
}

// FUNCTION: IMPERIALISM 0x004c70e0
void TBuildingView::SetUniversityDialogLocalizedTextAndRefresh(TStaticText* label,
                                                               short stringGroup,
                                                               short stringIndex) {
  label->SetTextFromStringResource(stringGroup, stringIndex, 0);
  CRect labelBounds;
  label->QueryBounds(&labelBounds);
  RECT invalidateRect;
  CopyRect(&invalidateRect, &labelBounds);
  InvalidateCityDialogRectRegion(&invalidateRect, 1);
}

// FUNCTION: IMPERIALISM 0x004c7180
void TBuildingView::Close() {
  if (isEmbeddedPage9C) {
    productionView98->buildingViewsAC[embeddedPageIndex9E] = 0;
  } else {
    g_pUiRuntimeContext->ClearActiveCityBuildingViewSlot(embeddedPageIndex9E);
  }
  TView::Close();
}
