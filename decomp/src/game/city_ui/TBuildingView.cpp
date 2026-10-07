#include "game/city_ui/TBuildingView.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TWindow.h"
#include "game/city/TCity.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TBuildingView, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x004c6f10
TBuildingView::~TBuildingView() {}

// FUNCTION: IMPERIALISM 0x004c6f30
void TBuildingView::ApplyCityViewSelectionPayloadAndRefreshControls(
    TCity* city, bool isEmbeddedPage, TCityProductionView* productionView,
    short embeddedPageIndex) {
  this->city = city;
  this->isEmbeddedPage = isEmbeddedPage;
  this->productionView = productionView;
  this->embeddedPageIndex = embeddedPageIndex;
  GetWindow()->controlValue = 0x65;
  DoStartup();
  UpdateFields();
}

// FUNCTION: IMPERIALISM 0x004c6fb0
void TBuildingView::UpdateFields() {}

// FUNCTION: IMPERIALISM 0x004c6fd0
void TBuildingView::DoStartup() {}

// FUNCTION: IMPERIALISM 0x004c6ff0
void TBuildingView::SetUniversityDialogTextAndRefresh(TStaticText* label, CString text) {
  label->SetTextAndMaybeRefresh(&text, false);
  CRect labelBounds;
  label->QueryBounds(&labelBounds);
  RECT invalidateRect;
  CopyRect(&invalidateRect, &labelBounds);
  InvalidateCityDialogRectRegion(&invalidateRect, 1);
}

// FUNCTION: IMPERIALISM 0x004c70e0
void TBuildingView::SetTextBox(TStaticText* label, short stringGroup, short stringIndex) {
  label->SetTextWithStrListID(stringGroup, stringIndex, false);
  CRect labelBounds;
  label->QueryBounds(&labelBounds);
  RECT invalidateRect;
  CopyRect(&invalidateRect, &labelBounds);
  InvalidateCityDialogRectRegion(&invalidateRect, 1);
}

// FUNCTION: IMPERIALISM 0x004c7180
void TBuildingView::Close() {
  if (isEmbeddedPage) {
    productionView->buildingViews[embeddedPageIndex] = 0;
  } else {
    g_pViewMgr->CloseBuilding(embeddedPageIndex);
  }
  TView::Close();
}
