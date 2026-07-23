#include "game/TUnitsView.h"
#include "game/CSubViewIterator.h"
#include "game/TCity.h"
#include "game/TColorKeyPicture.h"
// SYNTHETIC: IMPERIALISM 0x004c7f10
// TUnitsView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c7fb0
// TUnitsView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TUnitsView, TBuildingView)

// FUNCTION: IMPERIALISM 0x004c7fd0
TUnitsView::TUnitsView() : TBuildingView() {}

// SYNTHETIC: IMPERIALISM 0x004c8000
// TUnitsView::`scalar deleting destructor'
TUnitsView::~TUnitsView() {}

// FUNCTION: IMPERIALISM 0x004c8050
void TUnitsView::DoStartup() {
  CSubViewIterator iterator(this);
  TView* child = iterator.FirstSubView();
  while (iterator.MoreSubViews()) {
    if (child->controlTag == 0x69636f6e) { // 'icon'
      child->Free();
    }
    child = iterator.NextSubView();
  }

  short y = 0;
  for (short unitType = 0; unitType < 14; ++unitType) {
    short unitCount = city94->orderCountByType5c[unitType];
    for (short unit = 0; unit < unitCount; ++unit) {
      TColorKeyPicture* icon = new TColorKeyPicture;
      int offsetLayout[2] = {0x20, y};
      int sizeLayout[2] = {0x20, 0x18};
      icon->InitializePictureEntryBaseAndRefresh(this, offsetLayout, sizeLayout, 5, 5, 0x222e);
      icon->controlTag = 0x69636f6e; // 'icon'
      y = static_cast<short>(y + 0x18);
    }
  }
}
