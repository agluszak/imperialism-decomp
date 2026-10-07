#include "game/city_ui/TPurchaseCluster.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"

#include "game/ui_widgets/TAmtBar.h"
#include "game/city_ui/TBuildingView.h"
#include "game/ui_core/TEventHandler.h"
#include "game/globals/global_types.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

IMPLEMENT_DYNCREATE(TPurchaseCluster, TCluster)

// FUNCTION: IMPERIALISM 0x004cc3c0
TPurchaseCluster::TPurchaseCluster() : TCluster(), linkedControl(0) {}

// FUNCTION: IMPERIALISM 0x004cc420
TPurchaseCluster::~TPurchaseCluster() {}

// FUNCTION: IMPERIALISM 0x004cc440
void TPurchaseCluster::StuffValues(TEventHandler* control) {
  linkedControl = control;
  SetValue(static_cast<short>(control->enabled), true);
}

// FUNCTION: IMPERIALISM 0x004cc470
void TPurchaseCluster::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {}

// FUNCTION: IMPERIALISM 0x004cc490
void TPurchaseCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    if (sourceHandler->controlTag == kControlTagLaro) {
      linkedControl->SetEnable(static_cast<char>(GetValue() - 1));
    } else if (sourceHandler->controlTag == kControlTagRaro) {
      linkedControl->SetEnable(static_cast<char>(GetValue() + 1));
    }
    SetValue(static_cast<short>(linkedControl->enabled), true);
  }
  TCluster::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004cc550
void TPurchaseCluster::SetValue(short nValue, bool redrawFlag) {
  TNumberText* valueControl = static_cast<TNumberText*>(FindSubView(kControlTagValu));
  if (valueControl == NULL) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCityViews.cpp", 0x781);
  }
  valueControl->SetControlValue(nValue, 0);
  if (!redrawFlag) {
    return;
  }

  RECT bounds;
  bounds.left = valueControl->ownerLocalX + ownerLocalX;
  bounds.top = valueControl->ownerLocalY + ownerLocalY;
  bounds.right = bounds.left + valueControl->frameWidth;
  bounds.bottom = bounds.top + valueControl->frameHeight;
  RECT copiedBounds;
  CopyRect(&copiedBounds, &bounds);
  ownerContext->InvalidateCityDialogRectRegion(&copiedBounds, 1);
  static_cast<TBuildingView*>(ownerContext)->UpdateFields();
}

// FUNCTION: IMPERIALISM 0x004cc640
int TPurchaseCluster::GetValue() {
  TNumberText* valueControl = static_cast<TNumberText*>(FindSubView(kControlTagValu));
  if (valueControl == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCityViews.cpp", 0x793);
  }
  return valueControl->UpdateControlCachedIntFromWindowText();
}
