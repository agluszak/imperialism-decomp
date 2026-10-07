#include "game/navy_ui/TShipView.h"
#include "game/ui_tags_common.h"

#include "game/navy/TAdmiral.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_core/TEditText.h"
#include "game/navy/TMapOrderChildLinkNode.h"
#include "game/map/TMapUberPicture.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/navy/TShip.h"
#include "game/navy_ui/TShipFractionCluster.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/navy/TTaskForce.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/navy_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/navy_order.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x005653e0
TShipView::~TShipView() {}

IMPLEMENT_DYNCREATE(TShipView, TView)

// FUNCTION: IMPERIALISM 0x00565490
void TShipView::IShipView(TView* panel, int* offsetLayout, int* sizeLayout, int sizeDeterminerX,
                          int sizeDeterminerY, TShip* ship, TTaskForce* taskForce) {
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, sizeDeterminerX,
                                          sizeDeterminerY, 0);
  shipNode = ship;
  this->taskForce = taskForce;
}

// FUNCTION: IMPERIALISM 0x005654e0
void TShipView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws

  ApplyTextStyle(0, 0xa, 0x2b6a);

  CString statusLine;
  CString label;

  SetTextStyleAndApply(2, 0xc, 0x2b6a, 3);
  label = shipNode->name;

  CString orderStatusStrings[8];
  for (int i = 0; i < 8; ++i) {
    g_pSimMgr->GetString(0x2760, i, &orderStatusStrings[i]);
  }
  statusLine = orderStatusStrings[g_ShipOrderStatusStringIndexByResourceType[shipNode->type]];
  statusLine += s_szSpaceSeparator + label;

  SetQuickDrawTextOriginWithContextOffset(0x50, 0x18);
  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0xffffff);
  DrawTextWithCachedQuickDrawStyleState(&statusLine);

  if (shipNode->admiral != 0) {
    ApplyTextStyle(0, 9, 0x2b6a);
    CString admiralLine = s_szAdmiralPrefix + shipNode->admiral->displayName;
    label = admiralLine;
    SetQuickDrawTextOriginWithContextOffset(0x50, 0xc);
    DrawTextWithCachedQuickDrawStyleState(&label);
  }

  short normBase = shipNode->GetMaxStrength();
  short levelBucket = static_cast<short>(shipNode->strength * 20 / normBase) + 1;
  if (levelBucket > 0x14) {
    levelBucket = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short rowBucket = (levelBucket < 5) ? 0x1a : ((levelBucket > 0xe) ? 10 : 18);

  TQuickDrawBlitSurface* iconStripSurface =
      g_pMacViewMgr->tileOverlayStripWorlds[0]->GetBlitSurface();
  RECT srcRect = {0, rowBucket, levelBucket * 4 - 1, rowBucket + 7};
  RECT dstRect = {0x52, 0x1e, levelBucket * 4 + 0x51, 0x25};
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(iconStripSurface,
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                   &dstRect, 0x24, 0);

  SetQuickDrawTextOriginWithContextOffset(0x50, 0x20);
  DrawCenteredGuideLineOnMapDc(0x50, 0x26);
  DrawCenteredGuideLineOnMapDc(0xa2, 0x26);
  DrawCenteredGuideLineOnMapDc(0xa2, 0x20);
}

// FUNCTION: IMPERIALISM 0x005658d0
void TShipView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (sourceHandler->controlTag == kControlTagChec) {
    TMapOrderChildLinkNode* node = taskForce->shipList->FindNodeMatching(shipNode);
    int delta;
    if (node->active == 0) {
      taskForce->Select(shipNode, true);
      delta = 1;
    } else {
      taskForce->Select(shipNode, false);
      delta = -1;
    }

    TMapUberPicture* mapUber = g_pViewMgr->mapUberPicture;
    TView* categoryControl = mapUber->categoryPages[mapUber->activeUnitCategoryIndex];
    if (categoryControl != NULL) {
      short resourceType = shipNode->GetToolbarSlot();
      TShipFractionCluster* shipFraction = static_cast<TShipFractionCluster*>(
          categoryControl->FindSubView(kControlTagCls0 + resourceType));
      if (delta > 0) {
        if (shipFraction->selectedShipCount < shipFraction->availableShipCount) {
          short newValue = shipFraction->selectedShipCount + 1;
          shipFraction->selectedShipCount = newValue;
          shipFraction->shipCountButton->SetValue(newValue, true);
        }
      } else if (shipFraction->selectedShipCount > 0) {
        short newValue = shipFraction->selectedShipCount - 1;
        shipFraction->selectedShipCount = newValue;
        shipFraction->shipCountButton->SetValue(newValue, true);
      }
    }
  } else if (sourceHandler->controlTag == kControlTagName) {
    RenameShip();
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00565a40
void TShipView::RenameShip() {
  TWindow* node = g_pAssetMgr->GetDialog(kTurnEventNameUnit);
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUOceanViews, 0x203);
  }

  TextStyle style;
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);

  TStaticText* titleControl = static_cast<TStaticText*>(node->FindSubView(kControlTagTitl));
  titleControl->AssertValid();
  titleControl->SetTextWithStrListID(0x2746, 5, true);
  titleControl->textStyle = style;

  TEditText* nameControl = static_cast<TEditText*>(node->FindSubView(kControlTagName));
  nameControl->AssertValid();
  CString editedName;
  editedName = shipNode->name;
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&editedName, 1);
  nameControl->textStyle = style;

  int modalResult = node->PoseModally();
  nameControl->GetCurrentText(&editedName);
  node->Close();
  node->Free();
  if (modalResult == kControlTagOkay) {
    shipNode->name = editedName;
  }
  RefreshControl();
}
