#include "game/navy_ui/TShipView.h"

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
#include "game/globals/prelude.h"
#include "game/globals/navy_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/navy_order.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x005653b0
// TShipView::`scalar deleting destructor'
TShipView::~TShipView() {}
// SYNTHETIC: IMPERIALISM 0x00565400
// TShipView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00565470
// TShipView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipView, TView)

TShipView::TShipView() {}

// FUNCTION: IMPERIALISM 0x005654e0
void TShipView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b6a);

  CString statusLine;
  CString label;

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(2, 0xc, 0x2b6a, 3);
  label = shipNode60->name;

  // 8-line order-status string pool (GetString group 0x2760), one entry per naval
  // order state; selected by type via
  // g_ShipOrderStatusStringIndexByResourceType_0065c7f8.
  CString orderStatusStrings[8];
  for (int i = 0; i < 8; ++i) {
    g_pSimMgr->GetString(0x2760, i, &orderStatusStrings[i]);
  }
  statusLine =
      orderStatusStrings[g_ShipOrderStatusStringIndexByResourceType_0065c7f8[shipNode60->type]];
  statusLine += s_szSpaceSeparator_00695794 + label;

  SetQuickDrawTextOriginWithContextOffset(0x50, 0x18);
  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0xffffff);
  DrawTextWithCachedQuickDrawStyleState(&statusLine);

  if (shipNode60->admiral != 0) {
    // An admiral is assigned to this ship: overwrite/replace the status line's
    // position with "Adm. <admiral name>" drawn one row higher.
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 9, 0x2b6a);
    CString admiralLine = s_szAdmiralPrefix_0069578c + shipNode60->admiral->displayName;
    label = admiralLine;
    SetQuickDrawTextOriginWithContextOffset(0x50, 0xc);
    DrawTextWithCachedQuickDrawStyleState(&label);
  }

  short normBase = shipNode60->GetMaxStrength();
  short levelBucket = static_cast<short>(shipNode60->strength * 20 / normBase) + 1;
  if (levelBucket > 0x14) {
    levelBucket = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short rowBucket = (levelBucket < 5) ? 0x1a : ((levelBucket > 0xe) ? 10 : 18);

  // The blit source surface is a per-level icon strip cached on TMacViewMgr; that
  // field isn't recovered yet, so it's read via a raw offset like the sibling
  // roster-row views (TArmyBoyView, TArmyUnitView, TMiniArmyView).
  TQuickDrawBlitSurface* iconStripSurface =
      g_pStrategicMapViewSystem->atlas694[0]->GetBlitSurface();
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
    TMapOrderChildLinkNode* node = field64->shipList->FindNodeMatching(shipNode60);
    int delta;
    if (node->active == 0) {
      field64->Select(shipNode60, 1);
      delta = 1;
    } else {
      field64->Select(shipNode60, 0);
      delta = -1;
    }

    TMapUberPicture* mapUber = g_pUiRuntimeContext->mapUberPictureF0;
    TView* categoryControl = mapUber->categoryPages[mapUber->activeUnitCategoryIndex96];
    if (categoryControl != nullptr) {
      short resourceType = shipNode60->GetToolbarSlot();
      TShipFractionCluster* shipFraction = static_cast<TShipFractionCluster*>(
          categoryControl->ResolveControlByTag(kControlTagCls0 + resourceType));
      if (delta > 0) {
        if (shipFraction->selectedShipCount94 < shipFraction->availableShipCount88) {
          short newValue = static_cast<short>(shipFraction->selectedShipCount94 + 1);
          shipFraction->selectedShipCount94 = newValue;
          shipFraction->shipCountButton90->SetValue(newValue, 1);
        }
      } else if (shipFraction->selectedShipCount94 > 0) {
        short newValue = static_cast<short>(shipFraction->selectedShipCount94 - 1);
        shipFraction->selectedShipCount94 = newValue;
        shipFraction->shipCountButton90->SetValue(newValue, 1);
      }
    }
  } else if (sourceHandler->controlTag == kControlTagName) {
    RunEngineerOrderNameEditDialogAndApply();
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}

// Same dialog (message context 0xdb4) and control shape as TArmyUnitView::
// HandleCrossUArmyViewsNameCommand (0x4a9ca0), but a genuinely different function (own thunk
// 0x4092ff, not 0x403986) with real differences: no forced default command (no
// SetField84/GetEmbeddedDialogBehavior calls), the title uses string index 5 instead of 1,
// the edited name is shipNode60->name (TShip's own name field, not TMilitaryUnit's
// name24 -- confirms the earlier field60+offset concern was specific to each class, not a
// shared conflict), and the commit condition is inverted: applies only when the modal result
// is exactly 'okay' (rather than "commit unless 'cncl'").
// FUNCTION: IMPERIALISM 0x00565a40
void TShipView::RunEngineerOrderNameEditDialogAndApply() {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventNameUnit));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUOceanViews_00698650, 0x203);
  }

  TextStyle style;
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);

  TStaticText* titleControl = static_cast<TStaticText*>(node->ResolveControlByTag(kControlTagTitl));
  titleControl->AssertValid();
  titleControl->SetTextFromStringResource(0x2746, 5, 1);
  titleControl->textStyle78 = style;

  TEditText* nameControl = static_cast<TEditText*>(node->ResolveControlByTag(kControlTagName));
  nameControl->AssertValid();
  CString editedName;
  editedName = shipNode60->name;
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&editedName, 1);
  nameControl->textStyle78 = style;

  int modalResult = node->PoseModally();
  nameControl->GetCurrentText(&editedName);
  node->Close();
  node->Free();
  if (modalResult == 0x6f6b6179 /* 'okay' */) {
    shipNode60->name = editedName;
  }
  RefreshControl();
}
