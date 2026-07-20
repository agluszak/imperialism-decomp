#include "game/TShipView.h"

#include "game/TAdmiral.h"
#include "game/TAssetMgr.h"
#include "game/TEditText.h"
#include "game/TMapOrderChildLinkNode.h"
#include "game/TMapUberPicture.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TShip.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TTaskForce.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/navy_order.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
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
void TShipView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other ApplyRectSlot110s

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b6a);

  CString statusLine;
  CString label;

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(2, 0xc, 0x2b6a, 3);
  label = shipNode60->displayName18;

  // 8-line order-status string pool (GetString group 0x2760), one entry per naval
  // order state; selected by resourceType04 via
  // g_ShipOrderStatusStringIndexByResourceType_0065c7f8.
  CString orderStatusStrings[8];
  for (int i = 0; i < 8; ++i) {
    g_pSimMgr->GetString(0x2760, i, &orderStatusStrings[i]);
  }
  statusLine = orderStatusStrings
      [g_ShipOrderStatusStringIndexByResourceType_0065c7f8[shipNode60->resourceType04]];
  statusLine += s_szSpaceSeparator_00695794 + label;

  SetQuickDrawTextOriginWithContextOffset(0x50, 0x18);
  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0xffffff);
  DrawTextWithCachedQuickDrawStyleState(&statusLine);

  if (shipNode60->admiralBacklink20 != 0) {
    // An admiral is assigned to this ship: overwrite/replace the status line's
    // position with "Adm. <admiral name>" drawn one row higher.
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 9, 0x2b6a);
    CString admiralLine = s_szAdmiralPrefix_0069578c + shipNode60->admiralBacklink20->displayName;
    label = admiralLine;
    SetQuickDrawTextOriginWithContextOffset(0x50, 0xc);
    DrawTextWithCachedQuickDrawStyleState(&label);
  }

  short normBase = GetNavyOrderNormalizationBaseByResourceType(shipNode60->resourceType04);
  short levelBucket = static_cast<short>(shipNode60->stockLevel1c * 20 / normBase) + 1;
  if (levelBucket > 0x14) {
    levelBucket = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short rowBucket = (levelBucket < 5) ? 0x1a : ((levelBucket > 0xe) ? 10 : 18);

  // The blit source surface is a per-level icon strip cached on TMacViewMgr; that
  // field isn't recovered yet, so it's read via a raw offset like the sibling
  // roster-row views (TArmyBoyView, TArmyUnitView, TMiniArmyView).
  TQuickDrawBlitSurface* iconStripSurface = reinterpret_cast<TQuickDrawBlitSurface*>(
      *reinterpret_cast<char**>(reinterpret_cast<char*>(g_pStrategicMapViewSystem) + 0x694) + 4);
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
void TShipView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (sourceHandler->controlTag == kControlTagChec) {
    TMapOrderChildLinkNode* node = field64->childOrderList->FindNodeMatching(shipNode60);
    int delta;
    if (node->active == 0) {
      field64->SetTaskForceOrderSelectionByNodeId(shipNode60, 1);
      delta = 1;
    } else {
      field64->SetTaskForceOrderSelectionByNodeId(shipNode60, 0);
      delta = -1;
    }

    TMapUberPicture* mapUber = g_pUiRuntimeContext->mapUberPictureF0;
    TView* categoryControl = mapUber->categoryPages[mapUber->activeUnitCategoryIndex96];
    if (categoryControl != nullptr) {
      short resourceType = shipNode60->GetOrderNodeDescriptorWord20ByResourceType();
      TStaticText* slider =
          static_cast<TStaticText*>(categoryControl->ResolveControlByTag(kControlTagCls0 + resourceType));
      // The original also range-checks against slider->field88 (a max-value short packed
      // into a dual-use void* field -- see the UNRESOLVED_FIELD_ATTRIBUTION note on
      // TStaticText::field88) before applying the delta; that guard is not modeled here.
      if (delta > 0) {
        short newValue = slider->field90 + 1;
        slider->field90 = newValue;
        slider->SetTextThemeCodeAndMaybeRefresh(newValue, 1);
      } else if (slider->field90 > 0) {
        short newValue = slider->field90 - 1;
        slider->field90 = newValue;
        slider->SetTextThemeCodeAndMaybeRefresh(newValue, 1);
      }
    }
  } else if (sourceHandler->controlTag == kControlTagName) {
    RunEngineerOrderNameEditDialogAndApply();
  }
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}

// Same dialog (message context 0xdb4) and control shape as TArmyUnitView::
// HandleCrossUArmyViewsNameCommand (0x4a9ca0), but a genuinely different function (own thunk
// 0x4092ff, not 0x403986) with real differences: no forced default command (no
// SetField84/GetEmbeddedDialogBehavior calls), the title uses string index 5 instead of 1,
// the edited name is shipNode60->displayName18 (TShip's own name field, not TMilitaryUnit's
// name24 -- confirms the earlier field60+offset concern was specific to each class, not a
// shared conflict), and the commit condition is inverted: applies only when the modal result
// is exactly 'okay' (rather than "commit unless 'cncl'").
// FUNCTION: IMPERIALISM 0x00565a40
void TShipView::RunEngineerOrderNameEditDialogAndApply() {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0xdb4));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUOceanViews_00698650, 0x203);
  }

  TUiTextStyleDescriptor style;
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);

  TStaticText* titleControl = static_cast<TStaticText*>(node->ResolveControlByTag(kControlTagTitl));
  titleControl->AssertValid();
  titleControl->LoadUiStringAndDispatchViaVslot1C8(0x2746, 5, 1);
  titleControl->textStyle78 = style;

  TEditText* nameControl = static_cast<TEditText*>(node->ResolveControlByTag(kControlTagName));
  nameControl->AssertValid();
  CString editedName;
  editedName = shipNode60->displayName18;
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&editedName, 1);
  nameControl->textStyle78 = style;

  int modalResult = node->ExecuteViewModalStateWithPushPopChain();
  nameControl->GetCurrentText(&editedName);
  node->CallVoidSlotA0();
  node->Free();
  if (modalResult == 0x6f6b6179 /* 'okay' */) {
    shipNode60->displayName18 = editedName;
  }
  RefreshControl();
}
