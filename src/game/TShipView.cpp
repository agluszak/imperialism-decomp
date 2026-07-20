#include "game/TShipView.h"

#include "game/TAdmiral.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TShip.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/navy_order.h"
#include "game/quickdraw_rendering.h"

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
void TShipView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}
