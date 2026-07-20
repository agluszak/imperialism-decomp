#include "game/TMiniShipView.h"

#include "game/TAdmiral.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TShip.h"
#include "game/TSimMgr.h"
#include "game/TTaskForce.h"
#include "game/global_data_tables.h"
#include "game/navy_order.h"
#include "game/quickdraw_rendering.h"

// FUNCTION: IMPERIALISM 0x00569d50
undefined TMiniShipView::OrphanRetStub_00569d50() {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x00569d70
// TMiniShipView::`scalar deleting destructor'
TMiniShipView::~TMiniShipView() {}
// SYNTHETIC: IMPERIALISM 0x00569dc0
// TMiniShipView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00569e40
// TMiniShipView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMiniShipView, TControl)

TMiniShipView::TMiniShipView() {}

// FUNCTION: IMPERIALISM 0x00569eb0
void TMiniShipView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other ApplyRectSlot110s

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(2, 0xc, 0x2b6a, 3);

  CString statusLine;
  CString label;
  label = shipNode84->displayName18;

  // Single-entry order-status string lookup (GetString group 0x2760): the index is
  // precomputed via g_ShipOrderStatusStringIndexByResourceType_0065c7f8, unlike
  // TShipView's sibling which builds the full 8-entry pool first.
  g_pSimMgr->GetString(
      0x2760, g_ShipOrderStatusStringIndexByResourceType_0065c7f8[shipNode84->resourceType04],
      &statusLine);
  statusLine += s_szSpaceSeparator_00695794 + label;

  TruncateTextToFitWidthWithEllipsis(&statusLine, 0x5a);
  SetQuickDrawTextOriginWithContextOffset(0xa, 0xc);
  DrawTextWithCachedQuickDrawStyleState(&statusLine);

  short normBase = GetNavyOrderNormalizationBaseByResourceType(shipNode84->resourceType04);
  short levelBucket = static_cast<short>(shipNode84->stockLevel1c * 20 / normBase) + 1;
  if (levelBucket > 0x14) {
    levelBucket = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short rowBucket = (levelBucket < 5) ? 0x1a : ((levelBucket > 0xe) ? 10 : 18);

  // The blit source surface is a per-level icon strip cached on TMacViewMgr; that
  // field isn't recovered yet, so it's read via a raw offset like the sibling
  // roster-row views (TShipView, TArmyBoyView, TArmyUnitView, TMiniArmyView).
  TQuickDrawBlitSurface* iconStripSurface = reinterpret_cast<TQuickDrawBlitSurface*>(
      *reinterpret_cast<char**>(reinterpret_cast<char*>(g_pStrategicMapViewSystem) + 0x694) + 4);
  RECT srcRect = {0, rowBucket, levelBucket * 4 - 1, rowBucket + 7};
  RECT dstRect = {0x8c, 4, levelBucket * 4 + 0x8b, 0xb};
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(iconStripSurface,
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                   &dstRect, 0x24, 0);

  SetQuickDrawStrokeColor(0x13);
  SetQuickDrawTextOriginWithContextOffset(0x8b, 6);
  DrawCenteredGuideLineOnMapDc(0x8b, 0xc);
  DrawCenteredGuideLineOnMapDc(0xdd, 0xc);
  DrawCenteredGuideLineOnMapDc(0xdd, 6);

  // A second, per-nation icon strip lives at TMacViewMgr+0x68c (distinct from the
  // per-level strip at +0x694 used above); also not yet recovered as a typed field.
  // Re-derived in each branch below rather than cached, matching the original (which
  // re-reads it separately at each blit site instead of hoisting it).

  if (shipNode84->admiralBacklink20 != 0) {
    // An admiral is assigned: draw the per-nation admiral-rank badge from the badge
    // strip's (nationId + 7)-th 16px row.
    TQuickDrawBlitSurface* badgeStripSurface = reinterpret_cast<TQuickDrawBlitSurface*>(
        *reinterpret_cast<char**>(reinterpret_cast<char*>(g_pStrategicMapViewSystem) + 0x68c) + 4);
    short nationId = g_pSimMgr->GetActiveNationId();
    short badgeRow = (nationId + 7) * 0x10;
    RECT badgeSrcRect = {0, badgeRow, 0x10, badgeRow + 0x10};
    RECT badgeDstRect = {0x64, 0, 0x74, 0x10};
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(badgeStripSurface,
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &badgeSrcRect, &badgeDstRect, 0x24, 0);
    UpdatePaletteIndexWithDefaultFallback(0x13);
  }

  if (shipNode84->ownerOrderEntry0c != 0) {
    // Order-type badge row, keyed by the owning task force's order-kind tag
    // (TTaskForce::attachment). 0 = no badge for that order kind.
    short orderTypeBadgeRowTable[10] = {0, 4, 3, 5, 5, 6, 2, 3, 0, 0};
    short orderKind = static_cast<short>(shipNode84->ownerOrderEntry0c->attachment);
    short badgeRow = orderTypeBadgeRowTable[orderKind];
    if (badgeRow != 0) {
      TQuickDrawBlitSurface* badgeStripSurface = reinterpret_cast<TQuickDrawBlitSurface*>(
          *reinterpret_cast<char**>(reinterpret_cast<char*>(g_pStrategicMapViewSystem) + 0x68c) +
          4);
      short badgeTop = badgeRow * 0x10;
      RECT badgeSrcRect = {0, badgeTop, 0x10, badgeTop + 0x10};
      RECT badgeDstRect = {0x78, 0, 0x88, 0x10};
      UpdatePaletteIndexWithDefaultFallback(0x10);
      BlitRectWithOptionalTransparency(badgeStripSurface,
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &badgeSrcRect, &badgeDstRect, 0x24, 0);
      UpdatePaletteIndexWithDefaultFallback(0x13);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0056a330
void TMiniShipView::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                         int arg4) {}
