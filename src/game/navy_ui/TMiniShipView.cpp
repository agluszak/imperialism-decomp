#include "game/navy_ui/TMiniShipView.h"

#include "game/navy/TAdmiral.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/navy/TShip.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/navy/TTaskForce.h"
#include "game/navy_ui/TSuperNavyRoster.h"
#include "game/globals/prelude.h"
#include "game/globals/navy_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/navy_order.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x00569d50
void TMiniShipView::Hilite() {}

// SYNTHETIC: IMPERIALISM 0x00569d70
// TMiniShipView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00569da0
TMiniShipView::~TMiniShipView() {}
// SYNTHETIC: IMPERIALISM 0x00569dc0
// TMiniShipView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00569e40
// TMiniShipView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMiniShipView, TControl)

// FUNCTION: IMPERIALISM 0x00569eb0
void TMiniShipView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(2, 0xc, 0x2b6a, 3);

  CString statusLine;
  CString label;
  label = shipNode84->name;

  // Single-entry order-status string lookup (GetString group 0x2760): the index is
  // precomputed via g_ShipOrderStatusStringIndexByResourceType_0065c7f8, unlike
  // TShipView's sibling which builds the full 8-entry pool first.
  g_pSimMgr->GetString(
      0x2760, g_ShipOrderStatusStringIndexByResourceType_0065c7f8[shipNode84->type], &statusLine);
  statusLine += s_szSpaceSeparator_00695794 + label;

  TruncateTextToFitWidthWithEllipsis(&statusLine, 0x5a);
  SetQuickDrawTextOriginWithContextOffset(0xa, 0xc);
  DrawTextWithCachedQuickDrawStyleState(&statusLine);

  short normBase = shipNode84->GetMaxStrength();
  short levelBucket = static_cast<short>(shipNode84->strength * 20 / normBase) + 1;
  if (levelBucket > 0x14) {
    levelBucket = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short rowBucket = (levelBucket < 5) ? 0x1a : ((levelBucket > 0xe) ? 10 : 18);

  // The blit source surface is a per-level icon strip cached on TMacViewMgr; that
  // field isn't recovered yet, so it's read via a raw offset like the sibling
  // roster-row views (TShipView, TArmyBoyView, TArmyUnitView, TMiniArmyView).
  TQuickDrawBlitSurface* iconStripSurface =
      g_pStrategicMapViewSystem->atlas694[0]->GetBlitSurface();
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

  if (shipNode84->admiral != 0) {
    // An admiral is assigned: draw the per-nation admiral-rank badge from the badge
    // strip's (nationId + 7)-th 16px row.
    TQuickDrawBlitSurface* badgeStripSurface =
        g_pStrategicMapViewSystem->atlas68c->GetBlitSurface();
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

  if (shipNode84->taskForce != 0) {
    // Order-type badge row, keyed by the owning task force's order-kind tag
    // (TTaskForce::shipOrders). 0 = no badge for that order kind.
    short orderTypeBadgeRowTable[10] = {0, 4, 3, 5, 5, 6, 2, 3, 0, 0};
    short orderKind = static_cast<short>(shipNode84->taskForce->shipOrders);
    short badgeRow = orderTypeBadgeRowTable[orderKind];
    if (badgeRow != 0) {
      TQuickDrawBlitSurface* badgeStripSurface =
          g_pStrategicMapViewSystem->atlas68c->GetBlitSurface();
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
void TMiniShipView::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  TSuperNavyRoster* roster = static_cast<TSuperNavyRoster*>(ownerContext);
  roster->AssertValid();

  TTaskForce* taskForce = shipNode84->taskForce;
  if (taskForce != 0) {
    roster->selectedTaskForce88 = taskForce;
    roster->selectedZone84 = 0;
  } else {
    roster->selectedTaskForce88 = 0;
    roster->selectedZone84 = shipNode84->location;
  }

  TControl::DoMouseCommand(point, event, origin);
}
