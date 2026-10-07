#include "game/navy_ui/TMiniShipView.h"

#include "game/navy/TAdmiral.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/navy/TShip.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/navy/TTaskForce.h"
#include "game/navy_ui/TSuperNavyRoster.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/navy_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/navy_order.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x00569d50
void TMiniShipView::Hilite() {}

// FUNCTION: IMPERIALISM 0x00569da0
TMiniShipView::~TMiniShipView() {}

IMPLEMENT_DYNCREATE(TMiniShipView, TControl)

// FUNCTION: IMPERIALISM 0x00569e60
void TMiniShipView::IMiniShipView(TView* panel, int* offsetLayout, int* sizeLayout, TShip* ship) {
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 5, 5, 0);
  eventNumber = 0x22;
  shipNode = ship;
}

// FUNCTION: IMPERIALISM 0x00569eb0
void TMiniShipView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(2, 0xc, 0x2b6a, 3);

  CString statusLine;
  CString label;
  label = shipNode->name;

  g_pSimMgr->GetString(0x2760, g_ShipOrderStatusStringIndexByResourceType[shipNode->type],
                       &statusLine);
  statusLine += s_szSpaceSeparator + label;

  TruncateTextToFitWidthWithEllipsis(&statusLine, 0x5a);
  SetQuickDrawTextOriginWithContextOffset(0xa, 0xc);
  DrawTextWithCachedQuickDrawStyleState(&statusLine);

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

  // The per-nation icon strip is re-read at each blit site, as in the original.

  if (shipNode->admiral != 0) {
    TQuickDrawBlitSurface* badgeStripSurface = g_pMacViewMgr->nationFleetWorld->GetBlitSurface();
    short nationId = g_pSimMgr->GetPlayerCountry();
    short badgeRow = (nationId + 7) * 0x10;
    RECT badgeSrcRect = {0, badgeRow, 0x10, badgeRow + 0x10};
    RECT badgeDstRect = {0x64, 0, 0x74, 0x10};
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(badgeStripSurface,
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &badgeSrcRect, &badgeDstRect, 0x24, 0);
    UpdatePaletteIndexWithDefaultFallback(0x13);
  }

  if (shipNode->taskForce != 0) {
    short orderTypeBadgeRowTable[10] = {0, 4, 3, 5, 5, 6, 2, 3, 0, 0};
    short orderKind = shipNode->taskForce->shipOrders;
    short badgeRow = orderTypeBadgeRowTable[orderKind];
    if (badgeRow != 0) {
      TQuickDrawBlitSurface* badgeStripSurface = g_pMacViewMgr->nationFleetWorld->GetBlitSurface();
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

  TTaskForce* taskForce = shipNode->taskForce;
  if (taskForce != 0) {
    roster->selectedTaskForce = taskForce;
    roster->selectedZone = 0;
  } else {
    roster->selectedTaskForce = 0;
    roster->selectedZone = shipNode->location;
  }

  TControl::DoMouseCommand(point, event, origin);
}
