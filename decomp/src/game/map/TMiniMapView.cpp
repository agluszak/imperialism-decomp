#include "game/map/TMiniMapView.h"

#include "game/ui_core/TMacViewMgr.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x0059a290
// TMiniMapView::CreateObject

// SYNTHETIC: IMPERIALISM 0x0059a360
// TMiniMapView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMiniMapView, TControl)

// FUNCTION: IMPERIALISM 0x0059a380
TMiniMapView::TMiniMapView()
    : TControl(), ownerPicture84(nullptr), scrollTileColumn88(0), scrollTileRow8c(0),
      markerBoxX90(0), markerBoxY94(0), markerBoxWidth98(g_defaultMarkerBoxWidth_006a460c),
      markerBoxHeight9c(8) {}

// SYNTHETIC: IMPERIALISM 0x0059a3f0
// TMiniMapView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0059a420
TMiniMapView::~TMiniMapView() {}

// FUNCTION: IMPERIALISM 0x0059a540
void TMiniMapView::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  TQuickDrawSurfaceContext* miniMapAtlas = g_pMacViewMgr->atlas670;
  if (miniMapAtlas == 0) {
    return;
  }

  short centerTile = g_pGlobalMapState->field6;
  short sourceColumn = static_cast<short>(centerTile % 108);
  short sourceRow = static_cast<short>(centerTile / 108);
  sourceColumn = static_cast<short>(sourceColumn - ((frameWidth34 / 2 - markerBoxWidth98) / 2) - 1);
  sourceRow = static_cast<short>(sourceRow - ((frameHeight38 / 2 - markerBoxHeight9c) / 2) - 1);

  int verticalClipOffset = 0;
  if (sourceColumn < 0) {
    sourceColumn = static_cast<short>(sourceColumn + 108);
  }
  if (sourceRow < 0) {
    verticalClipOffset = sourceRow * 2;
    sourceRow = 0;
  } else {
    short visibleRows = static_cast<short>((frameHeight38 + 1) / 2);
    if (sourceRow + visibleRows > 60) {
      verticalClipOffset = (sourceRow + visibleRows) * 2 - 120;
      sourceRow = static_cast<short>(60 - visibleRows);
    }
  }
  scrollTileColumn88 = sourceColumn;
  scrollTileRow8c = sourceRow;

  ResetQuickDrawStrokeState();
  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0xffffff);

  CRect sourceRect(sourceColumn * 2, sourceRow * 2, sourceColumn * 2 + frameWidth34,
                   sourceRow * 2 + frameHeight38);
  CRect destinationRect(0, 0, frameWidth34, frameHeight38);
  int overflow = sourceRect.right - 0xd7;
  if (overflow <= 0) {
    BlitRectWithOptionalTransparency(miniMapAtlas->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &sourceRect, &destinationRect, 0, 0);
  } else {
    CRect firstSource(sourceRect.left, sourceRect.top, 0xd7, sourceRect.bottom);
    CRect firstDestination(0, 0, 0xd7 - sourceRect.left, frameHeight38);
    if (g_pGlobalMapState->hexNeighborWrapHorizontally != 0 &&
        firstDestination.right <= frameWidth34 / 2) {
      FillRectWithQuickDrawBrushAndContextOffset(&firstDestination);
    } else {
      BlitRectWithOptionalTransparency(miniMapAtlas->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &firstSource, &firstDestination, 0, 0);
    }

    CRect secondSource(0, sourceRect.top, overflow, sourceRect.bottom);
    CRect secondDestination(frameWidth34 - overflow, 0, frameWidth34, frameHeight38);
    if (g_pGlobalMapState->hexNeighborWrapHorizontally != 0 && overflow <= frameWidth34 / 2) {
      FillRectWithQuickDrawBrushAndContextOffset(&secondDestination);
    } else {
      BlitRectWithOptionalTransparency(miniMapAtlas->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &secondSource, &secondDestination, 0, 0);
    }
  }

  short markerX = static_cast<short>(markerBoxX90);
  short markerY = static_cast<short>(markerBoxY94);
  if (g_applyMiniMapVerticalClipOffset_006993e8 != 0) {
    markerY = static_cast<short>(markerY + verticalClipOffset);
  }
  SetQuickDrawFillColor(0xffffff);
  SetQuickDrawTextOriginWithContextOffset(markerX, markerY);
  DrawCenteredGuideLineOnMapDc(static_cast<short>(markerX + markerBoxWidth98 * 2), markerY);
  DrawCenteredGuideLineOnMapDc(static_cast<short>(markerX + markerBoxWidth98 * 2),
                               static_cast<short>(markerY + markerBoxHeight9c * 2));
  DrawCenteredGuideLineOnMapDc(markerX, static_cast<short>(markerY + markerBoxHeight9c * 2));
  DrawCenteredGuideLineOnMapDc(markerX, markerY);
  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0xffffff);
}

// FUNCTION: IMPERIALISM 0x0059a920
void TMiniMapView::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                              CPoint& currentPoint, unsigned char commandFlag) {
  (void)startPoint;
  (void)previousPoint;
  (void)commandFlag;

  if (phase >= kTrackPhaseBegin && phase <= kTrackPhaseUpdate) {
    if (PointInBoundsAndActionable(&currentPoint) != 0) {
      markerBoxX90 = currentPoint.x - markerBoxWidth98;
      markerBoxY94 = currentPoint.y - markerBoxHeight9c;
      g_applyMiniMapVerticalClipOffset_006993e8 = 0;
      RefreshControl();
      ForceRedraw();
      g_applyMiniMapVerticalClipOffset_006993e8 = 1;
    }
    return;
  }

  if (phase == kTrackPhaseEnd) {
    g_applyMiniMapVerticalClipOffset_006993e8 = 1;
    int tileColumn = currentPoint.x / 2;
    int tileRow = currentPoint.y / 2;
    tileColumn = static_cast<short>(tileColumn) + static_cast<short>(scrollTileColumn88) -
                 markerBoxWidth98 / 2;
    tileRow =
        static_cast<short>(tileRow) + static_cast<short>(scrollTileRow8c) - markerBoxHeight9c / 2;

    if (static_cast<short>(tileColumn) < 0) {
      tileColumn += 108;
    } else if (static_cast<short>(tileColumn) >= 108) {
      tileColumn -= 108;
    }
    if (static_cast<short>(tileRow) < 0) {
      tileRow = 0;
    } else if (static_cast<short>(tileRow) > 60) {
      tileRow = 60;
    }

    ownerPicture84->SetUpperLeft(tileColumn, tileRow);
    markerBoxX90 = frameWidth34 / 2 - markerBoxWidth98;
    markerBoxY94 = frameHeight38 / 2 - markerBoxHeight9c;
    RefreshControl();
  }
}
