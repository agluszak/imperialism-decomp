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

IMPLEMENT_DYNCREATE(TMiniMapView, TControl)

// FUNCTION: IMPERIALISM 0x0059a380
TMiniMapView::TMiniMapView()
    : TControl(), ownerPicture(nullptr), scrollTileColumn(0), scrollTileRow(0), markerBoxX(0),
      markerBoxY(0), markerBoxWidth(g_defaultMarkerBoxWidth), markerBoxHeight(8) {}

// FUNCTION: IMPERIALISM 0x0059a420
TMiniMapView::~TMiniMapView() {}

// FUNCTION: IMPERIALISM 0x0059a440
void TMiniMapView::IMiniMapView(TView* panel, int* offsetLayout, int* sizeLayout,
                                int sizeDeterminerX, int sizeDeterminerY) {
  (void)sizeDeterminerX;
  (void)sizeDeterminerY;
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 4, 4, 0);
  markerBoxX = frameWidth / 2 - markerBoxWidth;
  markerBoxY = frameHeight / 2 - markerBoxHeight;
}

// FUNCTION: IMPERIALISM 0x0059a540
void TMiniMapView::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  TQuickDrawSurfaceContext* miniMapAtlas = g_pMacViewMgr->miniMapWorld;
  if (miniMapAtlas == 0) {
    return;
  }

  short centerTile = g_pGlobalMapState->mapViewOriginTile;
  short sourceColumn = static_cast<short>(centerTile % 108);
  short sourceRow = static_cast<short>(centerTile / 108);
  sourceColumn = static_cast<short>(sourceColumn - ((frameWidth / 2 - markerBoxWidth) / 2) - 1);
  sourceRow = static_cast<short>(sourceRow - ((frameHeight / 2 - markerBoxHeight) / 2) - 1);

  int verticalClipOffset = 0;
  if (sourceColumn < 0) {
    sourceColumn = static_cast<short>(sourceColumn + 108);
  }
  if (sourceRow < 0) {
    verticalClipOffset = sourceRow * 2;
    sourceRow = 0;
  } else {
    short visibleRows = static_cast<short>((frameHeight + 1) / 2);
    if (sourceRow + visibleRows > 60) {
      verticalClipOffset = (sourceRow + visibleRows) * 2 - 120;
      sourceRow = static_cast<short>(60 - visibleRows);
    }
  }
  scrollTileColumn = sourceColumn;
  scrollTileRow = sourceRow;

  ResetQuickDrawStrokeState();
  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0xffffff);

  CRect sourceRect(sourceColumn * 2, sourceRow * 2, sourceColumn * 2 + frameWidth,
                   sourceRow * 2 + frameHeight);
  CRect destinationRect(0, 0, frameWidth, frameHeight);
  int overflow = sourceRect.right - 0xd7;
  if (overflow <= 0) {
    BlitRectWithOptionalTransparency(miniMapAtlas->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &sourceRect, &destinationRect, 0, 0);
  } else {
    CRect firstSource(sourceRect.left, sourceRect.top, 0xd7, sourceRect.bottom);
    CRect firstDestination(0, 0, 0xd7 - sourceRect.left, frameHeight);
    if (g_pGlobalMapState->hexNeighborWrapHorizontally != 0 &&
        firstDestination.right <= frameWidth / 2) {
      FillRectWithQuickDrawBrushAndContextOffset(&firstDestination);
    } else {
      BlitRectWithOptionalTransparency(miniMapAtlas->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &firstSource, &firstDestination, 0, 0);
    }

    CRect secondSource(0, sourceRect.top, overflow, sourceRect.bottom);
    CRect secondDestination(frameWidth - overflow, 0, frameWidth, frameHeight);
    if (g_pGlobalMapState->hexNeighborWrapHorizontally != 0 && overflow <= frameWidth / 2) {
      FillRectWithQuickDrawBrushAndContextOffset(&secondDestination);
    } else {
      BlitRectWithOptionalTransparency(miniMapAtlas->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &secondSource, &secondDestination, 0, 0);
    }
  }

  short markerX = static_cast<short>(markerBoxX);
  short markerY = static_cast<short>(markerBoxY);
  if (g_applyMiniMapVerticalClipOffset) {
    markerY = static_cast<short>(markerY + verticalClipOffset);
  }
  SetQuickDrawFillColor(0xffffff);
  SetQuickDrawTextOriginWithContextOffset(markerX, markerY);
  DrawCenteredGuideLineOnMapDc(static_cast<short>(markerX + markerBoxWidth * 2), markerY);
  DrawCenteredGuideLineOnMapDc(static_cast<short>(markerX + markerBoxWidth * 2),
                               static_cast<short>(markerY + markerBoxHeight * 2));
  DrawCenteredGuideLineOnMapDc(markerX, static_cast<short>(markerY + markerBoxHeight * 2));
  DrawCenteredGuideLineOnMapDc(markerX, markerY);
  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0xffffff);
}

// FUNCTION: IMPERIALISM 0x0059a920
void TMiniMapView::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                              CPoint& currentPoint, bool commandFlag) {
  (void)startPoint;
  (void)previousPoint;
  (void)commandFlag;

  if (phase >= kTrackPhaseBegin && phase <= kTrackPhaseUpdate) {
    if (PointInBoundsAndActionable(&currentPoint) != 0) {
      markerBoxX = currentPoint.x - markerBoxWidth;
      markerBoxY = currentPoint.y - markerBoxHeight;
      g_applyMiniMapVerticalClipOffset = false;
      RefreshControl();
      ForceRedraw();
      g_applyMiniMapVerticalClipOffset = true;
    }
    return;
  }

  if (phase == kTrackPhaseEnd) {
    g_applyMiniMapVerticalClipOffset = true;
    int tileColumn = currentPoint.x / 2;
    int tileRow = currentPoint.y / 2;
    tileColumn =
        static_cast<short>(tileColumn) + static_cast<short>(scrollTileColumn) - markerBoxWidth / 2;
    tileRow = static_cast<short>(tileRow) + static_cast<short>(scrollTileRow) - markerBoxHeight / 2;

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

    ownerPicture->SetUpperLeft(tileColumn, tileRow);
    markerBoxX = frameWidth / 2 - markerBoxWidth;
    markerBoxY = frameHeight / 2 - markerBoxHeight;
    RefreshControl();
  }
}
