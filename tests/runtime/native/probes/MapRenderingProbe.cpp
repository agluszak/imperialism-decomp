#include "MapRenderingProbe.h"

#include "MapInteractionProbe.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/core/global_data_tables.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/map_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map_ui/TMapDialog.h"
#include "game/strategic_terrain.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TWindow.h"

namespace {

// The scratch surface the cursor is drawn onto. 32x32 is the system cursor extent; nothing here
// depends on the game's own sizes.
const int kCursorProbeExtent = 32;

// One tile's rendered extent, and the copy buffer that holds it. 0x40 square is the map's tile
// size in the zoomed-in mode these comparisons run in.
const int kTileExtent = 0x40;

// Lattice step for finding two distinct tiles in a frame; one tile's on-screen size.
const int kTileProbeStep = 32;

} // namespace

PrimarySurfaceGuard::PrimarySurfaceGuard() : savedSurface(0), savedFlags(0) {
  GetGWorld(&savedSurface, &savedFlags);
  SetGWorld(g_pPrimaryRenderSurfaceContext, savedFlags);
}

PrimarySurfaceGuard::~PrimarySurfaceGuard() {
  SetGWorld(savedSurface, savedFlags);
}

CapturedPixels::CapturedPixels() : pixels(0), width(0), height(0) {}

CapturedPixels::~CapturedPixels() {
  delete[] pixels;
}

bool CapturedPixels::CaptureFrom(TView* view) {
  delete[] pixels;
  pixels = 0;
  width = 0;
  height = 0;

  if (view == 0 || view->nativeWindow50 == 0 || view->nativeWindow50->m_hWnd == 0 ||
      view->frameWidth34 <= 0 || view->frameHeight38 <= 0) {
    return false;
  }

  BITMAPINFO bitmapInfo;
  ZeroMemory(&bitmapInfo, sizeof(bitmapInfo));
  bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
  bitmapInfo.bmiHeader.biWidth = view->frameWidth34;
  bitmapInfo.bmiHeader.biHeight = -view->frameHeight38;
  bitmapInfo.bmiHeader.biPlanes = 1;
  bitmapInfo.bmiHeader.biBitCount = 32;
  bitmapInfo.bmiHeader.biCompression = BI_RGB;

  HDC windowDc = GetDC(view->nativeWindow50->m_hWnd);
  void* capturedStorage = 0;
  HBITMAP bitmap = CreateDIBSection(windowDc, &bitmapInfo, DIB_RGB_COLORS, &capturedStorage, 0, 0);
  HDC memoryDc = CreateCompatibleDC(windowDc);
  HGDIOBJ previousBitmap = SelectObject(memoryDc, bitmap);
  BOOL copied = BitBlt(memoryDc, 0, 0, view->frameWidth34, view->frameHeight38, windowDc,
                       view->absoluteX, view->absoluteY, SRCCOPY);
  GdiFlush();

  const int pixelCount = view->frameWidth34 * view->frameHeight38;
  if (copied != 0 && capturedStorage != 0) {
    pixels = new unsigned long[pixelCount];
    memcpy(pixels, capturedStorage, pixelCount * sizeof(unsigned long));
    width = view->frameWidth34;
    height = view->frameHeight38;
  }

  SelectObject(memoryDc, previousBitmap);
  DeleteDC(memoryDc);
  DeleteObject(bitmap);
  ReleaseDC(view->nativeWindow50->m_hWnd, windowDc);
  return pixels != 0;
}

bool CapturedPixels::IsValid() const {
  return pixels != 0;
}

int CapturedPixels::Width() const {
  return width;
}

int CapturedPixels::Height() const {
  return height;
}

bool CapturedPixels::Matches(const CapturedPixels& other) const {
  if (pixels == 0 || other.pixels == 0 || width != other.width || height != other.height) {
    return false;
  }
  return memcmp(pixels, other.pixels, width * height * sizeof(unsigned long)) == 0;
}

bool CapturedPixels::MatchesOutside(const CapturedPixels& other, const CRect& ignored) const {
  if (pixels == 0 || other.pixels == 0 || width != other.width || height != other.height) {
    return false;
  }
  for (int y = 0; y < height; ++y) {
    for (int x = 0; x < width; ++x) {
      CPoint point(x, y);
      if (ignored.PtInRect(point)) {
        continue;
      }
      if (pixels[y * width + x] != other.pixels[y * width + x]) {
        return false;
      }
    }
  }
  return true;
}

bool MapRenderingProbe::CursorDrawsVisiblePixels(HCURSOR cursor) {
  BITMAPINFO bitmapInfo;
  ZeroMemory(&bitmapInfo, sizeof(bitmapInfo));
  bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
  bitmapInfo.bmiHeader.biWidth = kCursorProbeExtent;
  bitmapInfo.bmiHeader.biHeight = -kCursorProbeExtent;
  bitmapInfo.bmiHeader.biPlanes = 1;
  bitmapInfo.bmiHeader.biBitCount = 32;
  bitmapInfo.bmiHeader.biCompression = BI_RGB;

  void* pixelStorage = 0;
  HDC screenDc = GetDC(0);
  HBITMAP bitmap = CreateDIBSection(screenDc, &bitmapInfo, DIB_RGB_COLORS, &pixelStorage, 0, 0);
  DWORD* pixels = static_cast<DWORD*>(pixelStorage);
  HDC memoryDc = CreateCompatibleDC(screenDc);
  HGDIOBJ previousBitmap = SelectObject(memoryDc, bitmap);
  PatBlt(memoryDc, 0, 0, kCursorProbeExtent, kCursorProbeExtent, WHITENESS);
  BOOL drewCursor =
      DrawIconEx(memoryDc, 0, 0, cursor, kCursorProbeExtent, kCursorProbeExtent, 0, 0, DI_NORMAL);

  bool changedPixel = false;
  if (drewCursor != 0) {
    for (int index = 0; index < kCursorProbeExtent * kCursorProbeExtent; ++index) {
      if ((pixels[index] & 0x00ffffff) != 0x00ffffff) {
        changedPixel = true;
        break;
      }
    }
  }

  SelectObject(memoryDc, previousBitmap);
  DeleteDC(memoryDc);
  DeleteObject(bitmap);
  ReleaseDC(0, screenDc);
  return changedPixel;
}

bool MapRenderingProbe::CursorIsActiveAndVisible(HCURSOR expected) {
  return expected != 0 && GetCursor() == expected && CursorDrawsVisiblePixels(expected);
}

bool MapRenderingProbe::DevelopmentClassChangesTilePixels(TMapDialog* mapDialog, short tileIndex,
                                                          unsigned char initialClass,
                                                          unsigned char completedClass) {
  if (mapDialog == 0) {
    return false;
  }
  TBitmapSurfaceNode** surfaceHandle = GetGWorldPixMap(mapDialog->quickDrawSurface350);
  if (surfaceHandle == 0 || *surfaceHandle == 0 || !LockPixels(surfaceHandle)) {
    return false;
  }

  TBitmapSurfaceNode* surface = *surfaceHandle;
  const int stride = surface->stride & 0x3fff;
  unsigned char before[kTileExtent * kTileExtent];
  unsigned char after[kTileExtent * kTileExtent];
  TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[tileIndex];
  const unsigned char savedDevelopmentClasses = terrain.developmentClassNibbles0c;
  TQuickDrawSurfaceContext* savedSurface;
  int savedSurfaceFlags;
  GetGWorld(&savedSurface, &savedSurfaceFlags);
  SetGWorld(mapDialog->quickDrawSurface350, savedSurfaceFlags);

  terrain.developmentClassNibbles0c =
      static_cast<unsigned char>((savedDevelopmentClasses & 0xf0) | initialClass);
  mapDialog->DrawOneTile(tileIndex, 0, 0);
  for (int row = 0; row < kTileExtent; ++row) {
    memcpy(before + row * kTileExtent, surface->pixelBits + row * stride, kTileExtent);
  }

  terrain.developmentClassNibbles0c =
      static_cast<unsigned char>((savedDevelopmentClasses & 0xf0) | completedClass);
  mapDialog->DrawOneTile(tileIndex, 0, 0);
  for (int afterRow = 0; afterRow < kTileExtent; ++afterRow) {
    memcpy(after + afterRow * kTileExtent, surface->pixelBits + afterRow * stride, kTileExtent);
  }

  // Put the tile back the way it was found, drawn state included: this probe observes, it does
  // not leave the map showing a state the model does not hold.
  terrain.developmentClassNibbles0c = savedDevelopmentClasses;
  mapDialog->DrawOneTile(tileIndex, 0, 0);
  SetGWorld(savedSurface, savedSurfaceFlags);
  UnlockPixels(surfaceHandle);
  return memcmp(before, after, sizeof(before)) != 0;
}

bool MapRenderingProbe::TransportConnectivityChangesTilePixels(TMapDialog* mapDialog) {
  if (mapDialog == 0 || g_pGlobalMapState == 0) {
    return false;
  }

  short tileIndex = -1;
  for (short candidate = 0; candidate < 0x1950; ++candidate) {
    TTerrainStateRecord& candidateTerrain = g_pGlobalMapState->terrainStateTable[candidate];
    if (candidateTerrain.GetTerrainKind() != kStrategicTerrainWater &&
        candidateTerrain.riverSpriteCode == kRiverSpriteCodeNone) {
      tileIndex = candidate;
      break;
    }
  }
  if (tileIndex == -1) {
    return false;
  }

  TBitmapSurfaceNode** surfaceHandle = GetGWorldPixMap(mapDialog->quickDrawSurface350);
  if (surfaceHandle == 0 || *surfaceHandle == 0 || !LockPixels(surfaceHandle)) {
    return false;
  }

  TBitmapSurfaceNode* surface = *surfaceHandle;
  const int stride = surface->stride & 0x3fff;
  unsigned char baseline[kTileExtent * kTileExtent];
  unsigned char road[kTileExtent * kTileExtent];
  unsigned char rail[kTileExtent * kTileExtent];
  TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[tileIndex];
  const signed char savedRoadFlags = terrain.adjacencyBits06;
  const unsigned char savedRailFlags = terrain.railFlags17;
  TQuickDrawSurfaceContext* savedSurface;
  int savedSurfaceFlags;
  GetGWorld(&savedSurface, &savedSurfaceFlags);
  SetGWorld(mapDialog->quickDrawSurface350, savedSurfaceFlags);

  terrain.adjacencyBits06 = 0;
  terrain.railFlags17 = 0;
  mapDialog->DrawOneTile(tileIndex, 0, 0);
  for (int row = 0; row < kTileExtent; ++row) {
    memcpy(baseline + row * kTileExtent, surface->pixelBits + row * stride, kTileExtent);
  }

  terrain.adjacencyBits06 = 1;
  mapDialog->DrawOneTile(tileIndex, 0, 0);
  for (int roadRow = 0; roadRow < kTileExtent; ++roadRow) {
    memcpy(road + roadRow * kTileExtent, surface->pixelBits + roadRow * stride, kTileExtent);
  }

  terrain.adjacencyBits06 = 0;
  terrain.railFlags17 = 1;
  mapDialog->DrawOneTile(tileIndex, 0, 0);
  for (int railRow = 0; railRow < kTileExtent; ++railRow) {
    memcpy(rail + railRow * kTileExtent, surface->pixelBits + railRow * stride, kTileExtent);
  }

  terrain.adjacencyBits06 = savedRoadFlags;
  terrain.railFlags17 = savedRailFlags;
  mapDialog->DrawOneTile(tileIndex, 0, 0);
  SetGWorld(savedSurface, savedSurfaceFlags);
  UnlockPixels(surfaceHandle);

  return memcmp(baseline, road, sizeof(baseline)) != 0 &&
         memcmp(baseline, rail, sizeof(baseline)) != 0;
}

bool MapRenderingProbe::HoverMovementRestoresPreviousTiles(TMapDialog* mapDialog,
                                                           short excludedTile) {
  if (mapDialog == 0 || mapDialog->nativeWindow50 == 0) {
    return false;
  }
  RedrawWindow(mapDialog->nativeWindow50->m_hWnd, 0, 0, RDW_INVALIDATE | RDW_UPDATENOW);

  CapturedPixels baseline;
  if (!baseline.CaptureFrom(mapDialog)) {
    return false;
  }

  // Walk the frame on a tile-sized lattice for two points that resolve to different tiles.
  // Derived from the map's own ConvertPoint, never written as literal coordinates.
  CPoint firstPoint;
  CPoint secondPoint;
  short firstTile = -1;
  short secondTile = -1;
  for (int y = kTileProbeStep; y < mapDialog->frameHeight38 && secondTile == -1;
       y += kTileProbeStep) {
    for (int x = kTileProbeStep; x < mapDialog->frameWidth34; x += kTileProbeStep) {
      short column;
      short row;
      short band;
      CPoint point(x, y);
      mapDialog->ConvertPoint(point, column, row, band);
      short tile = static_cast<short>(ComputeStridedRecordAddress6C(column, row));
      if (tile == excludedTile) {
        continue;
      }
      if (firstTile == -1) {
        firstPoint = point;
        firstTile = tile;
      } else if (tile != firstTile) {
        secondPoint = point;
        secondTile = tile;
        break;
      }
    }
  }
  if (secondTile == -1) {
    return false;
  }

  if (!MapInteractionProbe::HoverAcrossLocalPoints(mapDialog, firstPoint, secondPoint)) {
    return false;
  }

  CapturedPixels afterMovement;
  if (!afterMovement.CaptureFrom(mapDialog) || afterMovement.Width() != baseline.Width() ||
      afterMovement.Height() != baseline.Height()) {
    return false;
  }

  short projectedY;
  short projectedX;
  ProjectTileIndexToWrappedScreenOffsetByScale(secondTile, &mapDialog->viewportOrigin, &projectedY,
                                               &projectedX, 1);
  const CRect currentHoverRect(projectedX - 1, projectedY - 1, projectedX + 0x42,
                               projectedY + 0x42);
  return baseline.MatchesOutside(afterMovement, currentHoverRect);
}
