#include "game/navy_ui/TOceanDialog.h"

#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/gfx/CDib.h"
#include "game/gfx/CTemporaryRegion.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/military/TCivUnit.h"
#include "game/city_ui/TCountry.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/gfx/TResourceMgr.h"
#include "game/navy/TOcean.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/map/TZone.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/map_globals.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

void NormalizeWrappedMapCoord108x60(short* xCoord, short* yCoord);

namespace {
class ScopedOceanMapPaletteSelection {
public:
  ScopedOceanMapPaletteSelection()
      : m_dc(GetActiveQuickDrawDc()),
        m_previousPalette(m_dc->SelectPalette(g_pResourceMgr->EnsureDefaultDibPalette(), FALSE)) {}

  ~ScopedOceanMapPaletteSelection() {
    m_dc->SelectPalette(m_previousPalette, FALSE);
  }

private:
  CDC* m_dc;
  CPalette* m_previousPalette;
};

} // namespace

IMPLEMENT_DYNCREATE(TOceanDialog, TWorldView)

// FUNCTION: IMPERIALISM 0x00565e90
TOceanDialog::TOceanDialog() : scrollRowOffset(0), scrollColOffset(0) {
  viewportOrigin.x = g_nOceanDialogSeedViewportOffsetX;
  viewportOrigin.y = g_nOceanDialogSeedViewportOffsetY;
  projectionScale = 4;
  previewSquareRadius = 0x10;
}

// FUNCTION: IMPERIALISM 0x00565f10
TOceanDialog::~TOceanDialog() {}

// FUNCTION: IMPERIALISM 0x00565f50
void TOceanDialog::DoPostCreate(int arg) {
  TWorldView::DoPostCreate(arg);
  projectionScale = 4;
  previewSquareRadius = 0x10;
}

// Mac oracle: TOceanDialog::InvalidateZone(TZone*).
// FUNCTION: IMPERIALISM 0x00565f80
void TOceanDialog::InvalidateZone(TZone* zone) {
  if (zone != 0) {
    CRect bounds = BoundingRect(zone);
    InvalidateCityDialogRectRegion(&bounds, 1);
  }
}

// FUNCTION: IMPERIALISM 0x00565fc0
void TOceanDialog::InvalidateTile(short tileIndex) {
  if (tileIndex < 0) {
    return;
  }

  int row = tileIndex / kStrategicMapColumns;
  int x = ((tileIndex - scrollColOffset + kStrategicMapColumns) % kStrategicMapColumns) << 4;
  if ((row & 1) == 0) {
    x -= 8;
  }
  int y = (row - scrollRowOffset) << 4;
  CRect tileRect(x, y, x + 0x10, y + 0x10);
  InvalidateCityDialogRectRegion(&tileRect, 1);
}

// FUNCTION: IMPERIALISM 0x00566060
CRect TOceanDialog::BoundingRect(TZone* zone) {
  tagRECT bounds;
  bounds.right = -2000;
  bounds.bottom = -2000;
  int minLeft = 1000;
  int minRowMirror = 1000;
  bounds.left = 1000;
  bounds.top = 1000;
  int i = 0;
  do {
    if (static_cast<short>(
            g_pGlobalMapState->terrainStateTable[static_cast<short>(i)].ownerNationTag) ==
        zone->seedNationId) {
      int row = i / 0x6c;
      int col = (row & 1) + 1 + (i % 0x6c) * 2;
      if (col < minLeft) {
        minLeft = col;
        bounds.left = col;
      }
      if (bounds.right < col) {
        bounds.right = col;
      }
      if (row < bounds.top) {
        bounds.top = row;
      }
      minRowMirror = bounds.top;
      if (bounds.bottom < row) {
        bounds.bottom = row;
      }
    }
    ++i;
  } while (i < kStrategicTileCount);
  CRect result;
  if (minRowMirror == 1000) {
    result.left = 0;
    result.top = 0;
    result.right = 0;
    result.bottom = 0;
  } else {
    OffsetRect(&bounds, scrollColOffset * -2, -static_cast<int>(scrollRowOffset));
    result.left = bounds.left * 8;
    result.top = bounds.top << 4;
    result.right = bounds.right * 8;
    result.bottom = bounds.bottom << 4;
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x005661d0
void TOceanDialog::ConvertPoint(const CPoint& point, short& outColumn, short& outRow,
                                short& outRegionBand) {
  outRow = static_cast<short>(scrollRowOffset + point.y / 0x10);

  int adjustedX = point.x;
  if ((outRow & 1) == 0) {
    adjustedX += 8;
  }
  outColumn = static_cast<short>(scrollColOffset + adjustedX / 0x10);
  NormalizeWrappedMapCoord108x60(&outColumn, &outRow);

  outRegionBand = 2;
  TMapUberPicture* mapPicture = static_cast<TMapUberPicture*>(ownerContext);
  if (mapPicture->activeUnitCategoryIndex == 0) {
    int tileIndex = TileIndexFromColumnRow(outColumn, outRow);
    TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    if ((tile.activeFlags & 1) != 0) {
      short ownerNation = static_cast<short>(tile.ownerNationTag);
      if (ownerNation == g_pSimMgr->GetPlayerCountry() || ownerNation >= 7) {
        outRegionBand = 1;
      }
    }
  }
}

// Draws the guide-line border around a hex map cell: for each edge where the cell's own
// value differs from the corresponding neighbor value, it moves the pen origin and strokes a
// centered guide line via the two quickdraw helpers. `neighborValues` holds the adjacent

// FUNCTION: IMPERIALISM 0x005662e0
void DrawTileClassCornerTick(short colorCode, int x, int y, unsigned int cornerFlags) {
  int stepX = (cornerFlags & 1) != 0 ? -1 : 1;
  int stepY = (cornerFlags & 2) != 0 ? -1 : 1;
  int originX = (cornerFlags & 1) != 0 ? x + 0xf : x;
  int originY = (cornerFlags & 2) != 0 ? y + 0xd : y + 2;

  g_pViewMgr->SetForeColor(colorCode);
  SetQuickDrawTextOriginWithContextOffset(static_cast<short>(originX), static_cast<short>(originY));

  int tipY = originY - stepY * 2;
  DrawCenteredGuideLineOnMapDc(static_cast<short>(originX + stepX * 2), static_cast<short>(tipY));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(originX), static_cast<short>(tipY));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(originX), static_cast<short>(tipY + stepY));
}
// cell values indexed by edge.
// FUNCTION: IMPERIALISM 0x005663c0
void DrawHexCellBorderGuideLines(int baseX, int baseY, short cellValue, short* neighborValues) {
  if (cellValue != neighborValues[4]) {
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX),
                                            static_cast<short>(baseY + 3));
    DrawCenteredGuideLineOnMapDc(static_cast<short>(baseX), static_cast<short>(baseY + 0xc));
    if (neighborValues[4] == neighborValues[5]) {
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX),
                                              static_cast<short>(baseY + 3));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(baseX + 3), static_cast<short>(baseY));
    } else if (cellValue != neighborValues[5]) {
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX), static_cast<short>(baseY));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(baseX), static_cast<short>(baseY + 3));
    }
    if (neighborValues[4] == neighborValues[3]) {
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX),
                                              static_cast<short>(baseY + 0xd));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(baseX + 2), static_cast<short>(baseY + 0xf));
    } else if (cellValue != neighborValues[3]) {
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX),
                                              static_cast<short>(baseY + 0xd));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(baseX), static_cast<short>(baseY + 0xf));
    }
  }

  if (cellValue != neighborValues[5]) {
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX + 4),
                                            static_cast<short>(baseY));
    DrawCenteredGuideLineOnMapDc(static_cast<short>(baseX + 4), static_cast<short>(baseY));
    if (cellValue != neighborValues[0]) {
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX + 5),
                                              static_cast<short>(baseY));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(baseX + 10), static_cast<short>(baseY));
    }
    if (neighborValues[4] != neighborValues[5]) {
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX), static_cast<short>(baseY));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(baseX + 3), static_cast<short>(baseY));
    }
  }
  if (cellValue != neighborValues[0]) {
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX + 0xb),
                                            static_cast<short>(baseY));
    DrawCenteredGuideLineOnMapDc(static_cast<short>(baseX + 0xd), static_cast<short>(baseY));
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX + 0xd),
                                            static_cast<short>(baseY));
    int endY = (neighborValues[0] == neighborValues[1]) ? baseY + 2 : baseY;
    DrawCenteredGuideLineOnMapDc(static_cast<short>(baseX + 0xf), static_cast<short>(endY));
  }
  if (cellValue != neighborValues[1] && neighborValues[1] == neighborValues[2]) {
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX + 0xd),
                                            static_cast<short>(baseY + 0xf));
    DrawCenteredGuideLineOnMapDc(static_cast<short>(baseX + 0xf), static_cast<short>(baseY + 0xd));
  }
}

// FUNCTION: IMPERIALISM 0x005665e0
void TOceanDialog::FrameCursorArea() {
  TMapUberPicture* mapPicture = static_cast<TMapUberPicture*>(ownerContext);
  if (mapPicture->activeUnitCategoryIndex != 0) {
    return;
  }

  bool frameHoveredTile = cursorId != 0xffff && cursorId != 0x3f0;
  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0xffffff);

  short projectedY;
  short projectedX;
  ForwardProjectTileIndexToWrappedScreenOffsetByScale(paintedHoverTileIndex, &viewportOrigin,
                                                      &projectedY, &projectedX, projectionScale);
  CRect tileRect(projectedX, projectedY, projectedX + previewSquareRadius,
                 projectedY + previewSquareRadius);
  BlitRectWithOptionalTransparency(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &tileRect,
                                   &tileRect, 0, 0);

  if (frameHoveredTile) {
    ForwardProjectTileIndexToWrappedScreenOffsetByScale(hoveredTileIndex, &viewportOrigin,
                                                        &projectedY, &projectedX, projectionScale);
    tileRect.SetRect(projectedX, projectedY, projectedX + previewSquareRadius,
                     projectedY + previewSquareRadius);
    QDFrameRect(&tileRect);
  }
}

// FUNCTION: IMPERIALISM 0x00566750
void TOceanDialog::RefreshMapTile(short tileIndex) {
  if (tileIndex < 0) {
    return;
  }

  int row = tileIndex / kStrategicMapColumns;
  int screenX = ((tileIndex - scrollColOffset + kStrategicMapColumns) % kStrategicMapColumns) << 4;
  if ((row & 1) == 0) {
    screenX -= 8;
  }
  int screenY = (row - scrollRowOffset) << 4;
  CRect tileRect(screenX, screenY, screenX + 0x10, screenY + 0x10);
  InvalidateCityDialogRectRegion(&tileRect, 1);
}

// FUNCTION: IMPERIALISM 0x005667f0
void TOceanDialog::Draw(RECT* rectBuffer) {
  CTemporaryRegion savedClip;
  CTemporaryRegion scratchRegionA;
  CTemporaryRegion scratchRegionB;
  (void)scratchRegionA;
  (void)scratchRegionB;
  register unsigned char currentBorder = 0;

  int viewportRowParity = scrollRowOffset & 1;
  int baseTileIndex = scrollRowOffset * kStrategicMapColumns;
  bool blankWrappedLeftEdge = g_pGlobalMapState->hexNeighborWrapHorizontally != 0 &&
                              (scrollColOffset < 2 || scrollColOffset > 100);
  bool blankWrappedRightEdge = g_pGlobalMapState->hexNeighborWrapHorizontally != 0 &&
                               scrollColOffset <= 100 && scrollColOffset > 70;

  CRect viewportDestinationRect(0, 0, frameWidth, frameHeight);
  CRect viewportSourceRect(0, 0, frameWidth, frameHeight);
  SetGlobalQuickDrawOrigin(static_cast<short>(absoluteX), static_cast<short>(absoluteY));
  GetClip(savedClip.tempRgn);

  TQuickDrawSurfaceContext* previousSurface = g_pPrimaryRenderSurfaceContext;
  int previousSurfaceFlags;
  GetGWorld(&previousSurface, &previousSurfaceFlags);
  SetGWorld(g_pPrimaryRenderSurfaceContext, previousSurfaceFlags);
  LockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));

  CDib* primaryDib = (*static_cast<TBitmapSurfaceNode**>(
                          g_pPrimaryRenderSurfaceContext->blitSurface.surfaceObject))
                         ->dib;
  int rowStep = -static_cast<int>((primaryDib->m_pInfoHeader->bmiHeader.biWidth + 3U) & ~3U);
  int bitmapHeight = primaryDib->m_pInfoHeader->bmiHeader.biHeight;
  if (bitmapHeight <= 0) {
    bitmapHeight = -bitmapHeight;
  }
  unsigned char* topRowPixels =
      static_cast<unsigned char*>(primaryDib->m_dibBits) - (bitmapHeight - 1) * rowStep;
  SetClip(savedClip.tempRgn);

  g_pViewMgr->SetForeColor(0x32);
  CRect clippedRect;
  clippedRect.left = rectBuffer->left;
  clippedRect.top = rectBuffer->top;
  clippedRect.right = rectBuffer->right;
  clippedRect.bottom = rectBuffer->bottom;
  FillRectWithQuickDrawBrushAndContextOffset(&clippedRect);

  int row;
  CRect tileRect;
  for (row = 0; row < 0x1c; ++row) {
    int screenY = row << 4;
    int column;
    for (column = 0; column <= 0x20; ++column) {
      int screenX = column << 4;
      if (viewportRowParity == 0) {
        screenX -= 8;
      }
      tileRect.left = screenX;
      tileRect.top = screenY;
      tileRect.right = screenX + 0x10;
      tileRect.bottom = screenY + 0x10;

      int unwrappedColumn = scrollColOffset + column;
      int tileIndex = baseTileIndex + unwrappedColumn;
      if (unwrappedColumn >= kStrategicMapColumns) {
        tileIndex -= 0x6c;
        if (blankWrappedRightEdge) {
          g_pViewMgr->SetForeColor(0);
          FillRectWithQuickDrawBrushAndContextOffset(&tileRect);
          continue;
        }
      } else if (blankWrappedLeftEdge && unwrappedColumn > 0x3c) {
        g_pViewMgr->SetForeColor(0);
        FillRectWithQuickDrawBrushAndContextOffset(&tileRect);
        continue;
      }

      unsigned char* tilePixels = topRowPixels + screenY * rowStep + screenX;
      int ownerTag = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag;
      if (ownerTag > 0x17) {
        ownerTag = 0x17;
      }
      short tileCityRecordIndex = g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex;
      currentBorder = g_aOceanMapBorderPaletteIndexByNationTag[ownerTag];
      bool isWater = g_pGlobalMapState->terrainStateTable[tileIndex].GetTerrainKind() ==
                     kStrategicTerrainWater;
      if (!isWater) {
        SetQuickDrawFillColorFromPaletteIndex(g_aOceanMapOwnerPaletteIndexByNationTag[ownerTag]);
        FillRectWithQuickDrawBrushAndContextOffset(&tileRect);
      }

      if (screenX >= 0) {
        short neighborTiles[6];
        short neighborOwners[6];
        short neighborCities[6];
        TMapMgr::GetNeighborTileIDArray(static_cast<short>(tileIndex), neighborTiles,
                                        g_pGlobalMapState->hexNeighborWrapHorizontally);

        int neighborIndex;
        for (neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
          short neighborTile = neighborTiles[neighborIndex];
          if (neighborTile <= -1) {
            neighborOwners[neighborIndex] = neighborTile;
            neighborCities[neighborIndex] = -1;
          } else {
            short neighborOwner = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag;
            if (neighborOwner > 0x17) {
              neighborOwner = 0x17;
            }
            neighborOwners[neighborIndex] = neighborOwner;
            neighborCities[neighborIndex] =
                g_pGlobalMapState->terrainStateTable[neighborTile].cityRecordIndex;
          }
        }

        unsigned char verticalOffsets[3][16];
        unsigned char diagonalOffsets[3][8];

        verticalOffsets[1][0] = 2;
        verticalOffsets[1][1] = 3;
        verticalOffsets[1][2] = 9;
        verticalOffsets[1][3] = 13;
        verticalOffsets[1][4] = 2;
        verticalOffsets[1][5] = 11;
        verticalOffsets[1][6] = 12;
        verticalOffsets[1][7] = 13;
        verticalOffsets[1][8] = 2;
        verticalOffsets[1][9] = 3;
        verticalOffsets[1][10] = 4;
        verticalOffsets[1][11] = 5;
        verticalOffsets[1][12] = 10;
        verticalOffsets[1][13] = 11;
        verticalOffsets[1][14] = 12;
        verticalOffsets[1][15] = 13;

        verticalOffsets[2][0] = 4;
        verticalOffsets[2][1] = 8;
        verticalOffsets[2][2] = 10;
        verticalOffsets[2][3] = 12;
        verticalOffsets[2][4] = 3;
        verticalOffsets[2][5] = 4;
        verticalOffsets[2][6] = 9;
        verticalOffsets[2][7] = 10;
        verticalOffsets[2][8] = 6;
        verticalOffsets[2][9] = 7;
        verticalOffsets[2][10] = 8;
        verticalOffsets[2][11] = 9;
        verticalOffsets[2][12] = 6;
        verticalOffsets[2][13] = 7;
        verticalOffsets[2][14] = 8;
        verticalOffsets[2][15] = 9;

        verticalOffsets[0][0] = 5;
        verticalOffsets[0][1] = 6;
        verticalOffsets[0][2] = 7;
        verticalOffsets[0][3] = 11;
        verticalOffsets[0][4] = 5;
        verticalOffsets[0][5] = 6;
        verticalOffsets[0][6] = 7;
        verticalOffsets[0][7] = 8;
        verticalOffsets[0][8] = 10;
        verticalOffsets[0][9] = 11;
        verticalOffsets[0][10] = 12;
        verticalOffsets[0][11] = 13;
        verticalOffsets[0][12] = 2;
        verticalOffsets[0][13] = 3;
        verticalOffsets[0][14] = 4;
        verticalOffsets[0][15] = 5;

        diagonalOffsets[2][0] = 2;
        diagonalOffsets[2][1] = 2;
        diagonalOffsets[2][2] = 5;
        diagonalOffsets[2][3] = 5;
        diagonalOffsets[2][4] = 2;
        diagonalOffsets[2][5] = 3;
        diagonalOffsets[2][6] = 2;
        diagonalOffsets[2][7] = 2;

        diagonalOffsets[1][0] = 3;
        diagonalOffsets[1][1] = 3;
        diagonalOffsets[1][2] = 3;
        diagonalOffsets[1][3] = 4;
        diagonalOffsets[1][4] = 4;
        diagonalOffsets[1][5] = 4;
        diagonalOffsets[1][6] = 3;
        diagonalOffsets[1][7] = 4;

        diagonalOffsets[0][0] = 4;
        diagonalOffsets[0][1] = 5;
        diagonalOffsets[0][2] = 2;
        diagonalOffsets[0][3] = 2;
        diagonalOffsets[0][4] = 5;
        diagonalOffsets[0][5] = 5;
        diagonalOffsets[0][6] = 5;
        diagonalOffsets[0][7] = 5;

        int patternIndex;
        int pixelIndex;
        unsigned char* currentOffset;
        unsigned char* neighborOffset;
        unsigned char* thirdOffset;

        if (neighborOwners[4] < 0 || neighborOwners[4] == ownerTag) {
          if (tileCityRecordIndex != neighborCities[4]) {
            for (pixelIndex = 0; pixelIndex < 16; ++pixelIndex) {
              tilePixels[pixelIndex * rowStep] = currentBorder;
            }
          }
        } else {
          unsigned char neighborBorder =
              g_aOceanMapBorderPaletteIndexByNationTag[neighborOwners[4]];
          patternIndex = (tileIndex % 4) * 4;
          if (neighborOwners[5] == neighborOwners[4]) {
            tilePixels[0] = g_aOceanMapOwnerPaletteIndexByNationTag[neighborOwners[4]];
            tilePixels[1] = neighborBorder;
            tilePixels[rowStep] = neighborBorder;
            tilePixels[rowStep + 1] = currentBorder;
          } else {
            tilePixels[0] = currentBorder;
            tilePixels[rowStep] = currentBorder;
          }
          currentOffset = &verticalOffsets[0][patternIndex];
          neighborOffset = &verticalOffsets[1][patternIndex];
          thirdOffset = &verticalOffsets[2][patternIndex];
          pixelIndex = 4;
          do {
            tilePixels[*thirdOffset * rowStep] = currentBorder;
            tilePixels[*neighborOffset * rowStep] = neighborBorder;
            tilePixels[*neighborOffset * rowStep + 1] = currentBorder;
            if (isWater) {
              tilePixels[*currentOffset * rowStep] = currentBorder;
              tilePixels[*thirdOffset * rowStep + 1] = currentBorder;
              tilePixels[*neighborOffset * rowStep + 2] = currentBorder;
            }
            ++currentOffset;
            ++neighborOffset;
            ++thirdOffset;
          } while (--pixelIndex != 0);
          unsigned char* lowerLeft = tilePixels + 14 * rowStep;
          if (neighborOwners[3] == neighborOwners[4]) {
            lowerLeft[0] = neighborBorder;
            lowerLeft[1] = currentBorder;
            lowerLeft[rowStep] = neighborBorder;
            lowerLeft[rowStep + 1] = g_aOceanMapOwnerPaletteIndexByNationTag[neighborOwners[4]];
          } else {
            lowerLeft[0] = currentBorder;
            lowerLeft[rowStep] = currentBorder;
          }
        }

        if (neighborOwners[1] >= 0 && neighborOwners[1] != ownerTag) {
          unsigned char neighborBorder =
              g_aOceanMapBorderPaletteIndexByNationTag[neighborOwners[1]];
          patternIndex = (neighborTiles[1] % 4) * 4;
          if (neighborOwners[0] == neighborOwners[1]) {
            tilePixels[14] = neighborBorder;
            tilePixels[15] = g_aOceanMapOwnerPaletteIndexByNationTag[neighborOwners[4]];
            tilePixels[rowStep + 15] = neighborBorder;
            tilePixels[rowStep + 14] = currentBorder;
          } else {
            tilePixels[15] = currentBorder;
            tilePixels[rowStep + 15] = currentBorder;
          }
          currentOffset = &verticalOffsets[0][patternIndex];
          neighborOffset = &verticalOffsets[1][patternIndex];
          thirdOffset = &verticalOffsets[2][patternIndex];
          pixelIndex = 4;
          do {
            tilePixels[*thirdOffset * rowStep + 15] = currentBorder;
            tilePixels[*neighborOffset * rowStep + 15] = neighborBorder;
            tilePixels[*neighborOffset * rowStep + 14] = currentBorder;
            if (isWater) {
              tilePixels[*currentOffset * rowStep + 15] = currentBorder;
              tilePixels[*thirdOffset * rowStep + 14] = currentBorder;
              tilePixels[*neighborOffset * rowStep + 13] = currentBorder;
            }
            ++currentOffset;
            ++neighborOffset;
            ++thirdOffset;
          } while (--pixelIndex != 0);
          unsigned char* lowerRight = tilePixels + 14 * rowStep + 15;
          if (neighborOwners[2] == neighborOwners[1]) {
            lowerRight[0] = neighborBorder;
            lowerRight[-1] = currentBorder;
            lowerRight[rowStep] = neighborBorder;
            lowerRight[rowStep - 1] = g_aOceanMapOwnerPaletteIndexByNationTag[neighborOwners[4]];
          } else {
            lowerRight[0] = currentBorder;
            lowerRight[rowStep] = currentBorder;
          }
        }

        if (neighborOwners[5] < 0 || neighborOwners[5] == ownerTag) {
          if (tileCityRecordIndex != neighborCities[5]) {
            memset(tilePixels, currentBorder, 8);
          }
        } else {
          unsigned char neighborBorder =
              g_aOceanMapBorderPaletteIndexByNationTag[neighborOwners[5]];
          patternIndex = (tileIndex % 4) * 2;
          if (neighborOwners[5] != neighborOwners[4]) {
            tilePixels[0] = currentBorder;
            tilePixels[1] = currentBorder;
          }
          currentOffset = &diagonalOffsets[0][patternIndex];
          neighborOffset = &diagonalOffsets[1][patternIndex];
          thirdOffset = &diagonalOffsets[2][patternIndex];
          pixelIndex = 2;
          do {
            tilePixels[*neighborOffset] = currentBorder;
            tilePixels[*currentOffset] = neighborBorder;
            tilePixels[rowStep + *currentOffset] = currentBorder;
            if (isWater) {
              tilePixels[*thirdOffset] = currentBorder;
              tilePixels[rowStep + *neighborOffset] = currentBorder;
              tilePixels[rowStep * 2 + *currentOffset] = currentBorder;
            }
            ++currentOffset;
            ++neighborOffset;
            ++thirdOffset;
          } while (--pixelIndex != 0);
          if (neighborOwners[0] != ownerTag) {
            tilePixels[6] = currentBorder;
            tilePixels[7] = currentBorder;
          }
        }

        if (neighborOwners[0] < 0 || neighborOwners[0] == ownerTag) {
          if (tileCityRecordIndex != neighborCities[0]) {
            memset(tilePixels + 8, currentBorder, 8);
          }
        } else {
          unsigned char neighborBorder =
              g_aOceanMapBorderPaletteIndexByNationTag[neighborOwners[0]];
          patternIndex = (neighborTiles[0] % 4) * 2;
          unsigned char* upperRight = tilePixels + 8;
          if (neighborOwners[5] != ownerTag) {
            upperRight[0] = currentBorder;
            upperRight[1] = currentBorder;
          }
          currentOffset = &diagonalOffsets[0][patternIndex];
          neighborOffset = &diagonalOffsets[1][patternIndex];
          thirdOffset = &diagonalOffsets[2][patternIndex];
          pixelIndex = 2;
          do {
            upperRight[*neighborOffset] = currentBorder;
            upperRight[*currentOffset] = neighborBorder;
            upperRight[rowStep + *currentOffset] = currentBorder;
            if (isWater) {
              upperRight[*thirdOffset] = currentBorder;
              upperRight[rowStep + *neighborOffset] = currentBorder;
              upperRight[rowStep * 2 + *currentOffset] = currentBorder;
            }
            ++currentOffset;
            ++neighborOffset;
            ++thirdOffset;
          } while (--pixelIndex != 0);
          if (neighborOwners[0] != neighborOwners[1]) {
            upperRight[6] = currentBorder;
            upperRight[7] = currentBorder;
          }
        }

        if (neighborOwners[2] >= 0 && neighborOwners[2] != ownerTag) {
          unsigned char neighborBorder =
              g_aOceanMapBorderPaletteIndexByNationTag[neighborOwners[2]];
          patternIndex = (neighborTiles[2] % 4) * 2;
          unsigned char* lowerRight = tilePixels + 15 * rowStep + 8;
          lowerRight[0] = currentBorder;
          lowerRight[1] = currentBorder;
          currentOffset = &diagonalOffsets[0][patternIndex];
          neighborOffset = &diagonalOffsets[1][patternIndex];
          thirdOffset = &diagonalOffsets[2][patternIndex];
          pixelIndex = 2;
          do {
            lowerRight[*neighborOffset] = currentBorder;
            lowerRight[*thirdOffset] = neighborBorder;
            lowerRight[*thirdOffset - rowStep] = currentBorder;
            if (isWater) {
              lowerRight[*currentOffset] = currentBorder;
              lowerRight[*neighborOffset - rowStep] = currentBorder;
              lowerRight[*thirdOffset - rowStep * 2] = currentBorder;
            }
            ++currentOffset;
            ++neighborOffset;
            ++thirdOffset;
          } while (--pixelIndex != 0);
          if (neighborOwners[2] != neighborOwners[1]) {
            lowerRight[6] = currentBorder;
            lowerRight[7] = currentBorder;
          }
        }

        if (neighborOwners[3] >= 0 && neighborOwners[3] != ownerTag) {
          unsigned char neighborBorder =
              g_aOceanMapBorderPaletteIndexByNationTag[neighborOwners[3]];
          patternIndex = (tileIndex % 4) * 2;
          unsigned char* lowerLeft = tilePixels + 15 * rowStep;
          if (neighborOwners[3] != neighborOwners[4]) {
            lowerLeft[0] = currentBorder;
            lowerLeft[1] = currentBorder;
          }
          currentOffset = &diagonalOffsets[0][patternIndex];
          neighborOffset = &diagonalOffsets[1][patternIndex];
          thirdOffset = &diagonalOffsets[2][patternIndex];
          pixelIndex = 2;
          do {
            lowerLeft[*neighborOffset] = currentBorder;
            lowerLeft[*thirdOffset] = neighborBorder;
            lowerLeft[*thirdOffset - rowStep] = currentBorder;
            if (isWater) {
              lowerLeft[*currentOffset] = currentBorder;
              lowerLeft[*neighborOffset - rowStep] = currentBorder;
              lowerLeft[*thirdOffset - rowStep * 2] = currentBorder;
            }
            ++currentOffset;
            ++neighborOffset;
            ++thirdOffset;
          } while (--pixelIndex != 0);
          if (neighborOwners[3] != neighborOwners[2]) {
            lowerLeft[6] = currentBorder;
            lowerLeft[7] = currentBorder;
          }
        }
      }

      bool hasImprovementSprite =
          g_pGlobalMapState->terrainStateTable[tileIndex].tileActionState > -1 ||
          g_pGlobalMapState->terrainStateTable[tileIndex].perTileVisitedFlag > 0 ||
          (((g_pGlobalMapState->terrainStateTable[tileIndex].activeFlags & 3) != 0) &&
           g_pGlobalMapState->terrainStateTable[tileIndex].gateFlag != 0) ||
          (g_pGlobalMapState->terrainStateTable[tileIndex].activeFlags & 4) != 0;
      if (!hasImprovementSprite) {
        continue;
      }

      TQuickDrawSurfaceContext* spriteAtlas;
      short spriteX;
      if (g_pGlobalMapState->terrainStateTable[tileIndex].tileActionState >= 2) {
        spriteAtlas = g_pMacViewMgr->nationFleetWorld;
        spriteX = static_cast<short>(g_pGlobalMapState->terrainStateTable[tileIndex].tileActionState
                                     << 4);
      } else if (g_pGlobalMapState->terrainStateTable[tileIndex].perTileVisitedFlag > 0) {
        spriteAtlas = g_pMacViewMgr->tileOverlayStripWorlds[7];
        spriteX = static_cast<short>(
            (g_pGlobalMapState->terrainStateTable[tileIndex].perTileVisitedFlag - 1) << 4);
      } else {
        spriteAtlas = g_pMacViewMgr->gaugeWorld;
        spriteX =
            g_pGlobalMapState->GetMapImprovementTileSpriteOffset(static_cast<short>(tileIndex));
      }

      CRect sourceRect(spriteX, 0, spriteX + 0x10, 0x10);
      UpdatePaletteIndexWithDefaultFallback(0x10);
      if (g_pPrimaryRenderSurfaceContext->blitSurface.surfaceDib != 0) {
        int surfaceHeight = g_pPrimaryRenderSurfaceContext->blitSurface.surfaceDib->m_pInfoHeader
                                ->bmiHeader.biHeight;
        if (surfaceHeight <= 0) {
          surfaceHeight = -surfaceHeight;
        }
        OffsetRect(&tileRect, 0, surfaceHeight - tileRect.top - tileRect.bottom);
      }
      BlitRectWithOptionalTransparency(spriteAtlas->GetBlitSurface(),
                                       g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                       &sourceRect, &tileRect, 0x24, 0);
      UpdatePaletteIndexWithDefaultFallback(0x13);
    }

    ++baseTileIndex;
    baseTileIndex += 0x6b;
    viewportRowParity = 1 - viewportRowParity;
  }

  if (g_bDrawOceanRouteOverlay) {
    g_pViewMgr->SetForeColor(0x3c);
    int routeIndex = 0;
    short viewportRow = scrollRowOffset;
    short viewportColumnX2 = static_cast<short>(scrollColOffset * 2 + 1);
    if (g_pActiveMapOrderContext->routeNodeCount > 0) {
      do {
        CRect& route = g_pActiveMapOrderContext->routeSegments[routeIndex];
        short endX = static_cast<short>((route.right - viewportColumnX2 + 0xd8) % 0xd8);
        short startX = static_cast<short>((route.left - viewportColumnX2 + 0xd8) % 0xd8);
        int span = abs(static_cast<int>(startX) - static_cast<int>(endX));
        if (span > 0x6c) {
          if (startX > 0x6c) {
            startX = static_cast<short>(startX - 0xd8);
          } else if (endX > 0x6c) {
            endX = static_cast<short>(endX - 0xd8);
          }
        }
        SetQuickDrawTextOriginWithContextOffset(static_cast<short>((startX * 0x10) / 2),
                                                static_cast<short>((route.top - viewportRow) << 4));
        DrawCenteredGuideLineOnMapDc(static_cast<short>((endX * 0x10) / 2),
                                     static_cast<short>((route.bottom - viewportRow) << 4));
        ++routeIndex;
      } while (routeIndex < g_pActiveMapOrderContext->routeNodeCount);
    }
  }

  if (g_bDrawOceanZoneLabels) {
    InitializeUiTextStyleDescriptorAndApplyQuickDraw(2, 0xc, 0x2b68, 3);
    for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
      int tileIndex = zone->tileOrTerrainId;
      if (tileIndex == -1) {
        continue;
      }
      short viewportRow = scrollRowOffset;
      short viewportColumn = scrollColOffset;
      int tileRow = tileIndex / kStrategicMapColumns;
      int labelY = (tileRow - viewportRow) * 0x10 + 8;
      int labelX =
          ((tileIndex - viewportColumn + kStrategicMapColumns) % kStrategicMapColumns) * 0x10 +
          ((static_cast<signed char>(tileRow) & 1) << 3);
      if (labelX < rectBuffer->left || labelX > rectBuffer->right || labelY < rectBuffer->top ||
          labelY > rectBuffer->bottom) {
        continue;
      }

      SetQuickDrawFillColorFromPaletteIndex(zone->QueryPortZoneCapability() ? 0 : 0x13);
      CString label;
      zone->AssignZoneDisplayNameToOutputRef(&label);
      SetQuickDrawTextOriginWithContextOffset(
          static_cast<short>(
              labelX - MeasureTextRangeWithCachedQuickDrawStyle(
                           static_cast<LPCSTR>(label), 0, static_cast<short>(label.GetLength())) /
                           2),
          static_cast<short>(labelY + 0x10));
      DrawTextWithCachedQuickDrawStyleState(&label);
    }
  }

  if (g_bDrawOceanNationLabels) {
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0x41, 0xc, 0x2b68);
    SetQuickDrawTextFace(0x41);
    TCountry** descriptorSlot = g_apTerrainTypeDescriptorTable;
    do {
      TCountry* descriptor = *descriptorSlot;
      if (descriptor != 0) {
        int tileIndex = descriptor->GetOrComputeOverlayAnchorTileIndex();
        if (tileIndex == -1) {
          break;
        }
        short viewportRow = scrollRowOffset;
        short viewportColumn = scrollColOffset;
        int tileRow = tileIndex / kStrategicMapColumns;
        int labelY = (tileRow - viewportRow) * 0x10 + 8;
        int labelX =
            ((tileIndex - viewportColumn + kStrategicMapColumns) % kStrategicMapColumns) * 0x10 +
            ((static_cast<signed char>(tileRow) & 1) << 3);
        if (labelX >= rectBuffer->left && labelX <= rectBuffer->right &&
            labelY >= rectBuffer->top && labelY <= rectBuffer->bottom) {
          CString label;
          descriptor->FormatOverlayTerrainLabelText(&label);
          short labelWidth = MeasureTextExtentWithCachedQuickDrawStyle(&label);
          labelX -= labelWidth / 2;
          SetQuickDrawFillColorFromPaletteIndex(0x13);
          SetQuickDrawTextOriginWithContextOffset(static_cast<short>(labelX + 1),
                                                  static_cast<short>(labelY + 1));
          DrawTextWithCachedQuickDrawStyleState(&label);
          SetQuickDrawFillColorFromPaletteIndex(0);
          SetQuickDrawTextOriginWithContextOffset(static_cast<short>(labelX),
                                                  static_cast<short>(labelY));
          DrawTextWithCachedQuickDrawStyleState(&label);
        }
      }
      ++descriptorSlot;
    } while (descriptorSlot < g_apTerrainTypeDescriptorTable + kTerrainTypeDescriptorTableCount);
  }

  if (g_bTransferOceanViewportToActiveSurface) {
    SetGWorld(previousSurface, previousSurfaceFlags);
    BlitRectWithOptionalTransparency(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &viewportSourceRect, &viewportDestinationRect, 0, 0);
    UnlockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
  }
}

// Draws one wrapped route segment in the ocean map's doubled-column coordinate system.
// FUNCTION: IMPERIALISM 0x00567f00
void DrawOceanRouteSegment(short sourceColumn, int sourceRow, short destinationColumn,
                           int destinationRow) {
  int difference = sourceColumn - destinationColumn;
  if (abs(difference) > 0x6c) {
    if (sourceColumn < 0x6d) {
      if (destinationColumn > kStrategicMapColumns) {
        destinationColumn = static_cast<short>(destinationColumn - 0xd8);
      }
    } else {
      sourceColumn = static_cast<short>(sourceColumn - 0xd8);
    }
  }
  SetQuickDrawTextOriginWithContextOffset(static_cast<short>((sourceColumn * 0x10) / 2),
                                          static_cast<short>(sourceRow << 4));
  DrawCenteredGuideLineOnMapDc(static_cast<short>((destinationColumn * 0x10) / 2),
                               static_cast<short>(destinationRow << 4));
}

// FUNCTION: IMPERIALISM 0x00567fa0
void TOceanDialog::RenderMapOrderEntryTilePreview(TCivUnit* orderEntry, int projectedX,
                                                  int projectedY, int flag, short tileIndex) {
  (void)tileIndex;

  CRect destinationRect(projectedY, projectedX, projectedY + 0x10, projectedX + 0x10);
  short spriteStripOffset = 0xe0;
  if (alternateOverlayEnabled) {
    spriteStripOffset = 0xf0;
  } else {
    int ownerNation = static_cast<int>(
        g_pGlobalMapState->terrainStateTable[orderEntry->tileIndex].ownerNationTag);
    if (ownerNation > 0x17) {
      ownerNation = 0x17;
    }
    ScopedOceanMapPaletteSelection paletteSelection;
    SetQuickDrawFillColorFromPaletteIndex(g_aOceanMapOwnerPaletteIndexByNationTag[ownerNation]);
    FillRectWithQuickDrawBrushAndContextOffset(&destinationRect);
  }

  CRect sourceRect(spriteStripOffset, 0, spriteStripOffset + 0x10, 0x10);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pMacViewMgr->gaugeWorld->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &sourceRect,
                                   &destinationRect, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// FUNCTION: IMPERIALISM 0x00568120
void TOceanDialog::RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, CRect* dstRect,
                                                                 int flag) {

  short cityRecordIndex = g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex;
  TMilitaryUnit* stationedUnit = 0;
  if (cityRecordIndex >= 0 && cityRecordIndex < 0x180) {
    stationedUnit = g_pGlobalMapState->cityScoreTable[cityRecordIndex].stationedUnitChain;
  }
  if (stationedUnit == 0) {
    return;
  }

  short spriteStripOffset = g_pGlobalMapState->GetMapImprovementTileSpriteOffset(tileIndex);
  if (alternateOverlayEnabled) {
    spriteStripOffset = static_cast<short>(spriteStripOffset + 0x10);
  } else {
    int ownerNation =
        static_cast<int>(g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag);
    if (ownerNation > 0x17) {
      ownerNation = 0x17;
    }
    ScopedOceanMapPaletteSelection paletteSelection;
    SetQuickDrawFillColorFromPaletteIndex(g_aOceanMapOwnerPaletteIndexByNationTag[ownerNation]);
    FillRectWithQuickDrawBrushAndContextOffset(dstRect);
  }

  CRect sourceRect(spriteStripOffset, 0, spriteStripOffset + 0x10, 0x10);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pMacViewMgr->gaugeWorld->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &sourceRect,
                                   dstRect, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// FUNCTION: IMPERIALISM 0x005682d0
void TOceanDialog::RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, CRect* dstRect,
                                                                 bool altOverlay) {

  signed char tileActionClass = g_pGlobalMapState->terrainStateTable[tileIndex].tileActionState;
  if (tileActionClass < 0 || tileActionClass >= kMapTileActionStateOceanAtlasFrameCount) {
    return;
  }

  short spriteX = static_cast<short>(tileActionClass * 0x10);
  if (!alternateOverlayEnabled) {
    ScopedOceanMapPaletteSelection paletteSelection;
    g_pViewMgr->SetForeColor(0x32);
    FillRectWithQuickDrawBrushAndContextOffset(dstRect);
  } else {
    spriteX = static_cast<short>(spriteX + 0x10);
  }

  CRect sourceRect(spriteX, 0, spriteX + 0x10, 0x10);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pMacViewMgr->nationFleetWorld->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &sourceRect,
                                   dstRect, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);

  if (tileActionClass == 0xe) {
    return;
  }

  CRect leftSatelliteRect(dstRect->left - 8, dstRect->top - 0x10, dstRect->left + 8, dstRect->top);
  ClipRect(&leftSatelliteRect);
  if (!alternateOverlayEnabled) {
    ScopedOceanMapPaletteSelection paletteSelection;
    g_pViewMgr->SetForeColor(0x32);
    FillRectWithQuickDrawBrushAndContextOffset(&leftSatelliteRect);
  }
  spriteX = static_cast<short>(spriteX + 0x20);
  sourceRect.SetRect(spriteX, 0, spriteX + 0x10, 0x10);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pMacViewMgr->nationFleetWorld->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &sourceRect,
                                   &leftSatelliteRect, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);

  CRect rightSatelliteRect(dstRect->left + 8, dstRect->top - 0x10, dstRect->left + 0x18,
                           dstRect->top);
  ClipRect(&rightSatelliteRect);
  if (!alternateOverlayEnabled) {
    ScopedOceanMapPaletteSelection paletteSelection;
    g_pViewMgr->SetForeColor(0x32);
    FillRectWithQuickDrawBrushAndContextOffset(&rightSatelliteRect);
  }
  spriteX = static_cast<short>(spriteX + 0x20);
  sourceRect.SetRect(spriteX, 0, spriteX + 0x10, 0x10);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pMacViewMgr->nationFleetWorld->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &sourceRect,
                                   &rightSatelliteRect, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// FUNCTION: IMPERIALISM 0x00568640
void TOceanDialog::ForwardProjectTileIndexToWrappedScreenOffsetByScale(int tileIndex,
                                                                       const CPoint* viewportOrigin,
                                                                       short* outVerticalOffset,
                                                                       short* outHorizontalOffset,
                                                                       int projectionScale) {

  short mapTileIndex = static_cast<short>(tileIndex);
  int row = mapTileIndex / kStrategicMapColumns;
  *outVerticalOffset = static_cast<short>((row - scrollRowOffset) << 4);
  *outHorizontalOffset =
      static_cast<short>(((((mapTileIndex - scrollColOffset) + kStrategicMapColumns) % 0x6c) << 4) -
                         (((~row) & 1) * 8));
}

// FUNCTION: IMPERIALISM 0x005686d0
void TOceanDialog::BuildTileViewportRect(short tileIndex, CRect* outRect) {
  if (tileIndex < 0) {
    *outRect = CRect(0, 0, 0, 0);
    return;
  }

  int index = tileIndex;
  int column = (index - scrollColOffset + kStrategicMapColumns) % kStrategicMapColumns;
  int row = index / kStrategicMapColumns;
  *outRect = CRect(column, row, 0, 0);
  int left = outRect->left;
  unsigned char rowParity = static_cast<unsigned char>(outRect->top);
  left <<= 4;
  outRect->left = left;
  if ((rowParity & 1) == 0) {
    outRect->left -= 8;
  }
  outRect->top = (outRect->top - scrollRowOffset) << 4;
  outRect->right = outRect->left + 0x10;
  outRect->bottom = outRect->top + 0x10;
}

// FUNCTION: IMPERIALISM 0x005687b0
bool TOceanDialog::IsTileVisible(short tileIndex) {
  short tileRow = static_cast<short>(tileIndex / kStrategicMapColumns);
  short tileColumn = static_cast<short>(tileIndex % kStrategicMapColumns);
  if (tileColumn < scrollColOffset) {
    tileColumn = static_cast<short>(tileColumn + kStrategicMapColumns);
  }

  if (tileRow < scrollRowOffset || tileRow >= scrollRowOffset + 0x1c ||
      tileColumn < scrollColOffset || tileRow >= scrollRowOffset + 0x20) {
    return false;
  }
  return true;
}

// Converts a viewport pixel point to a wrapped map tile index.
// FUNCTION: IMPERIALISM 0x00568840
int TOceanDialog::ComputeWrappedTileIndexFromViewportPoint(const CPoint* point) {
  int y = point->y;
  int yQuotient = (y + (y >> 31 & 0xf)) >> 4;
  short row = static_cast<short>(scrollRowOffset + yQuotient);
  int x = point->x;
  if ((row & 1) == 0) {
    x += 8;
  }
  int xQuotient = (x + (x >> 31 & 0xf)) >> 4;
  short column = static_cast<short>(scrollColOffset + xQuotient);
  NormalizeWrappedMapCoord108x60(&column, &row);
  return column + row * kStrategicMapColumns;
}

// FUNCTION: IMPERIALISM 0x005688d0
void TOceanDialog::SetMapViewCellCoordinates(int column, int row) {
  if (g_pGlobalMapState->hexNeighborWrapHorizontally != 0) {
    if (static_cast<short>(column) > 0x4c) {
      column = 0x4c;
    } else if (static_cast<short>(column) < 0) {
      column = 0;
    }
  }

  scrollColOffset = static_cast<short>(column);
  while (scrollColOffset < 0) {
    scrollColOffset = static_cast<short>(scrollColOffset + kStrategicMapColumns);
  }
  while (scrollColOffset >= kStrategicMapColumns) {
    scrollColOffset = static_cast<short>(scrollColOffset - kStrategicMapColumns);
  }

  scrollRowOffset = static_cast<short>(row);
  if (scrollRowOffset < 0) {
    scrollRowOffset = 0;
  }
  if (scrollRowOffset > 0x20) {
    scrollRowOffset = 0x20;
  }

  viewportOrigin.y = scrollRowOffset << 4;
  viewportOrigin.x = scrollColOffset << 4;
  g_pGlobalMapState->mapViewOriginTile =
      static_cast<short>(scrollColOffset + scrollRowOffset * kStrategicMapColumns);

  CRect invalidateRect(0, 0, 0x1ff, 0x1bf);
  InvalidateCityDialogRectRegion(&invalidateRect, 1);
  static_cast<TMapUberPicture*>(ownerContext)->InvalidateMiniMap();
}

// FUNCTION: IMPERIALISM 0x005689f0
void TOceanDialog::CenterOn(int tileIndex) {
  short centeredTileIndex = static_cast<short>(tileIndex);
  int row = centeredTileIndex / kStrategicMapColumns;
  int col = centeredTileIndex % kStrategicMapColumns;
  SetMapViewCellCoordinates(col - 0x10, row - 0xe);
}

// FUNCTION: IMPERIALISM 0x00568a40
void TOceanDialog::ApplyDirectionalNudgeAndRefreshDisplay(unsigned char directionFlags) {
  int col = scrollColOffset;
  int row = scrollRowOffset;
  if ((directionFlags & 1) != 0) {
    row -= 4;
  } else if ((directionFlags & 2) != 0) {
    row += 4;
  }
  if ((directionFlags & 4) != 0) {
    col += 4;
  } else if ((directionFlags & 8) != 0) {
    col -= 4;
  }
  SetMapViewCellCoordinates(col, row);
  g_pDisplayMgr->activeDialog->ForceRedraw();
}

// FUNCTION: IMPERIALISM 0x00568ab0
int TOceanDialog::GetCenterTile() {
  short row = static_cast<short>(scrollRowOffset + 0xe);
  short col = static_cast<short>(scrollColOffset + 0x10);
  NormalizeWrappedMapCoord108x60(&col, &row);
  return col + row * kStrategicMapColumns;
}
