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
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
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

// Standalone binary helper also reached via TWorldView.cpp/TMapDialog.cpp's identical
// bridge (0x51ace0); real signature void(short*, short*).
void NormalizeWrappedMapCoord108x60(short* xCoord, short* yCoord);

namespace {
// The original brackets the owner-color fill with an 8-byte compiler-generated
// palette-selection guard. Model that lifetime directly so VC5 emits the matching
// cleanup path while calls stay on the real MFC/API boundary.
class ScopedOceanMapPaletteSelection {
public:
  ScopedOceanMapPaletteSelection()
      : m_dc(GetActiveQuickDrawDc()),
        m_previousPalette(
            m_dc->SelectPalette(g_pModuleLibraryCacheState->EnsureDefaultDibPalette(), FALSE)) {}

  ~ScopedOceanMapPaletteSelection() {
    m_dc->SelectPalette(m_previousPalette, FALSE);
  }

private:
  CDC* m_dc;
  CPalette* m_previousPalette;
};

} // namespace

// SYNTHETIC: IMPERIALISM 0x00565db0
// TOceanDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x00565e70
// TOceanDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOceanDialog, TWorldView)

// FUNCTION: IMPERIALISM 0x00565e90
TOceanDialog::TOceanDialog() : scrollRowOffset7c(0), scrollColOffset7e(0) {
  // Inherited TWorldView viewport fields seeded from the ocean-dialog seed globals
  // (0x6a3ff0/0x6a3ff4); their only writer is the reset helper at 0x56a3b0 which zeroes
  // both. projectionScale/previewSquareRadius are fixed layout constants for the
  // ocean dialog.
  viewportOrigin.x = g_nOceanDialogSeedViewportOffsetX;
  viewportOrigin.y = g_nOceanDialogSeedViewportOffsetY;
  projectionScale = 4;
  previewSquareRadius = 0x10;
}

// SYNTHETIC: IMPERIALISM 0x00565ee0
// TOceanDialog::`scalar deleting destructor'
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

  int row = tileIndex / 0x6c;
  int x = ((tileIndex - scrollColOffset7e + 0x6c) % 0x6c) << 4;
  if ((row & 1) == 0) {
    x -= 8;
  }
  int y = (row - scrollRowOffset7c) << 4;
  CRect tileRect(x, y, x + 0x10, y + 0x10);
  InvalidateCityDialogRectRegion(&tileRect, 1);
}

// Computes the viewport-space bounding rectangle of every strategic tile whose owner tag
// matches the order entry's field at +0x12, converted through the dialog's scroll offsets.
// Emits a zero rect when nothing matches.
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
            g_pGlobalMapState->terrainStateTable[static_cast<short>(i)].ownerNationTag04) ==
        zone->seedNationId12) {
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
  } while (i < 0x1950);
  CRect result;
  if (minRowMirror == 1000) {
    result.left = 0;
    result.top = 0;
    result.right = 0;
    result.bottom = 0;
  } else {
    OffsetRect(&bounds, scrollColOffset7e * -2, -static_cast<int>(scrollRowOffset7c));
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
  outRow = static_cast<short>(scrollRowOffset7c + point.y / 0x10);

  int adjustedX = point.x;
  if ((outRow & 1) == 0) {
    adjustedX += 8;
  }
  outColumn = static_cast<short>(scrollColOffset7e + adjustedX / 0x10);
  NormalizeWrappedMapCoord108x60(&outColumn, &outRow);

  outRegionBand = 2;
  TMapUberPicture* mapPicture = static_cast<TMapUberPicture*>(ownerContext);
  if (mapPicture->activeUnitCategoryIndex96 == 0) {
    int tileIndex = ComputeStridedRecordAddress6C(outColumn, outRow);
    TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    if ((tile.activeFlags1c & 1) != 0) {
      short ownerNation = static_cast<short>(tile.ownerNationTag04);
      if (ownerNation == g_pSimMgr->GetActiveNationId() || ownerNation >= 7) {
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
  int iVar1;
  int iVar2;

  if (cellValue == neighborValues[4]) {
    goto strokeLower;
  }
  iVar2 = baseY + 3;
  SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX), static_cast<short>(iVar2));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(baseX), static_cast<short>(baseY + 0xc));
  if (neighborValues[4] == neighborValues[5]) {
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX), static_cast<short>(iVar2));
    iVar1 = baseX + 3;
    iVar2 = baseY;
  strokeDiag:
    DrawCenteredGuideLineOnMapDc(static_cast<short>(iVar1), static_cast<short>(iVar2));
  } else if (cellValue != neighborValues[5]) {
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX), static_cast<short>(baseY));
    iVar1 = baseX;
    goto strokeDiag;
  }
  if (neighborValues[4] == neighborValues[3]) {
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX),
                                            static_cast<short>(baseY + 0xd));
    iVar2 = baseX + 2;
  } else {
    if (cellValue == neighborValues[3]) {
      goto strokeLower;
    }
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX),
                                            static_cast<short>(baseY + 0xd));
    iVar2 = baseX;
  }
  DrawCenteredGuideLineOnMapDc(static_cast<short>(iVar2), static_cast<short>(baseY + 0xf));

strokeLower:
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
    iVar2 = baseX + 0xd;
    DrawCenteredGuideLineOnMapDc(static_cast<short>(iVar2), static_cast<short>(baseY));
    if (neighborValues[0] == neighborValues[1]) {
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(iVar2), static_cast<short>(baseY));
      iVar2 = baseY + 2;
    } else {
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(iVar2), static_cast<short>(baseY));
      iVar2 = baseY;
    }
    DrawCenteredGuideLineOnMapDc(static_cast<short>(baseX + 0xf), static_cast<short>(iVar2));
  }
  if (cellValue != neighborValues[1] && neighborValues[1] == neighborValues[2]) {
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(baseX + 0xd),
                                            static_cast<short>(baseY + 0xf));
    DrawCenteredGuideLineOnMapDc(static_cast<short>(baseX + 0xf), static_cast<short>(baseY + 0xd));
  }
}

// FUNCTION: IMPERIALISM 0x005665e0
void TOceanDialog::RenderStrategicTileSelectionAndNeighborHighlights() {
  TMapUberPicture* mapPicture = static_cast<TMapUberPicture*>(ownerContext);
  if (mapPicture->activeUnitCategoryIndex96 != 0) {
    return;
  }

  bool frameHoveredTile = cursorId4e != 0xffff && cursorId4e != 0x3f0;
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

  int row = tileIndex / 0x6c;
  int screenX = ((tileIndex - scrollColOffset7e + 0x6c) % 0x6c) << 4;
  if ((row & 1) == 0) {
    screenX -= 8;
  }
  int screenY = (row - scrollRowOffset7c) << 4;
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

  bool evenViewportRow = (scrollRowOffset7c & 1) == 0;
  bool blankWrappedLeftEdge = g_pGlobalMapState->hexNeighborWrapHorizontally != 0 &&
                              (scrollColOffset7e < 2 || scrollColOffset7e > 100);
  bool blankWrappedRightEdge = g_pGlobalMapState->hexNeighborWrapHorizontally != 0 &&
                               scrollColOffset7e > 70 && scrollColOffset7e <= 100;

  CRect viewportRect(0, 0, frameWidth34, frameHeight38);
  SetGlobalQuickDrawOrigin(static_cast<short>(absoluteX), static_cast<short>(absoluteY));
  GetClip(savedClip.tempRgn);

  TQuickDrawSurfaceContext* previousSurface = 0;
  int previousSurfaceFlags = 0;
  GetGWorld(&previousSurface, &previousSurfaceFlags);
  SetGWorld(g_pPrimaryRenderSurfaceContext, previousSurfaceFlags);
  LockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
  SetClip(savedClip.tempRgn);

  TQuickDrawBlitSurface* primarySurface = g_pPrimaryRenderSurfaceContext->GetBlitSurface();
  int bitmapHeight = primarySurface->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
  if (bitmapHeight < 1) {
    bitmapHeight = -bitmapHeight;
  }
  unsigned int bitmapStride =
      (primarySurface->surfaceDib->m_pInfoHeader->bmiHeader.biWidth + 3U) & ~3U;
  int rowStep = -static_cast<int>(bitmapStride);
  unsigned char* topRowPixels = primarySurface->pixelBits - (bitmapHeight - 1) * rowStep;

  g_pViewMgr->ApplyLegendSplitSlot34(0x32);
  CRect clippedRect(*rectBuffer);
  FillRectWithQuickDrawBrushAndContextOffset(&clippedRect);

  int row;
  int baseTileIndex = scrollRowOffset7c * 0x6c;
  for (row = 0; row < 0x1c; ++row) {
    int screenY = row << 4;
    int column;
    for (column = 0; column < 0x21; ++column) {
      int screenX = column << 4;
      if (evenViewportRow) {
        screenX -= 8;
      }
      CRect tileRect(screenX, screenY, screenX + 0x10, screenY + 0x10);

      int unwrappedColumn = scrollColOffset7e + column;
      int tileIndex = baseTileIndex + unwrappedColumn;
      bool blankCell = false;
      if (unwrappedColumn >= 0x6c) {
        tileIndex -= 0x6c;
        blankCell = !blankWrappedRightEdge;
      } else if (blankWrappedLeftEdge && unwrappedColumn > 0x3c) {
        blankCell = true;
      }

      if (blankCell) {
        g_pViewMgr->ApplyLegendSplitSlot34(0);
        FillRectWithQuickDrawBrushAndContextOffset(&tileRect);
        continue;
      }

      TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
      int ownerTag = tile.ownerNationTag04;
      if (ownerTag > 0x17) {
        ownerTag = 0x17;
      }
      if (tile.GetTerrainKind() != kStrategicTerrainWater) {
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
          if (neighborTile < 0) {
            neighborOwners[neighborIndex] = neighborTile;
            neighborCities[neighborIndex] = -1;
          } else {
            TTerrainStateRecord& neighbor = g_pGlobalMapState->terrainStateTable[neighborTile];
            short neighborOwner = neighbor.ownerNationTag04;
            if (neighborOwner > 0x17) {
              neighborOwner = 0x17;
            }
            neighborOwners[neighborIndex] = neighborOwner;
            neighborCities[neighborIndex] = neighbor.cityRecordIndex;
          }
        }

        unsigned char verticalNeighborOffsets[16];
        verticalNeighborOffsets[0] = 2;
        verticalNeighborOffsets[1] = 3;
        verticalNeighborOffsets[2] = 9;
        verticalNeighborOffsets[3] = 13;
        verticalNeighborOffsets[4] = 2;
        verticalNeighborOffsets[5] = 11;
        verticalNeighborOffsets[6] = 12;
        verticalNeighborOffsets[7] = 13;
        verticalNeighborOffsets[8] = 2;
        verticalNeighborOffsets[9] = 3;
        verticalNeighborOffsets[10] = 4;
        verticalNeighborOffsets[11] = 5;
        verticalNeighborOffsets[12] = 10;
        verticalNeighborOffsets[13] = 11;
        verticalNeighborOffsets[14] = 12;
        verticalNeighborOffsets[15] = 13;

        unsigned char verticalWaterOffsets[16];
        verticalWaterOffsets[0] = 4;
        verticalWaterOffsets[1] = 8;
        verticalWaterOffsets[2] = 10;
        verticalWaterOffsets[3] = 12;
        verticalWaterOffsets[4] = 3;
        verticalWaterOffsets[5] = 4;
        verticalWaterOffsets[6] = 9;
        verticalWaterOffsets[7] = 10;
        verticalWaterOffsets[8] = 6;
        verticalWaterOffsets[9] = 7;
        verticalWaterOffsets[10] = 8;
        verticalWaterOffsets[11] = 9;
        verticalWaterOffsets[12] = 6;
        verticalWaterOffsets[13] = 7;
        verticalWaterOffsets[14] = 8;
        verticalWaterOffsets[15] = 9;

        unsigned char verticalCurrentOffsets[16];
        verticalCurrentOffsets[0] = 5;
        verticalCurrentOffsets[1] = 6;
        verticalCurrentOffsets[2] = 7;
        verticalCurrentOffsets[3] = 11;
        verticalCurrentOffsets[4] = 5;
        verticalCurrentOffsets[5] = 6;
        verticalCurrentOffsets[6] = 7;
        verticalCurrentOffsets[7] = 8;
        verticalCurrentOffsets[8] = 10;
        verticalCurrentOffsets[9] = 11;
        verticalCurrentOffsets[10] = 12;
        verticalCurrentOffsets[11] = 13;
        verticalCurrentOffsets[12] = 2;
        verticalCurrentOffsets[13] = 3;
        verticalCurrentOffsets[14] = 4;
        verticalCurrentOffsets[15] = 5;

        unsigned char diagonalCurrentOffsets[8];
        diagonalCurrentOffsets[0] = 4;
        diagonalCurrentOffsets[1] = 5;
        diagonalCurrentOffsets[2] = 2;
        diagonalCurrentOffsets[3] = 2;
        diagonalCurrentOffsets[4] = 5;
        diagonalCurrentOffsets[5] = 5;
        diagonalCurrentOffsets[6] = 5;
        diagonalCurrentOffsets[7] = 5;

        unsigned char diagonalNeighborOffsets[8];
        diagonalNeighborOffsets[0] = 3;
        diagonalNeighborOffsets[1] = 3;
        diagonalNeighborOffsets[2] = 3;
        diagonalNeighborOffsets[3] = 4;
        diagonalNeighborOffsets[4] = 4;
        diagonalNeighborOffsets[5] = 4;
        diagonalNeighborOffsets[6] = 3;
        diagonalNeighborOffsets[7] = 4;

        unsigned char diagonalWaterOffsets[8];
        diagonalWaterOffsets[0] = 2;
        diagonalWaterOffsets[1] = 2;
        diagonalWaterOffsets[2] = 5;
        diagonalWaterOffsets[3] = 5;
        diagonalWaterOffsets[4] = 2;
        diagonalWaterOffsets[5] = 3;
        diagonalWaterOffsets[6] = 2;
        diagonalWaterOffsets[7] = 2;

        unsigned char* tilePixels = topRowPixels + screenY * rowStep + screenX;
        unsigned char currentBorder = g_aOceanMapBorderPaletteIndexByNationTag[ownerTag];
        bool isWater = tile.GetTerrainKind() == kStrategicTerrainWater;
        int patternIndex;
        int pixelIndex;

        if (neighborOwners[4] >= 0 && neighborOwners[4] != ownerTag) {
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
          for (pixelIndex = 0; pixelIndex < 4; ++pixelIndex) {
            int currentOffset = verticalCurrentOffsets[patternIndex + pixelIndex];
            int neighborOffset = verticalNeighborOffsets[patternIndex + pixelIndex];
            tilePixels[verticalWaterOffsets[patternIndex + pixelIndex] * rowStep] = currentBorder;
            tilePixels[neighborOffset * rowStep] = neighborBorder;
            tilePixels[neighborOffset * rowStep + 1] = currentBorder;
            if (isWater) {
              tilePixels[currentOffset * rowStep] = currentBorder;
              tilePixels[verticalWaterOffsets[patternIndex + pixelIndex] * rowStep + 1] =
                  currentBorder;
              tilePixels[neighborOffset * rowStep + 2] = currentBorder;
            }
          }
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
        } else if (tile.cityRecordIndex != neighborCities[4]) {
          for (pixelIndex = 0; pixelIndex < 16; ++pixelIndex) {
            tilePixels[pixelIndex * rowStep] = currentBorder;
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
          for (pixelIndex = 0; pixelIndex < 4; ++pixelIndex) {
            int currentOffset = verticalCurrentOffsets[patternIndex + pixelIndex];
            int neighborOffset = verticalNeighborOffsets[patternIndex + pixelIndex];
            tilePixels[verticalWaterOffsets[patternIndex + pixelIndex] * rowStep + 15] =
                currentBorder;
            tilePixels[neighborOffset * rowStep + 15] = neighborBorder;
            tilePixels[neighborOffset * rowStep + 14] = currentBorder;
            if (isWater) {
              tilePixels[currentOffset * rowStep + 15] = currentBorder;
              tilePixels[verticalWaterOffsets[patternIndex + pixelIndex] * rowStep + 14] =
                  currentBorder;
              tilePixels[neighborOffset * rowStep + 13] = currentBorder;
            }
          }
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

        if (neighborOwners[5] >= 0 && neighborOwners[5] != ownerTag) {
          unsigned char neighborBorder =
              g_aOceanMapBorderPaletteIndexByNationTag[neighborOwners[5]];
          patternIndex = (tileIndex % 4) * 2;
          if (neighborOwners[5] != neighborOwners[4]) {
            tilePixels[0] = currentBorder;
            tilePixels[1] = currentBorder;
          }
          for (pixelIndex = 0; pixelIndex < 2; ++pixelIndex) {
            int currentOffset = diagonalCurrentOffsets[patternIndex + pixelIndex];
            int neighborOffset = diagonalNeighborOffsets[patternIndex + pixelIndex];
            tilePixels[neighborOffset] = currentBorder;
            tilePixels[currentOffset] = neighborBorder;
            tilePixels[rowStep + currentOffset] = currentBorder;
            if (isWater) {
              tilePixels[diagonalWaterOffsets[patternIndex + pixelIndex]] = currentBorder;
              tilePixels[rowStep + neighborOffset] = currentBorder;
              tilePixels[rowStep * 2 + currentOffset] = currentBorder;
            }
          }
          if (neighborOwners[0] != ownerTag) {
            tilePixels[6] = currentBorder;
            tilePixels[7] = currentBorder;
          }
        } else if (tile.cityRecordIndex != neighborCities[5]) {
          memset(tilePixels, currentBorder, 8);
        }

        if (neighborOwners[0] >= 0 && neighborOwners[0] != ownerTag) {
          unsigned char neighborBorder =
              g_aOceanMapBorderPaletteIndexByNationTag[neighborOwners[0]];
          patternIndex = (neighborTiles[0] % 4) * 2;
          unsigned char* upperRight = tilePixels + 8;
          if (neighborOwners[5] != ownerTag) {
            upperRight[0] = currentBorder;
            upperRight[1] = currentBorder;
          }
          for (pixelIndex = 0; pixelIndex < 2; ++pixelIndex) {
            int currentOffset = diagonalCurrentOffsets[patternIndex + pixelIndex];
            int neighborOffset = diagonalNeighborOffsets[patternIndex + pixelIndex];
            upperRight[neighborOffset] = currentBorder;
            upperRight[currentOffset] = neighborBorder;
            upperRight[rowStep + currentOffset] = currentBorder;
            if (isWater) {
              upperRight[diagonalWaterOffsets[patternIndex + pixelIndex]] = currentBorder;
              upperRight[rowStep + neighborOffset] = currentBorder;
              upperRight[rowStep * 2 + currentOffset] = currentBorder;
            }
          }
          if (neighborOwners[0] != neighborOwners[1]) {
            upperRight[6] = currentBorder;
            upperRight[7] = currentBorder;
          }
        } else if (tile.cityRecordIndex != neighborCities[0]) {
          memset(tilePixels + 8, currentBorder, 8);
        }

        if (neighborOwners[2] >= 0 && neighborOwners[2] != ownerTag) {
          unsigned char neighborBorder =
              g_aOceanMapBorderPaletteIndexByNationTag[neighborOwners[2]];
          patternIndex = (neighborTiles[2] % 4) * 2;
          unsigned char* lowerRight = tilePixels + 15 * rowStep + 8;
          lowerRight[0] = currentBorder;
          lowerRight[1] = currentBorder;
          for (pixelIndex = 0; pixelIndex < 2; ++pixelIndex) {
            int currentOffset = diagonalCurrentOffsets[patternIndex + pixelIndex];
            int neighborOffset = diagonalNeighborOffsets[patternIndex + pixelIndex];
            int edgeOffset = diagonalWaterOffsets[patternIndex + pixelIndex];
            lowerRight[neighborOffset] = currentBorder;
            lowerRight[edgeOffset] = neighborBorder;
            lowerRight[edgeOffset - rowStep] = currentBorder;
            if (isWater) {
              lowerRight[currentOffset] = currentBorder;
              lowerRight[neighborOffset - rowStep] = currentBorder;
              lowerRight[edgeOffset - rowStep * 2] = currentBorder;
            }
          }
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
          for (pixelIndex = 0; pixelIndex < 2; ++pixelIndex) {
            int currentOffset = diagonalCurrentOffsets[patternIndex + pixelIndex];
            int neighborOffset = diagonalNeighborOffsets[patternIndex + pixelIndex];
            int edgeOffset = diagonalWaterOffsets[patternIndex + pixelIndex];
            lowerLeft[neighborOffset] = currentBorder;
            lowerLeft[edgeOffset] = neighborBorder;
            lowerLeft[edgeOffset - rowStep] = currentBorder;
            if (isWater) {
              lowerLeft[currentOffset] = currentBorder;
              lowerLeft[neighborOffset - rowStep] = currentBorder;
              lowerLeft[edgeOffset - rowStep * 2] = currentBorder;
            }
          }
          if (neighborOwners[3] != neighborOwners[2]) {
            lowerLeft[6] = currentBorder;
            lowerLeft[7] = currentBorder;
          }
        }
      }

      bool hasImprovementSprite = tile.tileActionState16 >= 0 || tile.perTileVisitedFlag0f > 0 ||
                                  (((tile.activeFlags1c & 3) != 0) && tile.gateFlag != 0) ||
                                  (tile.activeFlags1c & 4) != 0;
      if (!hasImprovementSprite) {
        continue;
      }

      TQuickDrawSurfaceContext* spriteAtlas;
      short spriteX;
      if (tile.tileActionState16 >= 2) {
        spriteAtlas = g_pMacViewMgr->atlas68c;
        spriteX = static_cast<short>(tile.tileActionState16 << 4);
      } else if (tile.perTileVisitedFlag0f > 0) {
        spriteAtlas = g_pMacViewMgr->atlas694[7];
        spriteX = static_cast<short>((tile.perTileVisitedFlag0f - 1) << 4);
      } else {
        spriteAtlas = g_pMacViewMgr->atlas688;
        spriteX =
            g_pGlobalMapState->GetMapImprovementTileSpriteOffset(static_cast<short>(tileIndex));
      }

      CRect sourceRect(spriteX, 0, spriteX + 0x10, 0x10);
      CRect destinationRect(tileRect);
      UpdatePaletteIndexWithDefaultFallback(0x10);
      if (g_pPrimaryRenderSurfaceContext->blitSurface.surfaceDib != 0) {
        int surfaceHeight =
            g_pPrimaryRenderSurfaceContext->blitSurface.surfaceDib->GetAbsoluteHeight();
        OffsetRect(&destinationRect, 0,
                   surfaceHeight - destinationRect.top - destinationRect.bottom);
      }
      BlitRectWithOptionalTransparency(spriteAtlas->GetBlitSurface(),
                                       g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                       &sourceRect, &destinationRect, 0x24, 0);
      UpdatePaletteIndexWithDefaultFallback(0x13);
    }

    ++baseTileIndex;
    baseTileIndex += 0x6b;
    evenViewportRow = !evenViewportRow;
  }

  if (g_bDrawOceanRouteOverlay != 0 && g_pActiveMapOrderContext != 0) {
    g_pViewMgr->ApplyLegendSplitSlot34(0x3c);
    int viewportColumnX2 = scrollColOffset7e * 2 + 1;
    for (int routeIndex = 0; routeIndex < g_pActiveMapOrderContext->routeNodeCount; ++routeIndex) {
      CRect& route = g_pActiveMapOrderContext->routeSegments[routeIndex];
      short startX = static_cast<short>((route.left - viewportColumnX2 + 0xd8) % 0xd8);
      short endX = static_cast<short>((route.right - viewportColumnX2 + 0xd8) % 0xd8);
      int span = startX - endX;
      if (span < 0) {
        span = -span;
      }
      if (span > 0x6c) {
        if (startX > 0x6c) {
          startX = static_cast<short>(startX - 0xd8);
        } else if (endX > 0x6c) {
          endX = static_cast<short>(endX - 0xd8);
        }
      }
      SetQuickDrawTextOriginWithContextOffset(
          static_cast<short>((startX * 0x10) / 2),
          static_cast<short>((route.top - scrollRowOffset7c) << 4));
      DrawCenteredGuideLineOnMapDc(static_cast<short>((endX * 0x10) / 2),
                                   static_cast<short>((route.bottom - scrollRowOffset7c) << 4));
    }
  }

  if (g_bDrawOceanZoneLabels != 0) {
    InitializeUiTextStyleDescriptorAndApplyQuickDraw(2, 0xc, 0x2b68, 3);
    for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
      int tileIndex = zone->tileOrTerrainId0c;
      if (tileIndex == -1) {
        continue;
      }
      int tileRow = tileIndex / 0x6c;
      int labelY = (tileRow - scrollRowOffset7c) * 0x10 + 8;
      int labelX = ((tileIndex - scrollColOffset7e + 0x6c) % 0x6c) * 0x10 + ((tileRow & 1) << 3);
      if (labelX < rectBuffer->left || labelX > rectBuffer->right || labelY < rectBuffer->top ||
          labelY > rectBuffer->bottom) {
        continue;
      }

      SetQuickDrawFillColorFromPaletteIndex(zone->QueryPortZoneCapability() ? 0 : 0x13);
      CString label;
      zone->AssignZoneDisplayNameToOutputRef(&label);
      short labelWidth = MeasureTextRangeWithCachedQuickDrawStyle(
          static_cast<LPCSTR>(label), 0, static_cast<short>(label.GetLength()));
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(labelX - labelWidth / 2),
                                              static_cast<short>(labelY + 8));
      DrawTextWithCachedQuickDrawStyleState(&label);
    }
  }

  if (g_bDrawOceanNationLabels != 0) {
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b68);
    SetQuickDrawTextFace(0x41);
    int descriptorIndex;
    for (descriptorIndex = 0; descriptorIndex < kTerrainTypeDescriptorTableCount;
         ++descriptorIndex) {
      TCountry* descriptor = g_apTerrainTypeDescriptorTable[descriptorIndex];
      if (descriptor == 0) {
        continue;
      }
      int tileIndex = descriptor->GetOrComputeOverlayAnchorTileIndex();
      if (tileIndex == -1) {
        break;
      }
      int tileRow = tileIndex / 0x6c;
      int labelY = (tileRow - scrollRowOffset7c) * 0x10 + 8;
      int labelX = ((tileIndex - scrollColOffset7e + 0x6c) % 0x6c) * 0x10 + ((tileRow & 1) << 3);
      if (labelX < rectBuffer->left || labelX > rectBuffer->right || labelY < rectBuffer->top ||
          labelY > rectBuffer->bottom) {
        continue;
      }

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

  if (g_bTransferOceanViewportToActiveSurface != 0) {
    SetGWorld(previousSurface, previousSurfaceFlags);
    BlitRectWithOptionalTransparency(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &viewportRect, &viewportRect, 0, 0);
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
      if (destinationColumn > 0x6c) {
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
  (void)flag;
  (void)tileIndex;

  CRect destinationRect(projectedY, projectedX, projectedY + 0x10, projectedX + 0x10);
  short spriteStripOffset = 0xe0;
  if (alternateOverlayEnabled != 0) {
    spriteStripOffset = 0xf0;
  } else {
    int ownerNation = static_cast<int>(
        g_pGlobalMapState->terrainStateTable[orderEntry->tileIndex06].ownerNationTag04);
    if (ownerNation > 0x17) {
      ownerNation = 0x17;
    }
    ScopedOceanMapPaletteSelection paletteSelection;
    SetQuickDrawFillColorFromPaletteIndex(g_aOceanMapOwnerPaletteIndexByNationTag[ownerNation]);
    FillRectWithQuickDrawBrushAndContextOffset(&destinationRect);
  }

  CRect sourceRect(spriteStripOffset, 0, spriteStripOffset + 0x10, 0x10);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas688->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &sourceRect,
                                   &destinationRect, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// FUNCTION: IMPERIALISM 0x00568120
void TOceanDialog::RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, CRect* dstRect,
                                                                 int flag) {
  (void)flag;

  short cityRecordIndex = g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex;
  TMilitaryUnit* stationedUnit = 0;
  if (cityRecordIndex >= 0 && cityRecordIndex < 0x180) {
    stationedUnit = g_pGlobalMapState->cityScoreTable[cityRecordIndex].stationedUnitChain98;
  }
  if (stationedUnit == 0) {
    return;
  }

  short spriteStripOffset = g_pGlobalMapState->GetMapImprovementTileSpriteOffset(tileIndex);
  if (alternateOverlayEnabled != 0) {
    spriteStripOffset = static_cast<short>(spriteStripOffset + 0x10);
  } else {
    int ownerNation =
        static_cast<int>(g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04);
    if (ownerNation > 0x17) {
      ownerNation = 0x17;
    }
    ScopedOceanMapPaletteSelection paletteSelection;
    SetQuickDrawFillColorFromPaletteIndex(g_aOceanMapOwnerPaletteIndexByNationTag[ownerNation]);
    FillRectWithQuickDrawBrushAndContextOffset(dstRect);
  }

  CRect sourceRect(spriteStripOffset, 0, spriteStripOffset + 0x10, 0x10);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas688->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &sourceRect,
                                   dstRect, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// FUNCTION: IMPERIALISM 0x005682d0
void TOceanDialog::RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, CRect* dstRect,
                                                                 unsigned char altOverlay) {
  (void)altOverlay;

  signed char tileActionClass = g_pGlobalMapState->terrainStateTable[tileIndex].tileActionState16;
  if (tileActionClass < 0 || tileActionClass >= kMapTileActionStateOceanAtlasFrameCount) {
    return;
  }

  short spriteX = static_cast<short>(tileActionClass * 0x10);
  if (alternateOverlayEnabled == 0) {
    ScopedOceanMapPaletteSelection paletteSelection;
    g_pViewMgr->ApplyLegendSplitSlot34(0x32);
    FillRectWithQuickDrawBrushAndContextOffset(dstRect);
  } else {
    spriteX = static_cast<short>(spriteX + 0x10);
  }

  CRect sourceRect(spriteX, 0, spriteX + 0x10, 0x10);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas68c->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &sourceRect,
                                   dstRect, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);

  if (tileActionClass == 0xe) {
    return;
  }

  CRect leftSatelliteRect(dstRect->left - 8, dstRect->top - 0x10, dstRect->left + 8, dstRect->top);
  ClipRect(&leftSatelliteRect);
  if (alternateOverlayEnabled == 0) {
    ScopedOceanMapPaletteSelection paletteSelection;
    g_pViewMgr->ApplyLegendSplitSlot34(0x32);
    FillRectWithQuickDrawBrushAndContextOffset(&leftSatelliteRect);
  }
  spriteX = static_cast<short>(spriteX + 0x20);
  sourceRect.SetRect(spriteX, 0, spriteX + 0x10, 0x10);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas68c->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &sourceRect,
                                   &leftSatelliteRect, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);

  CRect rightSatelliteRect(dstRect->left + 8, dstRect->top - 0x10, dstRect->left + 0x18,
                           dstRect->top);
  ClipRect(&rightSatelliteRect);
  if (alternateOverlayEnabled == 0) {
    ScopedOceanMapPaletteSelection paletteSelection;
    g_pViewMgr->ApplyLegendSplitSlot34(0x32);
    FillRectWithQuickDrawBrushAndContextOffset(&rightSatelliteRect);
  }
  spriteX = static_cast<short>(spriteX + 0x20);
  sourceRect.SetRect(spriteX, 0, spriteX + 0x10, 0x10);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas68c->GetBlitSurface(),
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
  (void)viewportOrigin;
  (void)projectionScale;

  short mapTileIndex = static_cast<short>(tileIndex);
  int row = mapTileIndex / 0x6c;
  *outVerticalOffset = static_cast<short>((row - scrollRowOffset7c) << 4);
  *outHorizontalOffset = static_cast<short>(
      ((((mapTileIndex - scrollColOffset7e) + 0x6c) % 0x6c) << 4) - (((~row) & 1) * 8));
}

// FUNCTION: IMPERIALISM 0x005687b0
unsigned char TOceanDialog::IsTileVisible(short tileIndex) {
  short tileRow = static_cast<short>(tileIndex / 0x6c);
  short tileColumn = static_cast<short>(tileIndex % 0x6c);
  if (tileColumn < scrollColOffset7e) {
    tileColumn = static_cast<short>(tileColumn + 0x6c);
  }

  if (tileRow < scrollRowOffset7c || tileRow >= scrollRowOffset7c + 0x1c ||
      tileColumn < scrollColOffset7e || tileRow >= scrollRowOffset7c + 0x20) {
    return 0;
  }
  return 1;
}

// Converts a viewport pixel point to a wrapped map tile index.
// FUNCTION: IMPERIALISM 0x00568840
int TOceanDialog::ComputeWrappedTileIndexFromViewportPoint(const CPoint* point) {
  int y = point->y;
  int yQuotient = (y + (y >> 31 & 0xf)) >> 4;
  short row = static_cast<short>(scrollRowOffset7c + yQuotient);
  int x = point->x;
  if ((row & 1) == 0) {
    x += 8;
  }
  int xQuotient = (x + (x >> 31 & 0xf)) >> 4;
  short column = static_cast<short>(scrollColOffset7e + xQuotient);
  NormalizeWrappedMapCoord108x60(&column, &row);
  return column + row * 0x6c;
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

  scrollColOffset7e = static_cast<short>(column);
  while (scrollColOffset7e < 0) {
    scrollColOffset7e = static_cast<short>(scrollColOffset7e + 0x6c);
  }
  while (scrollColOffset7e >= 0x6c) {
    scrollColOffset7e = static_cast<short>(scrollColOffset7e - 0x6c);
  }

  scrollRowOffset7c = static_cast<short>(row);
  if (scrollRowOffset7c < 0) {
    scrollRowOffset7c = 0;
  }
  if (scrollRowOffset7c > 0x20) {
    scrollRowOffset7c = 0x20;
  }

  viewportOrigin.y = scrollRowOffset7c << 4;
  viewportOrigin.x = scrollColOffset7e << 4;
  g_pGlobalMapState->field6 = static_cast<short>(scrollColOffset7e + scrollRowOffset7c * 0x6c);

  CRect invalidateRect(0, 0, 0x1ff, 0x1bf);
  InvalidateCityDialogRectRegion(&invalidateRect, 1);
  static_cast<TMapUberPicture*>(ownerContext)->InvalidateMiniMap();
}

// FUNCTION: IMPERIALISM 0x005689f0
void TOceanDialog::CenterOn(int tileIndex) {
  short centeredTileIndex = static_cast<short>(tileIndex);
  int row = centeredTileIndex / 0x6c;
  int col = centeredTileIndex % 0x6c;
  SetMapViewCellCoordinates(col - 0x10, row - 0xe);
}

// FUNCTION: IMPERIALISM 0x00568a40
void TOceanDialog::ApplyDirectionalNudgeAndRefreshDisplay(unsigned char directionFlags) {
  // Nudged values are passed to the slot-0x1e4 virtual (SetMapViewCellCoordinates), which is
  // a genuine 3-byte RET-8 no-op in every reachable override -- VERIFIED, so the nudge is
  // effectively discarded and no persistence happens. Residual <100% here is the original's
  // 16-bit partial-register load idiom (`mov ax, [+0x7e]`, no sign-extend), which clean C++
  // can't reproduce without a type-pun; kept as the natural `int` load.
  int col = scrollColOffset7e;
  int row = scrollRowOffset7c;
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
int TOceanDialog::ComputeWrappedTileIndexFromObjectOffset7C7E() {
  short row = static_cast<short>(scrollRowOffset7c + 0xe);
  short col = static_cast<short>(scrollColOffset7e + 0x10);
  NormalizeWrappedMapCoord108x60(&col, &row);
  return col + row * 0x6c;
}
