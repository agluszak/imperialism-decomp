#include "game/TOceanDialog.h"

#include "game/ScopedMapQuickDrawContext.h"
#include "game/TCivUnit.h"
#include "game/TDisplayMgr.h"
#include "game/TMacViewMgr.h"
#include "game/TMapMgr.h"
#include "game/TMapUberPicture.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TSimMgr.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_regions.h"
#include "game/quickdraw_rendering.h"

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
  // both. projectionScale76/previewSquareRadius78 are fixed layout constants for the
  // ocean dialog.
  viewportOffsetX = g_nOceanDialogSeedViewportOffsetX;
  viewportOffsetY = g_nOceanDialogSeedViewportOffsetY;
  projectionScale76 = 4;
  previewSquareRadius78 = 0x10;
}

// SYNTHETIC: IMPERIALISM 0x00565ee0
// TOceanDialog::`scalar deleting destructor'
TOceanDialog::~TOceanDialog() {}

// FUNCTION: IMPERIALISM 0x00565f50
void TOceanDialog::DoPostCreate(int arg) {
  TWorldView::DoPostCreate(arg);
  projectionScale76 = 4;
  previewSquareRadius78 = 0x10;
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
    result.SetRectEmpty();
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
    TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    if ((tile.activeFlags1c & 1) != 0) {
      short ownerNation = static_cast<short>(tile.ownerNationTag04);
      if (ownerNation == g_pSimMgr->GetActiveNationId() || ownerNation >= 7) {
        outRegionBand = 1;
      }
    }
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
  ForwardProjectTileIndexToWrappedScreenOffsetByScale(paintedHoverTileIndex6e,
                                                      reinterpret_cast<short*>(&viewportOffsetX),
                                                      &projectedY, &projectedX, projectionScale76);
  CRect tileRect(projectedX, projectedY, projectedX + previewSquareRadius78,
                 projectedY + previewSquareRadius78);
  BlitRectWithOptionalTransparency(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &tileRect,
                                   &tileRect, 0, 0);

  if (frameHoveredTile) {
    ForwardProjectTileIndexToWrappedScreenOffsetByScale(
        hoveredTileIndex6c, reinterpret_cast<short*>(&viewportOffsetX), &projectedY, &projectedX,
        projectionScale76);
    tileRect.SetRect(projectedX, projectedY, projectedX + previewSquareRadius78,
                     projectedY + previewSquareRadius78);
    QDFrameRect(&tileRect);
  }
}

// FUNCTION: IMPERIALISM 0x00566750
void TOceanDialog::OrphanRetStub_005966c0(short arg1) {
  (void)arg1;
}

// FUNCTION: IMPERIALISM 0x005667f0
void TOceanDialog::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
}

// FUNCTION: IMPERIALISM 0x00567fa0
void TOceanDialog::RenderMapOrderEntryTilePreview(TCivUnit* orderEntry, int projectedX,
                                                  int projectedY, int flag, short tileIndex) {
  (void)flag;
  (void)tileIndex;

  CRect destinationRect(projectedY, projectedX, projectedY + 0x10, projectedX + 0x10);
  short spriteStripOffset = 0xe0;
  if (overlayFlagByte74 != 0) {
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
  BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas688->GetBlitSurface(),
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
  if (overlayFlagByte74 != 0) {
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
  BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas688->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &sourceRect,
                                   dstRect, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// FUNCTION: IMPERIALISM 0x005682d0
void TOceanDialog::RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, CRect* dstRect,
                                                                 unsigned char altOverlay) {
  (void)tileIndex;
  (void)dstRect;
  (void)altOverlay;
}

// FUNCTION: IMPERIALISM 0x00568640
void TOceanDialog::ForwardProjectTileIndexToWrappedScreenOffsetByScale(int tileIndex,
                                                                       short* viewportOriginXY,
                                                                       short* outVerticalOffset,
                                                                       short* outHorizontalOffset,
                                                                       int projectionScale) {
  (void)viewportOriginXY;
  (void)projectionScale;

  short mapTileIndex = static_cast<short>(tileIndex);
  int row = mapTileIndex / 0x6c;
  *outVerticalOffset = static_cast<short>((row - scrollRowOffset7c) << 4);
  *outHorizontalOffset = static_cast<short>(
      ((((mapTileIndex - scrollColOffset7e) + 0x6c) % 0x6c) << 4) - (((~row) & 1) * 8));
}

// FUNCTION: IMPERIALISM 0x005687b0
undefined TOceanDialog::OrphanLeaf_NoCall_Ins02_005966e0(short arg1) {
  (void)arg1;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005688d0
void TOceanDialog::SetMapViewCellCoordinates(int column, int row) {
  if (g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) {
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

  viewportOffsetY = scrollRowOffset7c << 4;
  viewportOffsetX = scrollColOffset7e << 4;
  g_pGlobalMapState->field6 = static_cast<short>(scrollColOffset7e + scrollRowOffset7c * 0x6c);

  CRect invalidateRect(0, 0, 0x1ff, 0x1bf);
  InvalidateCityDialogRectRegion(&invalidateRect, 1);
  static_cast<TMapUberPicture*>(ownerContext)->InvalidateMiniMap();
}

// FUNCTION: IMPERIALISM 0x005689f0
void TOceanDialog::CenterOn(int tileIndex) {
  short promotedTileIndex = static_cast<short>(tileIndex);
  int row = promotedTileIndex / 0x6c;
  int col = promotedTileIndex % 0x6c;
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
