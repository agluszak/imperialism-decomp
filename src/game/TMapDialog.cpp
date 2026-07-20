#include "game/TMapDialog.h"

#include <stdlib.h>
#include "game/TAnimator.h"
#include "game/TDisplayMgr.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TMapMgr.h"
#include "game/TMapUberPicture.h"
#include "game/TOcean.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/CTemporaryRegion.h"
#include "game/TGlobalMapState.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

void NormalizeWrappedMapCoord108x60(short* xCoord, short* yCoord);

static inline double DefaultMapCellScale() {
  return 0.015625;
}

double g_mapCellRowScale_006a3360 = DefaultMapCellScale();
double g_mapCellColumnScale_006a3388 = DefaultMapCellScale();

// Genuine __cdecl free function (bare RET; every caller cleans the 0x14 arg bytes) — not a
// TMapDialog member, despite living among the map-dialog projection code. The vertical
// (row-based) output is the THIRD parameter and the horizontal the fourth — the original
// stores through [esp+0x18] for Y and [esp+0x1c] for X.
// FUNCTION: IMPERIALISM 0x00512440
void ProjectTileIndexToWrappedScreenOffsetByScale(short tileIndex, short* originXY, short* outY,
                                                  short* outX, short scale) {
  unsigned int row = static_cast<unsigned int>(tileIndex / 0x6c);
  *outY = static_cast<short>(row) * 0x40 - originXY[2];
  short projectedX = static_cast<short>((tileIndex % 0x6c) << 6) - *originXY;
  *outX = projectedX;
  if ((row & 1U) != 0) {
    projectedX = static_cast<short>(projectedX + 0x20);
    *outX = projectedX;
    if (projectedX >= 0x1ae0) {
      *outX = static_cast<short>(projectedX - 0x1b00);
    }
  }
  while (*outX < -0x40) {
    *outX = static_cast<short>(*outX + 0x1b00);
  }
  *outY = static_cast<short>(*outY / scale);
  *outX = static_cast<short>(*outX / scale);
}
// SYNTHETIC: IMPERIALISM 0x005199c0
// TMapDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x00519b30
// TMapDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMapDialog, TWorldView)

// Zero the marker/overlay state, center the view on the map's current tile (splitting
// g_pGlobalMapState->field6 into row/col and dispatching the coordinate update virtually —
// the vptr is already TMapDialog's), then seed the scroll/zoom words (previewSquareRadius78 = 0x40 tile
// pixel size). The split writes only the low words of the two locals, so they are ints whose
// addresses pass as short* (the high words are dead), matching the original stack reads.
// FUNCTION: IMPERIALISM 0x00519b50
TMapDialog::TMapDialog() : TWorldView() {
  int row;
  int col;
  viewportOffsetX = 0;
  field34c = 0;
  field35c = 0;
  viewportOffsetY = 0;
  SplitTileIndexToRowAndColumn(g_pGlobalMapState->field6, reinterpret_cast<short*>(&row),
                               reinterpret_cast<short*>(&col));
  SetMapViewCellCoordinates(col, row);
  field354 = 0;
  field356 = -1;
  field358 = 0;
  projectionScale76 = 1;
  previewSquareRadius78 = 0x40;
  field360 = 0;
}

// SYNTHETIC: IMPERIALISM 0x00519C40
// TMapDialog::`scalar deleting destructor'
TMapDialog::~TMapDialog() {}

// FUNCTION: IMPERIALISM 0x00519c90
void TMapDialog::Free() {
  if (quickDrawSurface350 != 0) {
    quickDrawSurface350 = 0;
  }
  field35c = 0;
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x00519D30
void TMapDialog::NoOpUiLifecycleHook(int arg) {
  TWorldView::NoOpUiLifecycleHook(arg);

  projectionScale76 = 1;
  previewSquareRadius78 = 0x40;

  RECT surfaceBounds = {0, 0, 0x1680, 0x40};
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&quickDrawSurface350, 8, &surfaceBounds);

  ResetAllTileMarkersToSentinel();

  g_pCitySiteCachedPrimaryRenderSurfaceContext = g_pPrimaryRenderSurfaceContext;
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagGold);
}

// FUNCTION: IMPERIALISM 0x00519e00
void TMapDialog::RenderStrategicTileSelectionAndNeighborHighlights() {}

// Draw the selection outline around a hex tile: for each of the six neighbor
// tiles (neighborTiles[0..5], -1 = none), project it to screen and stroke the
// shared hex-cell edges, skipping an interior edge when the adjacent neighbor is
// also present so shared borders are drawn once. 0x3f is the cell size, 0x20 the
// half-cell.
// FUNCTION: IMPERIALISM 0x0051a2a0
void TMapDialog::DrawHexNeighborOutlineFromTileArray(short* neighborTiles) {
  short* originXY = reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x60);
  short outY;
  short outX;

  g_pUiRuntimeContext->ApplyLegendSplitSlot34(0x3f);

  if (neighborTiles[0] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[0], originXY, &outY, &outX, 1);
    SetQuickDrawTextOriginWithContextOffset(outX, outY);
    DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY);
    DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY + 0x3f);
    if (neighborTiles[5] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX, outY);
      DrawCenteredGuideLineOnMapDc(outX, outY + 0x3f);
    }
    if (neighborTiles[1] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX + 0x20, outY);
      DrawCenteredGuideLineOnMapDc(outX + 0x20, outY + 0x3f);
    }
  }
  if (neighborTiles[1] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[1], originXY, &outY, &outX, 1);
    SetQuickDrawTextOriginWithContextOffset(outX + 0x20, outY);
    DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY);
    DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY + 0x3f);
    DrawCenteredGuideLineOnMapDc(outX + 0x20, outY + 0x3f);
    if (neighborTiles[0] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX, outY);
      DrawCenteredGuideLineOnMapDc(outX + 0x20, outY);
    }
    if (neighborTiles[2] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX, outY + 0x3f);
      DrawCenteredGuideLineOnMapDc(outX + 0x20, outY + 0x3f);
    }
  }
  if (neighborTiles[2] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[2], originXY, &outY, &outX, 1);
    SetQuickDrawTextOriginWithContextOffset(outX, outY + 0x3f);
    DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY + 0x3f);
    DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY);
    if (neighborTiles[3] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX, outY);
      DrawCenteredGuideLineOnMapDc(outX, outY + 0x3f);
    }
    if (neighborTiles[1] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX + 0x20, outY);
      DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY);
    }
  }
  if (neighborTiles[3] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[3], originXY, &outY, &outX, 1);
    SetQuickDrawTextOriginWithContextOffset(outX + 0x3f, outY + 0x3f);
    DrawCenteredGuideLineOnMapDc(outX, outY + 0x3f);
    DrawCenteredGuideLineOnMapDc(outX, outY);
    if (neighborTiles[2] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX + 0x3f, outY);
      DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY + 0x3f);
    }
    if (neighborTiles[4] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX, outY);
      DrawCenteredGuideLineOnMapDc(outX + 0x20, outY);
    }
  }
  if (neighborTiles[4] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[4], originXY, &outY, &outX, 1);
    SetQuickDrawTextOriginWithContextOffset(outX + 0x20, outY);
    DrawCenteredGuideLineOnMapDc(outX, outY);
    DrawCenteredGuideLineOnMapDc(outX, outY + 0x3f);
    DrawCenteredGuideLineOnMapDc(outX + 0x20, outY + 0x3f);
    if (neighborTiles[5] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX + 0x20, outY);
      DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY);
    }
    if (neighborTiles[3] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX + 0x20, outY + 0x3f);
      DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY + 0x3f);
    }
  }
  if (neighborTiles[5] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[5], originXY, &outY, &outX, 1);
    SetQuickDrawTextOriginWithContextOffset(outX, outY + 0x3f);
    DrawCenteredGuideLineOnMapDc(outX, outY);
    DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY);
    if (neighborTiles[0] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX + 0x3f, outY);
      DrawCenteredGuideLineOnMapDc(outX + 0x3f, outY + 0x3f);
    }
    if (neighborTiles[4] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outX, outY + 0x3f);
      DrawCenteredGuideLineOnMapDc(outX + 0x20, outY + 0x3f);
    }
  }
  SetQuickDrawFillColor(0);
}

// FUNCTION: IMPERIALISM 0x0051A900
void TMapDialog::UpdateMapDialogProjectedTileMarkerAndInvalidate(int tileIndex) {
  int originalTileIndex = tileIndex;
  short projectedY;
  ProjectTileIndexToWrappedScreenOffsetByScale(
      static_cast<short>(originalTileIndex), reinterpret_cast<short*>(&viewportOffsetX),
      &projectedY, reinterpret_cast<short*>(&tileIndex), 1);

  CRect invalidateRect(static_cast<short>(tileIndex), projectedY,
                       static_cast<short>(tileIndex) + 0x40, projectedY + 0x40);
  ReleaseTileMarkerForTile(static_cast<short>(originalTileIndex));
  InvalidateCityDialogRectRegion(&invalidateRect, 1);
}

// FUNCTION: IMPERIALISM 0x0051a990
void TMapDialog::ComputeWrappedMapCellAndRegionBandFromScreenCoord(int overlayRecord, short* outRow,
                                                                   unsigned short* outCol,
                                                                   short* outBand) {
  int* tileOffset = reinterpret_cast<int*>(overlayRecord);
  *outCol = static_cast<unsigned short>(
      static_cast<int>((viewportOffsetY + tileOffset[1]) * g_mapCellColumnScale_006a3388));
  short rowValue;
  if ((*outCol & 1) != 0) {
    rowValue = static_cast<short>(
        static_cast<int>((tileOffset[0] + viewportOffsetX + 0x20) * g_mapCellRowScale_006a3360));
    --rowValue;
  } else {
    rowValue = static_cast<short>(
        static_cast<int>((tileOffset[0] + viewportOffsetX) * g_mapCellRowScale_006a3360));
  }
  *outRow = rowValue;
  NormalizeWrappedMapCoord108x60(outRow, reinterpret_cast<short*>(outCol));

  int wrappedY = viewportOffsetY + tileOffset[1];
  short bandRow = static_cast<short>(wrappedY % 0x40);

  short bandCol = 0;
  if ((*outCol & 1) != 0) {
    int wrappedX = tileOffset[0] + 0x20 + viewportOffsetX;
    bandCol = static_cast<short>(wrappedX % 0x40 - 1);
  } else {
    int wrappedX = tileOffset[0] + viewportOffsetX;
    bandCol = static_cast<short>(wrappedX % 0x40);
  }

  if (bandCol < 0x20) {
    *outBand = static_cast<short>((bandRow < 0x20) + 1);
    return;
  }
  *outBand = static_cast<short>((bandRow >= 0x20) + 3);
}

// FUNCTION: IMPERIALISM 0x0051aad0
void TMapDialog::OrphanRetStub_005966c0(short arg1) {
  (void)arg1;
}

// FUNCTION: IMPERIALISM 0x0051ab60
undefined TMapDialog::OrphanLeaf_NoCall_Ins02_005966e0(short arg1) {
  (void)arg1;
  return 0;
}

// Centers the map view on the given tile (column offset by half the viewport tile span,
// row offset by 3) and invalidates the whole 0x200x0x1c0 dialog surface. The split writes
// only the low words of the arg slot / col local (same short*-into-int idiom as the ctor).
// FUNCTION: IMPERIALISM 0x0051ac40
void TMapDialog::UpdateMapDialogTileRowColumnMarkerAndInvalidate(int arg1) {
  int col;
  SplitTileIndexToRowAndColumn(static_cast<short>(arg1), reinterpret_cast<short*>(&arg1),
                               reinterpret_cast<short*>(&col));
  SetMapViewCellCoordinates(col - static_cast<short>(g_wMapDialogViewportTileSpan) / 2, arg1 - 3);
  RECT invalidateRect;
  invalidateRect.left = 0;
  invalidateRect.top = 0;
  invalidateRect.right = 0x1ff;
  invalidateRect.bottom = 0x1bf;
  InvalidateCityDialogRectRegion(&invalidateRect, 1);
}

// FUNCTION: IMPERIALISM 0x0051ace0
undefined TMapDialog::HasRenderableParentAndContentSlotA2() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051ad70
void TMapDialog::SetMapViewTileIndex(int arg1) {
  int tileCol;
  SplitTileIndexToRowAndColumn(static_cast<short>(arg1), reinterpret_cast<short*>(&arg1),
                               reinterpret_cast<short*>(&tileCol));
  SetMapViewCellCoordinates(tileCol, arg1);
}

// FUNCTION: IMPERIALISM 0x0051adc0
void TMapDialog::SetMapViewCellCoordinates(int arg1, int arg2) {
  SetMapDialogCellCoordinatesAndRefresh(arg1, arg2, 0);
}

// Clamps/wraps the requested viewport cell (108x54 tile map, viewport span from
// g_wMapDialogViewportTileSpan when horizontal wrap is off), commits the new viewport
// offsets (Y before X, matching the original store order), records the new center tile
// in g_pGlobalMapState->field6, invalidates the dialog surface, refreshes the owning
// uber-picture's mini-map, and translates/prunes the transient animation rects.
// `mode` is dead in this implementation (the slot's convention keeps it; TCitySiteView's
// override forwards it here unchanged, and all known call sites pass 0).
// FUNCTION: IMPERIALISM 0x0051adf0
void TMapDialog::SetMapDialogCellCoordinatesAndRefresh(int col, int row, int mode) {
  (void)mode;
  if (g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) {
    int span = g_wMapDialogViewportTileSpan;
    if (static_cast<short>(col) > 0x6e - static_cast<short>(span)) {
      col = 0x6e - span;
    } else if (static_cast<short>(col) < 1) {
      col = 1;
    }
  }
  if (static_cast<short>(col) < 0) {
    col = col + 0x6c;
  } else if (static_cast<short>(col) >= 0x6c) {
    col = col - 0x6c;
  }
  if (static_cast<short>(row) < 0) {
    row = 0;
  } else if (static_cast<short>(row) > 0x35) {
    row = 0x35;
  }

  int oldY = viewportOffsetY;
  int oldX = viewportOffsetX;
  viewportOffsetY = static_cast<short>(row) << 6;
  viewportOffsetX = static_cast<short>(col) << 6;

  g_pGlobalMapState->field6 = static_cast<short>(ComputeStridedRecordAddress6C(col, row));

  if (ownerContext != 0) {
    RECT rect;
    rect.left = 0;
    rect.top = 0;
    rect.right = 0x200;
    rect.bottom = 0x1c0;
    InvalidateCityDialogRectRegion(&rect, 1);
    static_cast<TMapUberPicture*>(ownerContext)->RefreshMiniMapIfPresent();
  }
  int dx = oldX - viewportOffsetX;
  int dy = oldY - viewportOffsetY;
  RECT clip;
  clip.left = -0x40;
  clip.top = -0x40;
  clip.right = 0x240;
  clip.bottom = 0x200;
  g_pUiAnimator->TranslateListRectsAndDropNonIntersectingEntries(dx, dy, clip);
}

// FUNCTION: IMPERIALISM 0x0051AF60
undefined TMapDialog::UpdateMapInteractionPreviewParityAndRenderTransientSprites(int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051b1c0
void TMapDialog::PopulateMapContextInfoPanelStringsByTileSelection(short tileIndex, int unusedArg) {
  (void)unusedArg;
  CString mainText;
  CString numberText;
  CString nameText;
  CString cityName;

  TView* titleControl = ResolveControlByTag(0x7469746c); // 'titl'
  if (titleControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUMapDlog_006973D0, 0x459);
  }
  g_pSimMgr->GetString(0x1cb7, g_pGlobalMapState->terrainStateTable[tileIndex].terrainType00,
                       &mainText);
  numberText.Format(g_szDecimalFormat, tileIndex);
  mainText += " (#" + numberText + g_szUiCloseParen_006973C8;
  static_cast<TStaticText*>(titleControl)
      ->AssignTextSharedRefIfChangedAndMaybeInvalidate(&mainText, 1);

  TView* infoControl = ResolveControlByTag(0x696e666f); // 'info'
  if (infoControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUMapDlog_006973D0, 0x463);
  }
  mainText = CString(g_szEmptyString);

  TView* locationControl;
  short cityIndex = g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex;
  if (cityIndex != -1) {
    if (g_pGlobalMapState->cityScoreTable[cityIndex].cityTileIndex04 == tileIndex) {
      if (g_pGlobalMapState->terrainStateTable[tileIndex].activeFlags1c & 1) {
        mainText += "National Capitol\n";
      } else {
        mainText += "Province Capitol\n";
      }
      for (short resourceType = 7; resourceType <= 0x10; resourceType++) {
        short count = g_pGlobalMapState->cityScoreTable[cityIndex]
                          .resourceDevelopmentCounts82[resourceType - 7];
        if (count != 0) {
          numberText.Format(g_szDecimalFormat, count);
          g_pSimMgr->GetString(0x2711, resourceType, &nameText);
          mainText += numberText + " " + nameText + "\n";
        }
      }
    }
    for (int edge = 0; edge < 2; edge++) {
      short resourceType = g_pGlobalMapState->terrainStateTable[tileIndex].resourceTypeByEdge[edge];
      if (resourceType != -1) {
        g_pSimMgr->GetString(0x2711, resourceType, &nameText);
        numberText.Format(
            g_szDecimalFormat,
            static_cast<signed char>(
                g_pGlobalMapState->FindResourceCapabilityRequirementLevel(tileIndex, edge)));
        mainText += numberText + " " + nameText + "\n";
      }
    }
    static_cast<TStaticText*>(infoControl)
        ->AssignTextSharedRefIfChangedAndMaybeInvalidate(&mainText, 1);

    g_pGlobalMapState->AssignCityRecordDisplayName(cityIndex, &cityName);
    TCountry* owner = g_apTerrainTypeDescriptorTable[g_pGlobalMapState->terrainStateTable[tileIndex]
                                                         .ownerNationTag04];
    if (owner != 0 && owner->encodedNationSlot >= 0x64 && owner->encodedNationSlot < 0xc8) {
      static_cast<TGreatPower*>(owner)->LoadNationDisplayNameSharedRefFromField8(&nameText);
    } else {
      // The original invokes this on the table entry even when it is null.
      owner->FormatOverlayTerrainLabelText(&nameText);
    }
    mainText = cityName + ", " + nameText;

    char currentOwner = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04;
    char formerOwner = g_pGlobalMapState->terrainStateTable[tileIndex].formerOwnerNationTag03;
    if (currentOwner != formerOwner) {
      if (static_cast<short>(formerOwner) >= 0 && static_cast<short>(formerOwner) <= 0x17 &&
          g_apTerrainTypeDescriptorTable[formerOwner] != 0) {
        static_cast<TGreatPower*>(g_apTerrainTypeDescriptorTable[formerOwner])
            ->LoadNationDisplayNameSharedRefFromField8(&nameText);
      } else {
        nameText.Format(g_szDecimalFormat, static_cast<short>(formerOwner));
        nameText = "#" + nameText;
      }
      mainText = mainText + " (formerly of " + nameText + g_szUiCloseParen_006973C8;
    }
    locationControl = ResolveControlByTag(0x6c6f6361); // 'loca'
    if (locationControl == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUMapDlog_006973D0, 0x4a3);
    }
  } else {
    TZone* zone = g_pActiveMapOrderContext->GetMapActionContextEntryByNationCodeOffset17(
        g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04);
    zone->AssignZoneDisplayNameToOutputRef(&mainText);
    locationControl = ResolveControlByTag(0x6c6f6361); // 'loca'
    if (locationControl == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUMapDlog_006973D0, 0x4ab);
    }
  }
  static_cast<TStaticText*>(locationControl)
      ->AssignTextSharedRefIfChangedAndMaybeInvalidate(&mainText, 1);
}

// FUNCTION: IMPERIALISM 0x0051e0b0
void InitializeMapInteractionPreviewScaleXDefault() {
  g_MapPreviewScaleX6A3410 = 0.015625;
}

// FUNCTION: IMPERIALISM 0x0051e0e0
void InitializeMapInteractionPreviewScaleYDefault() {
  g_MapPreviewScaleY6A33D0 = 0.015625;
}

// FUNCTION: IMPERIALISM 0x0051e1a0
void TMapDialog::ResetAllTileMarkersToSentinel() {
  g_pGlobalMapState->ResetAllTileSpriteVariantIndexToSentinel();
  for (int i = 0; i < 90; i++) {
    tileMarkers7c[i].flag = 0;
    tileMarkers7c[i].a = -1;
    tileMarkers7c[i].b = -1;
    tileMarkers7c[i].c = -1;
  }
}

// FUNCTION: IMPERIALISM 0x0051e1f0
void TMapDialog::ReleaseTileMarkerForTile(short tileIndex) {
  // Architecturally complete; the residual vs the original is MSVC hoisting the shared -1
  // sentinel into a callee-saved register (bl/bx/ebx) rather than immediates.
  short slot = g_pGlobalMapState->terrainStateTable[tileIndex].markerSlotIndex10;
  if (slot != -1) {
    g_pGlobalMapState->terrainStateTable[tileIndex].markerSlotIndex10 = -1;
    tileMarkers7c[slot].flag = 0;
    tileMarkers7c[slot].a = -1;
    tileMarkers7c[slot].b = -1;
    tileMarkers7c[slot].c = -1;
  }
}

// FUNCTION: IMPERIALISM 0x0051e260
void TMapDialog::ApplyRectSlot110(RECT* rectBuffer) {
  TView::ApplyRectSlot110(rectBuffer);
}

// FUNCTION: IMPERIALISM 0x0051EB40
undefined TMapDialog::RenderStrategicMapTileCell(short, short, short) {
  return 0;
}

// Two 10-way switches on the same pattern selector, each dispatching virtually into the
// guide-pattern family (slots 0x85-0x8e) with variant 1 (nationA's tint) then variant 2
// (nationB's). Ghidra's decompile of this function is broken (phantom register args from
// the deferred __cdecl stack cleanup); ported from the raw listing.
// FUNCTION: IMPERIALISM 0x00520670
void TMapDialog::RenderMapDialogBilateralRelationMarkers(short relationLevel, int originX,
                                                         int originY, int nationA, int nationB) {
  if (g_pDiplomacyTurnStateManager->IsPrimaryNationSlotIndex(nationA) == 0) {
    g_pUiRuntimeContext->ApplyTurnEventPaletteColorByEventCode(0x35);
  } else {
    g_pUiRuntimeContext->ApplyTurnEventPaletteColorByEventCode(nationA);
  }
  SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(2, 2);
  switch (relationLevel) {
  case 0:
    DrawMapDialogGuidePatternSetA_00520970(originX, originY, 1);
    break;
  case 1:
    DrawMapDialogGuidePatternSetB_00520a90(originX, originY, 1);
    break;
  case 2:
    DrawMapDialogGuidePatternSetC_00520c10(originX, originY, 1);
    break;
  case 3:
    DrawMapDialogGuidePatternSetD_00520d20(originX, originY, 1);
    break;
  case 4:
    DrawMapDialogTileGuidePatternByVariant(originX, originY, 1);
    break;
  case 5:
    DrawMapDialogGuidePatternSetE_00520fc0(originX, originY, 1);
    break;
  case 6:
    DrawMapDialogGuidePatternSetF_00521090(originX, originY, 1);
    break;
  case 7:
    DrawMapDialogGuidePatternSetG_005211c0(originX, originY, 1);
    break;
  case 8:
    DrawMapDialogGuidePatternSetH_00521340(originX, originY, 1);
    break;
  case 9:
    DrawMapDialogGuidePatternSetI_00521540(originX, originY, 1);
    break;
  }
  if (g_pDiplomacyTurnStateManager->IsPrimaryNationSlotIndex(nationB) == 0) {
    g_pUiRuntimeContext->ApplyTurnEventPaletteColorByEventCode(0x35);
  } else {
    g_pUiRuntimeContext->ApplyTurnEventPaletteColorByEventCode(nationB);
  }
  switch (relationLevel) {
  case 0:
    DrawMapDialogGuidePatternSetA_00520970(originX, originY, 2);
    break;
  case 1:
    DrawMapDialogGuidePatternSetB_00520a90(originX, originY, 2);
    break;
  case 2:
    DrawMapDialogGuidePatternSetC_00520c10(originX, originY, 2);
    break;
  case 3:
    DrawMapDialogGuidePatternSetD_00520d20(originX, originY, 2);
    break;
  case 4:
    DrawMapDialogTileGuidePatternByVariant(originX, originY, 2);
    break;
  case 5:
    DrawMapDialogGuidePatternSetE_00520fc0(originX, originY, 2);
    break;
  case 6:
    DrawMapDialogGuidePatternSetF_00521090(originX, originY, 2);
    break;
  case 7:
    DrawMapDialogGuidePatternSetG_005211c0(originX, originY, 2);
    break;
  case 8:
    DrawMapDialogGuidePatternSetH_00521340(originX, originY, 2);
    break;
  case 9:
    DrawMapDialogGuidePatternSetI_00521540(originX, originY, 2);
    break;
  }
}

// FUNCTION: IMPERIALISM 0x00520970
void TMapDialog::DrawMapDialogGuidePatternSetA_00520970(int originX, int originY, short variant) {
  int y1;
  int y2;
  if (variant == 0) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x18, originY);
    DrawCenteredGuideLineOnMapDc(originX + 0x20, originY + 9);
    DrawCenteredGuideLineOnMapDc(originX + 0x26, originY + 6);
    DrawCenteredGuideLineOnMapDc(originX + 0x2c, originY + 8);
    return;
  }
  if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x16, originY);
    y1 = originY + 10;
    DrawCenteredGuideLineOnMapDc(originX + 0x1e, y1);
    y2 = originY + 8;
  } else {
    if (variant != 2) {
      return;
    }
    SetQuickDrawTextOriginWithContextOffset(originX + 0x1a, originY);
    y1 = originY + 6;
    DrawCenteredGuideLineOnMapDc(originX + 0x22, y1);
    y2 = originY + 4;
  }
  DrawCenteredGuideLineOnMapDc(originX + 0x26, y2);
  DrawCenteredGuideLineOnMapDc(originX + 0x2c, y1);
}

// FUNCTION: IMPERIALISM 0x00520A90
void TMapDialog::DrawMapDialogGuidePatternSetB_00520a90(int originX, int originY, short variant) {
  if (variant == 0) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 8);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0xd);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0x14);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x19);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY + 0x20);
    return;
  }
  if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 10);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0xf);
    DrawCenteredGuideLineOnMapDc(originX + 0x31, originY + 0x14);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY + 0x19);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x20);
    return;
  }
  if (variant == 2) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 6);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + 0xb);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x13);
    DrawCenteredGuideLineOnMapDc(originX + 0x3c, originY + 0x19);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x20);
  }
}

// FUNCTION: IMPERIALISM 0x00520C10
void TMapDialog::DrawMapDialogGuidePatternSetC_00520c10(int originX, int originY, short variant) {
  int x1;
  int x2;
  int x3;
  if (variant == 1) {
    x1 = originX + 0x36;
    SetQuickDrawTextOriginWithContextOffset(x1, originY);
    x2 = originX + 0x34;
    DrawCenteredGuideLineOnMapDc(x2, originY + 9);
    x3 = originX + 0x38;
  } else if (variant == 2) {
    x1 = originX + 0x3a;
    SetQuickDrawTextOriginWithContextOffset(x1, originY);
    x2 = originX + 0x38;
    DrawCenteredGuideLineOnMapDc(x2, originY + 9);
    x3 = originX + 0x3c;
  } else {
    x1 = originX + 0x38;
    SetQuickDrawTextOriginWithContextOffset(x1, originY);
    x2 = originX + 0x36;
    DrawCenteredGuideLineOnMapDc(x2, originY + 9);
    x3 = originX + 0x3a;
  }
  DrawCenteredGuideLineOnMapDc(x3, originY + 0x12);
  DrawCenteredGuideLineOnMapDc(x2, originY + 0x19);
  DrawCenteredGuideLineOnMapDc(x1, originY + 0x20);
}

// FUNCTION: IMPERIALISM 0x00520D20
void TMapDialog::DrawMapDialogGuidePatternSetD_00520d20(int originX, int originY, short variant) {
  if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 10);
    DrawCenteredGuideLineOnMapDc(originX + 0x39, originY);
    return;
  }
  if (variant == 2) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 5);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + -3);
    return;
  }
  SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 8);
  DrawCenteredGuideLineOnMapDc(originX + 0x38, originY);
}

// FUNCTION: IMPERIALISM 0x00520DE0
void TMapDialog::DrawMapDialogTileGuidePatternByVariant(int originX, int originY, short variant) {
  if (variant == 0) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 8);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0xd);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0x14);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x19);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY + 0x20);
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 8);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY);
    return;
  }
  if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 10);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0xf);
    DrawCenteredGuideLineOnMapDc(originX + 0x31, originY + 0x14);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY + 0x19);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x20);
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 10);
    DrawCenteredGuideLineOnMapDc(originX + 0x39, originY);
    return;
  }
  if (variant == 2) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 6);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + 0xb);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x13);
    DrawCenteredGuideLineOnMapDc(originX + 0x3c, originY + 0x19);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x20);
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 5);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + -3);
  }
}

// FUNCTION: IMPERIALISM 0x00520FC0
void TMapDialog::DrawMapDialogGuidePatternSetE_00520fc0(int originX, int originY, short variant) {
  if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x36);
    DrawCenteredGuideLineOnMapDc(originX + 0x39, originY + 0x3e);
    return;
  }
  if (variant == 2) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x3a);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x42);
    return;
  }
  SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x38);
  DrawCenteredGuideLineOnMapDc(originX + 0x39, originY + 0x40);
}

// FUNCTION: IMPERIALISM 0x00521090
void TMapDialog::DrawMapDialogGuidePatternSetF_00521090(int originX, int originY, short variant) {
  int x1;
  int x2;
  if (variant == 1) {
    x1 = originX + 0x36;
    SetQuickDrawTextOriginWithContextOffset(x1, originY + 0x20);
    x2 = originX + 0x34;
    DrawCenteredGuideLineOnMapDc(x2, originY + 0x29);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY + 0x32);
  } else if (variant == 2) {
    x1 = originX + 0x3a;
    SetQuickDrawTextOriginWithContextOffset(x1, originY + 0x20);
    x2 = originX + 0x38;
    DrawCenteredGuideLineOnMapDc(x2, originY + 0x29);
    DrawCenteredGuideLineOnMapDc(originX + 0x3c, originY + 0x32);
  } else {
    x1 = originX + 0x38;
    SetQuickDrawTextOriginWithContextOffset(x1, originY + 0x20);
    x2 = originX + 0x36;
    DrawCenteredGuideLineOnMapDc(x2, originY + 0x29);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x32);
  }
  DrawCenteredGuideLineOnMapDc(x2, originY + 0x39);
  DrawCenteredGuideLineOnMapDc(x1, originY + 0x40);
}

// FUNCTION: IMPERIALISM 0x005211C0
void TMapDialog::DrawMapDialogGuidePatternSetG_005211c0(int originX, int originY, short variant) {
  if (variant == 0) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x38);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x33);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0x2c);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x27);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY + 0x20);
    return;
  }
  if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x36);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0x31);
    DrawCenteredGuideLineOnMapDc(originX + 0x30, originY + 0x2c);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + 0x27);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x20);
    return;
  }
  if (variant == 2) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x3a);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + 0x35);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x2d);
    DrawCenteredGuideLineOnMapDc(originX + 0x3c, originY + 0x27);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x20);
  }
}

// FUNCTION: IMPERIALISM 0x00521340
void TMapDialog::DrawMapDialogGuidePatternSetH_00521340(int originX, int originY, short variant) {
  if (variant == 0) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x38);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x33);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0x2c);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x27);
    DrawCenteredGuideLineOnMapDc(originX + 0x38, originY + 0x20);
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x38);
    DrawCenteredGuideLineOnMapDc(originX + 0x39, originY + 0x40);
    return;
  }
  if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x36);
    DrawCenteredGuideLineOnMapDc(originX + 0x34, originY + 0x31);
    DrawCenteredGuideLineOnMapDc(originX + 0x30, originY + 0x2c);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + 0x27);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x20);
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x36);
    DrawCenteredGuideLineOnMapDc(originX + 0x39, originY + 0x3e);
    return;
  }
  if (variant == 2) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x3a);
    DrawCenteredGuideLineOnMapDc(originX + 0x37, originY + 0x35);
    DrawCenteredGuideLineOnMapDc(originX + 0x36, originY + 0x2d);
    DrawCenteredGuideLineOnMapDc(originX + 0x3c, originY + 0x27);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x20);
    SetQuickDrawTextOriginWithContextOffset(originX + 0x2c, originY + 0x3a);
    DrawCenteredGuideLineOnMapDc(originX + 0x3a, originY + 0x42);
  }
}

// FUNCTION: IMPERIALISM 0x00521540
void TMapDialog::DrawMapDialogGuidePatternSetI_00521540(int originX, int originY, short variant) {
  int y1;
  if (variant == 0) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x18, originY + 0x40);
    DrawCenteredGuideLineOnMapDc(originX + 0x1a, originY + 0x3b);
    DrawCenteredGuideLineOnMapDc(originX + 0x24, originY + 0x36);
    y1 = originY + 0x38;
  } else if (variant == 1) {
    SetQuickDrawTextOriginWithContextOffset(originX + 0x16, originY + 0x3f);
    DrawCenteredGuideLineOnMapDc(originX + 0x18, originY + 0x39);
    DrawCenteredGuideLineOnMapDc(originX + 0x24, originY + 0x33);
    y1 = originY + 0x36;
  } else {
    if (variant != 2) {
      return;
    }
    SetQuickDrawTextOriginWithContextOffset(originX + 0x1a, originY + 0x40);
    DrawCenteredGuideLineOnMapDc(originX + 0x1c, originY + 0x3b);
    DrawCenteredGuideLineOnMapDc(originX + 0x24, originY + 0x38);
    y1 = originY + 0x3a;
  }
  DrawCenteredGuideLineOnMapDc(originX + 0x2a, y1);
  DrawCenteredGuideLineOnMapDc(originX + 0x2c, y1);
}

// FUNCTION: IMPERIALISM 0x00521680
undefined TMapDialog::DrawHexEdgeConnectionGlyphsByMask(unsigned char, int, int, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00521A40
undefined TMapDialog::EmitHexAdjacencyTransitionEventsByBitmask(unsigned char, int, int, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00522000
void TMapDialog::DrawMapDialogOwnershipMarkerForNation_00522000(unsigned char edgeMask, int screenX,
                                                                int screenY, short tileIndex) {
  g_pUiRuntimeContext->ApplyTurnEventPaletteColorByEventCode(
      g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04);
  if ((edgeMask & 0x20) != 0) {
    SetQuickDrawTextOriginWithContextOffset(screenX + 8, screenY + 8);
    DrawCenteredGuideLineOnMapDc(screenX + 0xc, screenY + 8);
    return;
  }
  if ((edgeMask & 8) != 0) {
    SetQuickDrawTextOriginWithContextOffset(screenX + 8, screenY + 0x38);
    DrawCenteredGuideLineOnMapDc(screenX + 0xc, screenY + 0x38);
    return;
  }
  if ((edgeMask & 2) != 0) {
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x2c, screenY + 0x2e);
    DrawCenteredGuideLineOnMapDc(screenX + 0x30, screenY + 0x2e);
  }
}

// FUNCTION: IMPERIALISM 0x005220F0
undefined TMapDialog::RenderMapDialogDiplomacyNeighborRelationHints(int, int, short) {
  return 0;
}

// Draws a guide line between two tiles' screen centers, wrapping the far tile across the
// 108-column seam and culling the line when both endpoints fall off the same screen edge.
// FUNCTION: IMPERIALISM 0x00522C10
void TMapDialog::DrawMapDialogWrappedTileConnectionMarker_00522c10(short col1, int row1, short col2,
                                                                   int row2) {
  if (abs(static_cast<int>(col1) - static_cast<int>(col2)) > 0x6c) {
    if (col1 > 0x6c) {
      col1 = col1 - 0xd8;
    } else if (col2 > 0x6c) {
      col2 = col2 - 0xd8;
    }
  }
  if (col1 < 0) {
    if (col2 < 0) {
      return;
    }
  } else if (col1 > 0x12 && col2 > 0x12) {
    return;
  }
  if (static_cast<short>(row1) < 0) {
    if (static_cast<short>(row2) < 0) {
      return;
    }
  } else if (static_cast<short>(row1) > 8 && static_cast<short>(row2) > 8) {
    return;
  }
  SetQuickDrawTextOriginWithContextOffset((col1 * 0x40) / 2 + 0x40, (row1 + 1) * 0x40);
  DrawCenteredGuideLineOnMapDc((col2 * 0x40) / 2 + 0x40, (row2 + 1) * 0x40);
}

// Draws the coastline "connection" line pattern linking this ocean tile to its ocean
// neighbors, per the 6-bit connectionMask (which adjacent hexes are ocean and joined).
// FUNCTION: IMPERIALISM 0x00522CF0
void TMapDialog::DrawHexNeighborConnectionMask(unsigned char connectionMask, int screenX,
                                               int screenY, short tileIndex) {
  short neighborTiles[6];
  TMapMgr::ComputeHexNeighborTileIndices(tileIndex, neighborTiles,
                                         g_pGlobalMapState->hexNeighborWrapHorizontally20);
  TTerrainStateRecordView* tiles = g_pGlobalMapState->terrainStateTable;
  unsigned char northeastOcean = connectionMask & 2;

  if ((connectionMask & 2) != 0 && tiles[neighborTiles[1]].terrainType00 == 5) {
    if ((connectionMask & 1) == 0 || tiles[neighborTiles[2]].terrainType00 != 5) {
      SetQuickDrawTextOriginWithContextOffset(screenX + 0x38, screenY);
      DrawCenteredGuideLineOnMapDc(screenX + 0x30, screenY + 8);
      DrawCenteredGuideLineOnMapDc(screenX + 0x30, screenY + 0x14);
      DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY + 0x20);
    } else {
      SetQuickDrawTextOriginWithContextOffset(screenX + 0x2c, screenY + 8);
      DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY + 0x14);
      DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY + 0x20);
      if ((connectionMask & 0x40) != 0) {
        SetQuickDrawTextOriginWithContextOffset(screenX + 0x38, screenY + 0x14);
        DrawCenteredGuideLineOnMapDc(screenX + 0x3c, screenY + 8);
        DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY);
      }
    }

    int bottomY;
    if ((connectionMask & 4) == 0 || tiles[neighborTiles[0]].terrainType00 != 5) {
      SetQuickDrawTextOriginWithContextOffset(screenX + 0x38, screenY + 0x20);
      DrawCenteredGuideLineOnMapDc(screenX + 0x3c, screenY + 0x28);
      bottomY = screenY + 0x34;
    } else {
      SetQuickDrawTextOriginWithContextOffset(screenX + 0x38, screenY + 0x20);
      DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY + 0x28);
      DrawCenteredGuideLineOnMapDc(screenX + 0x2c, screenY + 0x38);
      if ((connectionMask & 0x80) == 0) {
        goto tail;
      }
      SetQuickDrawTextOriginWithContextOffset(screenX + 0x38, screenY + 0x28);
      bottomY = screenY + 0x38;
    }
    DrawCenteredGuideLineOnMapDc(screenX + 0x3c, bottomY);
    DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY + 0x40);
  }

tail:
  if ((connectionMask & 1) != 0 && tiles[neighborTiles[2]].terrainType00 == 5) {
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x18, screenY);
    DrawCenteredGuideLineOnMapDc(screenX + 0x20, screenY + 8);
    DrawCenteredGuideLineOnMapDc(screenX + 0x2c, screenY + 8);
    if (northeastOcean == 0 && tiles[neighborTiles[1]].terrainType00 == 5) {
      SetQuickDrawTextOriginWithContextOffset(screenX + 0x38, screenY);
      DrawCenteredGuideLineOnMapDc(screenX + 0x30, screenY + 8);
      DrawCenteredGuideLineOnMapDc(screenX + 0x2c, screenY + 8);
    }
  }
  if ((connectionMask & 4) != 0 && tiles[neighborTiles[0]].terrainType00 == 5) {
    SetQuickDrawTextOriginWithContextOffset(screenX + 0x18, screenY + 0x40);
    DrawCenteredGuideLineOnMapDc(screenX + 0x20, screenY + 0x38);
    DrawCenteredGuideLineOnMapDc(screenX + 0x2c, screenY + 0x38);
    if (northeastOcean == 0 && tiles[neighborTiles[1]].terrainType00 == 5) {
      SetQuickDrawTextOriginWithContextOffset(screenX + 0x2c, screenY + 0x38);
      DrawCenteredGuideLineOnMapDc(screenX + 0x30, screenY + 0x38);
      DrawCenteredGuideLineOnMapDc(screenX + 0x38, screenY + 0x40);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00523060
undefined TMapDialog::MapDialogSetFillColor() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00523170
undefined TMapDialog::UpdateMapOrderEntryTilePreviewSlot(int, short, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00523640
void TMapDialog::RenderMapOrderEntryTilePreview(TCivUnit* orderEntry, int projectedX,
                                                int projectedY, int flag, short tileIndex) {
  (void)orderEntry;
  (void)projectedX;
  (void)projectedY;
  (void)flag;
  (void)tileIndex;
}

// FUNCTION: IMPERIALISM 0x00523b70
void TMapDialog::RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, void* dstRect,
                                                               int flag) {
  (void)tileIndex;
  (void)dstRect;
  (void)flag;
}

// FUNCTION: IMPERIALISM 0x00523ff0
void TMapDialog::RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, void* dstRect,
                                                               unsigned char altOverlay) {
  void* surfaceContext = reinterpret_cast<void*>(g_pActiveQuickDrawSurfaceContext);
  char* tileRecord =
      reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable) + tileIndex * 0x24;
  char ownerPaletteIndex = tileRecord[0x16];
  if ((ownerPaletteIndex < 0) || ('\x13' <= ownerPaletteIndex)) {
    return;
  }

  struct {
    long left;
    long top;
    long right;
    long bottom;
  } srcRect;

  if (altOverlay == 0) {
    surfaceContext = quickDrawSurface350;
    srcRect.left = static_cast<long>(static_cast<short>(ownerPaletteIndex * 0x40));
    srcRect.right = srcRect.left + 0x40;
    srcRect.top = 0;
    srcRect.bottom = 0x40;
    UpdatePaletteIndexWithDefaultFallback(0x10);
    int strategicBlitSource = *reinterpret_cast<int*>(0x006a21a8 + 0x690);
    reinterpret_cast<void(__stdcall*)(void*, void*, void*, void*, int, void*)>(
        BlitRectWithOptionalTransparency)(reinterpret_cast<void*>(strategicBlitSource + 4),
                                          reinterpret_cast<char*>(surfaceContext) + 4, &srcRect,
                                          dstRect, 0x24, 0);
    UpdatePaletteIndexWithDefaultFallback(0x13);
    return;
  }

  if (overlayFlagByte74 == 0) {
    short terrainFrameIndex = static_cast<short>(tileRecord[0x10]);
    if (terrainFrameIndex == -1) {
      return;
    }
    srcRect.left = static_cast<long>(terrainFrameIndex) << 6;
    srcRect.right = (terrainFrameIndex + 1) * 0x40;
    srcRect.top = 0;
    srcRect.bottom = 0x40;
    reinterpret_cast<void(__stdcall*)(void*, void*, void*, void*, int, void*)>(
        BlitRectWithOptionalTransparency)(
        reinterpret_cast<char*>(quickDrawSurface350) + 4,
        reinterpret_cast<char*>(g_pActiveQuickDrawSurfaceContext) + 4, &srcRect, dstRect, 0, 0);
    return;
  }

  srcRect.left = static_cast<long>(static_cast<short>(ownerPaletteIndex * 0x40 + 0x40));
  srcRect.right = srcRect.left + 0x40;
  srcRect.top = 0;
  srcRect.bottom = 0x40;
  UpdatePaletteIndexWithDefaultFallback(0x10);
  int strategicBlitSource = *reinterpret_cast<int*>(0x006a21a8 + 0x690);
  reinterpret_cast<void(__stdcall*)(void*, void*, void*, void*, int, void*)>(
      BlitRectWithOptionalTransparency)(reinterpret_cast<void*>(strategicBlitSource + 4),
                                        reinterpret_cast<char*>(surfaceContext) + 4, &srcRect,
                                        dstRect, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// FUNCTION: IMPERIALISM 0x005241B0
undefined TMapDialog::OrphanLeaf_NoCall_Ins100_005241b0(int, int, short, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005242F0
undefined TMapDialog::GetTEventHandlerClassNamePointer(int, int, short, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00524540
undefined TMapDialog::VTableSlot97(int, int, short, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00524670
undefined TMapDialog::InitializeForeignMinisterStateFlags(int, int, short, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005247A0
undefined TMapDialog::AddToForeignMinisterCounterAtIndex(int*, int*, short, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005249F0
undefined TMapDialog::SetForeignMinisterReadyFlag14(int*, int*, short, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00524B30
undefined TMapDialog::SelectCandidateTilesWithLowGroundUnitCount(unsigned int, int, short, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00524C60
undefined TMapDialog::OrphanLeaf_NoCall_Ins07_004d8920_9c(int, int, short, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00524E70
undefined TMapDialog::OrphanLeaf_NoCall_Ins07_004d8920_9d(int, int, short, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005250A0
undefined TMapDialog::CopyDiamondMaskBlockKernel(int*, int*, short, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005252D0
undefined TMapDialog::CopyDiagonalMaskNarrowingBlockKernel(int*, int*, short, short) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005254A0
undefined TMapDialog::CopyDiagonalMaskWideningBlockKernel(int*, int*, short, short) {
  return 0;
}

// Copies a 64-row tile block, 16 dwords (64 bytes) per row via two unrolled 8-dword
// stores, advancing source and destination by their own dword strides between rows.
// FUNCTION: IMPERIALISM 0x00525670
void TMapDialog::Copy64x64TileBlockWithStrideAdjustment(int* src, int* dest, short srcStride,
                                                        short destStride) {
  int srcStrideDwords = static_cast<short>(srcStride / 4);
  int destStrideDwords = static_cast<short>(destStride / 4);
  int row = 0x40;
  do {
    int inner = 2;
    int* s;
    int* d;
    do {
      s = src;
      d = dest;
      d[0] = s[0];
      d[1] = s[1];
      d[2] = s[2];
      d[3] = s[3];
      d[4] = s[4];
      d[5] = s[5];
      d[6] = s[6];
      d[7] = s[7];
      inner = inner - 1;
      dest = d + 8;
      src = s + 8;
    } while (inner != 0);
    row = row - 1;
    dest = d + destStrideDwords - 8;
    src = s + srcStrideDwords - 8;
  } while (row != 0);
}

// FUNCTION: IMPERIALISM 0x00525730
void TMapDialog::ForwardProjectTileIndexToWrappedScreenOffsetByScale(int arg1, int arg2, int arg3,
                                                                     int arg4, int arg5) {
  ProjectTileIndexToWrappedScreenOffsetByScale(
      static_cast<short>(arg1), reinterpret_cast<short*>(arg2), reinterpret_cast<short*>(arg3),
      reinterpret_cast<short*>(arg4), static_cast<short>(arg5));
}
