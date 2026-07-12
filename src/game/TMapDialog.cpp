#include "game/TMapDialog.h"
#include "game/TMapMgr.h"
#include "game/CTemporaryRegion.h"
#include "game/TGlobalMapState.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_invalidation_guard.h"

extern "C" long _ftol(void);

undefined4 thunk_NormalizeWrappedMapCoord108x60(void);
undefined4 ComputeStridedRecordAddress6C(void);
undefined4 thunk_ProjectTileIndexToWrappedScreenOffsetByScale(void);
undefined4 thunk_SplitTileIndexToRowAndColumn(void);

#define g_wMapDialogTileRowMarker (*reinterpret_cast<short*>(0x006a33b0))

// FUNCTION: IMPERIALISM 0x00512440
void TMapDialog::ProjectTileIndexToWrappedScreenOffsetByScale(short tileIndex, short* originXY,
                                                              short* outX, short* outY,
                                                              short scale) {
  unsigned int row = static_cast<unsigned int>(tileIndex / 0x6c);
  *outY = static_cast<short>(row) * 0x40 - originXY[2];
  short projectedX = static_cast<short>((tileIndex % 0x6c) << 6) - *originXY;
  *outX = projectedX;
  if ((row & 1U) != 0) {
    *outX = static_cast<short>(projectedX + 0x20);
    if (0x1adf < *outX) {
      *outX = static_cast<short>(projectedX - 0x1ae0);
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

// FUNCTION: IMPERIALISM 0x00519b50
TMapDialog::TMapDialog() {}

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
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x00519e00
void TMapDialog::RenderStrategicTileSelectionAndNeighborHighlights() {}

// Draw the selection outline around a hex tile: for each of the six neighbor
// tiles (neighborTiles[0..5], -1 = none), project it to screen and stroke the
// shared hex-cell edges, skipping an interior edge when the adjacent neighbor is
// also present so shared borders are drawn once. 0x3f is the cell size, 0x20 the
// half-cell. The projection's two outputs land as (outY = horizontal, outX =
// vertical) here.
// FUNCTION: IMPERIALISM 0x0051a2a0
void TMapDialog::DrawHexNeighborOutlineFromTileArray(short* neighborTiles) {
  short* originXY = reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x60);
  short outX;
  short outY;

  g_pUiRuntimeContext->ApplyLegendSplitSlot34(0x3f);

  if (neighborTiles[0] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[0], originXY, &outX, &outY, 1);
    SetQuickDrawTextOriginWithContextOffset(outY, outX);
    DrawCenteredGuideLineOnMapDc(outY + 0x3f, outX);
    DrawCenteredGuideLineOnMapDc(outY + 0x3f, outX + 0x3f);
    if (neighborTiles[5] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outY, outX);
      DrawCenteredGuideLineOnMapDc(outY, outX + 0x3f);
    }
    if (neighborTiles[1] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outY + 0x20, outX);
      DrawCenteredGuideLineOnMapDc(outY + 0x20, outX + 0x3f);
    }
  }
  if (neighborTiles[1] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[1], originXY, &outX, &outY, 1);
    SetQuickDrawTextOriginWithContextOffset(outY + 0x20, outX);
    DrawCenteredGuideLineOnMapDc(outY + 0x3f, outX);
    DrawCenteredGuideLineOnMapDc(outY + 0x3f, outX + 0x3f);
    DrawCenteredGuideLineOnMapDc(outY + 0x20, outX + 0x3f);
    if (neighborTiles[0] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outY, outX);
      DrawCenteredGuideLineOnMapDc(outY + 0x20, outX);
    }
    if (neighborTiles[2] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outY, outX + 0x3f);
      DrawCenteredGuideLineOnMapDc(outY + 0x20, outX + 0x3f);
    }
  }
  if (neighborTiles[2] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[2], originXY, &outX, &outY, 1);
    SetQuickDrawTextOriginWithContextOffset(outY, outX + 0x3f);
    DrawCenteredGuideLineOnMapDc(outY + 0x3f, outX + 0x3f);
    DrawCenteredGuideLineOnMapDc(outY + 0x3f, outX);
    if (neighborTiles[3] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outY, outX);
      DrawCenteredGuideLineOnMapDc(outY, outX + 0x3f);
    }
    if (neighborTiles[1] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outY + 0x20, outX);
      DrawCenteredGuideLineOnMapDc(outY + 0x3f, outX);
    }
  }
  if (neighborTiles[3] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[3], originXY, &outX, &outY, 1);
    SetQuickDrawTextOriginWithContextOffset(outY + 0x3f, outX + 0x3f);
    DrawCenteredGuideLineOnMapDc(outY, outX + 0x3f);
    DrawCenteredGuideLineOnMapDc(outY, outX);
    if (neighborTiles[2] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outY + 0x3f, outX);
      DrawCenteredGuideLineOnMapDc(outY + 0x3f, outX + 0x3f);
    }
    if (neighborTiles[4] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outY, outX);
      DrawCenteredGuideLineOnMapDc(outY + 0x20, outX);
    }
  }
  if (neighborTiles[4] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[4], originXY, &outX, &outY, 1);
    SetQuickDrawTextOriginWithContextOffset(outY + 0x20, outX);
    DrawCenteredGuideLineOnMapDc(outY, outX);
    DrawCenteredGuideLineOnMapDc(outY, outX + 0x3f);
    DrawCenteredGuideLineOnMapDc(outY + 0x20, outX + 0x3f);
    if (neighborTiles[5] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outY + 0x20, outX);
      DrawCenteredGuideLineOnMapDc(outY + 0x3f, outX);
    }
    if (neighborTiles[3] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outY + 0x20, outX + 0x3f);
      DrawCenteredGuideLineOnMapDc(outY + 0x3f, outX + 0x3f);
    }
  }
  if (neighborTiles[5] != -1) {
    ProjectTileIndexToWrappedScreenOffsetByScale(neighborTiles[5], originXY, &outX, &outY, 1);
    SetQuickDrawTextOriginWithContextOffset(outY, outX + 0x3f);
    DrawCenteredGuideLineOnMapDc(outY, outX);
    DrawCenteredGuideLineOnMapDc(outY + 0x3f, outX);
    if (neighborTiles[0] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outY + 0x3f, outX);
      DrawCenteredGuideLineOnMapDc(outY + 0x3f, outX + 0x3f);
    }
    if (neighborTiles[4] == -1) {
      SetQuickDrawTextOriginWithContextOffset(outY, outX + 0x3f);
      DrawCenteredGuideLineOnMapDc(outY + 0x20, outX + 0x3f);
    }
  }
  SetQuickDrawFillColor(0);
}

// FUNCTION: IMPERIALISM 0x0051A900
undefined TMapDialog::UpdateMapDialogProjectedTileMarkerAndInvalidate() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051a990
void TMapDialog::ComputeWrappedMapCellAndRegionBandFromScreenCoord(int overlayRecord, short* outRow,
                                                                   unsigned short* outCol,
                                                                   short* outBand) {
  int* tileOffset = reinterpret_cast<int*>(overlayRecord);
  unsigned int roundedCol = static_cast<unsigned int>(_ftol());
  *outCol = static_cast<unsigned short>(roundedCol);
  short rowValue = 0;
  if ((roundedCol & 1) == 0) {
    rowValue = static_cast<short>(_ftol());
  } else {
    rowValue = static_cast<short>(_ftol()) - 1;
  }
  *outRow = rowValue;
  reinterpret_cast<void(__cdecl*)(short*, short*)>(thunk_NormalizeWrappedMapCoord108x60)(
      outRow, reinterpret_cast<short*>(outCol));

  int wrappedY = viewportOffsetY + tileOffset[1];
  unsigned short signY = static_cast<unsigned short>(wrappedY >> 31);
  short bandRow = static_cast<short>(
                      (((static_cast<unsigned short>(wrappedY) ^ signY) - signY) & 0x3f) ^ signY) -
                  static_cast<short>(signY);

  short bandCol = 0;
  if ((*outCol & 1) == 0) {
    int wrappedX = tileOffset[0] + viewportOffsetX;
    unsigned short signX = static_cast<unsigned short>(wrappedX >> 31);
    bandCol = static_cast<short>(
        (((static_cast<unsigned short>(wrappedX) ^ signX) - signX) & 0x3f) ^ signX);
    bandCol = static_cast<short>(bandCol - static_cast<short>(signX));
  } else {
    int wrappedX = tileOffset[0] + 0x20 + viewportOffsetX;
    unsigned short signX = static_cast<unsigned short>(wrappedX >> 31);
    bandCol = static_cast<short>(
        ((((static_cast<unsigned short>(wrappedX) ^ signX) - signX) & 0x3f) ^ signX) -
        static_cast<short>(signX));
    bandCol = static_cast<short>(bandCol - 1);
  }

  if (bandCol < 0x20) {
    *outBand = static_cast<short>((bandRow < 0x20) + 1);
    return;
  }
  *outBand = static_cast<short>((0x1f < bandRow) + 3);
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

// FUNCTION: IMPERIALISM 0x0051ac40
void TMapDialog::UpdateMapDialogTileRowColumnMarkerAndInvalidate(int arg1) {
  int tileRowOutput[5] = {0};
  reinterpret_cast<void(__fastcall*)(TMapDialog*, int, int, int*, int*)>(
      thunk_SplitTileIndexToRowAndColumn)(this, 0, arg1, reinterpret_cast<int*>(&arg1),
                                          reinterpret_cast<int*>(&tileRowOutput[0]));
  ForwardMapDialogTileCoordUpdateToDerivedHandler(
      tileRowOutput[0] - static_cast<int>(g_wMapDialogTileRowMarker) / 2, arg1 - 3);
  int invalidateRect[3] = {0, 0x1ff, 0x1bf};
  reinterpret_cast<TView*>(this)->InvalidateCityDialogRectRegion(
      reinterpret_cast<RECT*>(&invalidateRect[0]), 1);
}

// FUNCTION: IMPERIALISM 0x0051ace0
undefined TMapDialog::HasRenderableParentAndContentSlotA2() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051ad70
void TMapDialog::OrphanRetStub_005966a0(int arg1) {
  int tileCol;
  reinterpret_cast<void(__cdecl*)(short, int*, int*)>(thunk_SplitTileIndexToRowAndColumn)(
      static_cast<short>(arg1), &arg1, &tileCol);
  OrphanRetStub_00596680(tileCol, arg1);
}

// FUNCTION: IMPERIALISM 0x0051adc0
void TMapDialog::OrphanRetStub_00596680(int arg1, int arg2) {
  ReleaseRuntimeSelectionOwnerAndDestroyObject(arg1, arg2, 0);
}

// FUNCTION: IMPERIALISM 0x0051adf0
undefined TMapDialog::ReleaseRuntimeSelectionOwnerAndDestroyObject(int param_1, int param_2,
                                                                   int param_3) {
  (void)param_1;
  (void)param_2;
  (void)param_3;
  return 0;
}

void TMapDialog::ForwardMapDialogTileCoordUpdateToDerivedHandler(int tileX, int tileY) {
  typedef void(__fastcall * TileCoordHandlerFn)(TView * self, int unusedEdx, int x, int y,
                                                int mode);
  TView* view = this;
  int* vtable = *reinterpret_cast<int**>(view);
  reinterpret_cast<TileCoordHandlerFn>(vtable[0x28c / 4])(view, 0, tileX, tileY, 0);
}

// FUNCTION: IMPERIALISM 0x0051AF60
undefined TMapDialog::UpdateMapInteractionPreviewParityAndRenderTransientSprites() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051e1a0
undefined TMapDialog::OrphanCallChain_C1_I20_0051e1a0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051e1f0
undefined TMapDialog::OrphanLeaf_NoCall_Ins21_0051e1f0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051e260
void TMapDialog::ApplyRectSlot110(RECT* rectBuffer) {
  TView::ApplyRectSlot110(rectBuffer);
}

// FUNCTION: IMPERIALISM 0x0051EB40
undefined TMapDialog::RenderStrategicMapTileCell() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00520670
undefined TMapDialog::RenderMapDialogBilateralRelationMarkers() {
  return 0;
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
undefined TMapDialog::DrawHexEdgeConnectionGlyphsByMask() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00521A40
undefined TMapDialog::EmitHexAdjacencyTransitionEventsByBitmask() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00522000
undefined TMapDialog::DrawMapDialogOwnershipMarkerForNation_00522000() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005220F0
undefined TMapDialog::RenderMapDialogDiplomacyNeighborRelationHints() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00522C10
undefined TMapDialog::DrawMapDialogWrappedTileConnectionMarker_00522c10() {
  return 0;
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
undefined TMapDialog::WrapperFor_SetQuickDrawFillColor_At00523060() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00523170
undefined TMapDialog::UpdateMapOrderEntryTilePreviewSlot() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00523640
void TMapDialog::RenderMapOrderEntryTilePreview(int arg1, int arg2, int arg3) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
}

// FUNCTION: IMPERIALISM 0x00523b70
void TMapDialog::RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, int arg2,
                                                               int arg3) {
  (void)tileIndex;
  (void)arg2;
  (void)arg3;
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

  if (field74 == 0) {
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
undefined TMapDialog::OrphanLeaf_NoCall_Ins100_005241b0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005242F0
undefined TMapDialog::GetTEventHandlerClassNamePointer() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00524540
undefined TMapDialog::VTableSlot97() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00524670
undefined TMapDialog::InitializeForeignMinisterStateFlags() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005247A0
undefined TMapDialog::AddToForeignMinisterCounterAtIndex() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005249F0
undefined TMapDialog::SetForeignMinisterReadyFlag14() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00524B30
undefined TMapDialog::SelectCandidateTilesWithLowGroundUnitCount() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00524C60
undefined TMapDialog::OrphanLeaf_NoCall_Ins07_004d8920_9c() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00524E70
undefined TMapDialog::OrphanLeaf_NoCall_Ins07_004d8920_9d() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005250A0
undefined TMapDialog::CopyDiamondMaskBlockKernel() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005252D0
undefined TMapDialog::CopyDiagonalMaskNarrowingBlockKernel() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005254A0
undefined TMapDialog::CopyDiagonalMaskWideningBlockKernel() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00525670
undefined TMapDialog::Copy64x64TileBlockWithStrideAdjustment() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00525730
void TMapDialog::ForwardProjectTileIndexToWrappedScreenOffsetByScale(int arg1, int arg2, int arg3,
                                                                     int arg4, int arg5) {
  reinterpret_cast<void(__fastcall*)(TMapDialog*, int, int, int, int, int, int)>(
      thunk_ProjectTileIndexToWrappedScreenOffsetByScale)(reinterpret_cast<TMapDialog*>(arg1), 0,
                                                          arg1, arg2, arg3, arg4, arg5);
}
