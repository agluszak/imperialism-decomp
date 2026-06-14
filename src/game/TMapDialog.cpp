#include "game/TMapDialog.h"
#include "game/QuickDrawSurfaceGuard.h"
#include "game/TGlobalMapState.h"
#include "game/TView.h"
#include "game/diplomacy_globals.h"
#include "game/quickdraw_globals.h"
#include "game/trade_quickdraw.h"

extern "C" long _ftol(void);

undefined4 thunk_NormalizeWrappedMapCoord108x60(void);
undefined4 ComputeStridedRecordAddress6C(void);
undefined4 thunk_ProjectTileIndexToWrappedScreenOffsetByScale(void);
undefined4 thunk_SplitTileIndexToRowAndColumn(void);
undefined4 thunk_InvalidateCityDialogRectRegion(void);

#define g_wMapDialogTileRowMarker (*reinterpret_cast<short*>(0x006a33b0))

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x00596100
void TMapDialog::RenderWrappedMapQuickDrawOverlayFromStridedRecords(int overlayRecord) {
  QuickDrawSurfaceGuard surface;

  short tileRow = 0;
  unsigned short tileCol = 0;
  short regionBand = 0;
  ComputeWrappedMapCellAndRegionBandFromScreenCoord(overlayRecord, &tileRow, &tileCol, &regionBand);
  reinterpret_cast<void(__cdecl*)(short*, short*)>(thunk_NormalizeWrappedMapCoord108x60)(
      &tileRow, reinterpret_cast<short*>(&tileCol));

  int stridedRecord = reinterpret_cast<int(__cdecl*)(int, int)>(ComputeStridedRecordAddress6C)(
      (int)tileRow, (int)tileCol);
  if (*reinterpret_cast<int*>(overlayRecord + 0x24) == 1) {
    DispatchOverlayEvent78FromStridedRecord(stridedRecord, regionBand);
    return;
  }

  if (((unsigned short)GetAsyncKeyState(0x11) & 0x8000) != 0) {
    InvokeDialogHooks1D8ThenE4(stridedRecord, regionBand);
    return;
  }

  if (((unsigned short)GetAsyncKeyState(0x10) & 0x8000) != 0) {
    DispatchOverlayEvent78FromStridedRecord(stridedRecord, regionBand);
    return;
  }

  if (*reinterpret_cast<int*>(reinterpret_cast<char*>(g_pGlobalUiRootController) + 0x24) < 2) {
    HandleMapClickByInteractionModeFromStridedRecord(stridedRecord, regionBand);
    return;
  }

  DispatchOverlayEvent78RootHighFromStridedRecord(stridedRecord, regionBand);
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
  short bandRow =
      static_cast<short>((((static_cast<unsigned short>(wrappedY) ^ signY) - signY) & 0x3f) ^ signY) -
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

// FUNCTION: IMPERIALISM 0x00523640
void TMapDialog::RenderMapOrderEntryTilePreview(int arg1, int arg2, int arg3) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
}

// FUNCTION: IMPERIALISM 0x00523b70
void TMapDialog::RenderTacticalStackCountIndicatorAndUnitBadge() {}

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
    void* quickDrawSurface = *reinterpret_cast<void**>(reinterpret_cast<char*>(this) + 0x350);
    surfaceContext = quickDrawSurface;
    srcRect.left = static_cast<long>(static_cast<short>(ownerPaletteIndex * 0x40));
    srcRect.right = srcRect.left + 0x40;
    srcRect.top = 0;
    srcRect.bottom = 0x40;
    reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x10);
    int strategicBlitSource = *reinterpret_cast<int*>(0x006a21a8 + 0x690);
    reinterpret_cast<void(__stdcall*)(void*, void*, void*, void*, int, void*)>(
        BlitRectWithOptionalTransparency)(
        reinterpret_cast<void*>(strategicBlitSource + 4),
        reinterpret_cast<char*>(surfaceContext) + 4, &srcRect, dstRect, 0x24, 0);
    reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x13);
    return;
  }

  if (*reinterpret_cast<unsigned char*>(reinterpret_cast<char*>(this) + 0x74) == 0) {
    short terrainFrameIndex = static_cast<short>(tileRecord[0x10]);
    if (terrainFrameIndex == -1) {
      return;
    }
    srcRect.left = static_cast<long>(terrainFrameIndex) << 6;
    srcRect.right = (terrainFrameIndex + 1) * 0x40;
    srcRect.top = 0;
    srcRect.bottom = 0x40;
    void* quickDrawSurface = *reinterpret_cast<void**>(reinterpret_cast<char*>(this) + 0x350);
    reinterpret_cast<void(__stdcall*)(void*, void*, void*, void*, int, void*)>(
        BlitRectWithOptionalTransparency)(
        reinterpret_cast<char*>(quickDrawSurface) + 4,
        reinterpret_cast<char*>(g_pActiveQuickDrawSurfaceContext) + 4, &srcRect, dstRect, 0, 0);
    return;
  }

  srcRect.left = static_cast<long>(static_cast<short>(ownerPaletteIndex * 0x40 + 0x40));
  srcRect.right = srcRect.left + 0x40;
  srcRect.top = 0;
  srcRect.bottom = 0x40;
  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x10);
  int strategicBlitSource = *reinterpret_cast<int*>(0x006a21a8 + 0x690);
  reinterpret_cast<void(__stdcall*)(void*, void*, void*, void*, int, void*)>(
      BlitRectWithOptionalTransparency)(
      reinterpret_cast<void*>(strategicBlitSource + 4),
      reinterpret_cast<char*>(surfaceContext) + 4, &srcRect, dstRect, 0x24, 0);
  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x13);
}

// FUNCTION: IMPERIALISM 0x00519e00
void TMapDialog::RenderStrategicTileSelectionAndNeighborHighlights() {}

// FUNCTION: IMPERIALISM 0x00525730
void TMapDialog::ForwardProjectTileIndexToWrappedScreenOffsetByScale(int arg1, int arg2, int arg3,
                                                                     int arg4, int arg5) {
  reinterpret_cast<void(__fastcall*)(TMapDialog*, int, int, int, int, int, int)>(
      thunk_ProjectTileIndexToWrappedScreenOffsetByScale)(
      reinterpret_cast<TMapDialog*>(arg1), 0, arg1, arg2, arg3, arg4, arg5);
}

// FUNCTION: IMPERIALISM 0x0051adc0
void TMapDialog::ForwardMapDialogTileCoordUpdateToDerivedHandler(int tileX, int tileY) {
  typedef void(__fastcall * TileCoordHandlerFn)(TView* self, int unusedEdx, int x, int y, int mode);
  TView* view = this;
  int* vtable = *reinterpret_cast<int**>(view);
  reinterpret_cast<TileCoordHandlerFn>(vtable[0x28c / 4])(view, 0, tileX, tileY, 0);
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
  reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
      reinterpret_cast<int>(&invalidateRect[0]), 1);
}
