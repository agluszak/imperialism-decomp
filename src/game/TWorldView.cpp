#include "game/TWorldView.h"
#include "game/MfcRuntime.h"

undefined4 thunk_WrapperFor_thunk_InvalidateCityDialogRectRegion_At0048b6d0(void);
undefined4 thunk_HandleMapClickByInteractionMode(void);

namespace {

#define kAddrTEventClassVtable 0x00649770

void DispatchOverlayEvent78Common(TWorldView* self, int stridedRecord) {
  undefined4* eventBlock = reinterpret_cast<undefined4*>(AllocateWithFallbackHandler(0));
  if (eventBlock == 0) {
    return;
  }
  eventBlock[1] = 0;
  eventBlock[2] = 0;
  eventBlock[3] = 0;
  eventBlock[4] = 0;
  eventBlock[0] = kAddrTEventClassVtable;
  eventBlock[2] = 0x78;
  eventBlock[1] = 0x78;
  eventBlock[3] = reinterpret_cast<undefined4>(self);
  eventBlock[4] = reinterpret_cast<undefined4>(self);
  *reinterpret_cast<unsigned short*>(reinterpret_cast<char*>(self) + 0x7a) =
      static_cast<unsigned short>(stridedRecord);
  self->DispatchEvent(reinterpret_cast<int>(eventBlock), eventBlock, 0);
}

} // namespace

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x00595c40
void TWorldView::SetFlagByteAndInvokeVslot1A4(unsigned char flagByte) {
  *reinterpret_cast<unsigned char*>(reinterpret_cast<char*>(this) + 0x74) = flagByte;
  RenderMapContextOverlayWithScopedClipAndSurface();
}

// FUNCTION: IMPERIALISM 0x00595c70
void TWorldView::RenderMapContextOverlayWithScopedClipAndSurface() {}

// FUNCTION: IMPERIALISM 0x00596020
void TWorldView::RenderMapOrderEntryTilePreview(int arg1, int arg2, int arg3) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
}

// FUNCTION: IMPERIALISM 0x00596040
void TWorldView::RenderTacticalStackCountIndicatorAndUnitBadge() {}

// FUNCTION: IMPERIALISM 0x00596060
void TWorldView::RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, void* dstRect,
                                                               unsigned char altOverlay) {
  (void)tileIndex;
  (void)dstRect;
  (void)altOverlay;
}

// FUNCTION: IMPERIALISM 0x00596080
void TWorldView::RenderStrategicTileSelectionAndNeighborHighlights() {}

// FUNCTION: IMPERIALISM 0x005960e0
void TWorldView::ForwardProjectTileIndexToWrappedScreenOffsetByScale(int arg1, int arg2, int arg3,
                                                                     int arg4, int arg5) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  (void)arg5;
}

// FUNCTION: IMPERIALISM 0x005960a0
short TWorldView::QueryMinusOneWordSlot1BC() {
  return -1;
}

// FUNCTION: IMPERIALISM 0x005960c0
void TWorldView::ComputeWrappedMapCellAndRegionBandFromScreenCoord(int overlayRecord, short* outRow,
                                                                   unsigned short* outCol,
                                                                   short* outBand) {
  (void)overlayRecord;
  (void)outRow;
  (void)outCol;
  (void)outBand;
}

// FUNCTION: IMPERIALISM 0x00596270
void TWorldView::InvokeDialogHooks1D8ThenE4(int stridedRecord, int dispatchContext) {
  (void)stridedRecord;
  (void)dispatchContext;
  UpdateMapDialogTileRowColumnMarkerAndInvalidate(0);
  reinterpret_cast<void(__fastcall*)(TWorldView*, int)>(
      thunk_WrapperFor_thunk_InvalidateCityDialogRectRegion_At0048b6d0)(this, 0);
}

// FUNCTION: IMPERIALISM 0x005962a0
void TWorldView::HandleMapTileClickSetOrderContextAndDispatchEvent79(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

// FUNCTION: IMPERIALISM 0x005963d0
void TWorldView::DispatchOverlayEvent78FromStridedRecord(int stridedRecord, int dispatchContext) {
  (void)dispatchContext;
  DispatchOverlayEvent78Common(this, stridedRecord);
}

// FUNCTION: IMPERIALISM 0x00596440
void TWorldView::DispatchOverlayEvent78RootHighFromStridedRecord(int stridedRecord,
                                                                 int dispatchContext) {
  (void)dispatchContext;
  DispatchOverlayEvent78Common(this, stridedRecord);
}

// FUNCTION: IMPERIALISM 0x005964b0
void TWorldView::HandleMapClickByInteractionModeFromStridedRecord(int stridedRecord,
                                                                  int dispatchContext) {
  reinterpret_cast<void(__fastcall*)(TWorldView*, int, short, int)>(
      thunk_HandleMapClickByInteractionMode)(this, 0, static_cast<short>(stridedRecord),
                                             dispatchContext);
}

// FUNCTION: IMPERIALISM 0x00594fc0
void TWorldView::UpdateMapDialogTileRowColumnMarkerAndInvalidate(int arg1) {
  (void)arg1;
}
