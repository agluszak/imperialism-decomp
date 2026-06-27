#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x668cb0
class TWorldView : public TView {
public:
  int viewportOffsetX; // field_0x60
  int viewportOffsetY; // field_0x64
  unsigned short field68;
  unsigned short field6a;
  unsigned short field6c;
  unsigned short field6e;
  unsigned short field76;
  unsigned short field78;
  unsigned short field7a;

  DECLARE_DYNCREATE(TWorldView)
  TWorldView();
  virtual ~TWorldView();

  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void ForwardParam(int param) override;
  virtual void HandleCursorHoverFallback(CPoint* point, int hitArg) override;
  virtual void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                   int hitArg) override;
  virtual void NoOpUiLifecycleHook(int arg) override;
  virtual char DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3,
                                             int arg4) override;

  virtual void SetFlagByteAndInvokeVslot1A4(unsigned char flagByte);
  virtual void RenderMapContextOverlayWithScopedClipAndSurface();
  virtual void RenderMapOrderEntryTilePreview(int arg1, int arg2, int arg3);
  virtual void RenderTacticalStackCountIndicatorAndUnitBadge();
  virtual void RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, void* dstRect,
                                                             unsigned char altOverlay);
  virtual void RenderStrategicTileSelectionAndNeighborHighlights();
  virtual void ForwardProjectTileIndexToWrappedScreenOffsetByScale(int arg1, int arg2, int arg3,
                                                                   int arg4, int arg5);
  virtual short QueryMinusOneWordSlot1BC();
  virtual void ComputeWrappedMapCellAndRegionBandFromScreenCoord(int overlayRecord, short* outRow,
                                                                 unsigned short* outCol,
                                                                 short* outBand);
  virtual void InvokeDialogHooks1D8ThenE4(int stridedRecord, int dispatchContext);
  virtual void HandleMapTileClickSetOrderContextAndDispatchEvent79(int arg1, int arg2);
  virtual void DispatchOverlayEvent78FromStridedRecord(int stridedRecord, int dispatchContext);
  virtual void DispatchOverlayEvent78RootHighFromStridedRecord(int stridedRecord,
                                                               int dispatchContext);
  virtual void HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags);
  virtual void UpdateMapDialogTileRowColumnMarkerAndInvalidate(int arg1);
  virtual short QueryMinusOneWordSlot77();
  virtual undefined OrphanRetStub_005966a0();
  virtual undefined OrphanRetStub_00596680();
  virtual undefined OrphanRetStub_005966c0();
  virtual undefined OrphanLeaf_NoCall_Ins02_005966e0();
  virtual void OrphanCallChain_C6_I29_00596700();
};
