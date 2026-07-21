#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TView.h"
#include "game/mfc.h"

class TCivUnit;

// VTABLE: IMPERIALISM 0x668cb0
class TWorldView : public TView {
public:
  int viewportOffsetX; // field_0x60
  int viewportOffsetY; // field_0x64
  unsigned short field68;
  unsigned short field6a;
  unsigned short field6c;
  unsigned short field6e;
  short hoverRegionBand70;
  // +0x72 active region-band index (1..4) the map cursor is currently rendered for --
  // one coherent field with a single meaning that two handlers cooperatively maintain
  // (an earlier note wrongly read the two accesses as unrelated). The hover handler
  // (HandleCursorHoverSelectionByChildHitTestAndFallback 0x5958b0) writes the hovered
  // band here and reads it to skip a redundant cursor re-render when neither the cell
  // (field6c/field6e) nor the band changed. The click handler
  // (HandleMapClickByInteractionMode 0x5964b0) advances it 1..4 to cycle the tile's
  // action interpretation, which also invalidates the hover dedup so the cursor
  // refreshes on the next mouse-move. Both uses read/write [this+0x72] as one word
  // (verified: same receiver, same offset), and the click's explicit 1..4 wrap fixes
  // the field's domain.
  short activeRegionBand72;
  // Written by SetFlagByteAndInvokeVslot1A4 (this+0x74=flagByte), read as a byte gate by
  // TMapDialog::RenderMapDialogTerrainOverlayFrameByTileOwner (selects the overlay style:
  // 0 = terrain-frame overlay, nonzero = the alternate palette-index blit).
  unsigned char overlayFlagByte74;
  unsigned char pad75;
  // projectionScale76: passed as the scale arg to
  // ForwardProjectTileIndexToWrappedScreenOffsetByScale when projecting a tile to screen
  // space for the map-context overlay preview.
  unsigned short projectionScale76;
  // previewSquareRadius78: half-extent the projected preview point is grown by on both axes
  // to build the preview/badge square (RenderMapContextOverlayWithScopedClipAndSurface).
  unsigned short previewSquareRadius78;
  // stridedCellRecord7a: strided map-cell record index stashed here before dispatching
  // through the owning view's vtable slot 0xd (see the ComputeWrappedMapCellAndRegionBand
  // callers in TWorldView.cpp).
  unsigned short stridedCellRecord7a;

  DECLARE_DYNCREATE(TWorldView)
  TWorldView();
  virtual ~TWorldView() override;

  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void ForwardParam(int param) override;
  virtual void HandleCursorHoverFallback(CPoint* point, RgnHandle hitArg) override;
  virtual void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                   RgnHandle hitArg) override;
  virtual void DoPostCreate(int arg) override;
  virtual char DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3, int arg4) override;

  virtual void SetFlagByteAndInvokeVslot1A4(unsigned char flagByte);
  virtual void RenderMapContextOverlayWithScopedClipAndSurface();
  // Five stack args, proven by the body's bare `RET 0x14` (a 5-arg no-op in this
  // class) and the 0x595c70 self-virtual call site's five pushes -- the previous
  // 3-arg declaration was a poison-pill arity mismatch. Args mirror the call
  // site: the selected civilian order entry, the projected screen X/Y, a flag
  // (always 1 there), and the entry's tile index.
  virtual void RenderMapOrderEntryTilePreview(TCivUnit* orderEntry, int projectedX, int projectedY,
                                              int flag, short tileIndex);
  virtual void RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, void* dstRect,
                                                             int flag);
  virtual void RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, void* dstRect,
                                                             unsigned char altOverlay);
  virtual void RenderStrategicTileSelectionAndNeighborHighlights();
  virtual void ForwardProjectTileIndexToWrappedScreenOffsetByScale(int arg1, int arg2, int arg3,
                                                                   int arg4, int arg5);
  // One ignored stack arg (body is `OR AX,0xffff; RET 0x4`) -- present only for
  // stack-cleanup fidelity; the previous 0-arg declaration purged 4 bytes short.
  virtual short QueryMinusOneWordSlot1BC(int unusedArg);
  virtual void ComputeWrappedMapCellAndRegionBandFromScreenCoord(int overlayRecord, short* outRow,
                                                                 unsigned short* outCol,
                                                                 short* outBand);
  virtual void InvokeDialogHooks1D8ThenE4(int stridedRecord, int dispatchContext);
  virtual void HandleMapTileClickSetOrderContextAndDispatchEvent79(int arg1, int arg2);
  virtual void DispatchOverlayEvent78FromStridedRecord(int stridedRecord, int dispatchContext);
  virtual void DispatchOverlayEvent78RootHighFromStridedRecord(int stridedRecord,
                                                               int dispatchContext);
  virtual void HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags);
  // Mac CodeWarrior identity: TWorldView::CenterOn(short). Windows consumes the promoted
  // stack dword at this virtual boundary.
  virtual void CenterOn(int tileIndex);
  virtual short QueryMinusOneWordSlot77();
  virtual void SetMapViewTileIndex(int arg1);
  virtual void SetMapViewCellCoordinates(int arg1, int arg2);
  virtual void OrphanRetStub_005966c0(short arg1);
  virtual undefined OrphanLeaf_NoCall_Ins02_005966e0(short arg1);
  virtual void OrphanCallChain_C6_I29_00596700(int arg1);
};
