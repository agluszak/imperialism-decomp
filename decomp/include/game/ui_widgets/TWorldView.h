#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/map_domain_types.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"

class TCivUnit;

// VTABLE: IMPERIALISM 0x668cb0
class TWorldView : public TView {
public:
  CPoint viewportOrigin;
  unsigned short hoveredTileCityRecordIndex;
  unsigned short paintedTileCityRecordIndex;
  // Hovered tile under the current cursor sample and the tile whose hover decoration is
  // currently painted. TWorldView's constructor initializes both to tile zero; the hover
  // path advances paintedHoverTileIndex after replacing the decoration.
  unsigned short hoveredTileIndex;
  unsigned short paintedHoverTileIndex;
  short hoverRegionBand;
  // +0x72 active region-band index (1..4) the map cursor is currently rendered for --
  // one coherent field with a single meaning that two handlers cooperatively maintain
  // (an earlier note wrongly read the two accesses as unrelated). The hover handler
  // (HandleCursorHoverSelectionByChildHitTestAndFallback 0x5958b0) writes the hovered
  // band here and reads it to skip a redundant cursor re-render when neither the cell
  // (hoveredTileIndex/paintedHoverTileIndex) nor the band changed. The click handler
  // (HandleMapClickByInteractionMode 0x5964b0) advances it 1..4 to cycle the tile's
  // action interpretation, which also invalidates the hover dedup so the cursor
  // refreshes on the next mouse-move. Both uses read/write [this+0x72] as one word
  // (verified: same receiver, same offset), and the click's explicit 1..4 wrap fixes
  // the field's domain.
  short activeRegionBand;
  // Written by SetMapOverlayModeAndRenderPreview (this+0x74=flagByte), read as a byte gate by
  // TMapDialog::RenderMapDialogTerrainOverlayFrameByTileOwner (selects the overlay style:
  // 0 = terrain-frame overlay, nonzero = the alternate palette-index blit).
  unsigned char alternateOverlayEnabled;
  unsigned char pad75;
  // projectionScale: passed as the scale arg to
  // ForwardProjectTileIndexToWrappedScreenOffsetByScale when projecting a tile to screen
  // space for the map-context overlay preview.
  unsigned short projectionScale;
  // previewSquareRadius: half-extent the projected preview point is grown by on both axes
  // to build the preview/badge square (RenderMapContextOverlayWithScopedClipAndSurface).
  unsigned short previewSquareRadius;
  // stridedCellRecordIndex: strided map-cell record index stashed here before dispatching
  // through the owning view's vtable slot 0xd (see the ComputeWrappedMapCellAndRegionBand
  // callers in TWorldView.cpp).
  short stridedCellRecordIndex;

  DECLARE_DYNCREATE(TWorldView)
  TWorldView();
  virtual ~TWorldView() override;

  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoKeyEvent(TToolboxEvent* event) override;
  virtual void DoSetCursor(CPoint* point, RgnHandle hitArg) override;
  virtual void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                   RgnHandle hitArg) override;
  virtual void DoPostCreate(int arg) override;
  virtual char HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) override;

  virtual void SetMapOverlayModeAndRenderPreview(unsigned char overlayMode);
  virtual void RenderMapContextOverlayWithScopedClipAndSurface();
  // Five stack args, proven by the body's bare `RET 0x14` (a 5-arg no-op in this
  // class) and the 0x595c70 self-virtual call site's five pushes -- the previous
  // 3-arg declaration was a poison-pill arity mismatch. Args mirror the call
  // site: the selected civilian order entry, the projected screen X/Y, a flag
  // (always 1 there), and the entry's tile index.
  virtual void RenderMapOrderEntryTilePreview(TCivUnit* orderEntry, int projectedX, int projectedY,
                                              int flag, short tileIndex);
  virtual void RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, CRect* dstRect,
                                                             int flag);
  virtual void RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, CRect* dstRect,
                                                             unsigned char altOverlay);
  virtual void RenderStrategicTileSelectionAndNeighborHighlights();
  virtual void ForwardProjectTileIndexToWrappedScreenOffsetByScale(int tileIndex,
                                                                   const CPoint* viewportOrigin,
                                                                   short* outVerticalOffset,
                                                                   short* outHorizontalOffset,
                                                                   int projectionScale);
  // One ignored stack arg (body is `OR AX,0xffff; RET 0x4`) -- present only for
  // stack-cleanup fidelity; the previous 0-arg declaration purged 4 bytes short.
  virtual short QueryMinusOneWordSlot1BC(int unusedArg);
  virtual void ConvertPoint(const CPoint& point, short& outColumn, short& outRow,
                            short& outRegionBand);
  virtual void CenterOnTileAndRefresh(int tileIndex, int dispatchContext);
  virtual void HandleMapTileClickSetOrderContextAndHandleEvent79(int arg1, int arg2);
  virtual void DispatchOverlayEvent78FromStridedRecord(int stridedRecord, int dispatchContext);
  virtual void DispatchOverlayEvent78RootHighFromStridedRecord(int stridedRecord,
                                                               int dispatchContext);
  virtual void HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags);
  // ORACLE: Mac names this TWorldView::CenterOn(short). The Windows virtual
  // consumes the promoted stack dword and concrete bodies reuse its upper word.
  virtual void CenterOn(int tileIndex);
  virtual short QueryMinusOneWordSlot77();
  virtual void SetMapViewTileIndex(int arg1);
  virtual void SetMapViewCellCoordinates(int column, int row);
  // Refreshes one map tile after its cached/rendered state changes. Concrete land/ocean
  // dialogs choose their own cache-release and invalidation strategy.
  virtual void RefreshMapTile(short tileIndex);
  // Mac CodeWarrior identity: TWorldView::IsTileVisible(short). Concrete map dialogs
  // test the tile against their projected viewport; the abstract base has no viewport.
  virtual unsigned char IsTileVisible(short tileIndex);
  // Mac CodeWarrior identity: TWorldView::NoticeTile(short) -- brings the tile into
  // view on this and the owner view, forces a redraw and holds it briefly.
  virtual void NoticeTile(int tileIndex);
};
ASSERT_SIZE(TWorldView, 0x7c);
