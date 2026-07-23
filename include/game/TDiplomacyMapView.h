#pragma once

#include "compat.h"
#include "game/diplomacy_domain_types.h"
#include "game/StrategicMapCallbackRecord.h"
#include "game/TPicture.h"
#include "game/mfc.h"
#include "game/quickdraw_regions.h"

class TUiStyleRef;
struct TQuickDrawBlitSurface;

struct DiplomacyMaskBufferRun {
  DiplomacyMaskBufferRun();
  ~DiplomacyMaskBufferRun();

  void BlitMonochromeMaskBytePatternToSurface(TQuickDrawBlitSurface* surface,
                                              TUiStyleRef paletteColor, const CPoint* origin,
                                              unsigned char flipVertical);

  unsigned char* maskBytesAt00;
  CRect boundsAt04;
};

ASSERT_SIZE(DiplomacyMaskBufferRun, 0x14);

// Constructor evidence calls TPicture::TPicture at 0x0048efc0, then writes the
// complete-object vfptr at 0x00655b68. The table at 0x0066f16c is separate
// turn-event dispatch/data, not an object vtable.
// VTABLE: IMPERIALISM 0x00655b68
class TDiplomacyMapView : public TPicture {
  friend class TInfoPanelView;

public:
  DECLARE_DYNCREATE(TDiplomacyMapView)
  virtual ~TDiplomacyMapView() override { // NOOP: verified empty in original 0x004f3cc0
  }
  void Free() override; // slot 0x07 0x4f3e60
  void DoEvent(int commandId, TEventHandler* sourceHandler,
               TEvent* event) override;           // slot 0x0f 0x4f70c0
  void DoKeyEvent(TToolboxEvent* event) override; // slot 0x12 0x4f7130
  void Close() override;                          // slot 0x28 0x4f3e30
  void DoSetCursor(CPoint* point,
                   RgnHandle hitArg) override; // slot 0x2c 0x4f5f90
  void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                           RgnHandle hitArg) override; // slot 0x35
  void DoPostCreate(int arg) override;                                                 // slot 0x37
  void Draw(RECT* rectBuffer) override;                                                // slot 0x44
  void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                      CPoint origin) override; // slot 0x47 0x4f5410

  virtual void RenderDiplomacyLegendSurfaceAndPresent(RECT* presentRect); // slot 0x73
  virtual void BuildCombinedTerrainTypeRegionMaskAndDispatch();           // slot 0x74
  virtual void RebuildDiplomacyLegendPaletteMode4AndBlit(int activeNationSlot,
                                                         const RECT* presentRect); // slot 0x75
  virtual void VisitNationSlotsForOverlay(int unusedMode);                         // slot 0x76
  virtual void RebuildDiplomacyLegendPaletteMode1AndBlit(int activeNationSlot,
                                                         const RECT* presentRect); // slot 0x77
  virtual void BlitDiplomacyMapEventPaletteMaskToSurface(short maskIndex,
                                                         int bmpId); // slot 0x78
  virtual void PoseOffer(short sourceNation, short targetNation,
                         short offerType); // slot 0x79 0x4f7080
  // 0x4f3ea0 (1534 bytes) -- rebuilds the diplomacy-map nation overlay geometry and hit
  // masks; body not yet ported (claimed as a manual stub so derived views can call it).
  void BuildDiplomacyNationOverlayGeometryAndHitMasks();

  TDiplomacyMapView();

  eDipAction ResolveDiplomacyActionFromClickAndUpdateTarget(CPoint* clickPoint);
  void BuildTurnEventMonochromeMaskBuffers(int maskIndex, int eventCode);
  // Mac CodeWarrior: TDiplomacyMapView::PoseWarOffer(short, long, long, long).
  char PoseWarOffer(short sourceNationSlot, int minorNationSlot, int enemyNationSlot,
                    int promptCode);
  void DrawVoteNuggets();
  // 0x4f4a30 -- Mac CodeWarrior names this TDiplomacyMapView::DrawNames(const VRect&).
  // Draws the per-nation map labels over nationLabelRects234: great powers 0..6,
  // then minors 7..22 with the default DIB palette selected for their theme colors.
  // presentRect is an ignored stack arg the original threads through.
  void DrawNames(const RECT* presentRect);
  // 0x4f4ec0 -- Mac CodeWarrior names this TDiplomacyMapView::DrawIcons(const VRect&).
  // Called unconditionally from Draw for interactionModeAt94 in
  // {1,2,4}: for every terrain-descriptor slot whose hit rect intersects presentRect,
  // draws a diplomacy-compatibility highlight (LookupOrderCompatibilityMatrixValue) into
  // nationAnchorRects3A4, a mode-specific status icon into nationTextHitRectsC4 (need/
  // grant level for mode 1, relation tier for mode 2, policy level for mode 4), and an
  // optional colony-boycott overlay. presentRect is only read, never threaded onward.
  void DrawIcons(RECT* presentRect);

  // 0x4f4620 -- resolves the 6 minister action-topic buttons (info/trty/gran/trad/
  // coun/offr), refreshes the info button's nation-slot selection, and (re)assigns
  // each button's hover-help text; called from DoPostCreate.
  void InitializeDiplomacyMinisterActionControlsAndLabels();

  // Mac CodeWarrior: TDiplomacyMapView::CheckEntanglements(int, eDipAction).
  // Confirms alliance/annexation offers that would inherit the target's wars. 0x4f74f0.
  char CheckEntanglements(int targetNationSlot, eDipAction action);

  // 0x4f6d90 -- selects a minister action topic: repositions the old/new topic buttons
  // via CaptureLayoutF0, toggles the 'ltab'/'rtab' bracket TPicture controls around the
  // new selection (and their picture-resource id), refreshes the picture-dependent
  // interaction mode, and invalidates the map region. Shared out-of-line method: called
  // from TDiplomacyMapView::DoEvent and TCouncilView::DoEvent (topicIndex from a
  // control-tag scan) and unconditionally with topicIndex=5 from
  // PoseWarOffer / InvalidateAndForwardTabSwitchToChild.
  void ChangeSelectedActionTopic(int topicIndex);

protected:
  // 0x90 — compared against a terrain-descriptor index in
  // ResolveDiplomacyActionFromClickAndUpdateTarget (matched to `actionCode != 0xd`); reset to 0
  // in the constructor.
  short selectedTerrainIndexAt90;
  char pad_92[0x02];
  // 0x94 — a mode/state code compared to 5 (`== 5` short-circuits the click handler); reset to
  // 0 in the constructor.
  int interactionModeAt94;
  short frameRegionSelectorAt98;
  char pad_9a[0x02];
  // 0x9c — QuickDraw region handle; disposed and cleared in Free (0x4f3e60), reset to 0 in the
  // constructor.
  RgnHandle regionAt9c;
  // 0xa0..0xb4 — the 6 diplomacy-minister action-topic button controls, resolved by
  // InitializeDiplomacyMinisterActionControlsAndLabels (0x4f4620) from the tag table at
  // 0x696960 (info/trty/gran/trad/coun/offr, in that exact order) via a real loop over
  // this array in the original -- stored uniformly as TControl* there. Index 0's real
  // class is TInfoPanelView (confirmed by its own SetInfoCountry(short)
  // call right after the loop); callers static_cast that one element rather than the
  // array carrying a mixed element type. Index 5 (the 'offr' button) is also
  // childControlAtB4's established "panel's child control" role -- not a conflict, just
  // two names for the same slot, kept below as a reference alias.
  // actionButtonsA0[5] (the 'offr' button) is also the panel's child control, read in
  // InvalidateAndForwardTabSwitchToChild / PoseWarOffer. Element 0's
  // real class (TInfoPanelView) is a TPanelView sibling, not a TControl descendant, so
  // this array is typed as TView* (their common base) rather than TControl* -- callers
  // cast each element to its own real type at the point of use.
  TView* actionButtonsA0[6];
  // 0xb8 — a state code compared to 5 (mirrors interactionModeAt94's pattern); reset to 0 by
  // Close (slot 0xa0) and in the constructor.
  int stateFlagAtB8;

public:
  // 0xbc -- action code written 0xd at the end of the overlay rebuild (matches
  // selectedTerrainIndexAt90's `actionCode != 0xd` comparison site); also written 7/8
  // by TGrantsView::DoEvent (via TPanelView::diplomacyMapView60) keyed off the parity of a
  // clicked control's tag -- public because that sibling panel writes it directly
  // through the panel's owner pointer, with no accessor method in the original.
  eDipAction actionCodeBC;
  // 0xc0 -- a row/index value derived from a clicked control's tag
  // ((controlTag - 0x6330) / 2), written by TGrantsView::DoEvent through
  // TPanelView::diplomacyMapView60.
  short selectedGrantRowC0;

protected:
  // 0xc2 -- active-nation snapshot stamped alongside 0x90/0x98 by the overlay rebuild.
  short activeNationC2;
  // Three consecutive per-nation RECT arrays filling 0xc4..0x514 exactly (23 nations):
  // text hit rects, name-label rects ([entry+0x170] writes), anchor marker rects
  // ([entry+0x2e0] writes) -- all rebuilt by BuildDiplomacyNationOverlayGeometryAndHitMasks.
  CRect nationTextHitRectsC4[23]; // 0x0c4..0x234
  CRect nationLabelRects234[23];  // 0x234..0x3a4
  CRect nationAnchorRects3A4[23]; // 0x3a4..0x514
  // +0x514..+0x520 -- map origin/extents. Rendering reads the named components, while
  // TInfoPanelView::DoEvent passes the same four dwords as an invalidation RECT.
  union {
    struct {
      int mapOriginPixelX514;
      int mapOriginPixelY518;
      int mapExtentPixelX51C;
      int mapExtentPixelY520;
    };
    RECT mapViewportRect514;
  };
  int legendSurfaceModeAt524;
  // 0x528 — highest pending-policy tier currently visible in the council vote animation.
  // DrawVoteNuggets draws entries at or below it; TCouncilView advances/resets it.
  short visibleVoteTier528;
  short currentCursorResourceId52A;
  // 0x52c -- per-tile flag: owner byte in g_pDiplomacyTurnStateManager's table != -1.
  bool tileHasOwnerFlags52C[0x180];
  // 0x6ac -- per-tile 10x7 marker rect anchored at the tile's hex-raster position.
  CRect tileMarkerRects6AC[0x180]; // 0x6ac..0x1eac
  // 0x1eac -- per-nation overlay hit-mask runs; 0x2078 -- per-nation label opcode
  // records (both rebuilt by BuildDiplomacyNationOverlayGeometryAndHitMasks).
  DiplomacyMaskBufferRun maskRuns[0x17];
  StrategicMapCallbackRecord packedColorRuns[0x17];
};

ASSERT_SIZE(TDiplomacyMapView, 0x24c8);
