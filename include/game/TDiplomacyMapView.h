#pragma once

#include "compat.h"
#include "game/StrategicMapCallbackRecord.h"
#include "game/TPicture.h"
#include "game/mfc.h"
#include "game/quickdraw_regions.h"

struct DiplomacyMaskBufferRun {
  DiplomacyMaskBufferRun();
  ~DiplomacyMaskBufferRun();

  void BlitMonochromeMaskBytePatternToSurface(int surfaceContext, int paletteByte, int* origin,
                                              int flipVertical);

  unsigned char* maskBytesAt00;
  int leftAt04;
  int topAt08;
  int rightAt0c;
  int bottomAt10;
};

ASSERT_SIZE(DiplomacyMaskBufferRun, 0x14);

// Constructor evidence calls TPicture::TPicture at 0x0048efc0, then writes the
// complete-object vfptr at 0x00655b68. The table at 0x0066f16c is separate
// turn-event dispatch/data, not an object vtable.
// VTABLE: IMPERIALISM 0x00655b68
class TDiplomacyMapView : public TPicture {
public:
  DECLARE_DYNCREATE(TDiplomacyMapView)
  virtual ~TDiplomacyMapView() override { // NOOP: verified empty in original 0x004f3cc0
  }
  void Free() override; // slot 0x07 0x4f3e60
  void HandleEvent(int commandId, TEventHandler* sourceHandler,
                   TEvent* event) override; // slot 0x0f 0x4f70c0
  void ForwardParam(int param) override;    // slot 0x12 0x4f7130
  void CallVoidSlotA0() override;           // slot 0x28 0x4f3e30
  void HandleCursorHoverFallback(CPoint* point,
                                 int hitArg) override; // slot 0x2c 0x4f5f90
  void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                           int hitArg) override; // slot 0x35
  void NoOpUiLifecycleHook(int arg) override;                                    // slot 0x37
  void ApplyRectSlot110(RECT* rectBuffer) override;                              // slot 0x44
  void BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                            int arg4) override; // slot 0x47 0x4f5410

  virtual void RenderDiplomacyLegendSurfaceAndPresent(const RECT* presentRect); // slot 0x73
  virtual void BuildCombinedTerrainTypeRegionMaskAndDispatch();                 // slot 0x74
  virtual void RebuildDiplomacyLegendPaletteMode4AndBlit(int activeNationSlot,
                                                         const RECT* presentRect); // slot 0x75
  virtual void OrphanLeaf_NoCall_Ins05_004f6820();                                 // slot 0x76
  virtual void RebuildDiplomacyLegendPaletteMode1AndBlit(int activeNationSlot,
                                                         const RECT* presentRect); // slot 0x77
  virtual void BlitDiplomacyMapEventPaletteMaskToSurface(short maskIndex,
                                                         int bmpId); // slot 0x78
  virtual void InvalidateAndForwardTabSwitchToChild(void* arg1, void* arg2,
                                                    void* arg3); // slot 0x79
  // 0x4f3ea0 (1534 bytes) -- rebuilds the diplomacy-map nation overlay geometry and hit
  // masks; body not yet ported (claimed as a manual stub so derived views can call it).
  void BuildDiplomacyNationOverlayGeometryAndHitMasks();

  TDiplomacyMapView();

  int ResolveDiplomacyActionFromClickAndUpdateTarget(CPoint* clickPoint);
  void BuildTurnEventMonochromeMaskBuffers(int maskIndex, int eventCode);
  void InvalidateAndRunChildWaitSheet(void* arg1, void* arg2, void* arg3, void* arg4);
  void RenderDiplomacyPendingPolicyIconsAndFrames();
  void SelectCandidateTilesWithLowGroundUnitCount(); // 0x005da040
  void OrphanLeaf_NoCall_Ins07_004d8920();           // 0x005da180

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
  char pad_a0[0x14];
  // 0xb4 — the panel's child control, read in InvalidateAndForwardTabSwitchToChild /
  // InvalidateAndRunChildWaitSheet.
  TControl* childControlAtB4;
  // 0xb8 — a state code compared to 5 (mirrors interactionModeAt94's pattern); reset to 0 by
  // CallVoidSlotA0 (slot 0xa0) and in the constructor.
  int stateFlagAtB8;
  // 0xbc -- action code written 0xd at the end of the overlay rebuild (matches
  // selectedTerrainIndexAt90's `actionCode != 0xd` comparison site).
  int actionCodeBC;
  short pad_c0;
  // 0xc2 -- active-nation snapshot stamped alongside 0x90/0x98 by the overlay rebuild.
  short activeNationC2;
  // Three consecutive per-nation RECT arrays filling 0xc4..0x514 exactly (23 nations):
  // text hit rects, name-label rects ([entry+0x170] writes), anchor marker rects
  // ([entry+0x2e0] writes) -- all rebuilt by BuildDiplomacyNationOverlayGeometryAndHitMasks.
  RECT nationTextHitRectsC4[23]; // 0x0c4..0x234
  RECT nationLabelRects234[23];  // 0x234..0x3a4
  RECT nationAnchorRects3A4[23]; // 0x3a4..0x514
  // +0x514/+0x518 -- map-view origin in screen pixels; the battle-report layout hook
  // (0x4acb60) stamps marker positions as origin + hex-raster offset.
  int mapOriginPixelX514;
  int mapOriginPixelY518;
  // +0x51c/+0x520 -- map extent in pixels (0x24d x 0x159, set with the origin).
  int mapExtentPixelX51C;
  int mapExtentPixelY520;
  int legendSurfaceModeAt524;
  // 0x528 — hovered/selected council slot index; TCouncilView's cursor-hover override
  // compares it against its own nation-count tail field.
  short field528;
  char pad_52a[0x2];
  // 0x52c -- per-tile flag: owner byte in g_pDiplomacyTurnStateManager's table != -1.
  unsigned char tileHasOwnerFlags52C[0x180];
  // 0x6ac -- per-tile 10x7 marker rect anchored at the tile's hex-raster position.
  RECT tileMarkerRects6AC[0x180]; // 0x6ac..0x1eac
  // 0x1eac -- per-nation overlay hit-mask runs; 0x2078 -- per-nation label opcode
  // records (both rebuilt by BuildDiplomacyNationOverlayGeometryAndHitMasks).
  DiplomacyMaskBufferRun maskRuns[0x17];
  StrategicMapCallbackRecord packedColorRuns[0x17];
};

ASSERT_SIZE(TDiplomacyMapView, 0x24c8);
