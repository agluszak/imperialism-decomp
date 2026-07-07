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
  void Free() override;                  // slot 0x07 0x4f3e60
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
  char pad_bc[0x468];
  int legendSurfaceModeAt524;
  // 0x528 — hovered/selected council slot index; TCouncilView's cursor-hover override
  // compares it against its own nation-count tail field.
  short field528;
  char pad_52a[0x1982];
  DiplomacyMaskBufferRun maskRuns[0x17];
  StrategicMapCallbackRecord packedColorRuns[0x17];
};

ASSERT_SIZE(TDiplomacyMapView, 0x24c8);
