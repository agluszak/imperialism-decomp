#pragma once

#include "compat.h"
#include "game/TPicture.h"
#include "game/mfc.h"

// Constructor evidence calls TPicture::TPicture at 0x0048efc0, then writes the
// complete-object vfptr at 0x00655b68. The table at 0x0066f16c is separate
// turn-event dispatch/data, not an object vtable.
// VTABLE: IMPERIALISM 0x00655b68
class TDiplomacyMapView : public TPicture {
public:
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x4f3b60
  virtual ~TDiplomacyMapView() override;                   // slot 0x01 scalar deleting dtor
  void Free() override;                                    // slot 0x07 0x4f3e60
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

private:
  char pad_90[0x08];
  short frameRegionSelectorAt98;
  char pad_9a[0x48a];
  int legendSurfaceModeAt524;
  char pad_528[0x1fa0];
};

ASSERT_SIZE(TDiplomacyMapView, 0x24c8);
