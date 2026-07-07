#pragma once

#include "compat.h"
#include "game/TNoHilitePicture.h"

// TODO(manifest): describe TCityProductionView and its role. Base edge
// (TNoHilitePicture) recovered from RTTI CRuntimeClass chain:
// TCityProductionView -> TNoHilitePicture -> TPicture -> TControl -> TView ->
// TEventHandler -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064fc20
class TCityProductionView : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TCityProductionView)
  virtual ~TCityProductionView() override;                 // slot 0x01 (scalar deleting destructor)
  void Free() override; // slot 0x07 0x4ba740 ReleaseCityBuildingControls
  void HandleEvent(int commandId, TEventHandler* sourceHandler,
                   TEvent* event) override; // slot 0x0f 0x4bc610
  void
  HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                      int hitArg) override; // slot 0x35 0x4bafa0
  void NoOpUiLifecycleHook(int arg) override;                               // slot 0x37 0x4ba3b0
  void ApplyRectSlot110(RECT* rectBuffer) override;                         // slot 0x44 0x4ba7b0
  void BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                            int arg4) override; // slot 0x47 0x4bc660
  void DispatchPictureResourceCommand(int eventType, void* eventSender, void* eventDataA,
                                      void* eventDataB, int commandFlag) override; // slot 0x68 0x4bc870
  // slots 0x02..0x06, 0x08..0x0e, 0x10..0x34, 0x36, 0x38..0x43, and
  // 0x45..0x67 and 0x69..0x73 inherited from TNoHilitePicture.
  virtual void
  BlitBitmapResourceRectWithScreenOffsetAndPalette(RECT* sourceRect, int surface, short offsetY,
                                                   short offsetX, undefined4 context,
                                                   undefined4 flags); // slot 0x74 0x4bac50
  virtual void RenderNationHeaderDateLabelWithPeriodicRefresh();      // slot 0x75 0x4badd0
  virtual void InitializeCityProductionDialog();                      // slot 0x76 0x4bb7a0
  virtual void UpdateCityProductionDialogCommodityValueControls();    // slot 0x77 0x4bc0b0
  virtual void RefreshCityBuildingActionAvailabilityIndicators();     // slot 0x78 0x4bc500
  virtual void OrphanCallChain_C5_I49_004bc910();                     // slot 0x79 0x4bc910
  virtual void RenderViewIntoPrimaryRenderContextWithTemporaryClip(); // slot 0x7a 0x4bc9b0
  virtual void RefreshCityDialogSummaryValues();                      // slot 0x7b 0x4bcaf0

  TCityProductionView();

private:
  char pad_94[0x10];
  short selectedBuildingSlotA4;
  unsigned char needsRefreshAtA6;
  char pad_a7;
  short currentMonthAtA8;
  short currentWeekAtAa;
  char pad_ac[0xe0];
};

