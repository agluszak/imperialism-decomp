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
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x4ba2c0
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
                                      void* eventDataB) override; // slot 0x68 0x4bc870
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

// === BEGIN GENERATED (TCityProductionView) — hand-seeded from
// `just ghidra-vtable-dump TCityProductionView 0x0064fc20`; refresh with
// `just gen-class TCityProductionView` after the class is in the manifest.
// clang-format off
// vtable @ 0x0064fc20 (124 slots), object size 0x18c, base TNoHilitePicture
//   slot 0x00  byte 0x00   0x004ba2c0  override  GetTCityProductionViewClassNamePointer
//   slot 0x01  byte 0x04   0x004ba360  override  scalar deleting destructor
//   slot 0x02..0x73 inherited from TNoHilitePicture
//   slot 0x07  byte 0x1c   0x004ba740  override  ReleaseCityBuildingControls
//   slot 0x0f  byte 0x3c   0x004bc610  override  HandleCityDialogToggleCommandOrForward
//   slot 0x35  byte 0xd4   0x004bafa0  override  HandleCityBuildingHoverSelection
//   slot 0x37  byte 0xdc   0x004ba3b0  override  InitializeCityBuildingControlRegions
//   slot 0x44  byte 0x110  0x004ba7b0  override  RenderCityBuildingIcons
//   slot 0x47  byte 0x11c  0x004bc660  override  HandleCityBuildingSlotClickAndDispatchAction
//   slot 0x68  byte 0x1a0  0x004bc870  override  QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x74  byte 0x1d0  0x004bac50  override  BlitBitmapResourceRectWithScreenOffsetAndPalette
//   slot 0x75  byte 0x1d4  0x004badd0  override  RenderNationHeaderDateLabelWithPeriodicRefresh
//   slot 0x76  byte 0x1d8  0x004bb7a0  override  InitializeCityProductionDialog
//   slot 0x77  byte 0x1dc  0x004bc0b0  override  UpdateCityProductionDialogCommodityValueControls
//   slot 0x78  byte 0x1e0  0x004bc500  override  RefreshCityBuildingActionAvailabilityIndicators
//   slot 0x79  byte 0x1e4  0x004bc910  override  OrphanCallChain_C5_I49_004bc910
//   slot 0x7a  byte 0x1e8  0x004bc9b0  override  RenderViewIntoPrimaryRenderContextWithTemporaryClip
//   slot 0x7b  byte 0x1ec  0x004bcaf0  override  RefreshCityDialogSummaryValues
// clang-format on
// === END GENERATED (TCityProductionView) ===
