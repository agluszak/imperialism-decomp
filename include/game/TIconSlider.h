#pragma once

#include "game/TIconBar.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00657c60
class TIconSlider : public TIconBar {
public:
  virtual CRuntimeClass* GetRuntimeClass() const override;
  virtual ~TIconSlider();

  virtual void NoOpUiLifecycleHook(int arg) override;
  virtual void ApplyRectSlot110(RECT* rectBuffer) override;
  virtual char DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3,
                                             int arg4) override;
  virtual void DispatchPictureResourceCommand(int nEventType, void* pEventSender, void* pEventDataA,
                                              void* pEventDataB) override;
  virtual undefined OrphanTiny_SetWordEcxOffset_96_005060f0(undefined2 param_1) override;
  virtual undefined OrphanLeaf_NoCall_Ins04_00506560(short param_1) override;
  virtual undefined OrphanCallChain_C2_I15_005065b0() override;
  virtual undefined Helper_Uses_WrapperFor_thunk_ResolveBmpResourceHandleWithDefault3B6_At00495c_At005066c0();
  virtual undefined OrphanCallChain_C1_I36_00506710(LPRECT param_1);

  TIconSlider();
};

// === BEGIN GENERATED (TIconSlider) — refreshed by `just gen-class TIconSlider`; do not hand-edit ===
// clang-format off
// vtable @ 0x00657c60 (122 slots), object size 0xbc, base TIconBar
//   slot 0x00  byte 0x00  0x005063a0  override  GetTEventHandlerClassNamePointer
//   slot 0x37  byte 0xdc  0x00506480  override  OrphanCallChain_C6_I49_004875d0
//   slot 0x44  byte 0x110  0x00506690  override  OrphanTiny_ReturnZero_0048a730
//   slot 0x46  byte 0x118  0x005065f0  override  SetForeignMinisterReadyFlag14
//   slot 0x68  byte 0x1a0  0x005067a0  override  QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x75  byte 0x1d4  0x00506590  override  OrphanTiny_SetWordEcxOffset_96_005060f0
//   slot 0x76  byte 0x1d8  0x00506560  override  OrphanLeaf_NoCall_Ins04_00506560
//   slot 0x77  byte 0x1dc  0x005065b0  override  OrphanCallChain_C2_I15_005065b0
//   slot 0x78  byte 0x1e0  0x005066c0  override  Helper_Uses_WrapperFor_thunk_ResolveBmpResourceHandleWithDefault3B6_At00495c_At005066c0
//   slot 0x79  byte 0x1e4  0x00506710  override  OrphanCallChain_C1_I36_00506710
// clang-format on
// === END GENERATED (TIconSlider) ===
