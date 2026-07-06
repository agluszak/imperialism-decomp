#pragma once

#include "game/TIconBar.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00657c60
class TIconSlider : public TIconBar {
public:
  DECLARE_DYNCREATE(TIconSlider)
  virtual ~TIconSlider() override;

  virtual void NoOpUiLifecycleHook(int arg) override;
  virtual void ApplyRectSlot110(RECT* rectBuffer) override;
  virtual char DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3,
                                             int arg4) override;
  virtual void DispatchPictureResourceCommand(int nEventType, void* pEventSender, void* pEventDataA,
                                              void* pEventDataB) override;
  virtual undefined OrphanTiny_SetWordEcxOffset_96_005060f0(undefined2 param_1) override;
  virtual undefined OrphanLeaf_NoCall_Ins04_00506560(short param_1);
  virtual undefined OrphanCallChain_C2_I15_005065b0();
  virtual undefined Helper_Uses_WrapperFor_thunk_ResolveBmpResourceHandleWithDefault3B6_At00495c_At005066c0();
  virtual undefined OrphanCallChain_C1_I36_00506710(LPRECT param_1);

  TIconSlider();
};

