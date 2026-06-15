#pragma once

#include "game/TView.h"

struct TControlPictureRectState {
  int value0;
  int value1;
  short value2;
};

// VTABLE: IMPERIALISM 0x64a098
class TControl : public TView {
public:
  int hasCommandTagResource;
  unsigned char commandTagResourceByte;
  unsigned char padding_65_to_67[3];
  RECT contentMargins68;
  int commandTagDefaultParam0;
  int commandTagDefaultParam1;
  unsigned short commandTagDefaultParam2;
  unsigned char padding_82[2];

  TControl();
  virtual CRuntimeClass* GetRuntimeClass() override; // 0x00 0x48e500 (override)
  // Slot 0x08 override (0x00435760): controls cannot be cloned (no engineer-dialog
  // state); assert via the McAppUI invalidation thunk and return null.
  virtual void* CloneEngineerDialogStateToNewInstance() override;
  void WrapperFor_ApplyRectMarginsInPlace_At0048e980(int* boundsBuffer);
  void OrphanTiny_SetDwordEcxOffset_60_0058e440(int value);

  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void BeginMouseCaptureAndStartRepeatTimer(Point32* point) override;
  virtual int QuerySelectedIndexSlotBC() override;
  virtual char PointInBoundsAndActionable(Point32* point) override;

  // TControl-branch slots 0x1A0-0x1BC (104-111), formerly mis-declared on TView.
  virtual void DispatchPictureResourceCommand(int eventType, void* eventSender, void* eventDataA,
                                              void* eventDataB);
  virtual void SwitchTab(int* boundsBuffer);
  virtual void AssertCityProductionGlobalStateInitialized(int arg1, int arg2);
  virtual void NoOpCityProductionDialogMethod(int arg1, int arg2);
  virtual void NoOpCityProductionDialogPictureHook(int arg);
  virtual void SetCityProductionDialogPictureRectAndMaybeRefresh(TControlPictureRectState* state,
                                                                 char refreshNow);
  virtual void SetControlPictureEntryAndMaybeRefresh(int* pictureEntryRef, bool refreshNow);
  virtual char LogUnhandledDialogMethodAndReturnFalse();
  virtual void SetControlStateFlagAndMaybeRefresh(bool enabledState, bool refreshNow);
};
