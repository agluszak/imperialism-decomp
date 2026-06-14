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

  TControl();
  void* GetTControlClassNamePointer();
  void WrapperFor_ApplyRectMarginsInPlace_At0048e980(int* boundsBuffer);
  void InvalidateOffsetRegionUsingChildClipRect(int* regionWrapper);
  void OrphanTiny_SetDwordEcxOffset_60_0058e440(int value);
  void WrapperFor_thunk_HandleCursorHoverSelectionByChildHitTestAndFallback_At0058c7c0(
      int* cursorPoint, int hitArg);

  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event);
  virtual void HandleCursorHoverSelectionByChildHitTestAndFallback(Point32* point, int hitArg);
  virtual char DispatchUiMouseMoveToChildren(Point32* point, int arg2, int arg3, int arg4);
  virtual void BeginMouseCaptureAndStartRepeatTimer(Point32* point);
  virtual char DispatchUiMouseEventToChildrenOrSelf_Impl(Point32* point, int arg2, int arg3,
                                                         int arg4);
  virtual void PaintVisibleChildrenIntersectingClipRect(struct RECT* clipRect, int bindArg);

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
