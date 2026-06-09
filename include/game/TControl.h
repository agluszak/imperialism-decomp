#pragma once

#include "game/TView.h"

// VTABLE: IMPERIALISM 0x64a098
class TControl : public TView {
public:
  int hasCommandTagResource;
  unsigned char commandTagResourceByte;
  unsigned char padding_65_to_67[3];
  int field68;
  int field6C;
  int field70;
  int field74;
  int commandTagDefaultParam0;
  int commandTagDefaultParam1;
  unsigned short commandTagDefaultParam2;

  TControl();
  void InvalidateCityDialogRectRegion(struct RECT* rect, int flag);
  void OrphanTiny_SetDwordEcxOffset_60_0058e440(int value);
  void WrapperFor_thunk_HandleCursorHoverSelectionByChildHitTestAndFallback_At0058c7c0(
      int* cursorPoint, int hitArg);

  // TControl-branch slots 0x1A0-0x1BC (104-111), formerly mis-declared on TView.
  virtual void vmethod_0104();
  virtual void SwitchTab(int arg1 = 0, int arg2 = 0, int arg3 = 0);
  virtual void InvokeSlot1A8();
  virtual void vmethod_0107();
  virtual void vmethod_0108();
  virtual void vmethod_0109();
  virtual void vmethod_0110();
  virtual char GetBoolSlot1BC();
  virtual void vmethod_0112();
};
