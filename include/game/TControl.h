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

  virtual void vmethod_0112();
  virtual void vmethod_0113();
  virtual void SetControlClassAndRefresh(int classState, int refreshFlag);
  virtual void vmethod_0115();
  virtual void ApplyMoveValue(int value);
  virtual void NotifyControlSelectionChange(void* boundEntry);
  virtual char GetControlFlag();
  virtual char GetBoolSlot1DC();
  virtual void DoControlAction();

};
