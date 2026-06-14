#pragma once

#include "decomp_types.h"

class TView;

// Shared city-dialog vtable prefix (slots 0x00-0x25) used by ApplicationUiRootController
// and the TView/TControl cluster. Object layout matches TView through +0x1c; derived
// classes diverge at +0x20 (ownerContext vs activeView).
class UiDialogHandlerPrefix {
public:
  int field04;
  int field08;
  int field0c;
  int field10;
  int field14;
  int field18;
  int field1c;

  UiDialogHandlerPrefix();

  virtual void* GetClassNamePointer();
  virtual ~UiDialogHandlerPrefix();
  virtual void vmethod_0002();
  virtual void vmethod_0003();
  virtual void vmethod_0004();
  virtual void vmethod_0005();
  virtual void vmethod_0006();
  virtual void CallVoidSlot1C();
  virtual void vmethod_0008();
  virtual void vmethod_0009();
  virtual char GetBoolSlot28();
  virtual void SetControlValue(int value);
  virtual int QueryStepValue();
  virtual void vmethod_0013(int* cmd);
  virtual void vmethod_0014(int command);
  virtual void vmethod_0015(int arg1 = 0, void* arg2 = 0, int arg3 = 0);
  virtual void DispatchEvent(int arg1, void* arg2, int arg3);
  virtual void vmethod_0017(int param);
  virtual void ForwardParam(int param);
  virtual char vmethod_0019();
  virtual void vmethod_0020();
  virtual void vmethod_0021();
  virtual TView* OwnerPanel();
  virtual char vmethod_0023();
  virtual char vmethod_0024();
  virtual void vmethod_0025();
  virtual void vmethod_0026(int gate);
  virtual void vmethod_0027();
  virtual void vmethod_0028();
  virtual void vmethod_0029();
  virtual void vmethod_0030();
  virtual char vmethod_0031();
  virtual char vmethod_0080();
  virtual void vmethod_0081();
  virtual char vmethod_0032();
  virtual void vmethod_0033(int arg);
  virtual void vmethod_0034();
  virtual void vmethod_0035();
};
