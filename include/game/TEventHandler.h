#pragma once

#include "decomp_types.h"

class TView;
class TEvent;

//
// The real shared base of TView and ApplicationUiRootController (TApplication). Both
// inherit this 37-slot interface (slots 0x00-0x24) and the fields through +0x1c; they
// diverge at +0x20 (TView::ownerContext vs ApplicationUiRootController::activeView) and
// each introduces its own virtuals at slot 0x25+. Proven by vtable comparison: TView
// (0x649858) and ApplicationUiRootController (0x648bd8) share the same body addresses for
// most of slots 0x02-0x24, overriding only a handful. Methods kept with their TView-era
// vmethod_* / semantic names so existing by-name callers/overrides keep resolving.
// VTABLE: IMPERIALISM 0x006497a0
class TEventHandler {
public:
  int field04;
  int field08;
  int field0c;
  int field10;
  int field14;
  int field18;
  int controlTag; // 0x1c

  TEventHandler() : field0c(0), field10(0x7fffffff), field14(0), field18(0) {}

  static void CreateTEventHandlerInstance(TEventHandler* handler);

  virtual void* GetTEventHandlerClassNamePointer(); // 0x00
  virtual ~TEventHandler();                         // 0x01
  virtual void vmethod_0002();                      // 0x02
  virtual void vmethod_0003();                      // 0x03
  virtual void vmethod_0004();                      // 0x04
  virtual void HandleCityDialogNoOpSlot14(int arg); // 0x05 0x485f70
  virtual void HandleCityDialogNoOpSlot18(int arg); // 0x06 0x485f90
  virtual void ReleaseRuntimeSelectionOwnerAndDestroyObject(); // 0x07 0x48a1b0
  virtual void vmethod_0008();                      // 0x08 0x48a7c0 AllocateUiResourceEntryHeaderCopyFromSource (TView overrides)
  virtual void vmethod_0009();                      // 0x09
  virtual char GetBoolSlot28();                     // 0x0a 0x48a240 GetCityDialogFlagByte4
  virtual void SetControlValue(int value);          // 0x0b 0x48a260 SetCityDialogFlagByte4
  virtual int QueryStepValue();                     // 0x0c 0x48a2c0 GetCityDialogValueDwordC
  virtual void vmethod_0013(int* cmd);              // 0x0d 0x48a3b0
  virtual void vmethod_0014(int command);           // 0x0e 0x48a3f0
  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event); // 0x0f 0x48a280
  virtual void DispatchEvent(int commandId, TEventHandler* sourceHandler, TEvent* event); // 0x10 0x48a2e0 DoEvent
  virtual void vmethod_0017(int param);             // 0x11 0x48a310
  virtual void ForwardParam(int param);             // 0x12 0x48a380
  virtual char CanHandleCityDialogActionFalse(int action); // 0x13 0x48a480
  virtual int GetCityDialogValueDword10();          // 0x14 0x415d50 field10
  virtual void SetCityDialogValueDword10(int value); // 0x15 0x415d70
  virtual class TView* OwnerPanel();                // 0x16
  virtual char vmethod_0023();                      // 0x17 0x48a530
  virtual char vmethod_0024();                      // 0x18 0x48a550
  virtual void vmethod_0025();                      // 0x19 0x48a690
  virtual void vmethod_0026(int gate);              // 0x1a 0x48a6b0
  virtual void HandleCityProductionNoOp();          // 0x1b 0x48a650
  virtual void DispatchUiCommand19ToParent();       // 0x1c 0x48a6d0
  virtual void DispatchCityProductionAction1A();    // 0x1d 0x48a670
  virtual void DispatchCityProductionAction1B();    // 0x1e 0x48a6f0
  virtual char ActivateCityProductionViewIfAllowed(); // 0x1f 0x48a570
  virtual char vmethod_0080();                      // 0x20 0x48a5e0
  virtual void vmethod_0081();                      // 0x21 0x48a710
  virtual char vmethod_0032();                      // 0x22 0x48a500
  virtual void vmethod_0033(int arg);               // 0x23 0x48a4a0
  virtual void SetUiResourceOwner(int owner);       // 0x24 0x48a4d0
};
