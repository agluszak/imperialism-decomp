#pragma once

#include "decomp_types.h"
#include "game/TEventHandler.h"
#include "game/CString.h"

// VTABLE: IMPERIALISM 0x649858
class TView : public TEventHandler {
public:
  int field10;
  int field14;
  int field18;
  int selectedControlTagOrState1c; // 0x1c
  class TView* ownerContext; // 0x20
  int ownerOffsetX; // 0x24
  int ownerOffsetY; // 0x28
  int field2c;
  int field30;
  int field34;
  int field38;
  int field3c;
  unsigned char padding_40_to_43[0x04];
  int field44;
  int field48;
  unsigned char flag4c;
  unsigned char flag4d;
  unsigned short field4e;
  int field50;
  unsigned short field54;
  unsigned char padding_56_to_57[0x02];
  CString sharedStringRef;
  int field5c;

  TView();
  void thunk_NoOpUiLifecycleHook(int passthroughArg = 0);
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
  virtual void vmethod_0013();
  virtual void vmethod_0014();
  virtual void vmethod_0015();
  virtual void DispatchEvent(int arg1, void* arg2, int arg3);
  virtual void vmethod_0017();
  virtual void ForwardParam(int param);
  virtual void vmethod_0019();
  virtual void vmethod_0020();
  virtual void vmethod_0021();
  virtual class TView* OwnerPanel();
  virtual void vmethod_0023();
  virtual void vmethod_0024();
  virtual void vmethod_0025();
  virtual void vmethod_0026();
  virtual void vmethod_0027();
  virtual void vmethod_0028();
  virtual void vmethod_0029();
  virtual void vmethod_0030();
  virtual void vmethod_0031();
  virtual void vmethod_0032();
  virtual void vmethod_0033();
  virtual void vmethod_0034();
  virtual void vmethod_0035();
  virtual void vmethod_0036();
  virtual class TControl* ResolveControlByTag(unsigned int controlTag);
  virtual void vmethod_0038();
  virtual void vmethod_0039();
  virtual void CallVoidSlotA0();
  virtual void SetEnabled(int enabledState, int refreshFlag);
  virtual void SetState(int state, int refreshFlag);
  virtual void vmethod_0043();
  virtual void vmethod_0044();
  virtual void vmethod_0045();
  virtual void vmethod_0046();
  virtual int QuerySelectedIndexSlotBC();
  virtual void vmethod_0048();
  virtual void vmethod_0049();
  virtual void vmethod_0050();
  virtual void vmethod_0051();
  virtual void vmethod_0052();
  virtual void vmethod_0053();
  virtual void vmethod_0054();
  virtual void vmethod_0055();
  virtual void vmethod_0056();
  virtual void RefreshControl();
  virtual void vmethod_0058();
  virtual int IsActionable();
  virtual void CaptureLayoutF0(int* buffer, int modeFlag);
  virtual void CaptureLayout(int* buffer, int modeFlag);
  virtual char Refresh();
  virtual void vmethod_0063();
  virtual void vmethod_0064();
  virtual void vmethod_0065();
  virtual void vmethod_0066();
  virtual void vmethod_0067();
  virtual void vmethod_0068();
  virtual void UpdateAfterBitmapChange(int unknownFlag);
  virtual void vmethod_0070();
  virtual void vmethod_0071();
  virtual void vmethod_0072(int arg1, int arg2, int arg3, int arg4);
  virtual void vmethod_0073();
  virtual void QueryContentBounds(int* boundsBuffer);
  virtual void QueryBounds(int* boundsBuffer);
  virtual void vmethod_0076();
  virtual void vmethod_0077();
  virtual void vmethod_0078();
  virtual void InvokeSlot13C();
  virtual void vmethod_0080();
  virtual void vmethod_0081();
  virtual void vmethod_0082();
  virtual void vmethod_0083();
  virtual void vmethod_0084();
  virtual void vmethod_0085();
  virtual void vmethod_0086();
  virtual void vmethod_0087();
  virtual void vmethod_0088();
  virtual void vmethod_0089();
  virtual void ApplyBounds(int* boundsBuffer, int modeFlag);
  virtual char vmethod_0091(void* arg1);
  virtual void vmethod_0092();
  virtual void vmethod_0093();
  virtual void vmethod_0094();
  virtual void vmethod_0095();
  virtual void vmethod_0096();
  virtual void vmethod_0097();
  virtual void vmethod_0098();
  virtual void vmethod_0099();
  virtual void vmethod_0100();
  virtual void vmethod_0101();
  virtual void vmethod_0102();
  virtual void vmethod_0103();
  // TView's real vtable is 104 slots (0x00-0x19c). Slots 0x1A0+ (formerly declared here
  // as vmethod_0104..0110, SwitchTab, GetBoolSlot1BC) belong to the sibling branches
  // (TControl, TCivDescription, TAmtBar, ...) that each introduce their own virtuals
  // there. See memory ui-vtable-hierarchy-ground-truth. The destructor is slot 1
  // (TEventHandler override), so its declaration position is irrelevant.
  virtual ~TView();
};
