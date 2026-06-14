#pragma once

#include "decomp_types.h"
#include "game/TEventHandler.h"
#include "game/CString.h"
#include "game/TViewNativeWindow.h"
#include "game/CPtrList.h"
#include "game/Point32.h"
#include "game/win_rect.h"

// VTABLE: IMPERIALISM 0x649858
class TView : public TEventHandler {
public:
  int field10;
  int field14;
  int field18;
  int controlTag;            // 0x1c
  class TView* ownerContext; // 0x20
  int ownerOffsetX;          // 0x24
  int ownerOffsetY;          // 0x28
  int field2c;
  int field30;
  int field34;
  int field38;
  int field3c;
  unsigned char padding_40_to_43[0x04];
  CPtrList* childList44;     // 0x44 — child-control list (CObList/CPtrList)
  int field48;
  unsigned char flag4c;
  unsigned char flag4d;
  unsigned short field4e;
  TViewNativeWindow* nativeWindow50; // 0x50 — host window (HWND at +0x1c)
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
  virtual void vmethod_0013(int* cmd);
  virtual void vmethod_0014(int command);
  virtual void vmethod_0015(int arg1 = 0, void* arg2 = 0, int arg3 = 0);
  virtual void DispatchEvent(int arg1, void* arg2, int arg3);
  virtual void vmethod_0017(int param);
  virtual void ForwardParam(int param);
  virtual char vmethod_0019();
  virtual void vmethod_0020();
  virtual void vmethod_0021();
  virtual class TView* OwnerPanel();
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
  // Slots 0x22-0x51 below are declared in EXACT vtable slot order (header declaration
  // order == emitted vtable order). Slot assignments are pinned by FUNCTION-marker
  // addresses, original-binary call offsets, and the byte-offset encoded in "SlotXX"
  // names. See memory tview-vtable-slot-scramble. vmethod_00NN placeholders fill the
  // remaining (body-owned-elsewhere / unported) slots; their exact position is
  // immaterial (base+derived stay name-consistent).
  virtual char vmethod_0032();                                       // 0x22 0x48a500
  virtual void vmethod_0033(int arg);                                // 0x23 0x48a4a0
  virtual void SetUiResourceOwner(int owner);                        // 0x24 0x48a4d0
  virtual class TControl* ResolveControlByTag(unsigned int controlTag); // 0x25 0x48afd0
  virtual void SwitchActiveChildAndNotify(class TView* child);       // 0x26 0x48af80
  virtual void DispatchSlot9CToLinkedChildren();                     // 0x27 0x48c820
  virtual void CallVoidSlotA0();                                     // 0x28 0x48c890
  virtual void SetEnabled(int enabledState, int refreshFlag);        // 0x29 0x48b1c0
  virtual void SetState(int state, int refreshFlag);                 // 0x2a 0x48b070
  virtual void vmethod_0034();                                       // 0x2b
  virtual void vmethod_0035();                                       // 0x2c
  virtual void vmethod_0073(int arg1, int arg2);                     // 0x2d 0x48c1c0
  virtual void vmethod_0043();                                       // 0x2e
  virtual int QuerySelectedIndexSlotBC();                            // 0x2f
  virtual void vmethod_0044();                                       // 0x30
  virtual void ForwardMapViewVirtualC4IfPresent(int param);          // 0x31 0x48ab90
  virtual void ValidateControlRectIfWindowActive(struct RECT* rect); // 0x32 0x48b690
  virtual char EvaluateControlInputGate();                           // 0x33 0x48c000
  virtual char HasRenderableParentAndContent();                      // 0x34 0x48c050
  virtual void vmethod_0045();                                       // 0x35
  virtual void DispatchControlEventToChildrenAndSelf(int eventArg);  // 0x36 0x48aaf0
  virtual void vmethod_0055(unsigned int styleSeed = 0);             // 0x37 0x48ab70
  virtual void NoOpUiCallback();                                     // 0x38 0x48abc0
  virtual void RefreshControl();                                     // 0x39 0x48b6d0
  virtual class TView* QueryOwnerContextPanel();                     // 0x3a 0x48b1a0
  virtual int IsActionable();                                        // 0x3b 0x48b200
  virtual void CaptureLayoutF0(int* buffer, int modeFlag);           // 0x3c 0x48b250
  virtual void CaptureLayout(int* buffer, int modeFlag);             // 0x3d 0x48b3f0
  virtual char Refresh();                                            // 0x3e 0x48b770
  virtual void PostRenderSlotFC();                                   // 0x3f
  virtual void BindMapQuickDrawDc(int arg);                          // 0x40 0x48b7b0
  virtual void ReleaseMapQuickDrawDc(int arg);                       // 0x41 0x48b7e0
  virtual void EnsureField48Buffer();                                // 0x42 0x48b810
  virtual void vmethod_0046();                                       // 0x43
  virtual void ApplyRectSlot110(int* rectBuffer);                    // 0x44
  virtual void vmethod_0048();                                       // 0x45
  virtual void vmethod_0053();                                       // 0x46
  virtual void vmethod_0067();                                       // 0x47
  virtual void vmethod_0070();                                       // 0x48
  virtual void vmethod_0071();                                       // 0x49
  virtual void QueryContentBounds(int* boundsBuffer);                // 0x4a 0x427260
  virtual void QueryBounds(int* boundsBuffer);                       // 0x4b 0x427290
  virtual void vmethod_0072(int arg1, int arg2, int arg3, int arg4); // 0x4c
  virtual void vmethod_0076(int* point = 0);                         // 0x4d 0x48ba80
  virtual void vmethod_0078(int* point = 0);                         // 0x4e 0x48ba40
  virtual void InvokeSlot13C();                                      // 0x4f 0x48b700
  virtual void OffsetRectByControlPosition(struct RECT* rect);       // 0x50 0x48bb00
  virtual void UpdateAfterBitmapChange(int unknownFlag);             // 0x51
  virtual Point32 TransformPointViaSlot138(Point32* inPoint);
  virtual struct RECT TransformRectViaSlot148(struct RECT* inRect);
  virtual void AddControlPosToPoint(int x, int y, int* outPoint);
  virtual void OffsetRectByCachedPos(struct RECT* inRect, struct RECT* outRect);
  virtual int* GetCachedPosPoint(int* outPoint);
  virtual void vmethod_0087(int* rectOut);
  virtual struct RECT BuildRectFromSlot158();
  virtual void vmethod_0089();
  virtual void ApplyBounds(int* boundsBuffer, int modeFlag);
  virtual char PointInBoundsAndActionable(Point32* point);
  virtual void vmethod_0092(class TView* child, int flag);
  virtual void vmethod_0093(class TView* child);
  virtual unsigned short GetField54();
  virtual char TestPointInBounds(Point32* point);
  virtual void vmethod_0096(int arg);
  virtual void vmethod_0097(int arg);
  virtual void vmethod_0098(int arg);
  virtual void vmethod_0099(int arg1, int arg2);
  virtual void DrawRectangleInCurrentUiContext(int* rect);
  virtual void AssertMcAppUiLine1914();
  virtual void AssertMcAppUiLine1922();
  virtual void SubtractPosAndDispatchToOwnerSlot19C(int* point);
  // TView's real vtable is 104 slots (0x00-0x19c). Slots 0x1A0+ (formerly declared here
  // as vmethod_0104..0110, SwitchTab, GetBoolSlot1BC) belong to the sibling branches
  // (TControl, TCivDescription, TAmtBar, ...) that each introduce their own virtuals
  // there. See memory ui-vtable-hierarchy-ground-truth. The destructor is slot 1
  // (TEventHandler override), so its declaration position is irrelevant.
  virtual ~TView();
};
