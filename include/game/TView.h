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
  virtual char vmethod_0024();
  virtual void vmethod_0025();
  virtual void vmethod_0026(int gate);
  virtual void vmethod_0027();
  virtual void vmethod_0028();
  virtual void vmethod_0029();
  virtual void vmethod_0030();
  virtual void vmethod_0031();
  virtual char vmethod_0080();
  virtual void vmethod_0081();
  virtual void vmethod_0032();
  virtual void vmethod_0033(int arg);
  virtual void vmethod_0034();
  virtual void vmethod_0035();
  virtual void SetUiResourceOwner(int owner);
  virtual class TControl* ResolveControlByTag(unsigned int controlTag);
  virtual void SwitchActiveChildAndNotify(class TView* child);
  virtual void DispatchSlot9CToLinkedChildren();
  virtual void CallVoidSlotA0();
  virtual void SetEnabled(int enabledState, int refreshFlag);
  virtual void SetState(int state, int refreshFlag);
  virtual void vmethod_0043();
  virtual void vmethod_0044();
  virtual void vmethod_0045();
  virtual void vmethod_0046();
  virtual int QuerySelectedIndexSlotBC();
  virtual void vmethod_0048();
  virtual void ForwardMapViewVirtualC4IfPresent(int param);
  virtual void ValidateControlRectIfWindowActive(struct RECT* rect);
  virtual char EvaluateControlInputGate();
  virtual char HasRenderableParentAndContent();
  virtual void vmethod_0053();
  virtual void DispatchControlEventToChildrenAndSelf(int eventArg);
  virtual void vmethod_0055(unsigned int styleSeed = 0);
  virtual void NoOpUiCallback();
  virtual void RefreshControl();
  virtual class TView* QueryOwnerContextPanel();
  virtual int IsActionable();
  virtual void CaptureLayoutF0(int* buffer, int modeFlag);
  virtual void CaptureLayout(int* buffer, int modeFlag);
  virtual char Refresh();
  virtual void PostRenderSlotFC();
  virtual void BindMapQuickDrawDc(int arg);
  virtual void ReleaseMapQuickDrawDc(int arg);
  virtual void EnsureField48Buffer();
  virtual void vmethod_0067();
  virtual void ApplyRectSlot110(int* rectBuffer);
  virtual void UpdateAfterBitmapChange(int unknownFlag);
  virtual void vmethod_0070();
  virtual void vmethod_0071();
  virtual void vmethod_0072(int arg1, int arg2, int arg3, int arg4);
  virtual void vmethod_0073(int arg1, int arg2);
  virtual void QueryContentBounds(int* boundsBuffer);
  virtual void QueryBounds(int* boundsBuffer);
  virtual void vmethod_0076();
  virtual void vmethod_0077();
  virtual void vmethod_0078(int* point = 0);
  virtual void InvokeSlot13C();
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
