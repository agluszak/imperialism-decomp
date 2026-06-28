#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TEventHandler.h"
#include "game/CString.h"
#include "game/mfc.h"

//
// TView inherits the 37-slot shared interface (slots 0x00-0x24) and fields through +0x1c
// from TEventHandler. It overrides only the few base slots whose vtable bodies differ
// (0x07 ReleaseRuntimeSelectionOwnerAndDestroyObject, 0x08 CloneEngineerDialogStateToNewInstance,
// 0x16 OwnerPanel) and introduces its own virtuals at slot 0x25+ (declared below in exact vtable
// slot order). See include/game/TEventHandler.h and memory tview-vtable-slot-scramble.
// VTABLE: IMPERIALISM 0x649858
class TView : public TEventHandler {
public:
  class TView* ownerContext; // 0x20
  int ownerOffsetX;          // 0x24
  int ownerOffsetY;          // 0x28
  int field2c;
  int field30;
  int field34;
  int field38;
  int field3c;
  unsigned char padding_40_to_43[0x04];
  CPtrList* childList44; // 0x44 — child-control list (CObList/CPtrList)
  int* field48;
  unsigned char flag4c;
  unsigned char flag4d;
  unsigned short field4e;
  CWnd* nativeWindow50; // 0x50 — host window (MFC CWnd; HWND via m_hWnd)
  unsigned short field54;
  unsigned char padding_56_to_57[0x02];
  CString sharedStringRef;
  int field5c;

  TView();
  void InitializeUiResourceEntryFrameAndParent(int ownerContext, TControl* panel, int* offsetLayout,
                                               int* sizeLayout, int layoutParam6, int layoutParam7,
                                               int attachFlag);
  void InvalidateCityDialogRectRegion(RECT* rect, int flag);
  void CopyCityDialogStateFromSource(TView* source);
  void EnableAndProcessFlag(CString sharedString);
  void PropagateUiResourceContextRecursive(CWnd* nativeWindow);
  void SerializeRecordList_0x0C_WithBlockPool_A(CArchive* archive);

  // Base-slot overrides (vtable bodies differ from TEventHandler's).
  DECLARE_DYNCREATE(TView)
  void Free() override;                       // 0x07
  TObject* ShallowClone() override;           // 0x08 0x48bfd0
  virtual class TView* OwnerPanel() override; // 0x16 0x48b180

  // TView-introduced virtuals (slots 0x25-0x67), in exact vtable slot order. Slot
  // assignments are pinned by FUNCTION-marker addresses, original-binary call offsets,
  // and the byte-offset encoded in "SlotXX" names. vmethod_00NN placeholders fill the
  // remaining (body-owned-elsewhere / unported) slots.
  virtual class TControl* ResolveControlByTag(unsigned int controlTag);           // 0x25 0x48afd0
  virtual void SwitchActiveChildAndNotify(class TView* child);                    // 0x26 0x48af80
  virtual void DispatchSlot9CToLinkedChildren();                                  // 0x27 0x48c820
  virtual void CallVoidSlotA0();                                                  // 0x28 0x48c890
  virtual void SetEnabled(int enabledState, int refreshFlag);                     // 0x29 0x48b1c0
  virtual void SetState(int state, int refreshFlag);                              // 0x2a 0x48b070
  virtual unsigned short GetField4E();                                            // 0x2b 0x427200
  virtual void HandleCursorHoverFallback(CPoint* point, int hitArg);              // 0x2c
  virtual void NoOpClipRegionSlot2D(int arg1, int arg2);                          // 0x2d 0x48c1c0
  virtual void RefreshCityProductionViewStateFromContext(int* clipRegionWrapper); // 0x2e 0x48c1e0
  virtual int QuerySelectedIndexSlotBC();                                         // 0x2f
  virtual void InvalidateOffsetRegionUsingChildClipRect(int* regionWrapper);      // 0x30 0x48b4b0
  virtual void ForwardMapViewVirtualC4IfPresent(int param);                       // 0x31 0x48ab90
  virtual void ValidateControlRectIfWindowActive(RECT* rect);                     // 0x32 0x48b690
  virtual char EvaluateControlInputGate();                                        // 0x33 0x48c000
  virtual char HasRenderableParentAndContent();                                   // 0x34 0x48c050
  virtual void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                   int hitArg); // 0x35 0x48c080
  virtual void DispatchControlEventToChildrenAndSelf(int eventArg);             // 0x36 0x48aaf0
  virtual void NoOpUiLifecycleHook(int arg);                                    // 0x37 0x48ab70
  virtual void NoOpUiCallback();                                                // 0x38 0x48abc0
  virtual void RefreshControl();                                                // 0x39 0x48b6d0
  virtual class TView* QueryOwnerContextPanel();                                // 0x3a 0x48b1a0
  virtual int IsActionable();                                                   // 0x3b 0x48b200
  virtual void CaptureLayoutF0(int* buffer, int modeFlag);                      // 0x3c 0x48b250
  virtual void CaptureLayout(int* buffer, int modeFlag);                        // 0x3d 0x48b3f0
  virtual char Refresh();                                                       // 0x3e 0x48b770
  virtual void PostRenderSlotFC();                                              // 0x3f
  virtual int BindMapQuickDrawDc(int arg);                                      // 0x40 0x48b7b0
  virtual void ReleaseMapQuickDrawDc(int arg);                                  // 0x41 0x48b7e0
  virtual void EnsureField48Buffer();                                           // 0x42 0x48b810
  virtual void PaintVisibleChildrenIntersectingClipRect(RECT* clipRect,
                                                        int bindArg); // 0x43 0x48b8d0
  virtual void ApplyRectSlot110(RECT* rectBuffer);                    // 0x44
  virtual void PaintOrInvalidateControl(int arg = 0);                 // 0x45
  virtual char DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3,
                                             int arg4); // 0x46 0x48c450
  virtual void BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                    int arg4); // 0x47
  virtual char DispatchUiMouseEventToChildrenOrSelf_Impl(CPoint* point, int arg2, int arg3,
                                                         int arg4); // 0x48 0x48c590
  virtual char HandleMouseCommandToSelf(CPoint* point, int arg2, int arg3,
                                        int arg4);                    // 0x49
  virtual void QueryContentBounds(RECT* boundsOut);                   // 0x4a 0x427260
  virtual void QueryBounds(RECT* boundsOut);                          // 0x4b 0x427290
  virtual void DispatchVslot134WithRectAndRectPlus8_Impl(RECT* rect); // 0x4c 0x4272d0
  virtual void TranslatePointToParentChain4D(int* point = 0);         // 0x4d 0x48ba80
  virtual void TranslatePointToParentChain4E(int* point = 0);         // 0x4e 0x48ba40
  virtual void InvokeSlot13C();                                       // 0x4f 0x48b700
  virtual void OffsetRectByControlPosition(RECT* rect);               // 0x50 0x48bb00
  virtual void UpdateAfterBitmapChange(int unknownFlag);              // 0x51
  virtual CPoint TransformPointViaSlot138(CPoint* inPoint);
  virtual RECT TransformRectViaSlot148(RECT* inRect);
  virtual void AddControlPosToPoint(int x, int y, int* outPoint);
  virtual void OffsetRectByCachedPos(RECT* inRect, RECT* outRect);
  virtual int* GetCachedPosPoint(int* outPoint);
  virtual void CopyRectFromBuildRectFromSlot158(RECT* rectOut); // 0x57 0x429410
  virtual RECT* BuildRectFromSlot158(RECT* rectOut);
  virtual void RecomputeAbsolutePositionRecursive();
  virtual void ApplyBounds(RECT* newBounds, int modeFlag);       // 0x5a 0x48c380
  virtual char PointInBoundsAndActionable(CPoint* point);        // 0x5b 0x48c6d0
  virtual void AttachChildControl(class TView* child, int flag); // 0x5c 0x48abe0
  virtual void DetachChildFromOwnerList(class TView* child);
  virtual unsigned short GetField54();
  virtual char TestPointInBounds(CPoint* point);
  virtual void ReturnFromUiSlot60(int arg);
  virtual void ReturnFromUiSlot61(int arg);
  virtual void ReturnFromUiSlot62(int arg);
  virtual void ReturnFromUiSlot63(int arg1, int arg2);
  virtual void DrawRectangleInCurrentUiContext(int* rect);
  virtual void AssertMcAppUiLine1914();
  virtual void AssertMcAppUiLine1922();
  virtual void SubtractPosAndDispatchToOwnerSlot19C(int* point);
  // TView's real vtable is 104 slots (0x00-0x19c). Slots 0x1A0+ belong to the sibling
  // branches (TControl, TCivDescription, TAmtBar, ...). The destructor is slot 1
  // (TEventHandler override), so its declaration position is irrelevant.
  virtual ~TView() override;
};
