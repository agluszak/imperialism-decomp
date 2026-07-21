#pragma once

#include "game/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064e5e0
class TItemBoyView : public TView {
public:
  DECLARE_DYNCREATE(TItemBoyView)
  virtual ~TItemBoyView() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x48b0b0)
  // slot 0x08 ShallowClone inherited unchanged (0x48bfd0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a IsEnabled inherited unchanged (0x48a240)
  // slot 0x0b SetEnable inherited unchanged (0x48a260)
  // slot 0x0c GetNextHandler inherited unchanged (0x48a2c0)
  // slot 0x0d DispatchQueuedUiCommandAndRelease inherited unchanged (0x48a3b0)
  // slot 0x0e DispatchUiSelectionToHandler inherited unchanged (0x48a3f0)
  // slot 0x0f DoEvent inherited unchanged (0x48a280)
  // slot 0x10 HandleEvent inherited unchanged (0x48a2e0)
  // slot 0x11 DoMenuCommand inherited unchanged (0x48a310)
  // slot 0x12 ForwardParam inherited unchanged (0x48a380)
  // slot 0x13 DoIdle inherited unchanged (0x48a480)
  // slot 0x14 GetIdleFreq inherited unchanged (0x415d50)
  // slot 0x15 SetIdleFreq inherited unchanged (0x415d70)
  // slot 0x16 GetWindow inherited unchanged (0x48b180)
  // slot 0x17 WantsToBeTarget inherited unchanged (0x48a530)
  // slot 0x18 WillingToResignTarget inherited unchanged (0x48a550)
  // slot 0x19 ResignedTarget inherited unchanged (0x48a690)
  // slot 0x1a TargetValidationFailed inherited unchanged (0x48a6b0)
  // slot 0x1b TargetValidationSucceeded inherited unchanged (0x48a650)
  // slot 0x1c BecameWindowTarget inherited unchanged (0x48a6d0)
  // slot 0x1d ResignedWindowTarget inherited unchanged (0x48a670)
  // slot 0x1e BecameTarget inherited unchanged (0x48a6f0)
  // slot 0x1f BecomeTarget inherited unchanged (0x48a570)
  // slot 0x20 ResignTarget inherited unchanged (0x48a5e0)
  // slot 0x21 SelectOwner inherited unchanged (0x48a710)
  // slot 0x22 IsTarget inherited unchanged (0x48a500)
  // slot 0x23 RemoveBehavior inherited unchanged (0x48a4a0)
  // slot 0x24 AddBehavior inherited unchanged (0x48a4d0)
  // slot 0x25 ResolveControlByTag inherited unchanged (0x48afd0)
  // slot 0x26 SwitchActiveChildAndNotify inherited unchanged (0x48af80)
  // slot 0x27 Open inherited unchanged (0x48c820)
  // slot 0x28 Close inherited unchanged (0x48c890)
  // slot 0x29 SetEnabled inherited unchanged (0x48b1c0)
  // slot 0x2a SetState inherited unchanged (0x48b070)
  // slot 0x2b GetField4E inherited unchanged (0x427200)
  // slot 0x2c DoSetCursor inherited unchanged (0x48c250)
  // slot 0x2d HandleHelp inherited unchanged (0x48c1c0)
  // slot 0x2e GetDrawableRegion inherited unchanged (0x48c1e0)
  // slot 0x2f GetEventNumber inherited unchanged (0x430bd0)
  // slot 0x30 InvalidateOffsetRegionUsingChildClipRect inherited unchanged (0x48b4b0)
  // slot 0x31 ForwardMapViewVirtualC4IfPresent inherited unchanged (0x48ab90)
  // slot 0x32 ValidateControlRectIfWindowActive inherited unchanged (0x48b690)
  // slot 0x33 EvaluateControlInputGate inherited unchanged (0x48c000)
  // slot 0x34 HasRenderableParentAndContent inherited unchanged (0x48c050)
  // slot 0x35 HandleCursorHoverSelectionByChildHitTestAndFallback inherited unchanged (0x48c080)
  // slot 0x36 DispatchControlEventToChildrenAndSelf inherited unchanged (0x48aaf0)
  // slot 0x37 DoPostCreate inherited unchanged (0x48ab70)
  // slot 0x38 NoOpUiCallback inherited unchanged (0x48abc0)
  // slot 0x39 RefreshControl inherited unchanged (0x48b6d0)
  // slot 0x3a QueryOwnerContextPanel inherited unchanged (0x48b1a0)
  // slot 0x3b IsActionable inherited unchanged (0x48b200)
  // slot 0x3c CaptureLayoutF0 inherited unchanged (0x48b250)
  // slot 0x3d CaptureLayout inherited unchanged (0x48b3f0)
  // slot 0x3e Refresh inherited unchanged (0x48b770)
  // slot 0x3f PostRender inherited unchanged (0x427220)
  // slot 0x40 BindMapQuickDrawDc inherited unchanged (0x48b7b0)
  // slot 0x41 ReleaseMapQuickDrawDc inherited unchanged (0x48b7e0)
  // slot 0x42 EnsureField48Buffer inherited unchanged (0x48b810)
  // slot 0x43 PaintVisibleChildrenIntersectingClipRect inherited unchanged (0x48b8d0)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4af9f0
  // slot 0x45 PaintOrInvalidateControl inherited unchanged (0x48b860)
  // slot 0x46 HandleMouseDown inherited unchanged (0x48c450)
  // slot 0x47 BeginMouseCaptureAndStartRepeatTimer inherited unchanged (0x430c10)
  // slot 0x48 HandleMouseUp inherited unchanged (0x48c590)
  // slot 0x49 DoMouseCommand inherited unchanged (0x427240)
  // slot 0x4a QueryContentBounds inherited unchanged (0x427260)
  // slot 0x4b QueryBounds inherited unchanged (0x427290)
  // slot 0x4c TranslateRectToWindow inherited unchanged (0x4272d0)
  // slot 0x4d TranslatePointToParentChain4D inherited unchanged (0x48ba80)
  // slot 0x4e TranslatePointToParentChain4E inherited unchanged (0x48ba40)
  // slot 0x4f ForceRedraw inherited unchanged (0x48b700)
  // slot 0x50 LocalToSuperVRect inherited unchanged (0x48bb00)
  // slot 0x51 SuperToLocal inherited unchanged (0x427330)
  // slot 0x52 ViewToQDPt inherited unchanged (0x48bb60)
  // slot 0x53 ViewToQDRect inherited unchanged (0x48bbb0)
  // slot 0x54 AddControlPosToPoint inherited unchanged (0x48bc30)
  // slot 0x55 OffsetRectByCachedPos inherited unchanged (0x48bc60)
  // slot 0x56 GetAbsolutePosition inherited unchanged (0x48bb30)
  // slot 0x57 GetDrawableQDRect inherited unchanged (0x429410)
  // slot 0x58 GetQDExtent inherited unchanged (0x48bce0)
  // slot 0x59 UpdateCoordinates inherited unchanged (0x48b2d0)
  // slot 0x5a UpdateRectCacheIfChangedAndInvalidateCityDialog inherited unchanged (0x48c380)
  // slot 0x5b PointInBoundsAndActionable inherited unchanged (0x48c6d0)
  // slot 0x5c AttachChildControl inherited unchanged (0x48abe0)
  // slot 0x5d DetachUiElementFromOwnerListAndClearBackref inherited unchanged (0x48ae60)
  // slot 0x5e GetHelpState inherited unchanged (0x48c970)
  // slot 0x5f ContainsMouse inherited unchanged (0x48c990)
  // slot 0x60 GoAwayByUser inherited unchanged (0x48c9e0)
  // slot 0x61 MoveByUser inherited unchanged (0x48ca00)
  // slot 0x62 ResizeByUser inherited unchanged (0x48ca20)
  // slot 0x63 ZoomByUser inherited unchanged (0x48ca40)
  // slot 0x64 DrawRectangleInCurrentUiContext inherited unchanged (0x48c750)
  // slot 0x65 AssertMcAppUILine1914 inherited unchanged (0x48c7a0)
  // slot 0x66 AssertMcAppUILine1922 inherited unchanged (0x48c7d0)
  // slot 0x67 WindowToLocal inherited unchanged (0x48bac0)

  TItemBoyView();

  // Draws `header` at a fixed origin, then blits a horizontal row of item-kind icons
  // (icon strip cached at *(g_pStrategicMapViewSystem + 0x674) + 4, distinct from the
  // Army/Navy boy views' +0x694 strip) using this->frameWidth34 (inherited from
  // TView) and the context's item count to lay out each icon's width. Non-virtual
  // helper called only from Draw; real name unrecovered (Ghidra's
  // provisional name for 0x4afb60 follows its usual scalar-deleting-destructor
  // template, but this is a plain paint helper, not a destructor -- verified from
  // the raw listing).
  void DrawItemHeaderAndIconRows(CString* header);

  // Unrecovered context object read by Draw/DrawItemHeaderAndIconRows:
  // +0 item "kind" id (short), +2 item count (short). Raw storage until the real
  // pointee class is identified (same pattern as TArmyBoyView::field60).
  void* field60; // +0x60
};
