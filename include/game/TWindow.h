#pragma once

#include "game/TDialogBehavior.h"
#include "game/TView.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TObject;

// VTABLE: IMPERIALISM 0x00649e58
class TWindow : public TView {
public:
  DECLARE_DYNCREATE(TWindow)
  virtual ~TWindow() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override;             // slot 0x07 0x48e2a0
  virtual TObject* ShallowClone() override; // slot 0x08 0x492d80
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a GetBoolSlot28 inherited unchanged (0x48a240)
  // slot 0x0b SetControlValue inherited unchanged (0x48a260)
  // slot 0x0c QueryStepValue inherited unchanged (0x48a2c0)
  // slot 0x0d DispatchQueuedUiCommandAndRelease inherited unchanged (0x48a3b0)
  // slot 0x0e DispatchUiSelectionToHandler inherited unchanged (0x48a3f0)
  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler,
                           TEvent* event) override; // slot 0x0f 0x0048dd50
  virtual void DispatchEvent(int commandId, TEventHandler* sourceHandler,
                             TEvent* event) override; // slot 0x10 0x48dd10
  // slot 0x11 vmethod_0017 inherited unchanged (0x48a310)
  // slot 0x12 ForwardParam inherited unchanged (0x48a380)
  // slot 0x13 DoIdle inherited unchanged (0x48a480)
  // slot 0x14 GetCityDialogValueDword10 inherited unchanged (0x415d50)
  // slot 0x15 SetCityDialogValueDword10 inherited unchanged (0x415d70)
  virtual class TView* OwnerPanel() override; // slot 0x16 0x492cc0
  // slot 0x17 vmethod_0023 inherited unchanged (0x48a530)
  // slot 0x18 GetDeactivateVetoCode inherited unchanged (0x48a550)
  // slot 0x19 OnDeactivated inherited unchanged (0x48a690)
  // slot 0x1a OnDeactivateVetoed inherited unchanged (0x48a6b0)
  // slot 0x1b HandleCityProductionNoOp inherited unchanged (0x48a650)
  // slot 0x1c DispatchUiCommand19ToParent inherited unchanged (0x48a6d0)
  // slot 0x1d DispatchCityProductionAction1A inherited unchanged (0x48a670)
  // slot 0x1e DispatchCityProductionAction1B inherited unchanged (0x48a6f0)
  // slot 0x1f ActivateCityProductionViewIfAllowed inherited unchanged (0x48a570)
  // slot 0x20 TryDeactivateActiveView inherited unchanged (0x48a5e0)
  // slot 0x21 vmethod_0081 inherited unchanged (0x48a710)
  // slot 0x22 IsActiveView inherited unchanged (0x48a500)
  // slot 0x23 DetachUiResourceOwnerIfMatches inherited unchanged (0x48a4a0)
  // slot 0x24 SetUiResourceOwner inherited unchanged (0x48a4d0)
  // slot 0x25 ResolveControlByTag inherited unchanged (0x48afd0)
  // slot 0x26 SwitchActiveChildAndNotify inherited unchanged (0x48af80)
  virtual CMcWindow* Open() override; // slot 0x27 0x48de00
  virtual void Close() override;      // slot 0x28 0x48e060
  // slot 0x29 SetEnabled inherited unchanged (0x48b1c0)
  // slot 0x2a SetState inherited unchanged (0x48b070)
  // slot 0x2b GetField4E inherited unchanged (0x427200)
  // slot 0x2c HandleCursorHoverFallback inherited unchanged (0x48c250)
  // slot 0x2d vmethod_0073 inherited unchanged (0x48c1c0)
  // slot 0x2e RefreshCityProductionViewStateFromContext inherited unchanged (0x48c1e0)
  // slot 0x2f QuerySelectedIndexSlotBC inherited unchanged (0x430bd0)
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
  virtual class TView* QueryOwnerContextPanel() override; // slot 0x3a 0x492ce0
  virtual char IsActionable() override;                   // slot 0x3b 0x48d980
  // slot 0x3c CaptureLayoutF0 inherited unchanged (0x48b250)
  // slot 0x3d CaptureLayout inherited unchanged (0x48b3f0)
  // slot 0x3e Refresh inherited unchanged (0x48b770)
  // slot 0x3f PostRenderSlotFC inherited unchanged (0x427220)
  // slot 0x40 BindMapQuickDrawDc inherited unchanged (0x48b7b0)
  // slot 0x41 ReleaseMapQuickDrawDc inherited unchanged (0x48b7e0)
  // slot 0x42 EnsureField48Buffer inherited unchanged (0x48b810)
  // slot 0x43 PaintVisibleChildrenIntersectingClipRect inherited unchanged (0x48b8d0)
  // slot 0x44 ApplyRectSlot110 inherited unchanged (0x430bf0)
  // slot 0x45 vmethod_0048 inherited unchanged (0x48b860)
  // slot 0x46 DispatchUiMouseMoveToChildren inherited unchanged (0x48c450)
  // slot 0x47 BeginMouseCaptureAndStartRepeatTimer inherited unchanged (0x430c10)
  // slot 0x48 DispatchUiMouseEventToChildrenOrSelf_Impl inherited unchanged (0x48c590)
  // slot 0x49 vmethod_0071 inherited unchanged (0x427240)
  // slot 0x4a QueryContentBounds inherited unchanged (0x427260)
  // slot 0x4b QueryBounds inherited unchanged (0x427290)
  virtual void DispatchVslot134WithRectAndRectPlus8_Impl(RECT* rect) override; // slot 0x4c 0x492d40
  virtual void TranslatePointToParentChain4D(CPoint* point = 0) override;      // slot 0x4d 0x492d20
  virtual void TranslatePointToParentChain4E(CPoint* point = 0) override;      // slot 0x4e 0x492d00
  // slot 0x4f InvokeSlot13C inherited unchanged (0x48b700)
  // slot 0x50 OffsetRectByControlPosition inherited unchanged (0x48bb00)
  // slot 0x51 UpdateAfterBitmapChange inherited unchanged (0x427330)
  // slot 0x52 CtrlSlot82_TransformPointViaSlot138_Impl inherited unchanged (0x48bb60)
  // slot 0x53 CtrlSlot83_TransformRectViaSlot148_Impl inherited unchanged (0x48bbb0)
  // slot 0x54 CtrlSlot84_AddControlPosToPoint_Impl inherited unchanged (0x48bc30)
  // slot 0x55 CtrlSlot85_OffsetRectByCachedPos_Impl inherited unchanged (0x48bc60)
  // slot 0x56 CtrlSlot86_GetCachedPosPoint_Impl inherited unchanged (0x48bb30)
  // slot 0x57 CopyRectFromBuildRectFromSlot158 inherited unchanged (0x429410)
  // slot 0x58 CtrlSlot88_BuildRectFromSlot158AndCachedSize_Impl inherited unchanged (0x48bce0)
  // slot 0x59 VTableSlot59 inherited unchanged (0x48b2d0)
  // slot 0x5a UpdateRectCacheIfChangedAndInvalidateCityDialog inherited unchanged (0x48c380)
  // slot 0x5b VTableSlot5B inherited unchanged (0x48c6d0)
  // slot 0x5c vmethod_0092 inherited unchanged (0x48abe0)
  // slot 0x5d DetachUiElementFromOwnerListAndClearBackref inherited unchanged (0x48ae60)
  // slot 0x5e CtrlSlot94_GetWordField54_Impl inherited unchanged (0x48c970)
  virtual char TestPointInBounds(CPoint* point) override;       // slot 0x5f 0x48e1c0
  virtual void ReturnFromUiSlot60(int arg) override;            // slot 0x60 0x48e1e0
  virtual void ReturnFromUiSlot61(int arg) override;            // slot 0x61 0x48e210
  virtual void ReturnFromUiSlot62(int arg) override;            // slot 0x62 0x48e240
  virtual void ReturnFromUiSlot63(int arg1, int arg2) override; // slot 0x63 0x48e270
  // slot 0x64 DrawRectangleInCurrentUiContext inherited unchanged (0x48c750)
  // slot 0x65 AssertMcAppUILine1914 inherited unchanged (0x48c7a0)
  // slot 0x66 AssertMcAppUILine1922 inherited unchanged (0x48c7d0)
  virtual void SubtractPosAndDispatchToOwnerSlot19C(CPoint* point) override; // slot 0x67 0x492d60
  virtual void SetField84(unsigned char param_1);                            // slot 0x68 0x48da40
  virtual void SetField88And8c(int param_1,
                               int param_2);           // slot 0x69 0x48d8a0
  virtual undefined GetDialogBehaviorByte10();         // slot 0x6a 0x48da10
  virtual int ExecuteViewModalStateWithPushPopChain(); // slot 0x6b 0x48da60
  virtual undefined GetDialogBehaviorByte20();         // slot 0x6c 0x48dc60
  // Forwards to GetEmbeddedDialogBehavior()'s own command-arming slot 0x0e (a no-op if
  // no behavior is attached), which stashes commandCode as armedCommandCode and
  // dispatches it to the behavior's owner. 0x48dc90.
  virtual undefined NotifyDialogBehaviorCommandArmed(undefined4 commandCode,
                                                     undefined4 flag); // slot 0x6d 0x48dc90
  virtual TDialogBehavior* GetEmbeddedDialogBehavior();                // slot 0x6e 0x48dcc0
  virtual void AssertMcAppUILine2554();                                // slot 0x6f 0x48dce0
  // Switching notifies the previous and new targets through TEventHandler slots.
  virtual void SetWindowTarget(TEventHandler* target); // slot 0x70 0x48ddc0
  virtual undefined
  WrapperFor_CenterWindowWithinOwnerOrWorkArea_At0048e150(char param_1, char param_2,
                                                          int unusedArg3); // slot 0x71 0x48e150
  virtual void AssertMcAppUILine2358(int unusedArg);                       // slot 0x72 0x48d8d0
  virtual undefined OrphanCallChain_C2_I39_0048d900(char param_1,
                                                    char param_2); // slot 0x73 0x48d900
  // MacApp TWindow::CloseAndFree(): Close (slot 0x28) then Free (slot 0x07).
  virtual void CloseAndFree();                       // slot 0x74 0x48e120
  virtual undefined SetWindowText(CString* param_1); // slot 0x75 0x48d9c0
  virtual undefined GetWindowText(CString* param_1); // slot 0x76 0x48d9f0

  // --- TWindow data members (object size 0xa0; the TView subobject ends at 0x60). ---
  // The 0x74 region is an embedded TDialogBehavior subobject (ConstructTDialogBehaviorBaseState
  // at +0x74). Remaining named fields are accessed directly by TWindow's own methods.
  // Offsets that are not yet attributed stay as padding.
  short windowStyleType; // 0x60 — window-type code; selects the CreateEx style bits
  unsigned char padding_62_to_63[0x02];
  // 0x64 — the currently-active linked window (init = this); switching targets
  // notifies the previous one via DispatchUiCommand19ToParent.
  TEventHandler* activeLinkedWindow64;
  unsigned char padding_68_to_6b[0x04]; // 0x68
  // 0x6c-0x71 — style/behavior booleans written by the UI resource builders. The names
  // remain offset-qualified where no Windows reader has established the exact behavior.
  bool resourceFlag6c; // 0x6c
  // 0x6d — for window-type codes 0x30/0x1f40, selects the captioned frame style
  // (0x00c80000) instead of the popup style (0x80c00000) in CMcWindow's CreateEx.
  bool useCaptionedFrameFlag6d;
  bool resourceFlag6e; // 0x6e
  bool resourceFlag6f; // 0x6f
  bool topmostFlag70;  // 0x70 — when set, CMcWindow adds WS_EX_TOPMOST
  bool resourceFlag71; // 0x71
  unsigned char padding_72_to_73[0x02];
  TDialogBehavior dialogBehavior; // 0x74
  int busyFlag98;                 // 0x98
  unsigned short windowFlags;     // 0x9c — flag word set by the dialog factory builders
  unsigned char padding_9e_to_9f[0x02];

  TWindow();
};
