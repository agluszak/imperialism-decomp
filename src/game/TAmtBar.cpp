// Included by src/game/trade_screen.cpp.
// Contains trade-screen core logic functions (address-ordered).

#include <new>

#pragma optimize("y", on)


// GHIDRA_NAME InitializeTradeSellControlState
// GHIDRA_PROTO void __cdecl InitializeTradeSellControlState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Initializes Sell/Bar/Arrow control style and enabled state for current
// nation/resource context; then initializes move/bar controls baseline. GHIDRA_COMMENT_END
/* Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context;
   then initializes move/bar controls baseline. */

#include "game/TAmtBar.h"
#include "game/TradeControl.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/trade_quickdraw.h"
#include "game/ui_widget_thunks.h"
#include "game/win_rect.h"

// FUNCTION: IMPERIALISM 0x005884c0
TAmtBar* __cdecl CreateTAmtBarInstance(void) {
  TAmtBar* amountBar =
      reinterpret_cast<TAmtBar*>(AllocateWithFallbackHandler(0x68));
  if (amountBar != 0) {
    new (amountBar) TAmtBar;
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x00588560
void* __cdecl GetTAmtBarClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTAmtBar);
}

// FUNCTION: IMPERIALISM 0x00588580
TAmtBar::TAmtBar() : TView(), rangeOrMaxValue(0), stepOrCurrentValue(0), auxValueA(0), auxValueB(0) {
}

// FUNCTION: IMPERIALISM 0x005885c0
TAmtBar::~TAmtBar() {
}

// FUNCTION: IMPERIALISM 0x00401e65
void __fastcall thunk_DestructTViewBaseState_005885F0(TView* amountBar) {
  amountBar->~TView();
}

// FUNCTION: IMPERIALISM 0x00588610
void __stdcall WrapperFor_thunk_NoOpUiLifecycleHook_At00588610(int passthroughArg) {
  ((void(__cdecl*)(int))thunk_NoOpUiLifecycleHook)(passthroughArg);
}

// FUNCTION: IMPERIALISM 0x00588690
void TAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache() {
  // ORIG_CALLCONV: __thiscall
  QuickDrawSurfaceGuard surface;
  short barRange = rangeOrMaxValue;
  TradeControl* control = reinterpret_cast<TradeControl*>(this);
  int contentBounds[4];
  int frameBounds[4];
  short controlWidth;
  short controlHeight;
  RECT panelRect;
  RECT contentRect;
  short guideValue = 0;
  short fillOrigin;

  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

  if (control->IsActionable() == 0 || control->Refresh() == 0) {
    return;
  }

  control->QueryContentBounds(contentBounds);
  ApplyRectClipRegion(contentBounds);

  control->QueryBounds(frameBounds);

  control->CtrlSlot78();

  controlWidth = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x34);
  controlHeight = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x38);

  panelRect.left = frameBounds[0];
  panelRect.top = frameBounds[1];
  panelRect.right = frameBounds[0] + (int)controlWidth;
  panelRect.bottom = frameBounds[1] + (int)controlHeight;

  contentRect.left = contentBounds[0];
  contentRect.top = contentBounds[1];
  contentRect.right = contentBounds[2];
  contentRect.bottom = contentBounds[3];

  reinterpret_cast<void(__cdecl*)(void*, void*, RECT*, RECT*, int, int)>(
      BlitRectWithOptionalTransparency)(
      reinterpret_cast<void*>(ReadIntAt(kAddrPrimaryRenderSurfaceContext) + 4),
      reinterpret_cast<void*>(ReadIntAt(kAddrActiveQuickDrawSurfaceContext) + 4), &panelRect,
      &contentRect, 0, 0);

  if (barRange > 0) {
    SetQuickDrawTextOrigin(0, 1);
    CallUiRuntimeSlot34(g_pUiRuntimeContext, auxValueB);
    SetQuickDrawStylePair(1, 7);
    guideValue = stepOrCurrentValue < barRange ? stepOrCurrentValue : barRange;
    DrawCenteredGuideLine((short)(guideValue - 1), 1);
    reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
  }

  fillOrigin = guideValue > 0 ? (short)(guideValue + 1) : 0;
  SetQuickDrawTextOrigin(fillOrigin, 4);
  SetQuickDrawFillColor(0);
  SetQuickDrawStylePair(1, 1);
  DrawCenteredGuideLine(controlWidth, 4);
  SetQuickDrawTextOrigin(stepOrCurrentValue, 0);
  reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
  DrawCenteredGuideLine((short)(stepOrCurrentValue - 1), controlHeight);
  reinterpret_cast<void(__cdecl*)(int)>(SnapshotHitRegionToClipCache)(0);
}

// GHIDRA_NAME OrphanCallChain_C2_I15_00588630
// GHIDRA_PROTO undefined OrphanCallChain_C2_I15_00588630()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=2; instructions=15
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=2; instructions=15 */

// FUNCTION: IMPERIALISM 0x00588ff0
void TradeMovePanelContext::HandleTradeMoveStepCommand(int commandId, void* eventArg,
                                                       int eventExtra) {
  // ORIG_CALLCONV: __thiscall
  void* owner = this;
  if (commandId == 100) {
    TradeControl* moveControl = ResolveOwnerControl(owner, kControlTagMove);
    if (moveControl == 0) {
      MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    }
    int moveValue = moveControl->QueryValue();
    CallApplyMoveValueSlot1D0(owner, moveValue + 1);
    return;
  }
  if (commandId != 0x65) {
    ::HandleTradeMoveControlAdjustment(this, commandId, eventArg, eventExtra);
    return;
  }
  TradeControl* moveControl = ResolveOwnerControl(owner, kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
  }
  int moveValue = moveControl->QueryValue();
  CallApplyMoveValueSlot1D0(owner, moveValue - 1);
}

// GHIDRA_NAME OrphanCallChain_C1_I06_005899c0
// GHIDRA_PROTO undefined OrphanCallChain_C1_I06_005899c0()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=1; instructions=6
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=1; instructions=6 */
