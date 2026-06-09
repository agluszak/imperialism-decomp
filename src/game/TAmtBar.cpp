#include <new>
#include "game/GameAssert.h"
#include "game/TAmtBar.h"
#include "game/trade_quickdraw.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/ui_widget_thunks.h"
#include "game/win_rect.h"

#pragma optimize("y", on)

// FUNCTION: IMPERIALISM 0x005884c0
TAmtBar* __cdecl CreateTAmtBarInstance(void) {
  TAmtBar* amountBar = reinterpret_cast<TAmtBar*>(AllocateWithFallbackHandler(0x68));
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
TAmtBar::TAmtBar()
    : TView(), rangeOrMaxValue(0), stepOrCurrentValue(0), auxValueA(0), auxValueB(0) {}

// FUNCTION: IMPERIALISM 0x005885c0
TAmtBar::~TAmtBar() {}

// FUNCTION: IMPERIALISM 0x00401e65
void __fastcall thunk_DestructTViewBaseState_005885F0(TView* amountBar) {
  amountBar->~TView();
}

// FUNCTION: IMPERIALISM 0x00588610
void __stdcall WrapperFor_thunk_NoOpUiLifecycleHook_At00588610(int passthroughArg) {
  ((void(__cdecl*)(int))thunk_NoOpUiLifecycleHook)(passthroughArg);
}

undefined4 thunk_DispatchPictureResourceCommand(int repeatState, void* arg8, void* argC,
                                                void* dispatchArg, void* arg14) {
  return 0;
};
undefined4 thunk_GetTickCountDiv16(void);

// FUNCTION: IMPERIALISM 0x00583bd0
void TAmtBar::HandleTradeArrowAutoRepeatTickAndDispatch(int repeatState, void* arg8, void* argC,
                                                        void* dispatchArg, void* arg14) {
  thunk_DispatchPictureResourceCommand(repeatState, arg8, argC, dispatchArg, arg14);

  if (repeatState == 2) {
    return;
  }

  unsigned int tick = (unsigned int)thunk_GetTickCountDiv16();
  int* repeatDeadline = reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x94);
  if (tick < (unsigned int)(*repeatDeadline + 5)) {
    return;
  }

  tick = (unsigned int)thunk_GetTickCountDiv16();
  *repeatDeadline = (int)tick;
  if (repeatState == 0) {
    *repeatDeadline = (int)tick + 10;
  }

  char isActive = this->vmethod_0091(dispatchArg);
  if (isActive == '\0') {
    return;
  }

  if (*reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x1c) == kControlTagRght) {
    this->DispatchEvent(100, 0, 0);
    return;
  }

  this->DispatchEvent(0x65, this, 0);
}

// FUNCTION: IMPERIALISM 0x00588690
void TAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache() {
  // ORIG_CALLCONV: __thiscall
  QuickDrawSurfaceGuard surface;
  short barRange = rangeOrMaxValue;
  int contentBounds[4];
  int frameBounds[4];
  short controlWidth;
  short controlHeight;
  RECT panelRect;
  RECT contentRect;
  short guideValue = 0;
  short fillOrigin;

  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

  if (this->IsActionable() == 0 || this->Refresh() == 0) {
    return;
  }

  this->QueryContentBounds(contentBounds);
  ApplyRectClipRegion(contentBounds);

  this->QueryBounds(frameBounds);

  this->vmethod_0078();

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
    g_pUiRuntimeContext->ApplyLegendSplitSlot34(auxValueB);
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

// FUNCTION: IMPERIALISM 0x00588630
void TAmtBar::OrphanCallChain_C2_I15_00588630(short valueAt60, short valueAt62) {
  this->stepOrCurrentValue = valueAt60;
  this->rangeOrMaxValue = valueAt62;
  this->RefreshControl();
  this->InvokeSlot13C();
}

// FUNCTION: IMPERIALISM 0x00588670
void TAmtBar::OrphanCallChain_C1_I03_00588670() {
  this->InvokeSlot1A8();
}

// GHIDRA_NAME OrphanCallChain_C1_I06_005899c0
// GHIDRA_PROTO undefined OrphanCallChain_C1_I06_005899c0()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=1; instructions=6
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=1; instructions=6 */

int TAmtBar::ApplyMoveClamp(int baseValue, int requestedValue) {
  return 0;
}

void TAmtBar::SetBarMetric(int value, int range) {}

void TAmtBar::InvokeSlot1A8() {}

void TAmtBar::SetBarMetricRatio(int value) {}

void TAmtBar::vmethod_0108() {}

void TAmtBar::ApplyStyleDescriptor(void* descriptorBuffer, int modeFlag) {}

void TAmtBar::vmethod_0110() {}

void TAmtBar::vmethod_0111() {}

void TAmtBar::vmethod_0112() {}

void TAmtBar::SetStyleState(int stateValue, int modeFlag) {}

void TAmtBar::SetBitmap(int bitmapIdValue, int unknownFlag) {}

void TAmtBar::InvokeSlot1CC(int value, int modeFlag) {}

void TAmtBar::vmethod_0116() {}

void TAmtBar::vmethod_0117() {}

void TAmtBar::vmethod_0118() {}

void TAmtBar::vmethod_0119() {}

void TAmtBar::vmethod_0120() {}

void TAmtBar::SetControlValueSlot1E4(int value, int updateFlag) {}

int TAmtBar::QueryValue() {
  return 0;
}
