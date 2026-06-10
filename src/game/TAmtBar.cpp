#include <new>

#include "game/TAmtBar.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/trade_quickdraw.h"
#include "game/ui_widget_thunks.h"
#include "game/win_rect.h"

#pragma optimize("y", on)

extern "C" char g_pClassDescTAmtBar = 0;

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
  return &g_pClassDescTAmtBar;
}

// FUNCTION: IMPERIALISM 0x00588580
TAmtBar::TAmtBar()
    : TView(), rangeOrMaxValue(0), stepOrCurrentValue(0), auxValueA(0), auxValueB(0) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x005885c0
// TAmtBar::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00401e65
void __fastcall thunk_DestructTViewBaseState_005885F0(TView* amountBar) {
  amountBar->~TView();
}

// FUNCTION: IMPERIALISM 0x00588610
void __cdecl WrapperFor_thunk_NoOpUiLifecycleHook_At00588610(void) {
  thunk_NoOpUiLifecycleHook();
}

// FUNCTION: IMPERIALISM 0x00588630
void TAmtBar::UpdateBarValuesAndRefresh(short valueAt60, short valueAt62) {
  this->stepOrCurrentValue = valueAt60;
  this->rangeOrMaxValue = valueAt62;
  this->RefreshControl();
  this->InvokeSlot13C();
}

// FUNCTION: IMPERIALISM 0x00588670
void TAmtBar::InvokeSlot1A8NoArg() {
  this->InvokeSlot1A8();
}

// FUNCTION: IMPERIALISM 0x00588690
void TAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache() {
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

  controlWidth = (short)this->field34;
  controlHeight = (short)this->field38;

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

int TAmtBar::ApplyMoveClamp(int baseValue, int requestedValue) {
  if (baseValue != 0) {
    return baseValue;
  }
  return requestedValue;
}

void TAmtBar::SetBarMetric(int value, int range) {
  stepOrCurrentValue = (short)value;
  rangeOrMaxValue = (short)range;
  RefreshControl();
}

void TAmtBar::InvokeSlot1A8() {}

void TAmtBar::SetBarMetricRatio(int value) {
  stepOrCurrentValue = (short)value;
  RefreshControl();
}

void TAmtBar::vmethod_0108() {}

void TAmtBar::ApplyStyleDescriptor(void* descriptorBuffer, int modeFlag) {
  (void)descriptorBuffer;
  (void)modeFlag;
}

void TAmtBar::vmethod_0110() {}

void TAmtBar::vmethod_0111() {}

void TAmtBar::vmethod_0112() {}

void TAmtBar::SetStyleState(int stateValue, int modeFlag) {
  (void)stateValue;
  (void)modeFlag;
}

void TAmtBar::SetBitmap(int bitmapIdValue, int unknownFlag) {
  (void)bitmapIdValue;
  (void)unknownFlag;
}

void TAmtBar::InvokeSlot1CC(int value, int modeFlag) {
  (void)value;
  (void)modeFlag;
}

void TAmtBar::vmethod_0116() {}

void TAmtBar::vmethod_0117() {}

void TAmtBar::vmethod_0118() {}

void TAmtBar::vmethod_0119() {}

void TAmtBar::vmethod_0120() {}

void TAmtBar::SetControlValueSlot1E4(int value, int updateFlag) {
  stepOrCurrentValue = (short)value;
  if (updateFlag != 0) {
    RefreshControl();
  }
}

int TAmtBar::QueryValue() {
  return (int)stepOrCurrentValue;
}
