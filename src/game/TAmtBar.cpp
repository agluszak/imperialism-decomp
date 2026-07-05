#include <new>

#include "game/global_data_tables.h"
#include "game/TAmtBar.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TUberCluster.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_widget_thunks.h"
#include "game/mfc.h"

undefined4 ftol(void);
// FUNCTION: IMPERIALISM 0x00586e50
int TAmtBar::ApplyMoveClamp(int baseValue, int requestedValue) {
  (void)requestedValue;
  return (int)(short)baseValue;
}

void TAmtBar::SetBarMetric(int value, int range) {
  UpdateBarValuesAndRefresh(static_cast<short>(value), static_cast<short>(range));
}

// FUNCTION: IMPERIALISM 0x005884c0
TAmtBar* __cdecl CreateTAmtBarInstance(void) {
  return new TAmtBar();
}
// SYNTHETIC: IMPERIALISM 0x00588560
// TAmtBar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAmtBar, TView)

// FUNCTION: IMPERIALISM 0x00588580
TAmtBar::TAmtBar()
    : TView(), rangeOrMaxValue(0), stepOrCurrentValue(0), auxValueA(0), auxValueB(0) {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x005885c0
// TAmtBar::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00588610
void TAmtBar::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);
}

// FUNCTION: IMPERIALISM 0x00588630
void TAmtBar::UpdateBarValuesAndRefresh(short valueAt60, short valueAt62) {
  this->stepOrCurrentValue = valueAt60;
  this->rangeOrMaxValue = valueAt62;
  this->RefreshControl();
  this->InvokeSlot13C();
}

// FUNCTION: IMPERIALISM 0x00588670
void TAmtBar::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  InvokeSlot1A8();
}

// FUNCTION: IMPERIALISM 0x00588690
void TAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache() {
  CTemporaryRegion surface;
  short barRange = rangeOrMaxValue;
  RECT contentBounds;
  RECT frameBounds;
  short controlWidth;
  short controlHeight;
  RECT panelRect;
  RECT contentRect;
  short guideValue = 0;
  short fillOrigin;

  GetClip(surface.tempRgn);

  if (this->IsActionable() == 0 || this->Refresh() == 0) {
    return;
  }

  this->QueryContentBounds(&contentBounds);
  ClipRect(&contentBounds);

  this->QueryBounds(&frameBounds);

  this->TranslatePointToParentChain4E();

  controlWidth = (short)this->field34;
  controlHeight = (short)this->field38;

  panelRect.left = frameBounds.left;
  panelRect.top = frameBounds.top;
  panelRect.right = frameBounds.left + (int)controlWidth;
  panelRect.bottom = frameBounds.top + (int)controlHeight;

  contentRect.left = contentBounds.left;
  contentRect.top = contentBounds.top;
  contentRect.right = contentBounds.right;
  contentRect.bottom = contentBounds.bottom;

  BlitQuickDrawSurfaces(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &panelRect,
                        &contentRect, 0);

  if (barRange > 0) {
    SetQuickDrawTextOriginWithContextOffset(0, 1);
    g_pUiRuntimeContext->ApplyLegendSplitSlot34(auxValueB);
    SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(1, 7);
    guideValue = stepOrCurrentValue < barRange ? stepOrCurrentValue : barRange;
    DrawCenteredGuideLineOnMapDc((short)(guideValue - 1), 1);
    ResetQuickDrawStrokeState();
  }

  fillOrigin = guideValue > 0 ? (short)(guideValue + 1) : 0;
  SetQuickDrawTextOriginWithContextOffset(fillOrigin, 4);
  SetQuickDrawFillColor(0);
  SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(1, 1);
  DrawCenteredGuideLineOnMapDc(controlWidth, 4);
  SetQuickDrawTextOriginWithContextOffset(stepOrCurrentValue, 0);
  ResetQuickDrawStrokeState();
  DrawCenteredGuideLineOnMapDc((short)(stepOrCurrentValue - 1), controlHeight);
  SetClip(surface.tempRgn);
}

// FUNCTION: IMPERIALISM 0x00588950
void TAmtBar::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3, int arg4) {
  (void)arg2;
  (void)arg3;
  (void)arg4;
  ClampAndApplyTradeMoveValue(reinterpret_cast<int*>(point));
}

void TAmtBar::ClampAndApplyTradeMoveValue(int* requestedValuePtr) {
  int baseValue;
  if (auxValueA < 1 ||
      static_cast<int>(field34) / (static_cast<int>(auxValueA) << 1) <= *requestedValuePtr) {
    int fildRequested = *requestedValuePtr;
    int fildField34 = static_cast<int>(field34);
    int fildAux = static_cast<int>(auxValueA);
    double ratio = static_cast<double>(fildRequested) /
                   (static_cast<double>(fildField34) * static_cast<double>(fildAux));
    ratio = ratio - *reinterpret_cast<double*>(0x006631a0);
    volatile double ftolOperand = ratio;
    (void)ftolOperand;
    baseValue = reinterpret_cast<int(__cdecl*)(void)>(::ftol)();
  } else {
    baseValue = 0;
  }

  int appliedValue = ApplyMoveClamp(baseValue, *requestedValuePtr);
  TView* owner = OwnerPanel();
  if (((short)appliedValue == 0) && *requestedValuePtr != 0) {
    TAmtBar* fallbackControl =
        reinterpret_cast<TAmtBar*>(owner->ResolveControlByTag(kControlTagMove));
    if (fallbackControl == 0) {
      fallbackControl = reinterpret_cast<TAmtBar*>(owner->ResolveControlByTag(kControlTagSell));
    }
    if (fallbackControl != 0 && fallbackControl->QueryValue() == 0) {
      appliedValue = 1;
    }
  }

  reinterpret_cast<TUberCluster*>(owner)->DispatchRuntimeApplyMoveValue(appliedValue);
}

void TAmtBar::SetBarMetricRatio(int value) {
  stepOrCurrentValue = (short)value;
  RefreshControl();
}

void TAmtBar::SetControlValueSlot1E4(int value, int updateFlag) {
  stepOrCurrentValue = (short)value;
  if (updateFlag != 0) {
    RefreshControl();
  }
}

int TAmtBar::QueryValue() {
  return (int)stepOrCurrentValue;
}

void TAmtBar::ApplyStyleDescriptor(void* descriptorBuffer, int modeFlag) {
  (void)descriptorBuffer;
  (void)modeFlag;
}

void TAmtBar::InvokeSlot1A8() {}

void TAmtBar::InvokeSlot1CC(int value, int modeFlag) {
  (void)value;
  (void)modeFlag;
}

void TAmtBar::SetBitmap(int bitmapIdValue, int unknownFlag) {
  (void)bitmapIdValue;
  (void)unknownFlag;
}

void TAmtBar::SetStyleState(int stateValue, int modeFlag) {
  (void)stateValue;
  (void)modeFlag;
}

TAmtBar::~TAmtBar() {}
