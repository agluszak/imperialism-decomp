// TCityProductionView temporary QuickDraw render-context slice.

#include "game/TCityProductionView.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/TGreatPower.h"
#include "game/UiRuntimeContext.h"
#include "game/TView.h"
#include "game/TMinor.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/bitmap_descriptor_helpers.h"
#include "game/quickdraw_rendering.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/mfc.h"
#include "game/ui_widget_thunks.h"

extern "C" short g_Render_Nation_Header_Value_006961E0[12] = {0};
extern "C" short g_Render_Nation_Header_Value_006961F8[12] = {0};
extern "C" short g_Render_Nation_Header_Value_00696210[12] = {0};
extern "C" short g_Render_Nation_Header_Value_00696228[12] = {0};

struct RuntimeLocalTime {
  int tm_sec;
  int tm_min;
  short tm_hour;
};

undefined4 GetCurrentLocalEpochSecondsWithTimezoneCache(void);
undefined4 ConvertEpochSecondsToLocalTmWithDstAdjust(void);
// SYNTHETIC: IMPERIALISM 0x004ba240
// TCityProductionView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ba2c0
// TCityProductionView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCityProductionView, TNoHilitePicture)

TCityProductionView::TCityProductionView() {}

// SYNTHETIC: IMPERIALISM 0x004ba360
// TCityProductionView::`scalar deleting destructor'
TCityProductionView::~TCityProductionView() {}

// FUNCTION: IMPERIALISM 0x004ba3b0
void TCityProductionView::NoOpUiLifecycleHook(int arg) {
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x004ba740
void TCityProductionView::Free() {}

// FUNCTION: IMPERIALISM 0x004ba7b0
void TCityProductionView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
}

// FUNCTION: IMPERIALISM 0x004bac50
void TCityProductionView::BlitBitmapResourceRectWithScreenOffsetAndPalette(
    RECT* sourceRect, int surface, short offsetY, short offsetX, undefined4 context,
    undefined4 flags) {
  (void)sourceRect;
  (void)surface;
  (void)offsetY;
  (void)offsetX;
  (void)context;
  (void)flags;
}

// FUNCTION: IMPERIALISM 0x004badd0
void TCityProductionView::RenderNationHeaderDateLabelWithPeriodicRefresh() {
  TGreatPower* nationState = g_apNationStates[g_pSimMgr->GetActiveNationId()];
  void* subObject = 0;
  if (nationState != 0) {
    subObject = *reinterpret_cast<void**>(reinterpret_cast<char*>(nationState) + 0x894);
  }
  short sVar2_val = static_cast<TMinor*>(subObject)->HasMinorStandingLinkSlot5C(0xe);

  int mask1 = -(sVar2_val == 2);
  int mask2 = -(sVar2_val == 2);
  short originX = (mask1 & 0xffe9) + 0x213;
  short sVar2 = (mask2 & 0x14) + 0x6b;

  if (currentMonthAtA8 < 0) {
    int epochSeconds;
    reinterpret_cast<void(__cdecl*)(int*)>(GetCurrentLocalEpochSecondsWithTimezoneCache)(
        &epochSeconds);
    RuntimeLocalTime* tm = reinterpret_cast<RuntimeLocalTime*(__cdecl*)(const int*)>(
        ConvertEpochSecondsToLocalTmWithDstAdjust)(&epochSeconds);

    int iVar4 = tm->tm_min;
    short sVar6 = static_cast<short>(iVar4 / 5);
    currentWeekAtAa = sVar6;

    short sVar1 = tm->tm_hour;
    currentMonthAtA8 = sVar1;
    if (6 < sVar6) {
      currentMonthAtA8 = sVar1 + 1;
    }
    if (11 < currentMonthAtA8) {
      currentMonthAtA8 -= 12;
    }
    if (11 < currentMonthAtA8) {
      currentMonthAtA8 -= 12;
    }
  }

  ResetQuickDrawStrokeState();
  g_pUiRuntimeContext->ApplyLegendSplitSlot34(1);
  SetQuickDrawTextOriginWithContextOffset(originX, sVar2);

  short offset_x1 = g_Render_Nation_Header_Value_006961E0[currentMonthAtA8];
  short offset_y1 = g_Render_Nation_Header_Value_006961F8[currentMonthAtA8];
  DrawCenteredGuideLineOnMapDc(static_cast<short>(offset_x1 + originX),
                               static_cast<short>(offset_y1 + sVar2));

  SetQuickDrawFillColor(0);
  SetQuickDrawTextOriginWithContextOffset(originX, sVar2);

  short offset_x2 = g_Render_Nation_Header_Value_00696210[currentWeekAtAa];
  short offset_y2 = g_Render_Nation_Header_Value_00696228[currentWeekAtAa];
  DrawCenteredGuideLineOnMapDc(static_cast<short>(offset_x2 + originX),
                               static_cast<short>(offset_y2 + sVar2));
}

// FUNCTION: IMPERIALISM 0x004bafa0
void TCityProductionView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                              RgnHandle hitArg) {
  (void)point;
  (void)hitArg;
}

// FUNCTION: IMPERIALISM 0x004bb7a0
void TCityProductionView::InitializeCityProductionDialog() {}

// FUNCTION: IMPERIALISM 0x004bc0b0
void TCityProductionView::UpdateCityProductionDialogCommodityValueControls() {}

// FUNCTION: IMPERIALISM 0x004bc500
void TCityProductionView::RefreshCityBuildingActionAvailabilityIndicators() {}

// FUNCTION: IMPERIALISM 0x004bc610
void TCityProductionView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)commandId;
  (void)sourceHandler;
  (void)event;
}

// FUNCTION: IMPERIALISM 0x004bc660
void TCityProductionView::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                               int arg4) {
  (void)point;
  (void)arg2;
  (void)arg3;
  (void)arg4;
}

// FUNCTION: IMPERIALISM 0x004bc870
void TCityProductionView::DispatchPictureResourceCommand(int eventType, void* eventSender,
                                                         void* eventDataA, void* eventDataB,
                                                         int commandFlag) {
  (void)commandFlag;
  (void)eventType;
  (void)eventSender;
  (void)eventDataA;
  (void)eventDataB;
}

// FUNCTION: IMPERIALISM 0x004bc910
void TCityProductionView::OrphanCallChain_C5_I49_004bc910() {}

// FUNCTION: IMPERIALISM 0x004bc9b0
void TCityProductionView::RenderViewIntoPrimaryRenderContextWithTemporaryClip() {
  CTemporaryRegion surface;

  RECT boundsRecord;
  this->QueryBounds(&boundsRecord);

  RECT clipRect;
  clipRect.left = boundsRecord.left;
  clipRect.top = boundsRecord.top;
  clipRect.right = boundsRecord.right;
  clipRect.bottom = boundsRecord.bottom;

  // Original pushes the guard's wrapper here and again into the snapshot below,
  // and hands ApplyRectSlot110 the same rect QueryBounds filled in.
  GetClip(surface.tempRgn);

  TQuickDrawSurfaceContext* previousSurface = 0;
  int contextFlags = 0;
  GetActiveQuickDrawSurfaceContextAndFlags(&previousSurface, &contextFlags);

  SetActiveQuickDrawSurfaceContext(g_pPrimaryRenderSurfaceContext, contextFlags);
  ClipRect(&clipRect);

  needsRefreshAtA6 = 1;
  this->ApplyRectSlot110(&boundsRecord);

  SetActiveQuickDrawSurfaceContext(previousSurface, contextFlags);
  SetClip(surface.tempRgn);
}

// FUNCTION: IMPERIALISM 0x004bcaf0
void TCityProductionView::RefreshCityDialogSummaryValues() {}
