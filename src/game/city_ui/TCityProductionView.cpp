// TCityProductionView temporary QuickDraw render-context slice.

#include "game/city_ui/TCityProductionView.h"

#include <time.h>
#include "game/ui_screens/TSimMgr.h"
#include "game/app/TAnimator.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/city_ui/TBuildingView.h"
#include "game/city/TCity.h"
#include "game/ui_core/TControl.h"
#include "game/globals/prelude.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TView.h"
#include "game/nation/TMinor.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/ui_widgets/TPlacard.h"
#include "game/city/TPopulationMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/TStaticText.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/app/TTransFocusAnimation.h"
#include "game/ui_core/TWindow.h"
#include "game/quickdraw_guards.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/mfc.h"
#include "game/gfx/ui_invalidation_guard.h"

extern "C" short g_Render_Nation_Header_Value_006961E0[12] = {0, 1,  2,  2,  2,  1,
                                                              0, -2, -2, -2, -2, -1};
extern "C" short g_Render_Nation_Header_Value_006961F8[12] = {-2, -2, -1, 1,  2,  2,
                                                              2,  2,  0,  -1, -2, -2};
extern "C" short g_Render_Nation_Header_Value_00696210[12] = {0, 2,  3,  3,  2,  2,
                                                              0, -2, -3, -3, -2, -1};
extern "C" short g_Render_Nation_Header_Value_00696228[12] = {-3, -2, 0, 2,  3,  4,
                                                              3,  3,  0, -1, -3, -3};

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
void TCityProductionView::DoPostCreate(int arg) {
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x004ba740
void TCityProductionView::Free() {
  g_pUiAnimator->FreeUiTransientRegistryPayloads();
  for (int i = 0; i < 16; ++i) {
    buildingClipRegionsEC[i] = DisposeRgn(buildingClipRegionsEC[i]);
  }
  g_pGlobalUiRootController->cursorRegionInvalid = 0;
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x004ba7b0
void TCityProductionView::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
}

// FUNCTION: IMPERIALISM 0x004bac50
void TCityProductionView::BlitBitmapResourceRectWithScreenOffsetAndPalette(
    RECT* destRect, TQuickDrawSurfaceContext* destContext, short offsetY, short offsetX,
    short resourceId, TQuickDrawSurfaceContext* restoreContext, int restoreFlags) {
  (void)destRect;
  (void)destContext;
  (void)offsetY;
  (void)offsetX;
  (void)resourceId;
  (void)restoreContext;
  (void)restoreFlags;
}

// FUNCTION: IMPERIALISM 0x004badd0
void TCityProductionView::RenderNationHeaderDateLabelWithPeriodicRefresh() {
  TGreatPower* nationState = g_apNationStates[g_pSimMgr->GetActiveNationId()];
  void* subObject = 0;
  if (nationState != 0) {
    subObject = *reinterpret_cast<void**>(reinterpret_cast<char*>(nationState) + 0x894);
  }
  short sVar2_val = static_cast<TMinor*>(subObject)->HasMinorStandingLinkSlot5C(0xe);

  int mask1 = -static_cast<int>(sVar2_val == 2);
  int mask2 = -static_cast<int>(sVar2_val == 2);
  short originX = (mask1 & 0xffe9) + 0x213;
  short sVar2 = (mask2 & 0x14) + 0x6b;

  if (currentMonthAtA8 < 0) {
    time_t epochSeconds;
    time(&epochSeconds);
    struct tm* tm = localtime(&epochSeconds);

    int iVar4 = tm->tm_min;
    short sVar6 = static_cast<short>(iVar4 / 5);
    currentWeekAtAA = sVar6;

    short sVar1 = static_cast<short>(tm->tm_hour);
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

  short offset_x2 = g_Render_Nation_Header_Value_00696210[currentWeekAtAA];
  short offset_y2 = g_Render_Nation_Header_Value_00696228[currentWeekAtAA];
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
void TCityProductionView::InitializeCityProductionDialog(TCity* city, TView* dialogRoot) {
  (void)city;
  (void)dialogRoot;
}

// FUNCTION: IMPERIALISM 0x004bc0b0
void TCityProductionView::UpdateUnits() {
  g_pUiRuntimeContext->RefreshMainViewNationIndicatorForCurrentTurnEvent();
  TPopulationMgr* population = city94->productionSummary1d8;

  TPlacard* placard = static_cast<TPlacard*>(ResolveControlByTag(0x756e7472)); // 'rtnu'
  if (placard == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x4b9);
  }
  placard->SetValue(population->baselineSlots10->lowSkillCount04, true);

  placard = static_cast<TPlacard*>(ResolveControlByTag(0x74617269)); // 'iart'
  if (placard == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x4bc);
  }
  placard->SetValue(population->baselineSlots10->mediumSkillCount06, true);

  placard = static_cast<TPlacard*>(ResolveControlByTag(0x70726f66)); // 'forp'
  if (placard == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x4bf);
  }
  placard->SetValue(population->baselineSlots10->highSkillCount08, true);

  placard = static_cast<TPlacard*>(ResolveControlByTag(0x706f7765)); // 'ewop'
  if (placard == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x4c2);
  }
  placard->SetValue(city94->powerAvailableB4, true);

  short* predictedNeeds = population->PredictedNeeds();
  const unsigned int tags[6] = {0x67726169, 0x70726f64, 0x6d656174,
                                0x68617264, 0x636c6f74, 0x6675726e};
  const short resourceIds[6] = {17, 18, 20, 15, 13, 14};
  const int assertionLines[6] = {0x4c8, 0x4cc, 0x4d0, 0x4d5, 0x4d8, 0x4db};
  for (int i = 0; i < 6; ++i) {
    placard = static_cast<TPlacard*>(ResolveControlByTag(tags[i]));
    if (placard == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8,
                                                   assertionLines[i]);
    }
    placard->SetValue(predictedNeeds[resourceIds[i]], true);
  }

  placard = static_cast<TPlacard*>(ResolveControlByTag(0x6c616250)); // 'Pbal'
  if (placard == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x4e0);
  }
  placard->SetValue(population->strength, true);
}

// FUNCTION: IMPERIALISM 0x004bc500
void TCityProductionView::UpdateToolbar() {
  UpdateUnits();
  for (int i = 0; i < 16; ++i) {
    if (buildingViewsAC[i] != 0) {
      buildingViewsAC[i]->UpdateFields();
    }
  }

  for (int group = 0; group < 8; ++group) {
    short buildingSlot = static_cast<short>(group < 7 ? group : 11);
    bool enabled;
    if (buildingSlot == 11) {
      enabled = city94->powerPlantUpgradeQueuedFlag04 == 0 &&
                city94->trailingOrderSlots[1]->quantityField04 > 0;
    } else if (city94->trailingOrderSlots[buildingSlot + 2]->quantityField04 > 0) {
      enabled = false;
    } else {
      enabled = city94->productionAccum1fc[buildingSlot] < city94->GetBuildingType(buildingSlot);
    }
    for (int animation = 0; animation < 3; ++animation) {
      if (buildingActionAnimations12C[group][animation] != 0) {
        buildingActionAnimations12C[group][animation]->enabledFlag = enabled;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004bc610
void TCityProductionView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId >= 10000) {
    g_pStrategicMapViewSystem->OpenConstructionWindow(static_cast<short>(commandId - 10000), city94,
                                                      this);
    return;
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004bc660
void TCityProductionView::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  (void)event;
  (void)origin;
  short buildingSlot = -1;
  CPoint localPoint(point);
  for (int priority = 15; priority >= 0; --priority) {
    short candidate = g_cityBuildingHitTestOrder[priority];
    if (PtInRgn(&localPoint, buildingClipRegionsEC[candidate])) {
      buildingSlot = candidate;
      break;
    }
  }
  if (buildingSlot < 0) {
    return;
  }

  if (buildingSlot == 15 && buildingViewsAC[15] == 0) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0xbdb, 0, 1);
    buildingViewsAC[15] = g_pStrategicMapViewSystem->OpenBuildingWindow(15, city94, 0, 0, 0);
    UpdateToolbar();
    return;
  }

  if (buildingViewsAC[buildingSlot] == 0) {
    if (city94->GetBuildingType(buildingSlot) == 0 && city94->IsCapacityCenter(buildingSlot)) {
      bool available = true;
      if (buildingSlot == 6 || buildingSlot == 11) {
        short nationId = g_pSimMgr->GetActiveNationId();
        available =
            g_pCityOrderCapabilityState->orderCapRows277[nationId].techStatusByTechId[19] == 2;
      }
      if (available) {
        TrackMouse(kTrackPhaseEnd, localPoint, localPoint, localPoint, 0);
        UpdateToolbar();
        return;
      }
    }

    g_pSfxPlaybackSystem->PlaySoundEffect(
        static_cast<short>(g_cityBuildingSoundCueOffsets[buildingSlot] + 3000), 0, 1);
    buildingViewsAC[buildingSlot] =
        g_pStrategicMapViewSystem->OpenBuildingWindow(buildingSlot, city94, 0, 0, 0);
  }
  UpdateToolbar();
}

// FUNCTION: IMPERIALISM 0x004bc870
void TCityProductionView::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                                     CPoint& currentPoint, unsigned char commandFlag) {
  (void)commandFlag;
  (void)startPoint;
  (void)previousPoint;
  if (phase != kTrackPhaseEnd) {
    return;
  }

  CPoint point(currentPoint);
  for (int priority = 15; priority >= 0; --priority) {
    short buildingSlot = g_cityBuildingHitTestOrder[priority];
    if (PtInRgn(&point, buildingClipRegionsEC[buildingSlot])) {
      HandleEvent(buildingSlot + 10000, this, 0);
      return;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004bc910
void TCityProductionView::CloseAndSaveWindows() {
  for (short buildingSlot = 0; buildingSlot < 16; ++buildingSlot) {
    TBuildingView* buildingView = buildingViewsAC[buildingSlot];
    if (buildingView != 0) {
      TWindow* window = buildingView->GetWindow();
      city94->SetBuildingWindowState(buildingSlot, 1, static_cast<short>(window->ownerLocalX),
                                     static_cast<short>(window->ownerLocalY));
      window->Close();
      window->Free();
      buildingViewsAC[buildingSlot] = 0;
    } else {
      city94->SetBuildingWindowState(buildingSlot, 0, 0, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004bc9b0
void TCityProductionView::SetBuildingPicture(short buildingSlot, short buildingType) {
  (void)buildingSlot;
  (void)buildingType;
  CTemporaryRegion surface;

  CRect boundsRecord;
  this->QueryBounds(&boundsRecord);

  RECT clipRect;
  clipRect.left = boundsRecord.left;
  clipRect.top = boundsRecord.top;
  clipRect.right = boundsRecord.right;
  clipRect.bottom = boundsRecord.bottom;

  // Original pushes the guard's wrapper here and again into the snapshot below,
  // and hands Draw the same rect QueryBounds filled in.
  GetClip(surface.tempRgn);

  TQuickDrawSurfaceContext* previousSurface = 0;
  int contextFlags = 0;
  GetGWorld(&previousSurface, &contextFlags);

  SetGWorld(g_pPrimaryRenderSurfaceContext, contextFlags);
  ClipRect(&clipRect);

  needsRefreshAtA6 = 1;
  this->Draw(&boundsRecord);

  SetGWorld(previousSurface, contextFlags);
  SetClip(surface.tempRgn);
}

// FUNCTION: IMPERIALISM 0x004bcaf0
void TCityProductionView::UpdateFields() {
  CString numberText;
  CString summaryText;
  int i;

  short total = 0;
  for (i = 0; i < 14; ++i) {
    total = static_cast<short>(total + city94->orderCountByType5c[i]);
  }
  numberText.Format(g_szDecimalFormat, total);
  summaryText = g_szCityProductionShipyardPrefix + numberText;
  TStaticText* summary =
      static_cast<TStaticText*>(ResolveControlByTag(0x75736869)); // shipyard summary
  if (summary == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x5ea);
  }
  summary->SetTextAndMaybeRefresh(&summaryText, 1);

  total = 0;
  for (i = 25; i < 29; ++i) {
    TProductionOrder* order = static_cast<TProductionOrder*>(city94->orderSlotsE4[i]);
    if (order == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x5f2);
    }
    total = static_cast<short>(total + order->quantityField04);
  }
  numberText.Format(g_szDecimalFormat, total);
  summaryText = g_szCityProductionArmoryPrefix + numberText;
  summary = static_cast<TStaticText*>(ResolveControlByTag(0x7561726d)); // armory summary
  if (summary == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x5f8);
  }
  summary->SetTextAndMaybeRefresh(&summaryText, 1);

  total = 0;
  for (i = 34; i < 39; ++i) {
    TProductionOrder* order = static_cast<TProductionOrder*>(city94->orderSlotsE4[i]);
    if (order == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x600);
    }
    total = static_cast<short>(total + order->quantityField04);
  }
  numberText.Format(g_szDecimalFormat, total);
  summaryText = g_szCityProductionUniversityPrefix + numberText;
  summary = static_cast<TStaticText*>(ResolveControlByTag(0x75756e69)); // university summary
  if (summary == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x606);
  }
  summary->SetTextAndMaybeRefresh(&summaryText, 1);
  UpdateToolbar();
}
