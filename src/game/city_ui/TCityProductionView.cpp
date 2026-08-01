// TCityProductionView temporary QuickDraw render-context slice.

#include "game/city_ui/TCityProductionView.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"

#include <time.h>
#include "game/ui_screens/TSimMgr.h"
#include "game/app/TAnimator.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/city_ui/TBuildingView.h"
#include "game/city/TCity.h"
#include "game/ui_core/TControl.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/ui_widgets/TPlacard.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/city/TPopulationMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/TStaticText.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/app/TTransFocusAnimation.h"
#include "game/ui_core/TWindow.h"
#include "game/quickdraw_guards.h"
#include "game/gfx/CTemporaryRegion.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/gfx/CDib.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/ui_core/TBitmapResourceLoader.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/mfc.h"
#include "game/gfx/ui_invalidation_guard.h"
#ifdef IMPERIALISM_RUNTIME_TESTS
#include "RuntimeTestDriver.h"
#endif

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

// FUNCTION: IMPERIALISM 0x004ba2e0
TCityProductionView::TCityProductionView() {
  selectedBuildingSlotA4 = -1;
  needsRefreshAtA6 = false;
  for (int i = 0; i < 16; i = i + 1) {
    buildingClipRegionsEC[i] = 0;
  }
  for (int viewSlot = 0; viewSlot < 16; viewSlot = viewSlot + 1) {
    buildingViewsAC[viewSlot] = 0;
  }
  currentMonthAtA8 = -1;
  for (int group = 0; group < 8; group = group + 1) {
    for (int slot = 0; slot < 3; slot = slot + 1) {
      buildingActionAnimations12C[group][slot] = 0;
    }
  }
}

// SYNTHETIC: IMPERIALISM 0x004ba360
// TCityProductionView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004ba390
TCityProductionView::~TCityProductionView() {}

// FUNCTION: IMPERIALISM 0x004ba3b0
void TCityProductionView::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);
  g_pAmbitApplication->cursorRegionInvalid = 1;

  // Per building slot: build a mouse clip region from the slot bitmap's outline polygon.
  for (int slot = 0; slot < 16; ++slot) {
    TGreatPower* nation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    TCity* city = (nation != 0) ? nation->city : 0;
    short level = city->GetNextBuildingType(slot);
    CDib* bitmap = g_pModuleLibraryCacheState->LoadBmpResourceByIdCached(
        static_cast<unsigned short>(level * 0x10 + 0x1bbc + slot));
    POINT* outlinePolygon = bitmap->BuildNonTransparentOutlinePolygon(0xffffffff);
    buildingClipRegionsEC[slot] = NewRgn();
    (*buildingClipRegionsEC[slot])->rgn.DeleteObject();
    HRGN polygonRegion = ::CreatePolygonRgn(outlinePolygon + 1, outlinePolygon[0].x, WINDING);
    (*buildingClipRegionsEC[slot])->rgn.Attach(polygonRegion);
    delete[] outlinePolygon;
    g_pModuleLibraryCacheState->ReleaseRecordByHandle(bitmap);

    short x = g_anCityBuildingSlotCoords[g_nCityBuildingSlotXOffsetIndex + slot * 2];
    short y = g_anCityBuildingSlotCoords[g_nCityBuildingSlotYOffsetIndex + slot * 2];
    OffsetRgn(buildingClipRegionsEC[slot], x, y);
  }

  TWindow* window = GetWindow();
  window->nativeWindow50->ModifyStyle(0, 0x02000000, 0);

  TGreatPower* nation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
  TCity* city = (nation != 0) ? nation->city : 0;

  // Build eight groups of three action-focus animations from the layout/resource tables.
  int tableOffset = 0;
  for (int buildingSlot = 0; tableOffset < 0x18; ++buildingSlot, tableOffset += 3) {
    short actionCount =
        city->GetNextBuildingType(static_cast<short>(tableOffset < 0x15 ? buildingSlot : 0xb));
    if (actionCount <= 0) {
      continue;
    }
    int row = (actionCount - 1) + tableOffset;
    for (int action = 0; action < 3; ++action) {
      RECT bounds = g_aCityBuildingLayoutRects[row * 3 + action];
      if (bounds.right < 1) {
        buildingActionAnimations12C[buildingSlot][action] = 0;
        continue;
      }
      OffsetRect(&bounds, 0x32, 0x23);
      short resourceId = g_awCityBuildingActionResourceIds[row * 3 + action];
      int animationId = (actionCount - 1) * 3 + action + (buildingSlot + 0x5dc) * 10;
      TTransFocusAnimation* animation =
          new TTransFocusAnimation(this, &bounds, resourceId, static_cast<short>(animationId),
                                   (buildingSlot != 7 ? 2 : 0) + 5, 0);
      g_pUiAnimator->AddObjectToUiTransientRegistry(animation);
      buildingActionAnimations12C[buildingSlot][action] = animation;
      InvalidateCityDialogRectRegion(&bounds, 1);
      needsRefreshAtA6 = 1;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004ba740
void TCityProductionView::Free() {
  g_pUiAnimator->FreeUiTransientRegistryPayloads();
  for (int i = 0; i < 16; ++i) {
    buildingClipRegionsEC[i] = DisposeRgn(buildingClipRegionsEC[i]);
  }
  g_pAmbitApplication->cursorRegionInvalid = 0;
  TView::Free();
}

IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
// FUNCTION: IMPERIALISM 0x004ba7b0
void TCityProductionView::Draw(RECT* rectBuffer) {
  // Turn-event snapshot mode: blit the cached surface straight through and finish.
  if (g_pDisplayMgr->clipSnapshotEvent == 0x7db && this->needsRefreshAtA6 == 0) {
    RECT snapshot = *rectBuffer;
    BlitRectWithOptionalTransparency(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &snapshot,
                                     &snapshot, 0, 0);
    RenderNationHeaderDateLabelWithPeriodicRefresh();
    return;
  }
  this->needsRefreshAtA6 = 0;
  TPicture::Draw(rectBuffer);
#ifdef IMPERIALISM_RUNTIME_TESTS
  RuntimeTestDriver::Pulse();
#endif

  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  GetGWorld(&savedContext, &savedFlags);

  // Build an offscreen GWorld sized to the city backdrop bitmap (7000).
  TBitmapResourceLoader** backdropHandle = CreateBitmapResourceLoaderHandle(7000);
  RECT scratchBounds;
  CopyRect(&scratchBounds, &(*backdropHandle)->bitmapRect);
  TQuickDrawSurfaceContext* scratchContext = 0;
  g_pDisplayMgr->MakeNewGWorld(scratchContext, 8, scratchBounds);
  TBitmapResourceLoader* backdrop = *backdropHandle;
  backdrop->ReleaseBitmapResource();
  backdrop->flags &= 0xfe;
  delete backdrop;
  delete backdropHandle;

  SetGWorld(scratchContext, savedFlags);
  LockPixels(GetGWorldPixMap(scratchContext));

  for (int orderIndex = 0; orderIndex < 16; ++orderIndex) {
    SetGWorld(scratchContext, savedFlags);
    short slot = g_anCityBuildingSlotOrder[orderIndex];
    TGreatPower* nation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    TCity* city = (nation != 0) ? nation->city : 0;
    short level = city->GetNextBuildingType(slot);

    bool shouldDraw = level >= 1;
    if (!shouldDraw) {
      if (slot < 0 || slot > 6) {
        if (slot == 0xb && city->powerPlantUpgradeQueuedFlag04 != 0) {
          shouldDraw = true;
        }
      } else if (city->trailingOrderSlots1b0[slot + 2]->quantity > 0) {
        shouldDraw = true;
      }
    }
    if (!shouldDraw) {
      continue;
    }

    short pictureId;
    if (slot == 0xb) {
      pictureId = static_cast<short>((city->powerPlantUpgradeQueuedFlag04 != 0 ? 0x1b63 : 0x1b73));
    } else if (level == 0 || slot < 0 || slot > 5 ||
               city->trailingOrderSlots1b0[slot + 2]->quantity < 1 ||
               city->IsCapacityCenter(slot) == 0) {
      pictureId = static_cast<short>(slot + level * 0x10 + 0x1b58);
    } else {
      pictureId = static_cast<short>(slot + level * 0x10 + 0x1c84);
    }

    short drawX = g_anCityBuildingSlotCoords[g_nCityBuildingDrawXOffsetIndex + slot * 2];
    short drawY = g_anCityBuildingSlotCoords[g_nCityBuildingDrawYOffsetIndex + slot * 2];
    BlitBitmapResourceRectWithScreenOffsetAndPalette(&scratchBounds, scratchContext, drawX, drawY,
                                                     pictureId, savedContext, savedFlags);
#ifdef IMPERIALISM_RUNTIME_TESTS
    // A full city rebuild performs many independent resource blits. Report only
    // between completed blits; one blocked GDI/resource operation still trips the
    // five-second stale-heartbeat watchdog.
    RuntimeTestDriver::Pulse();
#endif

    if (slot == 0xf && city->ownerNationAc->pendingActionStatus.byAction[10] > '2') {
      SetGWorld(scratchContext, savedFlags);
      BlitBitmapResourceRectWithScreenOffsetAndPalette(&scratchBounds, scratchContext, 0xa6, 0x3c,
                                                       0x1b9e, savedContext, savedFlags);
    } else if (slot == 0xe && city->ownerNationAc->pendingActionStatus.byAction[11] >= '3') {
      SetGWorld(scratchContext, savedFlags);
      BlitBitmapResourceRectWithScreenOffsetAndPalette(&scratchBounds, scratchContext, 0x6d, 0x143,
                                                       0x1b9f, savedContext, savedFlags);
    }
  }

  for (int group = 0; group < 8; ++group) {
    for (int phase = 0; phase < 3; ++phase) {
      TTransFocusAnimation* animation = buildingActionAnimations12C[group][phase];
      if (animation != 0) {
        animation->UpdateBackground();
      }
    }
  }

  SetGWorld(savedContext, savedFlags);
  UnlockPixels(GetGWorldPixMap(scratchContext));
  g_pDisplayMgr->RemoveGWorld(scratchContext);
  RenderNationHeaderDateLabelWithPeriodicRefresh();
}
IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE

IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
// FUNCTION: IMPERIALISM 0x004bac50
void TCityProductionView::BlitBitmapResourceRectWithScreenOffsetAndPalette(
    RECT* destRect, TQuickDrawSurfaceContext* destContext, short offsetY, short offsetX,
    short resourceId, TQuickDrawSurfaceContext* restoreContext, int restoreFlags) {
  TBitmapResourceLoader** loaderHandle =
      CreateBitmapResourceLoaderHandle(static_cast<unsigned short>(resourceId));
  TBitmapResourceLoader* loader = *loaderHandle;
  if (loader != nullptr) {
    loader->EnsureBitmapResourceLoadedAndCopyRectSize();
    loader->flags |= 1;
    ResetQuickDrawStrokeState();
    BlitBitmapResourceLoaderToActiveDc(loaderHandle, destRect);
  }
  loader = *loaderHandle;
  loader->ReleaseBitmapResource();
  loader->flags &= 0xfe;
  delete loader;
  delete loaderHandle;

  RECT dest;
  dest.left = destRect->left;
  dest.top = destRect->top;
  dest.right = destRect->right;
  dest.bottom = destRect->bottom;
  OffsetRect(&dest, offsetX, offsetY);
  SetGWorld(restoreContext, restoreFlags);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  if (g_pPrimaryRenderSurfaceContext->blitSurface.surfaceDib != nullptr) {
    int surfaceHeight =
        g_pPrimaryRenderSurfaceContext->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (surfaceHeight < 1) {
      surfaceHeight = -surfaceHeight;
    }
    OffsetRect(&dest, 0, (surfaceHeight - dest.top) - dest.bottom);
  }
  BlitRectWithOptionalTransparency(destContext->GetBlitSurface(),
                                   g_pPrimaryRenderSurfaceContext->GetBlitSurface(), destRect,
                                   &dest, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}
IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE

// FUNCTION: IMPERIALISM 0x004badd0
void TCityProductionView::RenderNationHeaderDateLabelWithPeriodicRefresh() {
  TGreatPower* nationState = g_apNationStates[g_pSimMgr->GetActiveNationId()];
  TCity* subObject = 0;
  if (nationState != 0) {
    subObject = nationState->city; // +0x894
  }
  short nextBuildingType = subObject->GetNextBuildingType(0xe);

  int mask1 = -static_cast<int>(nextBuildingType == 2);
  int mask2 = -static_cast<int>(nextBuildingType == 2);
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
  g_pViewMgr->ApplyLegendSplitSlot34(1);
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
  CTemporaryRegion scopedRegion;
  CPoint hitPoint = *point;
  CString firstQuantityText;
  CString secondQuantityText;

  // Outside the city-backdrop hit area: fall back to the base child hit-test.
  if (point->y < 0x24 || point->y > 0x1e2 || point->x < 0x33 || point->x > 0x24d) {
    TView::HandleCursorHoverSelectionByChildHitTestAndFallback(point, hitArg);
    return;
  }

  // Hit-test the building clip regions in reverse draw order (topmost first).
  bool handled = false;
  for (int slotIndex = 15; slotIndex >= 0; --slotIndex) {
    if (handled) {
      break;
    }
    short slot = g_anCityBuildingSlotOrder[slotIndex];
    if (PtInRgn(&hitPoint, buildingClipRegionsEC[slot]) == 0) {
      continue;
    }

    CString hoverText;
    CString qualifierText;
    CString assembledText;
    CString templateText;

    TGreatPower* nation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    TCity* city = (nation != 0) ? nation->city : 0;
    short nextBuildingType = city->GetNextBuildingType(slot);
    bool available = city->IsCapacityCenter(slot) != 0;

    bool restrictedSlot = slot == 6 || slot == 0xb;
    bool technologyAvailable = true;
    if (restrictedSlot) {
      short activeNation = g_pSimMgr->GetActiveNationId();
      if (g_pTechMgr->orderCapRows277[activeNation].techStatusByTechId[0x13] != 2) {
        technologyAvailable = false;
        available = false;
      }
    }

    if (technologyAvailable) {
      g_pSimMgr->GetString(0x2719, slot, &hoverText);
      if (available) {
        if (slot == 0xb) {
          if (nextBuildingType == 0) {
            g_pSimMgr->GetString(0x2734, city->powerPlantUpgradeQueuedFlag04 != 0 ? 0x19 : 0x1a,
                                 &templateText);
            scanBracketExpressions(g_pSimMgr, &assembledText, static_cast<LPCSTR>(templateText),
                                   static_cast<LPCSTR>(hoverText));
          } else {
            firstQuantityText.Format(g_szDecimalFormat, city->trailingOrderSlots1b0[1]->quantity);
            g_pSimMgr->GetString(0x2734, 0x18, &qualifierText);
            g_pSimMgr->GetString(0x2734, 0x1d, &templateText);
            scanBracketExpressions(g_pSimMgr, &assembledText, static_cast<LPCSTR>(templateText),
                                   static_cast<LPCSTR>(hoverText),
                                   static_cast<LPCSTR>(firstQuantityText));
          }
        } else if (nextBuildingType == 0) {
          TProductionOrder* order = city->trailingOrderSlots1b0[slot + 2];
          g_pSimMgr->GetString(0x2734, order->quantity > 0 ? 0x19 : 0x1a, &templateText);
          scanBracketExpressions(g_pSimMgr, &assembledText, static_cast<LPCSTR>(templateText),
                                 static_cast<LPCSTR>(hoverText));
        } else {
          TProductionOrder* order = city->trailingOrderSlots1b0[slot + 2];
          short buildingType = static_cast<short>(city->GetBuildingType(slot));
          firstQuantityText.Format(g_szDecimalFormat,
                                   buildingType - city->productionAccum1fc[slot]);
          secondQuantityText.Format(g_szDecimalFormat, buildingType);
          g_pSimMgr->GetString(0x2734, 0x18, &qualifierText);
          g_pSimMgr->GetString(0x2734, order->quantity > 0 ? 0x1c : 0x1b, &templateText);
          scanBracketExpressions(g_pSimMgr, &assembledText, static_cast<LPCSTR>(templateText),
                                 static_cast<LPCSTR>(hoverText),
                                 static_cast<LPCSTR>(firstQuantityText),
                                 static_cast<LPCSTR>(secondQuantityText));
        }
        hoverText = assembledText;
      }
      g_pCursorControlPanel->SetTextAndLayoutRect(hoverText,
                                                  &g_aCityBuildingHoverSelectionRects[slot]);
    }

    if (restrictedSlot && technologyAvailable) {
      g_pCursorControlPanel->SetTextAndLayoutRect(CString(g_pCityBuildingHoverEmptyText_0064faa8),
                                                  &g_aCityBuildingHoverSelectionRects[slot]);
    }

    if (available) {
      if (selectedBuildingSlotA4 != slot && selectedBuildingSlotA4 != -1) {
        InvalidateOffsetRegionUsingChildClipRect(buildingClipRegionsEC[selectedBuildingSlotA4]);
      }
      if (city->GetNextBuildingType(slot) == 0) {
        ScopedMapQuickDrawContext drawContext(this);
        SetGlobalQuickDrawOrigin(static_cast<short>(absoluteX), static_cast<short>(absoluteY));
        GetClip(scopedRegion.tempRgn);
        SetClip(buildingClipRegionsEC[slot]);
        SetQuickDrawFillColor(0);
        QDFrameRgn(buildingClipRegionsEC[slot]);
        SetClip(scopedRegion.tempRgn);
      }
      selectedBuildingSlotA4 = slot;
    }
    handled = true;
  }

  if (!handled) {
    g_pCursorControlPanel->SetTextAndLayoutRect(CString(g_pCityBuildingHoverEmptyText_0064faa8),
                                                &g_cityBuildingHoverFallbackRect_006a2980);
    if (selectedBuildingSlotA4 != -1) {
      InvalidateOffsetRegionUsingChildClipRect(buildingClipRegionsEC[selectedBuildingSlotA4]);
      selectedBuildingSlotA4 = -1;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004bb7a0
void TCityProductionView::InitializeCityProductionDialog(TCity* city, TView* dialogRoot) {
  CString template1;
  CString value1;
  CString value2;
  CString value3;
  CString assembled;

  TGreatPower* nation = g_apNationStates[g_pSimMgr->GetActiveNationId()];

  this->city94 = city;
  this->dialogRoot98 = dialogRoot;
  UpdateToolbar();

  // Restore any building windows that were open when this city view was last active.
  for (short slot = 0; slot < 16; ++slot) {
    short current;
    short accum;
    if (city->GetBuildingWindowState(slot, &current, &accum)) {
      buildingViewsAC[slot] =
          g_pMacViewMgr->RestoreBuildingWindowAtSavedPosition(slot, city, 0, 0, 0, current, accum);
    }
  }

  short* summary = city->GetCitySummaryRecordSlot74();

  // Value blocks: bracket-expand a template with a summary count and the owner's need targets.
  static const struct {
    unsigned int tag;
    short assertLine;
    short summaryIndex;
    short needIndexA;
    short needIndexB;
    short templateIndex;
    short preludeIndex;
  } kValueBlocks[] = {
      {IMPERIALISM_FOURCC('m', 'e', 'a', 't'), 0x440, 0x14, 0x14, 0x13, 0x1e, 0x12},
      {IMPERIALISM_FOURCC('p', 'r', 'o', 'd'), 0x44e, 0x12, 0x12, -1, 0x1f, 0x12},
      {IMPERIALISM_FOURCC('g', 'r', 'a', 'i'), 0x459, 0x11, 0x11, -1, 0x1f, 0x11},
  };
  for (int i = 0; i < 3; ++i) {
    TStaticText* control =
        static_cast<TStaticText*>(dialogRoot->ResolveControlByTag(kValueBlocks[i].tag));
    if (control == nullptr) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8,
                                                   kValueBlocks[i].assertLine);
    }
    value1.Format(g_szDecimalFormat, summary[kValueBlocks[i].summaryIndex]);
    int needTotal = nation->GetNeedTargetByType(kValueBlocks[i].needIndexA);
    if (kValueBlocks[i].needIndexB != -1) {
      needTotal += nation->GetNeedTargetByType(kValueBlocks[i].needIndexB);
    }
    value2.Format(g_szDecimalFormat, needTotal);
    g_pSimMgr->GetStringPrelude(kValueBlocks[i].preludeIndex, &value3);
    g_pSimMgr->GetString(0x2734, kValueBlocks[i].templateIndex, &template1);
    scanBracketExpressions(g_pSimMgr, &assembled, static_cast<LPCSTR>(template1),
                           static_cast<LPCSTR>(value1), static_cast<LPCSTR>(value2),
                           static_cast<LPCSTR>(value3));
    SetControlHoverHelpText(assembled, control);
  }

  // Flag blocks: pick one of two localized strings by the control's actionable state.
  static const struct {
    unsigned int tag;
    short assertLine;
    short trueIndex;
    short falseIndex;
  } kFlagBlocks[] = {
      {IMPERIALISM_FOURCC('u', 'n', 't', 'r'), 0x465, 0xd, 0xe},
      {IMPERIALISM_FOURCC('t', 'r', 'a', 'i'), 0x46d, 0xf, 0x10},
      {IMPERIALISM_FOURCC('p', 'r', 'o', 'f'), 0x475, 0x11, 0x12},
      {IMPERIALISM_FOURCC('p', 'o', 'w', 'e'), 0x47d, 0x13, 0x14},
      {IMPERIALISM_FOURCC('s', 'i', 'c', 'k'), 0x489, 0x1, 0x2},
      {IMPERIALISM_FOURCC('d', 'e', 'a', 'd'), 0x492, 0x15, 0x16},
      {IMPERIALISM_FOURCC('l', 'a', 'b', 'P'), 0x49e, 0x17, 0x18},
  };
  for (int j = 0; j < 7; ++j) {
    TView* control = dialogRoot->ResolveControlByTag(kFlagBlocks[j].tag);
    if (control == nullptr) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8,
                                                   kFlagBlocks[j].assertLine);
    }
    short index = control->IsActionable() ? kFlagBlocks[j].trueIndex : kFlagBlocks[j].falseIndex;
    g_pSimMgr->GetString(0x2734, index, &template1);
    SetControlHoverHelpText(template1, control);
  }
}

// FUNCTION: IMPERIALISM 0x004bc0b0
void TCityProductionView::UpdateUnits() {
  g_pViewMgr->RefreshMainViewNationIndicatorForCurrentTurnEvent();
  TPopulationMgr* population = city94->productionSummary1d8;

  TPlacard* placard = static_cast<TPlacard*>(ResolveControlByTag(kControlTagUntr)); // 'rtnu'
  if (placard == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x4b9);
  }
  placard->SetValue(population->baselineSlots10->lowSkillCount04, true);

  placard = static_cast<TPlacard*>(ResolveControlByTag(kSummaryTagTrai)); // 'iart'
  if (placard == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x4bc);
  }
  placard->SetValue(population->baselineSlots10->mediumSkillCount06, true);

  placard = static_cast<TPlacard*>(ResolveControlByTag(kSummaryTagProf)); // 'forp'
  if (placard == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x4bf);
  }
  placard->SetValue(population->baselineSlots10->highSkillCount08, true);

  placard = static_cast<TPlacard*>(ResolveControlByTag(kSummaryTagPowe)); // 'ewop'
  if (placard == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x4c2);
  }
  placard->SetValue(city94->powerAvailableB4, true);

  short* predictedNeeds = population->PredictedNeeds();
  const unsigned int tags[6] = {kControlTagGrai, kControlTagProd, kControlTagMeat,
                                kControlTagHard, kControlTagClot, kControlTagFurn};
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

  placard = static_cast<TPlacard*>(ResolveControlByTag(kControlTagLabP)); // 'Pbal'
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
                city94->trailingOrderSlots1b0[1]->quantity > 0;
    } else if (city94->trailingOrderSlots1b0[buildingSlot + 2]->quantity > 0) {
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
    g_pMacViewMgr->OpenConstructionWindow(static_cast<short>(commandId - 10000), city94, this);
    return;
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004bc660
#if defined(IMPERIALISM_RUNTIME_TESTS)
bool TCityProductionView::ActivateBuildingSlotForRuntimeTest(short buildingSlot) {
  if (buildingSlot < 0 || buildingSlot >= 16 || buildingClipRegionsEC[buildingSlot] == 0) {
    return false;
  }

  CPoint point;
  for (point.y = 0; point.y < 768; ++point.y) {
    for (point.x = 0; point.x < 1024; ++point.x) {
      if (PtInRgn(&point, buildingClipRegionsEC[buildingSlot]) != 0) {
        DoMouseCommand(point, 0, CPoint(0, 0));
        return true;
      }
    }
  }
  return false;
}

TBuildingView* TCityProductionView::BuildingViewForRuntimeTest(short buildingSlot) {
  if (buildingSlot < 0 || buildingSlot >= 16) {
    return 0;
  }
  return buildingViewsAC[buildingSlot];
}

TTransFocusAnimation*
TCityProductionView::BuildingActionAnimationForRuntimeTest(short buildingSlot) {
  short group = buildingSlot == 11 ? 7 : buildingSlot;
  if (group < 0 || group >= 8) {
    return 0;
  }
  for (short action = 0; action < 3; ++action) {
    if (buildingActionAnimations12C[group][action] != 0) {
      return buildingActionAnimations12C[group][action];
    }
  }
  return 0;
}
#endif

void TCityProductionView::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  (void)event;
  (void)origin;
  short buildingSlot = -1;
  CPoint localPoint(point);
  for (int priority = 15; priority >= 0; --priority) {
    short candidate = g_anCityBuildingSlotOrder[priority];
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
    buildingViewsAC[15] = g_pMacViewMgr->OpenBuildingWindow(15, city94, 0, 0, 0);
    UpdateToolbar();
    return;
  }

  if (buildingViewsAC[buildingSlot] == 0) {
    if (city94->GetBuildingType(buildingSlot) == 0 && city94->IsCapacityCenter(buildingSlot)) {
      bool available = true;
      if (buildingSlot == 6 || buildingSlot == 11) {
        short nationId = g_pSimMgr->GetActiveNationId();
        available = g_pTechMgr->orderCapRows277[nationId].techStatusByTechId[19] == 2;
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
        g_pMacViewMgr->OpenBuildingWindow(buildingSlot, city94, 0, 0, 0);
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
    short buildingSlot = g_anCityBuildingSlotOrder[priority];
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
      static_cast<TStaticText*>(ResolveControlByTag(kControlTagUshi)); // shipyard summary
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
    total = static_cast<short>(total + order->quantity);
  }
  numberText.Format(g_szDecimalFormat, total);
  summaryText = g_szCityProductionArmoryPrefix + numberText;
  summary = static_cast<TStaticText*>(ResolveControlByTag(kControlTagUarm)); // armory summary
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
    total = static_cast<short>(total + order->quantity);
  }
  numberText.Format(g_szDecimalFormat, total);
  summaryText = g_szCityProductionUniversityPrefix + numberText;
  summary = static_cast<TStaticText*>(ResolveControlByTag(kControlTagUuni)); // university summary
  if (summary == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityDialogs_006962E8, 0x606);
  }
  summary->SetTextAndMaybeRefresh(&summaryText, 1);
  UpdateToolbar();
}
