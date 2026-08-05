#include "game/military_ui/TBattleReportView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

#include <new>
#include <string.h>

#include "game/gfx/CDib.h"
#include "game/GameAssert.h"
#include "game/app/TAnimator.h"
#include "game/assets/TAssetMgr.h"
#include "game/military/TArmyMgr.h"
#include "game/military_ui/TBattleUnitsView.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TWindow.h"
#include "game/TEvent.h"
#include "game/ui_screens/TBook.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/military_ui/TIdleMeAnimation.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/map/TMapMgr.h"
#include "game/map/TZone.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/military/mapped_flavor_text.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/military_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x00430a30
// TBattleReportView::`scalar deleting destructor'
// SYNTHETIC: IMPERIALISM 0x00430a60
// TBattleReportView::~TBattleReportView
TBattleReportView::~TBattleReportView() {}
// SYNTHETIC: IMPERIALISM 0x004acaa0
// TBattleReportView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004acb40
// TBattleReportView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBattleReportView, TDiplomacyMapView)

// Battle-report layout pass: restyles the report controls, places one marker per
// map-context action record on a 60x108 crowding grid (hex spiral search around each
// record's map cell), registers the report's idle animation, loads the label strings,
// and schedules the report audio cue.
// FUNCTION: IMPERIALISM 0x004acb60
void TBattleReportView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  BuildDiplomacyNationOverlayGeometryAndHitMasks();

  // 14-byte style buffer: the 10-byte descriptor plus 4 explicitly zeroed tail bytes
  // (the original zeroes them once before the first Build call).
  struct {
    TextStyle desc;
    unsigned char tail[4];
  } style;
  style.tail[0] = 0;
  style.tail[1] = 0;
  style.tail[2] = 0;
  style.tail[3] = 0;
  BuildUiTextStyleDescriptor(&style.desc, 0, 0xc, 0x2b67);

  char crowdGrid[0x654 * 4];
  memset(crowdGrid, 0, sizeof(crowdGrid));

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xe, 0x2b67);
  TControl* control = static_cast<TControl*>(ResolveControlByTag(kControlTagResu)); // 'user'
  control->AssertValid();
  control->InstallTextStyle(style.desc, 0);

  BuildUiTextStyleDescriptor(&style.desc, 2, 0xe, 0x2b67);
  control = static_cast<TControl*>(ResolveControlByTag(kControlTagLoca)); // 'acol'
  control->AssertValid();
  control->InstallTextStyle(style.desc, 0);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xc, 0x2b67);
  control = static_cast<TControl*>(ResolveControlByTag(kControlTagFadm)); // 'mdaf'
  control->AssertValid();
  control->InstallTextStyle(style.desc, 0);
  control = static_cast<TControl*>(ResolveControlByTag(kControlTagEadm)); // 'mdae'
  control->AssertValid();
  control->InstallTextStyle(style.desc, 0);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b67);
  control = static_cast<TControl*>(ResolveControlByTag(kControlTagFshp)); // 'phsf'
  control->AssertValid();
  control->InstallTextStyle(style.desc, 0);
  control = static_cast<TControl*>(ResolveControlByTag(kControlTagEshp)); // 'phse'
  control->AssertValid();
  control->InstallTextStyle(style.desc, 0);

  int selectedOrdinal = -1;
  int remaining = g_pMapContextActionManager->mapContextActionRecordList04->GetSize();
  for (; remaining > 0; remaining--) {
    MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
        g_pMapContextActionManager->mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(
            remaining));
    record->listOrdinal264 = static_cast<short>(remaining);
    record->placedFlag260 = 1;
    selectedOrdinal = remaining;

    short cell;
    if (record->actionType04 == 0 || record->actionType04 == 3 || record->actionType04 == 4) {
      cell = g_pGlobalMapState->cityScoreTable[reinterpret_cast<int>(record->location08)]
                 .cityTileIndex04;
    } else {
      cell = static_cast<short>(static_cast<TZone*>(record->location08)->tileOrTerrainId0c);
    }

    // Spiral outward from the record's cell until a free crowding-grid cell is found.
    int row = cell / 0x6c;
    int col = cell % 0x6c;
    int ringLeg = 1;
    int legStep = 0;
    int radius = 0;
    int foundCell = cell;
    TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, 4);
    TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, ringLeg);
    while (radius < 10) {
      int probe;
      if (row >= 0 && row < 0x3c && col >= 0 && col < 0x6c) {
        probe = col + row * 0x6c;
      } else {
        probe = -1;
      }
      if (probe != -1 && crowdGrid[probe] == 0) {
        if (row >= 0 && row < 0x3c && col >= 0 && col < 0x6c) {
          foundCell = col + row * 0x6c;
        } else {
          foundCell = -1;
        }
        break;
      }
      legStep++;
      if (legStep >= radius) {
        legStep = 0;
        ringLeg++;
        if (ringLeg >= 6) {
          ringLeg = 0;
          radius++;
          TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, 4);
        }
      }
      TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, ringLeg);
    }

    // Mark a radius-3 neighborhood around the found cell as crowded.
    row = foundCell / 0x6c;
    col = foundCell % 0x6c;
    int ring = 0;
    int markLeg = 1;
    int markStep = 0;
    int markLegLen = foundCell % 0x6c;
    TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, 4);
    TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, markLeg);
    while (ring < 3) {
      int probe;
      if (row >= 0 && row < 0x3c && col >= 0 && col < 0x6c) {
        probe = col + row * 0x6c;
      } else {
        probe = -1;
      }
      if (probe != -1) {
        crowdGrid[probe]++;
      }
      markStep++;
      if (markStep >= markLegLen) {
        markStep = 0;
        markLeg++;
        if (markLeg >= 6) {
          markLeg = 0;
          markLegLen++;
          ring++;
          TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, 4);
        }
      }
      TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, markLeg);
    }
    crowdGrid[foundCell]++;

    short markerColX2;
    unsigned short markerRow;
    SplitTileIndexToHexRasterColumnX2AndRow(foundCell, &markerColX2, &markerRow);
    record->markerPixelX258 = mapViewportRect514.left + (markerColX2 * 5) / 2 - 9;
    record->markerPixelY25c = mapViewportRect514.top + markerRow * 5 - 9;

    short spriteBase;
    if (record->nationIds[record->reportParticipantIndex02] == g_pSimMgr->GetActiveNationId()) {
      spriteBase = 0;
    } else if (record->nationIds[1 - record->reportParticipantIndex02] ==
               g_pSimMgr->GetActiveNationId()) {
      spriteBase = 4;
    } else {
      spriteBase = 8;
    }
    record->markerSpriteCode262 = spriteBase;
    if (record->actionType04 == 2) {
      record->markerSpriteCode262 = spriteBase + 2;
    }
  }

  if (selectedOrdinal == -1) {
    g_pSimMgr->StartNextPhase();
    selectedOrdinal = 1;
  }
  selectedReportIndex24c8 = selectedOrdinal - 1;
  RefreshMapContextSelectionPanelAndInfoLabels(static_cast<MapContextActionRecord*>(
      g_pMapContextActionManager->mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(
          selectedOrdinal)));
  SetIdleFreq(2);

  TIdleMeAnimation* animation = new TIdleMeAnimation();
  transientRegistryObject24cc = animation;
  RECT animationRect;
  animationRect.left = 0;
  animationRect.top = 0;
  animationRect.right = 0;
  animationRect.bottom = 0;
  int registryTag = g_nIdleMeAnimationNextRegistryTag;
  g_nIdleMeAnimationNextRegistryTag++;
  animation->IAnimation(this, &animationRect, 0, 0, 0, registryTag);
  g_pUiAnimator->AddObjectToUiTransientRegistry(animation);

  TInfoBarText* cursorPanel =
      static_cast<TInfoBarText*>(ResolveControlByTag(kControlTagCurs)); // 'surc'
  g_pCursorControlPanel = cursorPanel;
  cursorPanel->AssertValid();
  g_pCursorControlPanel->SetTextStyle(0, 0xe, 0x2b6b);
  g_pCursorControlPanel->SetTextAlignmentAndMaybeRefresh(1, 1);
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b67, 0x2b6c);

  SetControlHoverHelpText(g_pBattleReportSharedText_0064dc30,
                          ResolveControlByTag(kControlTagMain)); // 'main'
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x16, ResolveControlByTag(kControlTagFadm));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x16, ResolveControlByTag(kControlTagFshp));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x16, ResolveControlByTag(kControlTagFflg));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x17, ResolveControlByTag(kControlTagEadm));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x17, ResolveControlByTag(kControlTagEshp));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x17, ResolveControlByTag(kControlTagEflg));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x18, ResolveControlByTag(kControlTagLoca));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x19, ResolveControlByTag(kControlTagResu));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x1a, ResolveControlByTag(kControlTagPrev));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x1b, ResolveControlByTag(kControlTagNext));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x1c, ResolveControlByTag(kControlTagInfo));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x1d, ResolveControlByTag(kControlTagOkay));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x1e, ResolveControlByTag(kControlTagQuer));

  g_pSfxPlaybackSystem->ResetDualAudioCuePools();
  g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(5);
  g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();
}

// FUNCTION: IMPERIALISM 0x004ad560
void TBattleReportView::Free() {
  if (transientRegistryObject24cc != 0) {
    g_pUiAnimator->RemoveUiTransientRegistryObjectByTag(transientRegistryObject24cc->registryTag);
  }
  TDiplomacyMapView::Free();
}

// Blinks the selected battle marker on the strategic map: every 15th action-1 idle tick it
// blits one of the two marker sprite columns over the record's map pixel position and flips
// the phase, so the marker alternates while the report is open. The destination rect is
// mirrored into the DIB's bottom-up coordinate space before the blit.
// FUNCTION: IMPERIALISM 0x004ad5a0
char TBattleReportView::DoIdle(int action) {
  if (action == 1) {
    ++g_nBattleReportMarkerBlinkTicks;
    if (g_nBattleReportMarkerBlinkTicks >= 15) {
      ScopedMapQuickDrawContextGuard quickDraw(this);
      PrepareForDrawing();

      MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
          g_pMapContextActionManager->mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(
              selectedReportIndex24c8));

      RECT markerRect;
      markerRect.left = record->markerPixelX258;
      markerRect.top = record->markerPixelY25c;
      markerRect.right = record->markerPixelX258 + 0x12;
      markerRect.bottom = record->markerPixelY25c + 0x12;

      CDib* surfaceDib = g_pActiveQuickDrawSurfaceContext->blitSurface.surfaceDib;
      if (surfaceDib != 0) {
        int surfaceHeight = surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
        if (surfaceHeight <= 0) {
          surfaceHeight = -surfaceHeight;
        }
        OffsetRect(&markerRect, 0, surfaceHeight - markerRect.top - markerRect.bottom);
      }

      RECT spriteRect;
      spriteRect.left =
          (record->markerSpriteCode262 + (g_bBattleReportMarkerBlinkPhase == 0)) * 0x12;
      spriteRect.top = 0;
      spriteRect.right = spriteRect.left + 0x12;
      spriteRect.bottom = 0x12;

      UpdatePaletteIndexWithDefaultFallback(0x10);
      BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas694[3]->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &spriteRect, &markerRect, 0x24, 0);
      UpdatePaletteIndexWithDefaultFallback(0x13);

      g_nBattleReportMarkerBlinkTicks = 0;
      g_bBattleReportMarkerBlinkPhase = g_bBattleReportMarkerBlinkPhase == 0;
      PostRender();
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ad7a0
void TBattleReportView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    int tag = sourceHandler->controlTag;
    if (tag == IMPERIALISM_FOURCC('n', 'e', 'x', 't')) {
      int count = g_pMapContextActionManager->mapContextActionRecordList04->GetSize();
      if (selectedReportIndex24c8 < count) {
        RefreshMapContextSelectionPanelAndInfoLabels(static_cast<MapContextActionRecord*>(
            g_pMapContextActionManager->mapContextActionRecordList04
                ->GetPtrListEntryByOneBasedIndex(selectedReportIndex24c8 + 1)));
      }
      return;
    }
    if (tag == IMPERIALISM_FOURCC('i', 'n', 'f', 'o')) {
      TWindow* dialog =
          g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventDetailedBattleReport);
      if (dialog == 0) {
        GAME_FAIL_NIL_POINTER();
        TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UBattleReportViews.cpp",
                                                     0x1ef);
      }
      dialog->SetModality(1);

      TBook* book = static_cast<TBook*>(dialog->ResolveControlByTag(kControlTagDialog));
      book->AssertValid();
      BattleRecord* battleRecord = static_cast<BattleRecord*>(
          g_pMapContextActionManager->mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(
              selectedReportIndex24c8));
      // This command's open payload is a BattleRecord despite the shared DoEvent slot's
      // generic TEvent pointer type; retail reads the record fields directly from arg 3.
      BattleRecord* eventBattleRecord = reinterpret_cast<BattleRecord*>(event);

      TBattleUnitsView* leftPage =
          static_cast<TBattleUnitsView*>(book->ResolveControlByTag(kControlTagPage));
      leftPage->AssertValid();
      leftPage->StuffValues(*battleRecord, 0);
      TBattleUnitsView* rightPage =
          static_cast<TBattleUnitsView*>(book->ResolveControlByTag(kControlTagPagf));
      rightPage->AssertValid();
      rightPage->StuffValues(*eventBattleRecord, 1);
      if (leftPage->pageCount < rightPage->pageCount) {
        leftPage->pageCount = rightPage->pageCount;
      } else {
        rightPage->pageCount = leftPage->pageCount;
      }
      book->ShowPage(1);

      TPicture* leftFlag = static_cast<TPicture*>(book->ResolveControlByTag(kControlTagFlgL));
      leftFlag->AssertValid();
      TPicture* rightFlag = static_cast<TPicture*>(book->ResolveControlByTag(kControlTagFlgR));
      rightFlag->AssertValid();
      leftFlag->SetPictureResourceIdAndRefresh(
          static_cast<short>(0x1147 + static_cast<signed char>(eventBattleRecord->nationIds[0])),
          0);
      rightFlag->SetPictureResourceIdAndRefresh(
          static_cast<short>(0x114e + static_cast<signed char>(eventBattleRecord->nationIds[1])),
          0);

      TDropShadowText* leftNation =
          static_cast<TDropShadowText*>(book->ResolveControlByTag(kControlTagNatL));
      leftNation->AssertValid();
      TDropShadowText* rightNation =
          static_cast<TDropShadowText*>(book->ResolveControlByTag(kControlTagNatR));
      rightNation->AssertValid();
      ApplyUiTextStyleAndThemeFlags(leftNation, 0, 0xe, 0x2b6b, 0x2b6c);
      ApplyUiTextStyleAndThemeFlags(rightNation, 0, 0xe, 0x2b6b, 0x2b6c);
      leftNation->SetTextAlignmentAndMaybeRefresh(1, 0);
      rightNation->SetTextAlignmentAndMaybeRefresh(1, 0);
      {
        CString leftName(eventBattleRecord->nameBuffer0c[0].data);
        leftNation->SetTextAndMaybeRefresh(&leftName, 0);
      }
      {
        CString rightName(eventBattleRecord->nameBuffer0c[1].data);
        rightNation->SetTextAndMaybeRefresh(&rightName, 0);
      }

      SetControlHoverHelpText(CString(g_pBattleReportSharedText_0064dc30), dialog);
      LoadUiStringByGroupAndIndexToControlObject(0x2730, 0x22,
                                                 book->ResolveControlByTag(kControlTagOkay));
      CPoint placement;
      g_pViewMgr->ComputeTurnEventDialogPlacementByCode(dialog, &placement);
      dialog->Locate(placement, 0);
      TDialogBehavior* behavior = dialog->GetDialogBehavior();
      if (behavior != 0) {
        behavior->defaultCommandCode = kControlTagOkay;
      }
      dialog->PoseModally();
      dialog->Close();
      dialog->Free();
      return;
    }
    if (tag == IMPERIALISM_FOURCC('p', 'r', 'e', 'v')) {
      if (selectedReportIndex24c8 > 1) {
        RefreshMapContextSelectionPanelAndInfoLabels(static_cast<MapContextActionRecord*>(
            g_pMapContextActionManager->mapContextActionRecordList04
                ->GetPtrListEntryByOneBasedIndex(selectedReportIndex24c8 - 1)));
      }
      return;
    }
    if (tag == IMPERIALISM_FOURCC('o', 'k', 'a', 'y')) {
      g_pSimMgr->StartNextPhase();
      return;
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004adc80
void TBattleReportView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                            RgnHandle hitArg) {
  TView::HandleCursorHoverSelectionByChildHitTestAndFallback(point, hitArg);
}

// FUNCTION: IMPERIALISM 0x004adcb0
void TBattleReportView::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  (void)event;
  (void)origin;
  MapContextActionRecord* selectedRecord = 0;
  int remaining = g_pMapContextActionManager->mapContextActionRecordList04->GetSize();
  for (; remaining > 0; --remaining) {
    MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
        g_pMapContextActionManager->mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(
            remaining));
    if (record->placedFlag260 != 0 && point.x >= record->markerPixelX258 &&
        point.x < record->markerPixelX258 + 0x12 && point.y >= record->markerPixelY25c &&
        point.y < record->markerPixelY25c + 0x12) {
      selectedRecord = record;
    }
  }
  if (selectedRecord != 0) {
    RefreshMapContextSelectionPanelAndInfoLabels(selectedRecord);
  }
}

// FUNCTION: IMPERIALISM 0x004ade00
void TBattleReportView::Draw(RECT* rectBuffer) {
  TDiplomacyMapView::Draw(rectBuffer);
  RenderMapContextActionMarkers(rectBuffer);
}

// FUNCTION: IMPERIALISM 0x004ade30
void TBattleReportView::RenderMapContextActionMarkers(RECT* rectBuffer) {
  (void)rectBuffer; // ignored stack arg threaded through by the caller

  int count = g_pMapContextActionManager->mapContextActionRecordList04->GetSize();
  int boundary = (selectedReportIndex24c8 == 0) ? 1 : 0;
  int ordinal = count;
  if (ordinal >= boundary) {
    do {
      int index = (ordinal == 0) ? selectedReportIndex24c8 : ordinal;
      MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
          g_pMapContextActionManager->mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(
              index));

      if (selectedReportIndex24c8 != ordinal && record->placedFlag260 != 0) {
        RECT destRect;
        destRect.left = record->markerPixelX258;
        destRect.top = record->markerPixelY25c;
        destRect.right = destRect.left + 0x12;
        destRect.bottom = destRect.top + 0x12;

        CDib* activeDib = g_pActiveQuickDrawSurfaceContext->blitSurface.surfaceDib;
        if (activeDib != 0) {
          int surfaceHeight = activeDib->m_pInfoHeader->bmiHeader.biHeight;
          if (surfaceHeight < 1) {
            surfaceHeight = -surfaceHeight;
          }
          OffsetRect(&destRect, 0, (surfaceHeight - destRect.top) - destRect.bottom);
        }

        int spriteX = (record->markerSpriteCode262 + (ordinal == 0 ? 1 : 0)) * 0x12;
        RECT srcRect;
        srcRect.left = spriteX;
        srcRect.top = 0;
        srcRect.right = spriteX + 0x12;
        srcRect.bottom = 0x12;

        UpdatePaletteIndexWithDefaultFallback(0x10);
        BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas694[3]->GetBlitSurface(),
                                         g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                         &srcRect, &destRect, 0x24, 0);
        UpdatePaletteIndexWithDefaultFallback(0x13);
      }
      ordinal--;
    } while (ordinal >= boundary);
  }
}

// FUNCTION: IMPERIALISM 0x004adfc0
void TBattleReportView::RefreshMapContextSelectionPanelAndInfoLabels(
    MapContextActionRecord* record) {
  if (selectedReportIndex24c8 == static_cast<short>(record->listOrdinal264)) {
    return;
  }

  if (selectedReportIndex24c8 != 0) {
    MapContextActionRecord* oldRecord = static_cast<MapContextActionRecord*>(
        g_pMapContextActionManager->mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(
            selectedReportIndex24c8));
    RECT oldRect;
    oldRect.left = oldRecord->markerPixelX258;
    oldRect.top = oldRecord->markerPixelY25c;
    oldRect.right = oldRect.left + 18;
    oldRect.bottom = oldRect.top + 18;
    InvalidateCityDialogRectRegion(&oldRect, 1);
  }

  selectedReportIndex24c8 = static_cast<short>(record->listOrdinal264);
  if (selectedReportIndex24c8 != 0) {
    MapContextActionRecord* newRecord = static_cast<MapContextActionRecord*>(
        g_pMapContextActionManager->mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(
            selectedReportIndex24c8));
    RECT newRect;
    newRect.left = newRecord->markerPixelX258;
    newRect.top = newRecord->markerPixelY25c;
    newRect.right = newRect.left + 18;
    newRect.bottom = newRect.top + 18;
    InvalidateCityDialogRectRegion(&newRect, 1);
  }

  short participantIndex = static_cast<signed char>(record->displayedParticipantIndex03);
  short otherParticipantIndex = static_cast<short>(1 - participantIndex);
  int activeSideRelation;
  if (static_cast<signed char>(
          record->nationIds[static_cast<signed char>(record->reportParticipantIndex02)]) ==
      g_pSimMgr->GetActiveNationId()) {
    activeSideRelation = 1;
  } else if (static_cast<signed char>(
                 record
                     ->nationIds[1 - static_cast<signed char>(record->reportParticipantIndex02)]) ==
             g_pSimMgr->GetActiveNationId()) {
    activeSideRelation = -1;
  } else {
    activeSideRelation = 0;
  }
  char displayedParticipantIsActive =
      static_cast<signed char>(record->nationIds[participantIndex]) ==
      g_pSimMgr->GetActiveNationId();

  switch (record->actionType04) {
  case 0:
  case 3:
  case 4: {
    TStaticText* locaText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagLoca));
    locaText->AssertValid();
    CString strLocation;
    CString strTerrain;
    g_pGlobalMapState->AssignCityRecordDisplayName(reinterpret_cast<int>(record->location08),
                                                   &strLocation);
    int ownerNation = g_pGlobalMapState->cityScoreTable[reinterpret_cast<int>(record->location08)]
                          .ownerNationCode00;
    g_apTerrainTypeDescriptorTable[ownerNation]->FormatOverlayTerrainLabelText(&strTerrain);
    CString locationTemplate;
    g_pSimMgr->GetString(0x273d, 7, &locationTemplate);
    CString combinedStr;
    scanBracketExpressions(g_pSimMgr, &combinedStr, static_cast<LPCSTR>(locationTemplate),
                           static_cast<LPCSTR>(strLocation), static_cast<LPCSTR>(strTerrain));
    combinedStr += " ";
    locaText->SetTextAndMaybeRefresh(&combinedStr, 1);
    break;
  }
  case 1:
  case 2: {
    TStaticText* locaText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagLoca));
    locaText->AssertValid();
    CString nameStr;
    static_cast<TZone*>(record->location08)->AssignZoneDisplayNameToOutputRef(&nameStr);
    locaText->SetTextAndMaybeRefresh(&nameStr, 1);
    break;
  }
  default:
    break;
  }

  TPicture* friendlyFlag = static_cast<TPicture*>(ResolveControlByTag(kControlTagFflg));
  friendlyFlag->AssertValid();
  friendlyFlag->SetPictureResourceIdAndRefresh(
      static_cast<short>(0x1130 + static_cast<signed char>(record->nationIds[participantIndex])),
      1);

  TPicture* enemyFlag = static_cast<TPicture*>(ResolveControlByTag(kControlTagEflg));
  enemyFlag->AssertValid();
  enemyFlag->SetPictureResourceIdAndRefresh(
      static_cast<short>(0x1130 +
                         static_cast<signed char>(record->nationIds[otherParticipantIndex])),
      1);

  int userStringGroup;
  int userStringIndex;
  if (record->actionType04 == 2) {
    userStringGroup = 0x273c;
    userStringIndex = activeSideRelation + 5;
  } else if (record->actionType04 == 1) {
    userStringGroup = 0x273c;
    userStringIndex = activeSideRelation + 8;
  } else if (record->actionType04 == 3) {
    userStringGroup = 0x273d;
    userStringIndex = activeSideRelation + 40;
  } else if (record->actionType04 == 4) {
    userStringGroup = 0x273d;
    userStringIndex = activeSideRelation + 43;
  } else {
    userStringGroup = 0x273d;
    int activeHomeRegion =
        g_apTerrainTypeDescriptorTable[g_pSimMgr->GetActiveNationId()]->GetCapitolProvince();
    char activeNationOwnsBattleSite = activeHomeRegion == reinterpret_cast<int>(record->location08);
    char reportSidesAreSame =
        record->displayedParticipantIndex03 == record->reportParticipantIndex02;
    char reportParticipantIsActive =
        static_cast<signed char>(
            record->nationIds[static_cast<signed char>(record->reportParticipantIndex02)]) ==
        g_pSimMgr->GetActiveNationId();
    char activeNationIsOtherReportSide = activeSideRelation != 0 && !reportParticipantIsActive;
    int otherNation = static_cast<signed char>(record->nationIds[0]);
    if (otherNation == g_pSimMgr->GetActiveNationId()) {
      otherNation = static_cast<signed char>(record->nationIds[1]);
    }
    bool otherNationOwnsBattleSite =
        g_apTerrainTypeDescriptorTable[otherNation]->GetCapitolProvince() ==
        reinterpret_cast<int>(record->location08);

    if (activeNationOwnsBattleSite && displayedParticipantIsActive) {
      userStringIndex = 48;
    } else if (activeNationOwnsBattleSite && activeNationIsOtherReportSide) {
      userStringIndex = 49;
    } else if (reportParticipantIsActive && reportSidesAreSame && otherNationOwnsBattleSite) {
      userStringIndex = 48;
    } else if (reportParticipantIsActive && reportSidesAreSame) {
      userStringIndex = 4;
    } else if (reportParticipantIsActive) {
      userStringIndex = 7;
    } else if (activeNationIsOtherReportSide && reportSidesAreSame) {
      userStringIndex = 5;
    } else if (activeNationIsOtherReportSide) {
      userStringIndex = 2;
    } else if (reportSidesAreSame) {
      userStringIndex = 3;
    } else {
      userStringIndex = 6;
    }
  }
  --userStringIndex;

  CString userStr;
  g_pSimMgr->GetString(userStringGroup, static_cast<short>(userStringIndex), &userStr);
  TStaticText* userText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagResu));
  userText->AssertValid();
  userText->SetTextAndMaybeRefresh(&userStr, 1);

  {
    TStaticText* mdafText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagFadm));
    mdafText->AssertValid();
    CString mdafStr(record->nameBuffer0c[participantIndex].data);
    mdafText->SetTextAndMaybeRefresh(&mdafStr, 1);
  }

  {
    TStaticText* phsfText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagFshp));
    phsfText->AssertValid();
    CString phsfStr(record->overlayLabel4c[participantIndex].data);
    phsfText->SetTextAndMaybeRefresh(&phsfStr, 1);
  }

  {
    TStaticText* mdaeText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagEadm));
    mdaeText->AssertValid();
    CString mdaeStr(record->nameBuffer0c[otherParticipantIndex].data);
    mdaeText->SetTextAndMaybeRefresh(&mdaeStr, 1);
  }

  {
    TStaticText* phseText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagEshp));
    phseText->AssertValid();
    CString phseStr(record->overlayLabel4c[otherParticipantIndex].data);
    phseText->SetTextAndMaybeRefresh(&phseStr, 1);
  }

  char hasPrevious = selectedReportIndex24c8 > 1;
  int count = g_pMapContextActionManager->mapContextActionRecordList04->GetSize();
  char hasNext = selectedReportIndex24c8 < count;

  TControl* prevCtrl = static_cast<TControl*>(ResolveControlByTag(kControlTagPrev));
  prevCtrl->AssertValid();
  prevCtrl->ViewEnable(hasPrevious, 0);
  prevCtrl->Show(hasPrevious, 1);

  TControl* nextCtrl = static_cast<TControl*>(ResolveControlByTag(kControlTagNext));
  nextCtrl->AssertValid();
  nextCtrl->ViewEnable(hasNext, 0);
  nextCtrl->Show(hasNext, 1);

  bool enableInfo =
      (static_cast<signed char>(record->nationIds[0]) == g_pSimMgr->GetActiveNationId() ||
       static_cast<signed char>(record->nationIds[1]) == g_pSimMgr->GetActiveNationId());
  TControl* infoCtrl = static_cast<TControl*>(ResolveControlByTag(kControlTagInfo));
  infoCtrl->AssertValid();
  infoCtrl->ViewEnable(enableInfo, 0);
  infoCtrl->Show(enableInfo, 1);
}
