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
TBattleReportView::~TBattleReportView() {}

IMPLEMENT_DYNCREATE(TBattleReportView, TDiplomacyMapView)

// FUNCTION: IMPERIALISM 0x004acb60
void TBattleReportView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  BuildDiplomacyNationOverlayGeometryAndHitMasks();

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
  int remaining = g_pMapContextActionManager->mapContextActionRecordList->GetSize();
  for (; remaining > 0; remaining--) {
    MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
        g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
            remaining));
    record->listOrdinal = static_cast<short>(remaining);
    record->placedFlag = 1;
    selectedOrdinal = remaining;

    short cell;
    if (record->reportKind == kMapContextReportLandBattle ||
        record->reportKind == kMapContextReportPreemptedLandBattle ||
        record->reportKind == kMapContextReportUncontestedTakeover) {
      cell =
          g_pGlobalMapState->cityScoreTable[reinterpret_cast<int>(record->location)].cityTileIndex;
    } else {
      cell = static_cast<short>(static_cast<TZone*>(record->location)->tileOrTerrainId);
    }

    // Spiral outward from the record's cell until a free crowding-grid cell is found.
    int row = cell / kStrategicMapColumns;
    int col = cell % kStrategicMapColumns;
    int ringLeg = 1;
    int legStep = 0;
    int radius = 0;
    int foundCell = cell;
    TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, 4);
    TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, ringLeg);
    while (radius < 10) {
      int probe;
      if (row >= 0 && row < kStrategicMapRows && col >= 0 && col < kStrategicMapColumns) {
        probe = col + row * kStrategicMapColumns;
      } else {
        probe = -1;
      }
      if (probe != -1 && crowdGrid[probe] == 0) {
        if (row >= 0 && row < kStrategicMapRows && col >= 0 && col < kStrategicMapColumns) {
          foundCell = col + row * kStrategicMapColumns;
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
    row = foundCell / kStrategicMapColumns;
    col = foundCell % kStrategicMapColumns;
    int ring = 0;
    int markLeg = 1;
    int markStep = 0;
    int markLegLen = foundCell % kStrategicMapColumns;
    TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, 4);
    TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, markLeg);
    while (ring < 3) {
      int probe;
      if (row >= 0 && row < kStrategicMapRows && col >= 0 && col < kStrategicMapColumns) {
        probe = col + row * kStrategicMapColumns;
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
    record->markerPixelX = mapViewportRect.left + (markerColX2 * 5) / 2 - 9;
    record->markerPixelY = mapViewportRect.top + markerRow * 5 - 9;

    short spriteBase;
    if (record->nationIds[record->reportParticipantIndex] == g_pSimMgr->GetPlayerCountry()) {
      spriteBase = 0;
    } else if (record->nationIds[1 - record->reportParticipantIndex] ==
               g_pSimMgr->GetPlayerCountry()) {
      spriteBase = 4;
    } else {
      spriteBase = 8;
    }
    record->markerSpriteCode = spriteBase;
    if (record->reportKind == kMapContextReportMerchantInterception) {
      record->markerSpriteCode = spriteBase + 2;
    }
  }

  if (selectedOrdinal == -1) {
    g_pSimMgr->StartNextPhase();
    selectedOrdinal = 1;
  }
  selectedReportIndex = selectedOrdinal - 1;
  RefreshMapContextSelectionPanelAndInfoLabels(static_cast<MapContextActionRecord*>(
      g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
          selectedOrdinal)));
  SetIdleFreq(2);

  TIdleMeAnimation* animation = new TIdleMeAnimation();
  transientRegistryObject = animation;
  RECT animationRect;
  animationRect.left = 0;
  animationRect.top = 0;
  animationRect.right = 0;
  animationRect.bottom = 0;
  int registryTag = g_nIdleMeAnimationNextRegistryTag;
  g_nIdleMeAnimationNextRegistryTag++;
  animation->IAnimation(this, &animationRect, 0, 0, 0, registryTag);
  g_pUiAnimator->AddAnimation(animation);

  TInfoBarText* cursorPanel =
      static_cast<TInfoBarText*>(ResolveControlByTag(kControlTagCurs)); // 'surc'
  g_pCursorControlPanel = cursorPanel;
  cursorPanel->AssertValid();
  g_pCursorControlPanel->SetTextStyle(0, 0xe, 0x2b6b);
  g_pCursorControlPanel->SetJustification(1, true);
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b67, 0x2b6c);

  SetControlHoverHelpText(g_pBattleReportSharedText,
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
  g_pSfxPlaybackSystem->AddToPlayList(5);
  g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();
}

// FUNCTION: IMPERIALISM 0x004ad560
void TBattleReportView::Free() {
  if (transientRegistryObject != 0) {
    g_pUiAnimator->RemoveUiTransientRegistryObjectByTag(transientRegistryObject->registryTag);
  }
  TDiplomacyMapView::Free();
}

// FUNCTION: IMPERIALISM 0x004ad5a0
bool TBattleReportView::DoIdle(int action) {
  if (action == 1) {
    ++g_nBattleReportMarkerBlinkTicks;
    if (g_nBattleReportMarkerBlinkTicks >= 15) {
      ScopedMapQuickDrawContext quickDraw(this);
      PrepareForDrawing();

      MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
          g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
              selectedReportIndex));

      RECT markerRect;
      markerRect.left = record->markerPixelX;
      markerRect.top = record->markerPixelY;
      markerRect.right = record->markerPixelX + 0x12;
      markerRect.bottom = record->markerPixelY + 0x12;

      CDib* surfaceDib = g_pActiveQuickDrawSurfaceContext->blitSurface.surfaceDib;
      if (surfaceDib != 0) {
        int surfaceHeight = surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
        if (surfaceHeight <= 0) {
          surfaceHeight = -surfaceHeight;
        }
        OffsetRect(&markerRect, 0, surfaceHeight - markerRect.top - markerRect.bottom);
      }

      RECT spriteRect;
      spriteRect.left = (record->markerSpriteCode + (!g_bBattleReportMarkerBlinkPhase)) * 0x12;
      spriteRect.top = 0;
      spriteRect.right = spriteRect.left + 0x12;
      spriteRect.bottom = 0x12;

      UpdatePaletteIndexWithDefaultFallback(0x10);
      BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas694[3]->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &spriteRect, &markerRect, 0x24, 0);
      UpdatePaletteIndexWithDefaultFallback(0x13);

      g_nBattleReportMarkerBlinkTicks = 0;
      g_bBattleReportMarkerBlinkPhase = !g_bBattleReportMarkerBlinkPhase;
      PostRender();
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004ad7a0
void TBattleReportView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    int tag = sourceHandler->controlTag;
    if (tag == IMPERIALISM_FOURCC('n', 'e', 'x', 't')) {
      int count = g_pMapContextActionManager->mapContextActionRecordList->GetSize();
      if (selectedReportIndex < count) {
        RefreshMapContextSelectionPanelAndInfoLabels(static_cast<MapContextActionRecord*>(
            g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
                selectedReportIndex + 1)));
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
      dialog->SetModality(true);

      TBook* book = static_cast<TBook*>(dialog->ResolveControlByTag(kControlTagDialog));
      book->AssertValid();
      BattleRecord* battleRecord = static_cast<BattleRecord*>(
          g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
              selectedReportIndex));
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
      leftFlag->SetPictureRsrcID(
          static_cast<short>(0x1147 + static_cast<signed char>(eventBattleRecord->nationIds[0])),
          0);
      rightFlag->SetPictureRsrcID(
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
      leftNation->SetJustification(1, false);
      rightNation->SetJustification(1, false);
      {
        CString leftName(eventBattleRecord->nameBuffer[0].data);
        leftNation->SetTextAndMaybeRefresh(&leftName, false);
      }
      {
        CString rightName(eventBattleRecord->nameBuffer[1].data);
        rightNation->SetTextAndMaybeRefresh(&rightName, false);
      }

      SetControlHoverHelpText(CString(g_pBattleReportSharedText), dialog);
      LoadUiStringByGroupAndIndexToControlObject(0x2730, 0x22,
                                                 book->ResolveControlByTag(kControlTagOkay));
      CPoint placement;
      g_pViewMgr->GetTopLeftFor(dialog, &placement);
      dialog->Locate(placement, false);
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
      if (selectedReportIndex > 1) {
        RefreshMapContextSelectionPanelAndInfoLabels(static_cast<MapContextActionRecord*>(
            g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
                selectedReportIndex - 1)));
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
  int remaining = g_pMapContextActionManager->mapContextActionRecordList->GetSize();
  for (; remaining > 0; --remaining) {
    MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
        g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
            remaining));
    if (record->placedFlag != 0 && point.x >= record->markerPixelX &&
        point.x < record->markerPixelX + 0x12 && point.y >= record->markerPixelY &&
        point.y < record->markerPixelY + 0x12) {
      selectedRecord = record;
    }
  }
  if (selectedRecord != 0) {
    RefreshMapContextSelectionPanelAndInfoLabels(selectedRecord);
  }
}

// FUNCTION: IMPERIALISM 0x004add50
bool TBattleReportView::ShouldDisplay(MapContextActionRecord*) const {
  return true;
}

// FUNCTION: IMPERIALISM 0x004add70
MapContextActionRecord* TBattleReportView::GetBattleAt(const CPoint& point) const {
  MapContextActionRecord* selectedRecord = 0;
  int remaining = g_pMapContextActionManager->mapContextActionRecordList->GetSize();
  for (; remaining > 0; --remaining) {
    MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
        g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
            remaining));
    if (record->placedFlag != 0 && point.x >= record->markerPixelX &&
        point.x < record->markerPixelX + 0x12 && point.y >= record->markerPixelY &&
        point.y < record->markerPixelY + 0x12) {
      selectedRecord = record;
    }
  }
  return selectedRecord;
}

// FUNCTION: IMPERIALISM 0x004ade00
void TBattleReportView::Draw(RECT* rectBuffer) {
  TDiplomacyMapView::Draw(rectBuffer);
  RenderMapContextActionMarkers(rectBuffer);
}

// FUNCTION: IMPERIALISM 0x004ade30
void TBattleReportView::RenderMapContextActionMarkers(RECT* rectBuffer) {
  (void)rectBuffer; // ignored stack arg threaded through by the caller

  int count = g_pMapContextActionManager->mapContextActionRecordList->GetSize();
  int boundary = (selectedReportIndex == 0) ? 1 : 0;
  int ordinal = count;
  if (ordinal >= boundary) {
    do {
      int index = (ordinal == 0) ? selectedReportIndex : ordinal;
      MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
          g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
              index));

      if (selectedReportIndex != ordinal && record->placedFlag != 0) {
        RECT destRect;
        destRect.left = record->markerPixelX;
        destRect.top = record->markerPixelY;
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

        int spriteX = (record->markerSpriteCode + (ordinal == 0 ? 1 : 0)) * 0x12;
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
  if (selectedReportIndex == static_cast<short>(record->listOrdinal)) {
    return;
  }

  if (selectedReportIndex != 0) {
    MapContextActionRecord* oldRecord = static_cast<MapContextActionRecord*>(
        g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
            selectedReportIndex));
    RECT oldRect;
    oldRect.left = oldRecord->markerPixelX;
    oldRect.top = oldRecord->markerPixelY;
    oldRect.right = oldRect.left + 18;
    oldRect.bottom = oldRect.top + 18;
    InvalidateCityDialogRectRegion(&oldRect, 1);
  }

  selectedReportIndex = static_cast<short>(record->listOrdinal);
  if (selectedReportIndex != 0) {
    MapContextActionRecord* newRecord = static_cast<MapContextActionRecord*>(
        g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
            selectedReportIndex));
    RECT newRect;
    newRect.left = newRecord->markerPixelX;
    newRect.top = newRecord->markerPixelY;
    newRect.right = newRect.left + 18;
    newRect.bottom = newRect.top + 18;
    InvalidateCityDialogRectRegion(&newRect, 1);
  }

  short participantIndex = static_cast<signed char>(record->displayedParticipantIndex);
  short otherParticipantIndex = static_cast<short>(1 - participantIndex);
  int activeSideRelation;
  if (static_cast<signed char>(
          record->nationIds[static_cast<signed char>(record->reportParticipantIndex)]) ==
      g_pSimMgr->GetPlayerCountry()) {
    activeSideRelation = 1;
  } else if (static_cast<signed char>(
                 record->nationIds[1 - static_cast<signed char>(record->reportParticipantIndex)]) ==
             g_pSimMgr->GetPlayerCountry()) {
    activeSideRelation = -1;
  } else {
    activeSideRelation = 0;
  }
  bool displayedParticipantIsActive =
      static_cast<signed char>(record->nationIds[participantIndex]) ==
      g_pSimMgr->GetPlayerCountry();

  switch (record->reportKind) {
  case kMapContextReportLandBattle:
  case kMapContextReportPreemptedLandBattle:
  case kMapContextReportUncontestedTakeover: {
    TStaticText* locaText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagLoca));
    locaText->AssertValid();
    CString strLocation;
    CString strTerrain;
    g_pGlobalMapState->AssignCityRecordDisplayName(reinterpret_cast<int>(record->location),
                                                   &strLocation);
    int ownerNation =
        g_pGlobalMapState->cityScoreTable[reinterpret_cast<int>(record->location)].ownerNationCode;
    g_apTerrainTypeDescriptorTable[ownerNation]->FormatOverlayTerrainLabelText(&strTerrain);
    CString locationTemplate;
    g_pSimMgr->GetString(0x273d, 7, &locationTemplate);
    CString combinedStr;
    scanBracketExpressions(g_pSimMgr, &combinedStr, static_cast<LPCSTR>(locationTemplate),
                           static_cast<LPCSTR>(strLocation), static_cast<LPCSTR>(strTerrain));
    combinedStr += " ";
    locaText->SetTextAndMaybeRefresh(&combinedStr, true);
    break;
  }
  case kMapContextReportSeaBattle:
  case kMapContextReportMerchantInterception: {
    TStaticText* locaText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagLoca));
    locaText->AssertValid();
    CString nameStr;
    static_cast<TZone*>(record->location)->AssignZoneDisplayNameToOutputRef(&nameStr);
    locaText->SetTextAndMaybeRefresh(&nameStr, true);
    break;
  }
  default:
    break;
  }

  TPicture* friendlyFlag = static_cast<TPicture*>(ResolveControlByTag(kControlTagFflg));
  friendlyFlag->AssertValid();
  friendlyFlag->SetPictureRsrcID(
      static_cast<short>(0x1130 + static_cast<signed char>(record->nationIds[participantIndex])),
      1);

  TPicture* enemyFlag = static_cast<TPicture*>(ResolveControlByTag(kControlTagEflg));
  enemyFlag->AssertValid();
  enemyFlag->SetPictureRsrcID(
      static_cast<short>(0x1130 +
                         static_cast<signed char>(record->nationIds[otherParticipantIndex])),
      1);

  int userStringGroup;
  int userStringIndex;
  if (record->reportKind == kMapContextReportMerchantInterception) {
    userStringGroup = 0x273c;
    userStringIndex = activeSideRelation + 5;
  } else if (record->reportKind == kMapContextReportSeaBattle) {
    userStringGroup = 0x273c;
    userStringIndex = activeSideRelation + 8;
  } else if (record->reportKind == kMapContextReportPreemptedLandBattle) {
    userStringGroup = 0x273d;
    userStringIndex = activeSideRelation + 40;
  } else if (record->reportKind == kMapContextReportUncontestedTakeover) {
    userStringGroup = 0x273d;
    userStringIndex = activeSideRelation + 43;
  } else {
    userStringGroup = 0x273d;
    int activeHomeRegion =
        g_apTerrainTypeDescriptorTable[g_pSimMgr->GetPlayerCountry()]->GetCapitolProvince();
    bool activeNationOwnsBattleSite = activeHomeRegion == reinterpret_cast<int>(record->location);
    bool reportSidesAreSame = record->displayedParticipantIndex == record->reportParticipantIndex;
    bool reportParticipantIsActive =
        static_cast<signed char>(
            record->nationIds[static_cast<signed char>(record->reportParticipantIndex)]) ==
        g_pSimMgr->GetPlayerCountry();
    bool activeNationIsOtherReportSide = activeSideRelation != 0 && !reportParticipantIsActive;
    int otherNation = static_cast<signed char>(record->nationIds[0]);
    if (otherNation == g_pSimMgr->GetPlayerCountry()) {
      otherNation = static_cast<signed char>(record->nationIds[1]);
    }
    bool otherNationOwnsBattleSite =
        g_apTerrainTypeDescriptorTable[otherNation]->GetCapitolProvince() ==
        reinterpret_cast<int>(record->location);

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
  userText->SetTextAndMaybeRefresh(&userStr, true);

  {
    TStaticText* mdafText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagFadm));
    mdafText->AssertValid();
    CString mdafStr(record->nameBuffer[participantIndex].data);
    mdafText->SetTextAndMaybeRefresh(&mdafStr, true);
  }

  {
    TStaticText* phsfText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagFshp));
    phsfText->AssertValid();
    CString phsfStr(record->overlayLabel[participantIndex].data);
    phsfText->SetTextAndMaybeRefresh(&phsfStr, true);
  }

  {
    TStaticText* mdaeText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagEadm));
    mdaeText->AssertValid();
    CString mdaeStr(record->nameBuffer[otherParticipantIndex].data);
    mdaeText->SetTextAndMaybeRefresh(&mdaeStr, true);
  }

  {
    TStaticText* phseText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagEshp));
    phseText->AssertValid();
    CString phseStr(record->overlayLabel[otherParticipantIndex].data);
    phseText->SetTextAndMaybeRefresh(&phseStr, true);
  }

  bool hasPrevious = selectedReportIndex > 1;
  int count = g_pMapContextActionManager->mapContextActionRecordList->GetSize();
  bool hasNext = selectedReportIndex < count;

  TControl* prevCtrl = static_cast<TControl*>(ResolveControlByTag(kControlTagPrev));
  prevCtrl->AssertValid();
  prevCtrl->ViewEnable(hasPrevious, 0);
  prevCtrl->Show(hasPrevious, 1);

  TControl* nextCtrl = static_cast<TControl*>(ResolveControlByTag(kControlTagNext));
  nextCtrl->AssertValid();
  nextCtrl->ViewEnable(hasNext, 0);
  nextCtrl->Show(hasNext, 1);

  bool enableInfo =
      (static_cast<signed char>(record->nationIds[0]) == g_pSimMgr->GetPlayerCountry() ||
       static_cast<signed char>(record->nationIds[1]) == g_pSimMgr->GetPlayerCountry());
  TControl* infoCtrl = static_cast<TControl*>(ResolveControlByTag(kControlTagInfo));
  infoCtrl->AssertValid();
  infoCtrl->ViewEnable(enableInfo, 0);
  infoCtrl->Show(enableInfo, 1);
}
