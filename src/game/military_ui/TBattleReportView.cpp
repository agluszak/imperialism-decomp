#include "game/military_ui/TBattleReportView.h"

#include <string.h>

#include "game/gfx/CDib.h"
#include "game/app/TAnimator.h"
#include "game/military/TArmyMgr.h"
#include "game/ui_core/TControl.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/military_ui/TIdleMeAnimation.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/map/TMapMgr.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/globals/prelude.h"
#include "game/globals/military_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

TBattleReportView::TBattleReportView()
    : TDiplomacyMapView(), selectedReportIndex24c8(1), transientRegistryObject24cc(0) {}

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
  TControl* control = static_cast<TControl*>(ResolveControlByTag(0x72657375)); // 'user'
  control->AssertValid();
  control->InstallTextStyle(style.desc, 0);

  BuildUiTextStyleDescriptor(&style.desc, 2, 0xe, 0x2b67);
  control = static_cast<TControl*>(ResolveControlByTag(0x6c6f6361)); // 'acol'
  control->AssertValid();
  control->InstallTextStyle(style.desc, 0);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xc, 0x2b67);
  control = static_cast<TControl*>(ResolveControlByTag(0x6661646d)); // 'mdaf'
  control->AssertValid();
  control->InstallTextStyle(style.desc, 0);
  control = static_cast<TControl*>(ResolveControlByTag(0x6561646d)); // 'mdae'
  control->AssertValid();
  control->InstallTextStyle(style.desc, 0);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b67);
  control = static_cast<TControl*>(ResolveControlByTag(0x66736870)); // 'phsf'
  control->AssertValid();
  control->InstallTextStyle(style.desc, 0);
  control = static_cast<TControl*>(ResolveControlByTag(0x65736870)); // 'phse'
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
      cell = g_pGlobalMapState->cityScoreTable[record->tileOrObject08.tileIndex].cityTileIndex04;
    } else {
      cell =
          *reinterpret_cast<short*>(reinterpret_cast<char*>(record->tileOrObject08.object) + 0xc);
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
    record->markerPixelX258 = mapOriginPixelX514 + (markerColX2 * 5) / 2 - 9;
    record->markerPixelY25c = mapOriginPixelY518 + markerRow * 5 - 9;

    short spriteBase;
    if (record->nationIds[record->participantIndex02] == g_pSimMgr->GetActiveNationId()) {
      spriteBase = 0;
    } else if (record->nationIds[1 - record->participantIndex02] ==
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
  RefreshMapContextSelectionPanelAndInfoLabels(
      g_pMapContextActionManager->mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(
          selectedOrdinal));
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
  animation->InitializeAnimation(this, &animationRect, 0, 0, 0, registryTag);
  g_pUiAnimator->AddObjectToUiTransientRegistry(animation);

  TInfoBarText* cursorPanel = static_cast<TInfoBarText*>(ResolveControlByTag(0x63757273)); // 'surc'
  g_pCursorControlPanel = cursorPanel;
  cursorPanel->AssertValid();
  g_pCursorControlPanel->SetTextStyle(0, 0xe, 0x2b6b);
  g_pCursorControlPanel->SetTextAlignmentAndMaybeRefresh(1, 1);
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b67, 0x2b6c);

  SetControlHoverHelpText(g_pBattleReportSharedText_0064dc30,
                          ResolveControlByTag(0x6d61696e)); // 'main'
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x16, ResolveControlByTag(0x6661646d));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x16, ResolveControlByTag(0x66736870));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x16, ResolveControlByTag(0x66666c67));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x17, ResolveControlByTag(0x6561646d));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x17, ResolveControlByTag(0x65736870));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x17, ResolveControlByTag(0x65666c67));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x18, ResolveControlByTag(0x6c6f6361));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x19, ResolveControlByTag(0x72657375));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x1a, ResolveControlByTag(0x70726576));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x1b, ResolveControlByTag(0x6e657874));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x1c, ResolveControlByTag(0x696e666f));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x1d, ResolveControlByTag(0x6f6b6179));
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x1e, ResolveControlByTag(0x71756572));

  g_pSfxPlaybackSystem->ResetDualAudioCuePools();
  g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(5);
  g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();
}

// FUNCTION: IMPERIALISM 0x004ad560
void TBattleReportView::Free() {
  if (transientRegistryObject24cc != 0) {
    g_pUiAnimator->RemoveUiTransientRegistryObjectByTag(
        *reinterpret_cast<int*>(reinterpret_cast<char*>(transientRegistryObject24cc) + 0x18));
  }
  TDiplomacyMapView::Free();
}

// FUNCTION: IMPERIALISM 0x004ad5a0
char TBattleReportView::DoIdle(int action) {
  (void)action;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ad7a0
void TBattleReportView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)commandId;
  (void)sourceHandler;
  (void)event;
}

// FUNCTION: IMPERIALISM 0x004adc80
void TBattleReportView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                            RgnHandle hitArg) {
  (void)point;
  (void)hitArg;
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
        BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas694[3]->GetBlitSurface(),
                                         g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                         &srcRect, &destRect, 0x24, 0);
        UpdatePaletteIndexWithDefaultFallback(0x13);
      }
      ordinal--;
    } while (ordinal >= boundary);
  }
}

// FUNCTION: IMPERIALISM 0x004adfc0
void TBattleReportView::RefreshMapContextSelectionPanelAndInfoLabels(void* mapContextRecord) {
  (void)mapContextRecord;
}
