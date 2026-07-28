#include "game/gfx/TGameWindow.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_tags_common.h"

#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/THelpMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TUiEvent.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/assets/TMovieView.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/ui_core/TApplication.h"
#include "game/gfx/TDisplayMgr.h"

namespace {

const short kUiCommandHandledMarker = 0x29a;

} // namespace
// SYNTHETIC: IMPERIALISM 0x004ffb30
// TGameWindow::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ffbf0
// TGameWindow::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGameWindow, TWindow)

// FUNCTION: IMPERIALISM 0x004ffc10
TGameWindow::TGameWindow() {
  fieldAtA0 = 0;
  fieldAtA2 = 0x14;
  fieldAtA4 = 0;
  fieldAtA8 = 0;
  fieldAtAc = 0;
}

// SYNTHETIC: IMPERIALISM 0x004ffc60
// TGameWindow::`scalar deleting destructor'
// The teardown runs through the real TWindow base destructor (registry/modal unlink) via
// inheritance; TGameWindow adds no destruction of its own.
// FUNCTION: IMPERIALISM 0x004ffc90
TGameWindow::~TGameWindow() {}

// FUNCTION: IMPERIALISM 0x004ffcb0
CWnd* TGameWindow::Open() {
  if (IsActionable() == 0) {
    UpdateTurnOrderNavigationWindowLayout();
  }
  return TWindow::Open();
}

// FUNCTION: IMPERIALISM 0x004ffd10
char TGameWindow::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  return TView::HandleMouseDown(point, event, origin);
}

// FUNCTION: IMPERIALISM 0x004ffd40
char TGameWindow::HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  return TView::HandleMouseUp(point, event, origin);
}

// FUNCTION: IMPERIALISM 0x004ffd70
void TGameWindow::DoKeyEvent(TToolboxEvent* event) {
  TToolboxEvent* commandEvent = event;
  TControl* mainControl = static_cast<TControl*>(ResolveControlByTag(kControlTagMain));
  if (mainControl == 0) {
    return;
  }
  if (commandEvent->handledMarker == kUiCommandHandledMarker) {
    return;
  }
  if (g_pGlobalUiRootController->InModalState() != 0) {
    return;
  }
  commandEvent->handledMarker = kUiCommandHandledMarker;

  if (commandEvent->commandCode == kUiKeyHelpLowerCase ||
      commandEvent->commandCode == kUiKeyHelpUpperCase) {
    if (mainControl->ResolveControlByTag(kControlTagQuer) != 0) {
      if (g_pHelpMgr != 0) {
        g_pSfxPlaybackSystem->PlaySoundEffect(7000, 0, 1);
        if (g_pUiRuntimeContext->currentTurnEventCode == kTurnEventStrategicMap) {
          g_pUiRuntimeContext->DispatchUiRuntimeMessage101AAndRefreshActiveView();
          return;
        }
        g_pHelpMgr->SelectAndActivatePendingEventForCurrentView();
        return;
      }
    }
  }

  if (commandEvent->commandCode == kUiKeyEnter || commandEvent->commandCode == kUiKeyReturn ||
      commandEvent->commandCode == kUiKeyEscape || commandEvent->commandCode == kUiKeySpace) {
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap &&
        mainControl->ResolveControlByTag(kControlTagEnd) != 0) { // 'end '
      g_pSfxPlaybackSystem->PlaySoundEffect(7000, 0, 1);
      if (g_pSimMgr->mode != 0x11) {
        g_pSimMgr->StartNextPhase();
        return;
      }
      short nationId = g_pSimMgr->GetActiveNationId();
      short abilityIndex = g_pCityOrderCapabilityState->ConsumeFirstPendingAbilityUnlock(nationId);
      if (abilityIndex != -1) {
        g_pUiRuntimeContext->ShowAbilityStatusReport(abilityIndex);
        return;
      }
      g_pSimMgr->StartNextPhase();
      return;
    }
    if (g_pUiRuntimeContext->fieldF8 != 0) {
      TMovieView* activeMovieView = g_pUiRuntimeContext->activeMovieViewF4;
      if (activeMovieView == 0) {
        return;
      }
      activeMovieView->StopMovieIfActive();
      return;
    }
    mainControl->DoKeyEvent(event);
    return;
  }

  if (g_pSimMgr != 0 &&
      (g_pSimMgr->mode == 0x69 || g_pSimMgr->mode == 0x68 || g_pSimMgr->mode == 0x67 ||
       g_pSimMgr->mode == 0x6a || g_pSimMgr->mode == 0x6d ||
       g_pUiRuntimeContext->currentTurnEventCode == kTurnEventStrategicMap)) {
    switch (commandEvent->commandCode) {
    case 0x31:
      if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventTransport) {
        g_pSfxPlaybackSystem->PlaySoundEffect(7000, 0, 1);
        g_pSimMgr->EnterOptionalPhase(0x69);
      }
      return;
    case 0x32:
      if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventCityProduction) {
        g_pSfxPlaybackSystem->PlaySoundEffect(7000, 0, 1);
        g_pSimMgr->EnterOptionalPhase(0x6a);
      }
      return;
    case 0x33:
      if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventTradeOverview &&
          g_pUiRuntimeContext->currentTurnEventCode != kTurnEventIndustryOverview) {
        g_pSfxPlaybackSystem->PlaySoundEffect(7000, 0, 1);
        g_pSimMgr->EnterOptionalPhase(0x67);
      }
      return;
    case 0x34:
      if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventDiplomacyMap) {
        g_pSfxPlaybackSystem->PlaySoundEffect(7000, 0, 1);
        g_pSimMgr->EnterOptionalPhase(0x68);
      }
      return;
    case 0x35:
      if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventTechnologyStore) {
        g_pSfxPlaybackSystem->PlaySoundEffect(7000, 0, 1);
        g_pSimMgr->EnterOptionalPhase(0x6d);
      }
      return;
    default:
      mainControl->DoKeyEvent(event);
      return;
    }
  }
  mainControl->DoKeyEvent(event);
}

// FUNCTION: IMPERIALISM 0x00500160
void TGameWindow::UpdateTurnOrderNavigationWindowLayout() {
  if (g_pDisplayMgr->eventCode0e == kTurnEventSphereWindow) {
    CRect boundsRect;
    QueryBounds(&boundsRect);
    GlobalViewportRectDefaultsRecord** rectDefaultsHandle =
        InitializeGlobalRectDefaultsIfUninitialized();
    GlobalViewportRectDefaultsRecord* rectRecord = *rectDefaultsHandle;
    RECT globalRect;
    CopyRect(&globalRect, &rectRecord->viewportBounds);
    boundsRect.left = globalRect.left;
    boundsRect.top = globalRect.top;
    boundsRect.right = globalRect.right;
    boundsRect.bottom = globalRect.bottom;
    ApplyBounds(&boundsRect, 1);
  }
  NoOpTurnOrderNavigationVtableSlotA();
}

// FUNCTION: IMPERIALISM 0x00500200
void TGameWindow::NoOpTurnOrderNavigationVtableSlotA() {}

// FUNCTION: IMPERIALISM 0x00500220
void TGameWindow::NoOpTurnOrderNavigationVtableSlotB() {}

// FUNCTION: IMPERIALISM 0x00500240
void TGameWindow::Free() {
  NoOpTurnOrderNavigationVtableSlotB();
  TWindow::Free();
  if (g_pDisplayMgr != 0) {
    g_pDisplayMgr->activeDialog = 0;
  }
}
