#include "game/gfx/TGameWindow.h"

#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/THelpMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TUiEvent.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/assets/TMovieView.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/ui_core/TApplication.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_control_tags.h"

namespace {

const short kUiCommandHandledMarker = 0x29a;

static short QueryUiRuntimeEventCode() {
  return g_pUiRuntimeContext->currentTurnEventCode;
}

static short QueryUiRuntimeFieldF8() {
  return g_pUiRuntimeContext->fieldF8;
}

static TMovieView* QueryUiRuntimeActiveMovieView() {
  return g_pUiRuntimeContext->activeMovieViewF4;
}

} // namespace

namespace GameWindowInvoke {

static short ConsumeFirstPendingAbilityUnlockForNation(short nationId) {
  return g_pCityOrderCapabilityState->ConsumeFirstPendingAbilityUnlock(nationId);
}

static void DispatchUiRuntimeMessage101AAndRefreshActiveViewGate() {
  g_pUiRuntimeContext->DispatchUiRuntimeMessage101AAndRefreshActiveView();
}

static void SelectAndActivatePendingEventForCurrentViewGate() {
  g_pHelpMgr->SelectAndActivatePendingEventForCurrentView();
}

static void DispatchUiRuntimeAbilityUnlockSlot88Gate(int abilityIndex) {
  if (g_pUiRuntimeContext == nullptr) {
    return;
  }
  g_pUiRuntimeContext->ShowAbilityStatusReport(abilityIndex);
}

static void PlayClickSfx7000() {
  if (g_pSfxPlaybackSystem == nullptr) {
    return;
  }
  g_pSfxPlaybackSystem->PlaySoundEffect(7000, 0, 1);
}

} // namespace GameWindowInvoke
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
TGameWindow::~TGameWindow() {}

// FUNCTION: IMPERIALISM 0x004ffcb0
CMcWindow* TGameWindow::Open() {
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
  TControl* mainControl = static_cast<TControl*>(ResolveControlByTag(kTagMain));
  if (mainControl == 0) {
    return;
  }
  if (commandEvent->handledMarker == kUiCommandHandledMarker) {
    return;
  }
  if (g_pApplicationUiRootController->InModalState() != 0) {
    return;
  }
  commandEvent->handledMarker = kUiCommandHandledMarker;

  short commandCode = commandEvent->commandCode;
  if (commandCode == 0x68 || commandCode == 0x48) {
    if (mainControl->ResolveControlByTag(kTagQuery) != 0) {
      if (g_pHelpMgr != 0) {
        GameWindowInvoke::PlayClickSfx7000();
        if (QueryUiRuntimeEventCode() == kTurnEventStrategicMap) {
          GameWindowInvoke::DispatchUiRuntimeMessage101AAndRefreshActiveViewGate();
          return;
        }
        GameWindowInvoke::SelectAndActivatePendingEventForCurrentViewGate();
        return;
      }
    }
  }

  if (commandCode == 3 || commandCode == 0xd || commandCode == 0x1b || commandCode == 0x20) {
    if (QueryUiRuntimeEventCode() != kTurnEventStrategicMap &&
        mainControl->ResolveControlByTag(0x656e6420) != 0) { // 'end '
      GameWindowInvoke::PlayClickSfx7000();
      if (g_pSimMgr->mode != 0x11) {
        g_pSimMgr->StartNextPhase();
        return;
      }
      short nationId = g_pSimMgr->GetActiveNationId();
      short abilityIndex = GameWindowInvoke::ConsumeFirstPendingAbilityUnlockForNation(nationId);
      if (abilityIndex != -1) {
        GameWindowInvoke::DispatchUiRuntimeAbilityUnlockSlot88Gate(abilityIndex);
        return;
      }
      g_pSimMgr->StartNextPhase();
      return;
    }
    if (QueryUiRuntimeFieldF8() != 0) {
      TMovieView* activeMovieView = QueryUiRuntimeActiveMovieView();
      if (activeMovieView == 0) {
        return;
      }
      activeMovieView->StopMovieIfActive();
      return;
    }
    mainControl->DoKeyEvent(event);
    return;
  }

  if (g_pSimMgr == 0) {
    mainControl->DoKeyEvent(event);
    return;
  }
  if (g_pSimMgr->mode != 0x69 && g_pSimMgr->mode != 0x68 && g_pSimMgr->mode != 0x67 &&
      g_pSimMgr->mode != 0x6a && g_pSimMgr->mode != 0x6d &&
      QueryUiRuntimeEventCode() != kTurnEventStrategicMap) {
    mainControl->DoKeyEvent(event);
    return;
  }

  switch (commandCode) {
  case 0x31:
    if (QueryUiRuntimeEventCode() != kTurnEventTransport) {
      GameWindowInvoke::PlayClickSfx7000();
      g_pSimMgr->EnterOptionalPhase(0x69);
      return;
    }
    break;
  case 0x32:
    if (QueryUiRuntimeEventCode() != kTurnEventCityProduction) {
      GameWindowInvoke::PlayClickSfx7000();
      g_pSimMgr->EnterOptionalPhase(0x6a);
      return;
    }
    break;
  case 0x33:
    if (QueryUiRuntimeEventCode() != kTurnEventTradeOverview &&
        QueryUiRuntimeEventCode() != kTurnEventIndustryOverview) {
      GameWindowInvoke::PlayClickSfx7000();
      g_pSimMgr->EnterOptionalPhase(0x67);
      return;
    }
    break;
  case 0x34:
    if (QueryUiRuntimeEventCode() != kTurnEventDiplomacyMap) {
      GameWindowInvoke::PlayClickSfx7000();
      g_pSimMgr->EnterOptionalPhase(0x68);
      return;
    }
    break;
  case 0x35:
    if (QueryUiRuntimeEventCode() != kTurnEventTechnologyStore) {
      GameWindowInvoke::PlayClickSfx7000();
      g_pSimMgr->EnterOptionalPhase(0x6d);
      return;
    }
    break;
  default:
    mainControl->DoKeyEvent(event);
    return;
  }
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
