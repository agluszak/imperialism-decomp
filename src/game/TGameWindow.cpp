#include "game/TGameWindow.h"

#include "game/TSimMgr.h"
#include "game/THelpMgr.h"
#include "game/TTechMgr.h"
#include "game/TControl.h"
#include "game/TSimMgr.h"
#include "game/TUiEvent.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/TMovieView.h"
#include "game/UiRuntimeContext.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/TApplication.h"
#include "game/startup_helpers.h"
#include "game/ui_control_tags.h"


namespace {

const unsigned int kAddrSfxPlaybackSystem = 0x006a43ec;
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
  void* uiRuntime = g_pUiRuntimeContext;
  if (uiRuntime == 0) {
    return;
  }
  reinterpret_cast<void(__cdecl*)(int)>(*reinterpret_cast<void**>(
      reinterpret_cast<char*>(*reinterpret_cast<void**>(uiRuntime)) + 0x88))(abilityIndex);
}

static void PlayClickSfx7000() {
  void* sfxPlayer = *reinterpret_cast<void**>(kAddrSfxPlaybackSystem);
  if (sfxPlayer == 0) {
    return;
  }
  reinterpret_cast<void(__cdecl*)(int, int, int)>(*reinterpret_cast<void**>(
      reinterpret_cast<char*>(*reinterpret_cast<void**>(sfxPlayer)) + 0xb8))(7000, 0, 1);
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
void TGameWindow::DispatchSlot9CToLinkedChildren() {
  if (IsActionable() == 0) {
    UpdateTurnOrderNavigationWindowLayout();
  }
  TWindow::DispatchSlot9CToLinkedChildren();
}

// FUNCTION: IMPERIALISM 0x004ffd10
char TGameWindow::DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3, int arg4) {
  return TView::DispatchUiMouseMoveToChildren(point, arg2, arg3, arg4);
}

// FUNCTION: IMPERIALISM 0x004ffd40
char TGameWindow::DispatchUiMouseEventToChildrenOrSelf_Impl(CPoint* point, int arg2, int arg3,
                                                            int arg4) {
  return TView::DispatchUiMouseEventToChildrenOrSelf_Impl(point, arg2, arg3, arg4);
}

// FUNCTION: IMPERIALISM 0x004ffd70
void TGameWindow::ForwardParam(int param) {
  TKeyCommandEvent* commandEvent = reinterpret_cast<TKeyCommandEvent*>(param);
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
        if (QueryUiRuntimeEventCode() == 0x7dd) {
          GameWindowInvoke::DispatchUiRuntimeMessage101AAndRefreshActiveViewGate();
          return;
        }
        GameWindowInvoke::SelectAndActivatePendingEventForCurrentViewGate();
        return;
      }
    }
  }

  if (commandCode == 3 || commandCode == 0xd || commandCode == 0x1b || commandCode == 0x20) {
    if (QueryUiRuntimeEventCode() != 0x7dd &&
        mainControl->ResolveControlByTag(0x656e6420) != 0) { // 'end '
      GameWindowInvoke::PlayClickSfx7000();
      if (g_pSimMgr->mode != 0x11) {
        g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
        return;
      }
      short nationId = g_pSimMgr->GetActiveNationId();
      short abilityIndex = GameWindowInvoke::ConsumeFirstPendingAbilityUnlockForNation(nationId);
      if (abilityIndex != -1) {
        GameWindowInvoke::DispatchUiRuntimeAbilityUnlockSlot88Gate(abilityIndex);
        return;
      }
      g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
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
    mainControl->ForwardParam(param);
    return;
  }

  if (g_pSimMgr == 0) {
    mainControl->ForwardParam(param);
    return;
  }
  if (g_pSimMgr->mode != 0x69 && g_pSimMgr->mode != 0x68 && g_pSimMgr->mode != 0x67 &&
      g_pSimMgr->mode != 0x6a && g_pSimMgr->mode != 0x6d && QueryUiRuntimeEventCode() != 0x7dd) {
    mainControl->ForwardParam(param);
    return;
  }

  switch (commandCode) {
  case 0x31:
    if (QueryUiRuntimeEventCode() != 0x7de) {
      GameWindowInvoke::PlayClickSfx7000();
      g_pSimMgr->SetGlobalTurnStateCodeIfAllowed(0x69);
      return;
    }
    break;
  case 0x32:
    if (QueryUiRuntimeEventCode() != 0x7db) {
      GameWindowInvoke::PlayClickSfx7000();
      g_pSimMgr->SetGlobalTurnStateCodeIfAllowed(0x6a);
      return;
    }
    break;
  case 0x33:
    if (QueryUiRuntimeEventCode() != 0x7d9 && QueryUiRuntimeEventCode() != 0x7da) {
      GameWindowInvoke::PlayClickSfx7000();
      g_pSimMgr->SetGlobalTurnStateCodeIfAllowed(0x67);
      return;
    }
    break;
  case 0x34:
    if (QueryUiRuntimeEventCode() != 0x7d8) {
      GameWindowInvoke::PlayClickSfx7000();
      g_pSimMgr->SetGlobalTurnStateCodeIfAllowed(0x68);
      return;
    }
    break;
  case 0x35:
    if (QueryUiRuntimeEventCode() != 0x8fc) {
      GameWindowInvoke::PlayClickSfx7000();
      g_pSimMgr->SetGlobalTurnStateCodeIfAllowed(0x6d);
      return;
    }
    break;
  default:
    mainControl->ForwardParam(param);
    return;
  }
}

// FUNCTION: IMPERIALISM 0x00500160
void TGameWindow::UpdateTurnOrderNavigationWindowLayout() {
  if (g_pDisplayMgr->eventCode0e == 0x7d1) {
    RECT boundsRect;
    QueryBounds(&boundsRect);
    GlobalViewportRectDefaultsRecord** rectDefaultsHandle =
        InitializeGlobalRectDefaultsIfUninitialized();
    GlobalViewportRectDefaultsRecord* rectRecord = *rectDefaultsHandle;
    RECT globalRect;
    CopyRect(&globalRect, reinterpret_cast<RECT*>(&rectRecord->left));
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
