#include "game/gfx/TAmbitApplication.h"

#include "game/ImperialismApp.h"
#include "game/assets/TAssetMgr.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_core/TLanguageMgr.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/TStream.h"
#include "game/ui_core/TTurnEventDialogFactoryRegistry.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/app_init_globals.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

#include <mmsystem.h>

// SYNTHETIC: IMPERIALISM 0x004135f0
// TAmbitApplication::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00413620
TAmbitApplication::~TAmbitApplication() {}

// Mac-oracle name TAmbitApplication::DoSetupMenus() — a no-op on Windows (there is no
// menu bar to rebuild). Tentative attribution; the slot is a bare RET in the original.
// FUNCTION: IMPERIALISM 0x00414770
void TAmbitApplication::DoSetupMenus() {}

// FUNCTION: IMPERIALISM 0x00493250
unsigned int GetTickCountDiv16() {
  // 0x00493250 calls through the WINMM timeGetTime import at 0x006ab5fc, not KERNEL32
  // GetTickCount: timeGetTime resolves to 1ms under timeBeginPeriod, GetTickCount only to
  // the scheduler tick, and the >> 4 turns this into the game's ~16ms tick counter.
  return timeGetTime() >> 4;
}

// FUNCTION: IMPERIALISM 0x0049cc40
void SetCachedShowSplashFlag(BOOL showSplash) {
  g_cachedShowSplashFlag = showSplash;
}
// SYNTHETIC: IMPERIALISM 0x0049de40
// TAmbitApplication::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049deb0
// TAmbitApplication::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAmbitApplication, TApplication)

// FUNCTION: IMPERIALISM 0x0049ded0
void TAmbitApplication::IAmbitApplication() {
  edgeScrollTarget48 = 0;
  languagePackId50 = theApp.languagePackIdE4;

  if (g_pLanguageMgr == nullptr) {
    g_pLanguageMgr = new TLanguageMgr();
  }

  g_pLanguageMgr->ReloadPreplutNewsTableAndResources(languagePackId50);

  TSimMgr* simMgr = new TSimMgr();
  if (simMgr != nullptr) {
    simMgr->ISimMgr();
  }
  g_pSimMgr = simMgr;

  TAssetMgr* assetMgr = new TAssetMgr();
  assetMgr->ForwardEnsurePictWvDataGobLoadedBySlot(languagePackId50);
  g_pUiViewManager = assetMgr;

  EnsureTurnEventDialogFactoryRegistryInitialized();

  TViewMgr* viewMgr = new TViewMgr();
  if (viewMgr != nullptr) {
    viewMgr->LoadTurnEventCursorTable();
  }
  g_pUiRuntimeContext = viewMgr;

  TDisplayMgr* displayMgr = new TDisplayMgr();
  if (displayMgr != nullptr) {
    displayMgr->IDisplayMgr();
  }
  g_pDisplayMgr = displayMgr;

  TMacViewMgr* mapView = new TMacViewMgr();
  if (mapView != nullptr) {
    mapView->IMacViewMgr();
  }
  g_pStrategicMapViewSystem = mapView;

  if (g_pHelpMgr == nullptr) {
    g_pHelpMgr = new THelpMgr();
  }
  if (g_pHelpMgr != nullptr) {
    g_pHelpMgr->IHelpMgr();
  }

  if (g_pGameFlowState != nullptr) {
    g_pGameFlowState->Free();
    g_pGameFlowState = nullptr;
  }

  g_pGameFlowState = new TMultiplayerMgr();
  if (g_pGameFlowState != nullptr) {
    g_pGameFlowState->InitializeMultiplayerManagerForSessionContext(0);
  }
}

// FUNCTION: IMPERIALISM 0x0049e1a0
void TAmbitApplication::Free() {
  if (g_pLanguageMgr != nullptr) {
    g_pLanguageMgr->Free();
    g_pLanguageMgr = nullptr;
  }
  if (g_pStrategicMapViewSystem != nullptr) {
    g_pStrategicMapViewSystem->Free();
    g_pStrategicMapViewSystem = nullptr;
  }
  if (g_pHelpMgr != nullptr) {
    g_pHelpMgr->Free();
    g_pHelpMgr = nullptr;
  }
  g_pSimMgr->Free();

  if (g_pUiViewManager != nullptr) {
    g_pUiViewManager->Free();
    g_pUiViewManager = nullptr;
  }
  if (g_pUiRuntimeContext != nullptr) {
    g_pUiRuntimeContext->Free();
    g_pUiRuntimeContext = nullptr;
  }
  if (g_pDisplayMgr != nullptr) {
    g_pDisplayMgr->Free();
    g_pDisplayMgr = nullptr;
  }
  if (g_pGameFlowState != nullptr) {
    g_pGameFlowState->Free();
    g_pGameFlowState = nullptr;
  }
  TApplication::Free();
}

// FUNCTION: IMPERIALISM 0x0049e280
void TAmbitApplication::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  if (g_nSaveFormatVersion < 0x2a) {
    stream->ReadBytes(&languagePackId50, 2);
    languagePackId50 = 0x00657573;
  } else {
    stream->ReadBytes(&languagePackId50, 4);
  }
}

// FUNCTION: IMPERIALISM 0x0049e2f0
void TAmbitApplication::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&languagePackId50, 4);
}

// MacApp TAmbitApplication::HandleCursor(CPoint, Region**): on the map-style turn-event
// screens, auto-scroll the map picture when the cursor sits within 4px of the viewport
// edge (throttled to one scroll per 3 tick16 units); otherwise fall through to the base
// hook. The edge mask is 8=left, 4=right, 1=top, 2=bottom.
// FUNCTION: IMPERIALISM 0x0049e320
void TAmbitApplication::HandleCursor(int x, int y, void* cursorRegion) {
  if (!InModalState() && edgeScrollTarget48 != nullptr) {
    short code = g_pUiRuntimeContext->currentTurnEventCode;
    if (code == kTurnEventStrategicMap || code == kTurnEventCitySiteSelector ||
        code == kTurnEventTacticalView || code == kTurnEventProvisional0F3C ||
        code == kTurnEventMapEditor) {
      if (!InModalState()) {
        CPoint pt;
        pt.x = x;
        pt.y = y;

        g_pDisplayMgr->activeDialog->SuperToLocal(&pt);

        if (pt.x > -200 && pt.y > -200) {
          TView* activeDialog = g_pDisplayMgr->activeDialog;
          int width = activeDialog->frameWidth34;
          if (pt.x < width + 200) {
            int height = activeDialog->frameHeight38;
            if (pt.y < height + 200) {
              char edgeMask = 0;
              if (pt.x <= 4) {
                edgeMask = kMapScrollEdgeLeft;
              } else if (pt.x >= width - 4) {
                edgeMask = kMapScrollEdgeRight;
              }
              if (pt.y <= 4) {
                // The strategic-map backing surface is vertically reflected relative to
                // the window coordinate system.  Feed the map's "down-row" bit at the
                // top window edge so the visible viewport moves upward.
                edgeMask |= kMapScrollEdgeTop;
              } else if (pt.y >= height - 4) {
                edgeMask |= kMapScrollEdgeBottom;
              }
              if (edgeMask != 0) {
                int ticks = GetTickCountDiv16();
                // The reconstructed software compositor needs longer than the retail three-tick
                // cadence to finish a full strategic-map repaint. Keep one completed frame
                // between scroll steps instead of continuously invalidating the dialog and
                // starving the wood frame and toolbar paints.
                if (g_lastEdgeAutoScrollTick16 > ticks || g_lastEdgeAutoScrollTick16 + 12 < ticks) {
                  g_lastEdgeAutoScrollTick16 = ticks;
                  edgeScrollTarget48->Scroll(edgeMask);
                  return;
                }
              }
            }
          }
        }
      }
    }
  }
  TApplication::GetDefaultCursorRegion(x, y, cursorRegion);
}

// FUNCTION: IMPERIALISM 0x0049e4b0
void TAmbitApplication::DoKeyEvent(TToolboxEvent* event) {
  if (g_pDisplayMgr != nullptr && g_pDisplayMgr->activeDialog != nullptr) {
    g_pDisplayMgr->activeDialog->DoKeyEvent(event);
  }
}

// MacApp TAmbitApplication::CloseAndFreeWindow(TWindow*): dispatch the window's
// CloseAndFree (slot 0x74). The original does not null-check the window.
// FUNCTION: IMPERIALISM 0x0049e4e0
void TAmbitApplication::CloseAndFreeWindow(TWindow* window) {
  window->CloseAndFree();
}
