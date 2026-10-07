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
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/app_init_globals.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

#include <mmsystem.h>

//
// No own destructor: the original's slot is an ILT thunk to ~TApplication (0x004867e0), i.e.
// the base's. The implicit destructor the compiler gives this class is what the scalar
// deleting destructor calls, which is the same shape.

// FUNCTION: IMPERIALISM 0x00414770
void TAmbitApplication::DoSetupMenus() {}

// FUNCTION: IMPERIALISM 0x00493250
unsigned int GetTickCountDiv16() {
  return timeGetTime() >> 4;
}

// FUNCTION: IMPERIALISM 0x0049cc40
void SetCachedShowSplashFlag(BOOL showSplash) {
  g_cachedShowSplashFlag = showSplash;
}

IMPLEMENT_DYNCREATE(TAmbitApplication, TApplication)

// FUNCTION: IMPERIALISM 0x0049ded0
void TAmbitApplication::IAmbitApplication() {
  edgeScrollTarget = 0;
  languagePackId = theApp.languagePackId;

  if (g_pLanguageMgr == NULL) {
    g_pLanguageMgr = new TLanguageMgr();
  }

  g_pLanguageMgr->SetLanguage(languagePackId);

  TSimMgr* simMgr = new TSimMgr();
  if (simMgr != NULL) {
    simMgr->ISimMgr();
  }
  g_pSimMgr = simMgr;

  TAssetMgr* assetMgr = new TAssetMgr();
  assetMgr->ForwardEnsurePictWvDataGobLoadedBySlot(languagePackId);
  g_pAssetMgr = assetMgr;

  TViewMgr* viewMgr = new TViewMgr();
  if (viewMgr != NULL) {
    viewMgr->LoadTurnEventCursorTable();
  }
  g_pViewMgr = viewMgr;

  TDisplayMgr* displayMgr = new TDisplayMgr();
  if (displayMgr != NULL) {
    displayMgr->IDisplayMgr();
  }
  g_pDisplayMgr = displayMgr;

  TMacViewMgr* mapView = new TMacViewMgr();
  if (mapView != NULL) {
    mapView->IMacViewMgr();
  }
  g_pMacViewMgr = mapView;

  if (g_pHelpMgr == NULL) {
    g_pHelpMgr = new THelpMgr();
  }
  if (g_pHelpMgr != NULL) {
    g_pHelpMgr->IHelpMgr();
  }

  if (g_pGameFlowState != NULL) {
    g_pGameFlowState->Free();
    g_pGameFlowState = NULL;
  }

  g_pGameFlowState = new TMultiplayerMgr();
  if (g_pGameFlowState != NULL) {
    g_pGameFlowState->IMultiplayerMgr(0);
  }
}

// FUNCTION: IMPERIALISM 0x0049e1a0
void TAmbitApplication::Free() {
  if (g_pLanguageMgr != NULL) {
    g_pLanguageMgr->Free();
    g_pLanguageMgr = NULL;
  }
  if (g_pMacViewMgr != NULL) {
    g_pMacViewMgr->Free();
    g_pMacViewMgr = NULL;
  }
  if (g_pHelpMgr != NULL) {
    g_pHelpMgr->Free();
    g_pHelpMgr = NULL;
  }
  g_pSimMgr->Free();

  if (g_pAssetMgr != NULL) {
    g_pAssetMgr->Free();
    g_pAssetMgr = NULL;
  }
  if (g_pViewMgr != NULL) {
    g_pViewMgr->Free();
    g_pViewMgr = NULL;
  }
  if (g_pDisplayMgr != NULL) {
    g_pDisplayMgr->Free();
    g_pDisplayMgr = NULL;
  }
  if (g_pGameFlowState != NULL) {
    g_pGameFlowState->Free();
    g_pGameFlowState = NULL;
  }
  TApplication::Free();
}

// FUNCTION: IMPERIALISM 0x0049e280
void TAmbitApplication::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  if (g_nSaveFormatVersion < 0x2a) {
    stream->ReadBytes(&languagePackId, 2);
    languagePackId = 0x00657573;
  } else {
    stream->ReadBytes(&languagePackId, 4);
  }
}

// FUNCTION: IMPERIALISM 0x0049e2f0
void TAmbitApplication::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&languagePackId, 4);
}

// FUNCTION: IMPERIALISM 0x0049e320
void TAmbitApplication::HandleCursor(int x, int y, void* cursorRegion) {
  if (!InModalState() && edgeScrollTarget != NULL) {
    short code = g_pViewMgr->currentTurnEventCode;
    if (code == kTurnEventStrategicMap || code == kTurnEventCitySiteSelector ||
        code == kTurnEventTacticalView || code == kTurnEventTacticalStatusRefresh ||
        code == kTurnEventMapEditor) {
      if (!InModalState()) {
        CPoint pt;
        pt.x = x;
        pt.y = y;

        g_pDisplayMgr->activeDialog->SuperToLocal(&pt);

        if (pt.x > -200 && pt.y > -200) {
          TView* activeDialog = g_pDisplayMgr->activeDialog;
          int width = activeDialog->frameWidth;
          if (pt.x < width + 200) {
            int height = activeDialog->frameHeight;
            if (pt.y < height + 200) {
              char edgeMask = 0;
              if (pt.x <= 4) {
                edgeMask = kMapScrollEdgeLeft;
              } else if (pt.x >= width - 4) {
                edgeMask = kMapScrollEdgeRight;
              }
              if (pt.y <= 4) {
                edgeMask |= kMapScrollEdgeBottom;
              } else if (pt.y >= height - 4) {
                edgeMask |= kMapScrollEdgeTop;
              }
              if (edgeMask != 0) {
                int ticks = GetTickCountDiv16();
                if (g_lastEdgeAutoScrollTick16 > ticks || g_lastEdgeAutoScrollTick16 + 3 < ticks) {
                  g_lastEdgeAutoScrollTick16 = ticks;
                  edgeScrollTarget->Scroll(edgeMask);
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
  if (g_pDisplayMgr != NULL && g_pDisplayMgr->activeDialog != NULL) {
    g_pDisplayMgr->activeDialog->DoKeyEvent(event);
  }
}

// FUNCTION: IMPERIALISM 0x0049e4e0
void TAmbitApplication::CloseAndFreeWindow(TWindow* window) {
  window->CloseAndFree();
}
