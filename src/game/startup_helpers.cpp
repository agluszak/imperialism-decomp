#include "game/startup_helpers.h"

#include "game/ImperialismApp.h"
#include "game/TAmbitApplication.h"
#include "game/TAssetMgr.h"
#include "game/TDisplayMgr.h"
#include "game/TLanguageMgr.h"
#include "game/TMacViewMgr.h"
#include "game/TSimMgr.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/diplomacy_globals.h"
#include "game/config.h"
#include "game/THelpMgr.h"

void InitializeStrategicMapViewSystem(TMacViewMgr* self);

// Leaf factory helpers — minimal local bodies until each address is promoted.
TLanguageMgr* ConstructTLanguageMgrBaseState(TLanguageMgr* self) {
  return self;
}

void ReloadPreplutNewsTableAndResources(int languageTag) {
  (void)languageTag;
}

void InitializeTurnFlowStateDefaults(TSimMgr* sim) {
  (void)sim;
}

TAssetMgr* ConstructUiViewManager(TAssetMgr* self) {
  return self;
}

void ForwardEnsurePictWvDataGobLoadedBySlot(int languageTag) {
  (void)languageTag;
}

THelpMgr* ConstructTHelpMgrBaseState(THelpMgr* self) {
  return self;
}

// Define the global callback pointer
// GLOBAL: IMPERIALISM 0x006a7fac
extern "C" void* g_pGlobalCallback_006a7fac = nullptr;

// Define DAT_006a2018
// GLOBAL: IMPERIALISM 0x006a2018
extern "C" int DAT_006a2018 = 0;

namespace {

void* GetObjectValueAtOffset98(void* object) {
  if (object == nullptr) {
    return nullptr;
  }
  return *reinterpret_cast<void**>(reinterpret_cast<char*>(object) + 0x98);
}

void* GetMainContextFromActiveThread() {
  CWinThread* thread = AfxGetThread();
  if (thread == nullptr) {
    return nullptr;
  }
  // Original calls CWinThread vtable slot +0x7c; m_pMainWnd is the recovered host until that
  // virtual is promoted onto CWinThread.
  return thread->m_pMainWnd;
}

} // namespace

// FUNCTION: IMPERIALISM 0x00415760
BOOL WarnLowDiskSpaceAndConfirmContinue() {
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x00483340
void SetUiRuntimeContextAndActivateMain(TView* mainViewHost, TView* activeDialog) {
  if (mainViewHost == nullptr) {
    return;
  }
  *reinterpret_cast<TView**>(reinterpret_cast<char*>(mainViewHost) + 0x40) = activeDialog;
  mainViewHost->PropagateUiResourceContextRecursive(reinterpret_cast<CWnd*>(mainViewHost));
  if (activeDialog != nullptr) {
    activeDialog->ResolveControlByTag(0x6d61696e);
  }
}

// FUNCTION: IMPERIALISM 0x0049cc40
void SetGlobalDword6A2018(int value) {
  DAT_006a2018 = value;
}

// FUNCTION: IMPERIALISM 0x0049ded0
void InitializeGlobalRuntimeSystemsFromConfig(TAmbitApplication* app) {
  app->field_48 = 0;
  app->field_50 = theApp.field_E4;

  if (g_pLanguageMgr == nullptr) {
    TLanguageMgr* languageMgr = new TLanguageMgr();
    if (languageMgr == nullptr) {
      g_pLanguageMgr = nullptr;
    } else {
      g_pLanguageMgr = ConstructTLanguageMgrBaseState(languageMgr);
    }
  }

  ReloadPreplutNewsTableAndResources(app->field_50);

  TSimMgr* simMgr = new TSimMgr();
  if (simMgr != nullptr) {
    InitializeTurnFlowStateDefaults(simMgr);
  }
  g_pLocalizationTable = simMgr;

  TAssetMgr* assetMgr = new TAssetMgr();
  if (assetMgr != nullptr) {
    assetMgr = ConstructUiViewManager(assetMgr);
  }
  ForwardEnsurePictWvDataGobLoadedBySlot(app->field_50);
  g_pUiViewManager = assetMgr;

  TViewMgr* viewMgr = new TViewMgr();
  if (viewMgr != nullptr) {
    viewMgr->LoadTurnEventCursorTable();
  }
  g_pUiRuntimeContext = viewMgr;

  TDisplayMgr* displayMgr = new TDisplayMgr();
  if (displayMgr != nullptr) {
    displayMgr->InitializeTurnOrderNavigationDialogByViewportSize();
  }
  g_pDisplayMgr = displayMgr;

  TMacViewMgr* mapView = new TMacViewMgr();
  if (mapView != nullptr) {
    InitializeStrategicMapViewSystem(mapView);
  }
  g_pStrategicMapViewSystem = mapView;

  THelpMgr** helpMgrSlot = reinterpret_cast<THelpMgr**>(0x006a21b8);
  if (*helpMgrSlot == nullptr) {
    THelpMgr* helpMgr = new THelpMgr();
    if (helpMgr == nullptr) {
      *helpMgrSlot = nullptr;
    } else {
      *helpMgrSlot = ConstructTHelpMgrBaseState(helpMgr);
    }
  }
  if (*helpMgrSlot != nullptr) {
    (*helpMgrSlot)->InitializeHelpManagerIndexArrayAndState();
  }

  if (g_pGameFlowState != nullptr) {
    reinterpret_cast<TObject*>(g_pGameFlowState)->Free();
    g_pGameFlowState = nullptr;
  }

  Config configScratch;
  g_pGameFlowState = configScratch.InitDefaults();
}

// FUNCTION: IMPERIALISM 0x00412a70
void* InvokeAfxThreadVslot7CAndGetValueAtOffset98() {
  return GetObjectValueAtOffset98(GetMainContextFromActiveThread());
}

// FUNCTION: IMPERIALISM 0x005e7a80
void* SetGlobalCallback6A7FACAndReturnPrevious(void* callback) {
  extern undefined4 EnterIndexedCriticalSectionWithLazyInit();
  extern undefined4 LeaveIndexedCriticalSection();
  reinterpret_cast<void(__cdecl*)(int)>(EnterIndexedCriticalSectionWithLazyInit)(9);
  void* prev = g_pGlobalCallback_006a7fac;
  g_pGlobalCallback_006a7fac = callback;
  reinterpret_cast<void(__cdecl*)(int)>(LeaveIndexedCriticalSection)(9);
  return prev;
}
