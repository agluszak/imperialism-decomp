#include "game/TTurnEventDialogFactoryRegistry.h"

#include "game/TGameWindow.h"
#include "game/TView.h"
#include "game/global_data_tables.h"

extern void PushUiResourcePoolNode(void);
extern void PopUiResourcePoolNode_00479A80(void);
extern unsigned char* ZeroUiResourceContextStyleBytes(unsigned char* buffer);

#include "game/ui_control_tags.h"

namespace {

TView* BuildTurnOrderNavigationWindow(int offsetX, int offsetY, int width, int height,
                                      unsigned short layoutModeWord) {
  TGameWindow* window = new TGameWindow();
  if (window == 0) {
    return 0;
  }

  if (g_pUiResourceHead == 0) {
    g_pUiResourceHead = window;
  }
  g_pUiResourceContext = window;

  PushUiResourcePoolNode();

  int offsetLayout[2] = {offsetX, offsetY};
  int sizeLayout[2] = {width, height};
  window->InitializeUiResourceEntryFrameAndParent(0, 0, offsetLayout, sizeLayout, 0, 0, 1);

  window->controlTag = static_cast<int>(kControlTagWind);
  window->field3c = 0;
  window->SetEnabled(1, 0);
  window->SetState(width, 0);
  window->flag4c = 1;
  window->flag4d = 1;

  if (window->field48 != 0) {
    delete[] window->field48;
    window->field48 = 0;
  }
  window->EnsureField48Buffer();
  if (window->field48 != 0) {
    ZeroUiResourceContextStyleBytes(reinterpret_cast<unsigned char*>(window->field48));
    window->field48[1] = 0;
    window->field48[0] = 0xffffff;
  }

  char* bytes = reinterpret_cast<char*>(window);
  bytes[0x6d] = 0;
  bytes[0x6e] = 1;
  bytes[0x6f] = 1;
  bytes[0x71] = 1;
  *reinterpret_cast<unsigned short*>(bytes + 0x60) = layoutModeWord;
  *reinterpret_cast<unsigned short*>(bytes + 0x9c) = 8;

  g_pUiResourceContext = 0;
  PopUiResourcePoolNode_00479A80();

  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(0);
  }
  return g_pUiResourceHead;
}

} // namespace

// Turn-event dialog factory callbacks registered by InitializeTurnEventDialogFactoryRegistry.
// Each is invoked as factory(0, nEventCode) from RunRegisteredDialogFactoriesByEventCode.

// FUNCTION: IMPERIALISM 0x00415fe0
TView* __cdecl BuildTradeSchoolDialogControls(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0041b6d0
TView* __cdecl InitializeIndustryViewTradeMoveControlsAndCommodityRows(int nContextSlot,
                                                                       int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x00427360
TView* __cdecl InitializeIndustryOverviewPlacardsAndTradeStatusTags(int nContextSlot,
                                                                     int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x004295a0
TView* __cdecl BuildTurnEventDialogResourcesForEvent547Or7D8(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x00430c50
TView* __cdecl InitializeDealBookScreenControlsAndCommandTags(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x004357b0
TView* __cdecl BuildTurnEventDialogUiByCode(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  g_pUiResourceHead = 0;

  switch (static_cast<unsigned short>(nEventCode)) {
  case 0x7d1:
    return BuildTurnOrderNavigationWindow(5, 0x32, 0x258, 400, 2);
  case 0x7d2:
    return BuildTurnOrderNavigationWindow(0, 0x28, 0x280, 0x1e0, 4);
  default:
    return nullptr;
  }
}

// FUNCTION: IMPERIALISM 0x0043dbc0
TView* __cdecl InitializeArmyNavyReportViewsAndCommandTags(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0044a810
TView* __cdecl BuildTurnEventDialogResources_2508(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0044af90
TView* __cdecl InitializeJoinSelectorDialogControlsAndNationSlots(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0044fbc0
TView* __cdecl BuildUiResourceTreeByTemplateIdAndBindScreenContext(int nContextSlot,
                                                                   int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x004538a0
TView* __cdecl InitializeGameSetupScreenControlsAndModeTags(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0045b100
TView* __cdecl InitializeTacticalBattleViewToolbarAndDialogControls(int nContextSlot,
                                                                    int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0045d520
TView* __cdecl BuildTurnEventDialogResourcesForEvent898(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0045e0b0
TView* __cdecl BuildTurnEventDialogResourcesForEvent8FC(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x004601b0
TView* __cdecl InitializeTradeScreenBitmapControls(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0046fd10
TView* __cdecl BuildTurnEventDialogResourcesForEvent7DE(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x004749a0
TView* __cdecl BuildUniversityDialogShell(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x004793c0
int* CreateTurnEventDialogFactoryRegistryObject() {
  void* storage = new char[0x54];
  if (storage == nullptr) {
    return nullptr;
  }
  return InitializeTurnEventDialogFactoryRegistry(storage, (int*)storage);
}

// FUNCTION: IMPERIALISM 0x00479480
int* InitializeTurnEventDialogFactoryRegistry(void* storage, int* bootstrap) {
  (void)storage;
  EnsureTurnEventDialogFactoryRegistryInitialized();
  return bootstrap;
}

// FUNCTION: IMPERIALISM 0x00479710
void DestroyTurnEventDialogFactoryRegistryAndReleaseGlobalFactory(int* bootstrap) {
  if (g_pTurnEventDialogFactoryRegistry != nullptr) {
    delete g_pTurnEventDialogFactoryRegistry;
    g_pTurnEventDialogFactoryRegistry = nullptr;
  }
  (void)bootstrap;
}
