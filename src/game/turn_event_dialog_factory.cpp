#include "game/TTurnEventDialogFactoryRegistry.h"

#include "game/TView.h"

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
  (void)nEventCode;
  return nullptr;
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
