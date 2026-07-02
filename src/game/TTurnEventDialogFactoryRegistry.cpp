#include "game/TTurnEventDialogFactoryRegistry.h"

#include "game/TView.h"
#include "game/mfc.h"
#include "game/global_data_tables.h"

TView* __cdecl BuildTradeSchoolDialogControls(int nContextSlot, int nEventCode);
TView* __cdecl InitializeIndustryOverviewPlacardsAndTradeStatusTags(int nContextSlot,
                                                                    int nEventCode);
TView* __cdecl InitializeIndustryViewTradeMoveControlsAndCommodityRows(int nContextSlot,
                                                                       int nEventCode);
TView* __cdecl BuildTurnEventDialogResourcesForEvent547Or7D8(int nContextSlot, int nEventCode);
TView* __cdecl InitializeDealBookScreenControlsAndCommandTags(int nContextSlot, int nEventCode);
TView* __cdecl BuildTurnEventDialogUiByCode(int nContextSlot, int nEventCode);
TView* __cdecl InitializeArmyNavyReportViewsAndCommandTags(int nContextSlot, int nEventCode);
TView* __cdecl BuildTurnEventDialogResources_2508(int nContextSlot, int nEventCode);
TView* __cdecl InitializeJoinSelectorDialogControlsAndNationSlots(int nContextSlot, int nEventCode);
TView* __cdecl BuildUiResourceTreeByTemplateIdAndBindScreenContext(int nContextSlot,
                                                                   int nEventCode);
TView* __cdecl InitializeGameSetupScreenControlsAndModeTags(int nContextSlot, int nEventCode);
TView* __cdecl InitializeTacticalBattleViewToolbarAndDialogControls(int nContextSlot,
                                                                    int nEventCode);
TView* __cdecl BuildTurnEventDialogResourcesForEvent898(int nContextSlot, int nEventCode);
TView* __cdecl BuildTurnEventDialogResourcesForEvent8FC(int nContextSlot, int nEventCode);
TView* __cdecl InitializeTradeScreenBitmapControls(int nContextSlot, int nEventCode);
TView* __cdecl BuildTurnEventDialogResourcesForEvent7DE(int nContextSlot, int nEventCode);
TView* __cdecl BuildUniversityDialogShell(int nContextSlot, int nEventCode);

void RegisterStartupDialogFactoryCallbacks(TTurnEventDialogFactoryRegistry* registry) {
  static TurnEventDialogFactoryProc kStartupFactories[] = {
      BuildTradeSchoolDialogControls,
      InitializeIndustryOverviewPlacardsAndTradeStatusTags,
      InitializeIndustryViewTradeMoveControlsAndCommodityRows,
      BuildTurnEventDialogResourcesForEvent547Or7D8,
      InitializeDealBookScreenControlsAndCommandTags,
      BuildTurnEventDialogUiByCode,
      InitializeArmyNavyReportViewsAndCommandTags,
      BuildTurnEventDialogResources_2508,
      InitializeJoinSelectorDialogControlsAndNationSlots,
      BuildUiResourceTreeByTemplateIdAndBindScreenContext,
      InitializeGameSetupScreenControlsAndModeTags,
      InitializeTacticalBattleViewToolbarAndDialogControls,
      BuildTurnEventDialogResourcesForEvent898,
      BuildTurnEventDialogResourcesForEvent8FC,
      InitializeTradeScreenBitmapControls,
      BuildTurnEventDialogResourcesForEvent7DE,
      BuildUniversityDialogShell,
  };
  const int factoryCount = sizeof(kStartupFactories) / sizeof(kStartupFactories[0]);
  int factoryIndex;
  for (factoryIndex = 0; factoryIndex < factoryCount; ++factoryIndex) {
    registry->RegisterDialogFactoryCallback(kStartupFactories[factoryIndex]);
  }
}

// FUNCTION: IMPERIALISM 0x00491ad0
TTurnEventDialogFactoryRegistry::TTurnEventDialogFactoryRegistry() : TObject(), factories(10) {}

// SYNTHETIC: IMPERIALISM 0x00491b10
// TTurnEventDialogFactoryRegistry::`scalar deleting destructor'
TTurnEventDialogFactoryRegistry::~TTurnEventDialogFactoryRegistry() {}

// FUNCTION: IMPERIALISM 0x00491be0
void TTurnEventDialogFactoryRegistry::RegisterDialogFactoryCallback(
    TurnEventDialogFactoryProc factory) {
  factories.AddTail(factory);
}

// FUNCTION: IMPERIALISM 0x00491c80
TView* TTurnEventDialogFactoryRegistry::ResolveDialogNodeByMessageContext(int messageContext,
                                                                          int contextSlot) {
  int anchor[2] = {0, 0};
  return InvokeDialogFactoryFromPacket(contextSlot, nullptr, messageContext, anchor);
}

void EnsureTurnEventDialogFactoryRegistryInitialized() {
  if (g_pTurnEventDialogFactoryRegistry != nullptr) {
    return;
  }
  g_pTurnEventDialogFactoryRegistry = new TTurnEventDialogFactoryRegistry();
  RegisterStartupDialogFactoryCallbacks(g_pTurnEventDialogFactoryRegistry);
}

// FUNCTION: IMPERIALISM 0x00491cc0
TView* TTurnEventDialogFactoryRegistry::RunRegisteredDialogFactoriesByEventCode(int nContextId,
                                                                                TView* pEventPacket,
                                                                                int nEventCode,
                                                                                int* pAnchorPoint) {
  (void)nContextId;
  TView* result = nullptr;
  POSITION pos = factories.GetHeadPosition();
  while (pos != 0) {
    TurnEventDialogFactoryProc factory = factories.GetNext(pos);
    result = factory(0, nEventCode);
    if (result != nullptr) {
      break;
    }
  }

  if (result == nullptr) {
    return nullptr;
  }

  if (pEventPacket != nullptr) {
    pEventPacket->AttachChildControl(result, 0);
  }
  if (pAnchorPoint[1] != 0 || pAnchorPoint[0] != 0) {
    int layout[2];
    layout[0] = pAnchorPoint[0] + result->ownerOffsetX;
    layout[1] = pAnchorPoint[1] + result->ownerOffsetY;
    result->CaptureLayoutF0(layout, 0);
  }

  return result;
}

// FUNCTION: IMPERIALISM 0x00491d80
TView* TTurnEventDialogFactoryRegistry::InvokeDialogFactoryFromPacket(int nContextId,
                                                                      TView* pEventPacket,
                                                                      int nEventCode,
                                                                      int* pAnchorPoint) {
  const int savedFlag = g_McAppUiActiveFlag_006950AC;
  g_McAppUiActiveFlag_006950AC = 0;
  TView* result =
      RunRegisteredDialogFactoriesByEventCode(nContextId, pEventPacket, nEventCode, pAnchorPoint);
  if (result != nullptr) {
    result->DispatchControlEventToChildrenAndSelf(nContextId);
    result->NoOpUiCallback();
  }
  g_McAppUiActiveFlag_006950AC = savedFlag;
  return result;
}
