#include "game/TTurnEventDialogFactoryRegistry.h"

#include "game/TView.h"
#include "game/mfc.h"
#include "game/global_data_tables.h"
#include "game/turn_event_dialog_factory.h"

// Cursor over a container's SelectableTextOptionEntry list (built by
// BeginSelectableTextOptionEntryIterator, 0x00491a00, which is still an autogen stub
// pending the container/node type recovery). Fields named by offset from the iterator
// bodies: the traversal walks the container's +0x44 root using direction08 to pick the
// forward/backward links, caching the resolved entry pointer in currentEntry10. IsValid
// (0x00491ab0) simply reports whether that cached entry is non-null.
struct TSelectableTextOptionEntryIterator {
  void* currentNode00;  // +0x00 current tree/list node
  void* container04;    // +0x04 owning container (root at +0x44)
  int direction08;      // +0x08 traversal direction/mode
  int field0c;          // +0x0c
  void* currentEntry10; // +0x10 resolved current entry (validity field)

  bool IsValid(); // 0x00491ab0
};

// FUNCTION: IMPERIALISM 0x00491ab0
bool TSelectableTextOptionEntryIterator::IsValid() {
  return currentEntry10 != nullptr;
}

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

// The complete-object destructor companion to the scalar deleting destructor above; both
// are compiler-emitted from the same `~TTurnEventDialogFactoryRegistry() {}` body below
// (bd 1uj.44: previously misattributed to the junk placeholder class
// TTurnEventDialogFactoryRegistryState_0064B328).
// SYNTHETIC: IMPERIALISM 0x00491b40
// TTurnEventDialogFactoryRegistry::~TTurnEventDialogFactoryRegistry

// The `factories` CList<TurnEventDialogFactoryProc,TurnEventDialogFactoryProc> member's own
// compiler-emitted serializer/destructor, called through the member's CList vtable and from
// the complete-object destructor above.
// TEMPLATE: IMPERIALISM 0x004927e0
// ?Serialize@?$CList@P6APAVTView@@PAVCWnd@@H@ZP6APAV1@0H@Z@@UAEXAAVCArchive@@@Z

// TEMPLATE: IMPERIALISM 0x00492980
// ??_G?$CList@P6APAVTView@@PAVCWnd@@H@ZP6APAV1@0H@Z@@UAEPAXI@Z

// TEMPLATE: IMPERIALISM 0x004929b0
// ??1?$CList@P6APAVTView@@PAVCWnd@@H@ZP6APAV1@0H@Z@@UAE@XZ

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

  if (result != nullptr) {
    if (pEventPacket != nullptr) {
      pEventPacket->AttachChildControl(result, 0);
    }
    if (pAnchorPoint[1] != 0 || pAnchorPoint[0] != 0) {
      int layout[2];
      layout[0] = pAnchorPoint[0] + result->ownerLocalX;
      layout[1] = pAnchorPoint[1] + result->ownerLocalY;
      result->CaptureLayoutF0(layout, 0);
    }
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
