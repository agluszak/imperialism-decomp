#include "game/ui_core/TTurnEventDialogFactoryRegistry.h"
#include "game/ui_tags_common.h"

#include "game/CSubViewIterator.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/turn_event_dialog_factory.h"

// FUNCTION: IMPERIALISM 0x00491960
CSubViewIterator::CSubViewIterator(const TView* owner, char forward) {
  // Same as the single-arg ctor below except the direction comes from the caller;
  // position00 is likewise left uninitialised until FirstSubView().
  ownerView04 = owner;
  direction08 = forward;
  identTag = kControlTagSpSpSpSp;
  currentChild10 = nullptr;
}

// FUNCTION: IMPERIALISM 0x004919a0
CSubViewIterator::CSubViewIterator(const TView* owner) {
  // The single-arg (const TView*) ctor defaults the traversal forward; position00 is left
  // uninitialised until FirstSubView(), matching the original (which never writes +0 here).
  ownerView04 = owner;
  direction08 = 1;
  identTag = kControlTagSpSpSpSp;
  currentChild10 = nullptr;
}

// FUNCTION: IMPERIALISM 0x00491a00
TView* CSubViewIterator::FirstSubView() {
  TViewChildList* list = ownerView04->childList;
  if (list == nullptr) {
    position00 = nullptr;
  } else {
    position00 = (direction08 != 0) ? list->GetHeadPosition() : list->GetTailPosition();
  }
  if (position00 == nullptr) {
    currentChild10 = nullptr;
    return currentChild10;
  }
  currentChild10 = (direction08 != 0) ? list->GetNext(position00) : list->GetPrev(position00);
  return currentChild10;
}

// FUNCTION: IMPERIALISM 0x00491a70
TView* CSubViewIterator::NextSubView() {
  if (position00 == nullptr) {
    currentChild10 = nullptr;
    return currentChild10;
  }
  // GetNext/GetPrev only touch the node, not the list object; the owner's childList is
  // named only to satisfy the member-call form and is optimised away.
  TViewChildList* list = ownerView04->childList;
  currentChild10 = (direction08 != 0) ? list->GetNext(position00) : list->GetPrev(position00);
  return currentChild10;
}

// FUNCTION: IMPERIALISM 0x00491ab0
int CSubViewIterator::MoreSubViews() {
  // Returns int (not bool), matching the sibling CIterator::More(): call sites test the
  // full eax register.
  return currentChild10 != nullptr;
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

// The `factories` CList<TurnEventDialogFactoryProc,TurnEventDialogFactoryProc> member's own
// compiler-emitted serializer/destructor, called through the member's CList vtable and from
// the complete-object destructor above.

// Empty in source: the 116 bytes at 0x00491b40 are all compiler output (EH frame plus
// the inlined destruction of the `factories` CList member).
// FUNCTION: IMPERIALISM 0x00491b40
TTurnEventDialogFactoryRegistry::~TTurnEventDialogFactoryRegistry() {}

// FUNCTION: IMPERIALISM 0x00491be0
void TTurnEventDialogFactoryRegistry::RegisterDialogFactoryCallback(
    TurnEventDialogFactoryProc factory) {
  factories.AddTail(factory);
}

// FUNCTION: IMPERIALISM 0x00491c80
TView*
TTurnEventDialogFactoryRegistry::ResolveDialogNodeByMessageContext(TurnEventId messageContext,
                                                                   int contextSlot) {
  CPoint anchor(0, 0);
  return InvokeDialogFactoryFromPacket(contextSlot, nullptr, messageContext, anchor);
}

// FUNCTION: IMPERIALISM 0x00491cc0
TView* TTurnEventDialogFactoryRegistry::RunRegisteredDialogFactoriesByEventCode(
    int nContextId, TView* pEventPacket, TurnEventId nEventCode, const CPoint& anchorPoint) {
  (void)nContextId;
  TView* result = nullptr;
  POSITION pos = factories.GetHeadPosition();
  while (pos != 0) {
    TurnEventDialogFactoryProc factory = factories.GetNext(pos);
    result = factory(0, static_cast<int>(nEventCode));
    if (result != nullptr) {
      break;
    }
  }

  if (result != nullptr) {
    if (pEventPacket != nullptr) {
      pEventPacket->AttachChildControl(result, 0);
    }
    if (anchorPoint.y != 0 || anchorPoint.x != 0) {
      CPoint position;
      position.x = anchorPoint.x + result->ownerLocalX;
      position.y = result->ownerLocalY + anchorPoint.y;
      result->Locate(position, 0);
    }
  }

  return result;
}

// FUNCTION: IMPERIALISM 0x00491d80
TView* TTurnEventDialogFactoryRegistry::InvokeDialogFactoryFromPacket(int nContextId,
                                                                      TView* pEventPacket,
                                                                      TurnEventId nEventCode,
                                                                      const CPoint& anchorPoint) {
  const int savedFlag = g_McAppUiActiveFlag_006950AC;
  g_McAppUiActiveFlag_006950AC = 0;
  TView* result =
      RunRegisteredDialogFactoriesByEventCode(nContextId, pEventPacket, nEventCode, anchorPoint);
  if (result != nullptr) {
    result->DispatchControlEventToChildrenAndSelf(nContextId);
    result->NoOpUiCallback();
  }
  g_McAppUiActiveFlag_006950AC = savedFlag;
  return result;
}
