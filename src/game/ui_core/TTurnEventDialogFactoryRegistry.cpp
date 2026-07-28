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
  identTag0c = kControlTagSpSpSpSp;
  currentChild10 = nullptr;
}

// FUNCTION: IMPERIALISM 0x004919a0
CSubViewIterator::CSubViewIterator(const TView* owner) {
  // The single-arg (const TView*) ctor defaults the traversal forward; position00 is left
  // uninitialised until FirstSubView(), matching the original (which never writes +0 here).
  ownerView04 = owner;
  direction08 = 1;
  identTag0c = kControlTagSpSpSpSp;
  currentChild10 = nullptr;
}

// FUNCTION: IMPERIALISM 0x00491a00
TView* CSubViewIterator::FirstSubView() {
  TViewChildList* list = ownerView04->childList44;
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
  // GetNext/GetPrev only touch the node, not the list object; the owner's childList44 is
  // named only to satisfy the member-call form and is optimised away.
  TViewChildList* list = ownerView04->childList44;
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

// SYNTHETIC: IMPERIALISM 0x00491b10
// TTurnEventDialogFactoryRegistry::`scalar deleting destructor'

// The `factories` CList<TurnEventDialogFactoryProc,TurnEventDialogFactoryProc> member's own
// compiler-emitted serializer/destructor, called through the member's CList vtable and from
// the complete-object destructor above.
// TEMPLATE: IMPERIALISM 0x004927e0
// ?Serialize@?$CList@P6APAVTView@@PAVCWnd@@H@ZP6APAV1@0H@Z@@UAEXAAVCArchive@@@Z

// TEMPLATE: IMPERIALISM 0x00492980
// ??_G?$CList@P6APAVTView@@PAVCWnd@@H@ZP6APAV1@0H@Z@@UAEPAXI@Z

// TEMPLATE: IMPERIALISM 0x004929b0
// ??1?$CList@P6APAVTView@@PAVCWnd@@H@ZP6APAV1@0H@Z@@UAE@XZ

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

void EnsureTurnEventDialogFactoryRegistryInitialized() {
  if (g_pTurnEventDialogFactoryRegistry != nullptr) {
    return;
  }
  g_pTurnEventDialogFactoryRegistry = new TTurnEventDialogFactoryRegistry();
  RegisterStartupDialogFactoryCallbacks(g_pTurnEventDialogFactoryRegistry);
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
      // Operand order follows the original: ADD EDX,EAX is anchor[0] + ownerLocalX
      // (0x00491d16) but ADD EAX,ECX is ownerLocalY + anchor[1] (0x00491d1b).
      // VC5 still schedules the +0x28 load ahead of +0x24 here and neither operand
      // reordering nor sequencing the first load into a local changes that (both
      // measured, both 92.59%), so the residual is left alone rather than contorted.
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
