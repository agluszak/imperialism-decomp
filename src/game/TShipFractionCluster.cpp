#include "game/TShipFractionCluster.h"
#include "game/TWindow.h"

#include "game/TOcean.h"
#include "game/TTaskForce.h"
#include "game/TTechMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x0044a6f0
TShipFractionCluster::TShipFractionCluster() {}

// SYNTHETIC: IMPERIALISM 0x0044a720
// TShipFractionCluster::`scalar deleting destructor'
TShipFractionCluster::~TShipFractionCluster() {}
// SYNTHETIC: IMPERIALISM 0x00568cd0
// TShipFractionCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x00568d50
// TShipFractionCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipFractionCluster, TCluster)

// FUNCTION: IMPERIALISM 0x00568d70
void TShipFractionCluster::DoPostCreate(int arg) {
  TCluster::DoPostCreate(arg);

  mainSelectionView8c = GetWindow()->ResolveControlByTag(kControlTagMain);
  mainSelectionView8c->AssertValid();

  TView* shipControl = ResolveControlByTag(kControlTagShip);
  shipControl->AssertValid();

  short slot = GetEnabledIndustryCapabilitySlotByClass(static_cast<short>(controlTag - 0x7330));
  if (slot != 0) {
    // The original also calls shipControl's own vtbl slot 0x1c8 (LoadUiStringAndDispatch
    // ViaVslot1C8-shaped) here with a computed (slot + 0x5e6, 0) argument pair -- exact
    // group/index semantics not resolved, so left unmodeled.
    LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2716, static_cast<short>(slot + 1),
                                                          controlTag);
    SetEnabled(1, 1);
  } else {
    SetEnabled(0, 1);
    SetControlHoverHelpText(CString(g_pShipFractionSharedText_0065c830), this);
  }

  shipCountButton90 = static_cast<TNumberedArrowButton*>(ResolveControlByTag(kControlTagArro));
  availableShipCount88 = 1;
  SetAvailableAndSelectedShipCounts(0, -1);
}

// FUNCTION: IMPERIALISM 0x00568eb0
void TShipFractionCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x64) {
    if (selectedShipCount94 < availableShipCount88) {
      selectedShipCount94 = static_cast<short>(selectedShipCount94 + 1);
      shipCountButton90->SetValue(selectedShipCount94, 1);
      SelectTaskForceOrderForActiveNationClass(1);
    }
  } else if (commandId == 0x65) {
    if (selectedShipCount94 > 0) {
      selectedShipCount94 = static_cast<short>(selectedShipCount94 - 1);
      shipCountButton90->SetValue(selectedShipCount94, 1);
      SelectTaskForceOrderForActiveNationClass(0);
    }
  } else {
    TCluster::DoEvent(commandId, sourceHandler, event);
  }
}

// Shared tail for the increment/decrement handlers above: reselects this cluster's task
// force order entry for the active nation class and notifies the main selection view's
// listener.
void TShipFractionCluster::SelectTaskForceOrderForActiveNationClass(char activeFlag) {
  g_pActiveMapOrderContext->selectedTaskForce14->Select(static_cast<short>(controlTag - 0x7330),
                                                        activeFlag);
  // TODO: the original then calls mainSelectionView8c's own vtable slot 0x1b0 with an arg
  // read from a sub-object at mainSelectionView8c+0xa0
  // (NotifyTaskForceSelectionListenerByWord62, 0x599a20). Its concrete class beyond
  // TView isn't confirmed, so this notify step is left unmodeled rather than guessing a
  // type for the +0xa0 field.
}

// The original names this via a stale/reused symbol ("TToolBarCluster::..."); confirmed as
// a real TShipFractionCluster method by receiver evidence (ResolveControlByTag(kControlTagShip),
// availableShipCount88/shipCountButton90 matching this class's own layout). The Mac
// symbol oracle calls this method Set(int, int); Windows callers pass the available and
// selected ship counts respectively.
// FUNCTION: IMPERIALISM 0x00568f90
void TShipFractionCluster::SetAvailableAndSelectedShipCounts(int availableCount,
                                                             int selectedCount) {
  TView* shipControl = ResolveControlByTag(kControlTagShip);
  if (availableCount != 0) {
    if (availableShipCount88 == 0) {
      short slot = GetEnabledIndustryCapabilitySlotByClass(static_cast<short>(controlTag - 0x7330));
      shipControl->SetEnabled(1, 1);
      shipCountButton90->SetEnabled(1, 1);
      LoadUiStringByGroupAndIndexToGlobalControlTag(0x2716, static_cast<short>(slot + 1),
                                                    controlTag);
    }
  } else if (availableShipCount88 != 0) {
    shipControl->SetEnabled(0, 1);
    shipCountButton90->SetEnabled(0, 1);
    SetControlHoverHelpTextAltEntry(CString(g_pShipFractionSharedText_0065c830), this);
  }

  RefreshControl();
  availableShipCount88 = static_cast<short>(availableCount);
  selectedShipCount94 = static_cast<short>(availableCount);
  if (selectedCount > -1) {
    selectedShipCount94 = static_cast<short>(selectedCount);
  }
  if (availableCount > 0) {
    shipCountButton90->SetValue(selectedShipCount94, 1);
  }
}
