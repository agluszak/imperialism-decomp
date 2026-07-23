#include "game/navy_ui/TShipFractionCluster.h"
#include "game/ui_core/TWindow.h"

#include "game/navy/TOcean.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TPicture.h"
#include "game/navy/TTaskForce.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
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

  mainSelectionView8c =
      static_cast<TMapUberPicture*>(GetWindow()->ResolveControlByTag(kControlTagMain));
  mainSelectionView8c->AssertValid();

  TPicture* shipControl = static_cast<TPicture*>(ResolveControlByTag(kControlTagShip));
  shipControl->AssertValid();

  short slot = GetEnabledIndustryCapabilitySlotByClass(static_cast<short>(controlTag - 0x7330));
  if (slot != 0) {
    shipControl->SetPictureResourceIdAndRefresh(static_cast<short>(slot + 0x5e6), 0);
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
      g_pActiveMapOrderContext->selectedTaskForce14->Select(static_cast<short>(controlTag - 0x7330),
                                                            1);
      mainSelectionView8c->UpdateRoster();
    }
  } else if (commandId == 0x65) {
    if (selectedShipCount94 > 0) {
      selectedShipCount94 = static_cast<short>(selectedShipCount94 - 1);
      shipCountButton90->SetValue(selectedShipCount94, 1);
      g_pActiveMapOrderContext->selectedTaskForce14->Select(static_cast<short>(controlTag - 0x7330),
                                                            0);
      mainSelectionView8c->UpdateRoster();
    }
  } else {
    TCluster::DoEvent(commandId, sourceHandler, event);
  }
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
