#include "game/navy_ui/TShipFractionCluster.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/ui_core/TWindow.h"

#include "game/navy/TOcean.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TPicture.h"
#include "game/navy/TTaskForce.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/navy_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x0044a6f0
TShipFractionCluster::TShipFractionCluster() {}

// FUNCTION: IMPERIALISM 0x0044a750
TShipFractionCluster::~TShipFractionCluster() {}

IMPLEMENT_DYNCREATE(TShipFractionCluster, TCluster)

// FUNCTION: IMPERIALISM 0x00568d70
void TShipFractionCluster::DoPostCreate(int arg) {
  TCluster::DoPostCreate(arg);

  mainSelectionView =
      static_cast<TMapUberPicture*>(GetWindow()->ResolveControlByTag(kControlTagMain));
  mainSelectionView->AssertValid();

  TPicture* shipControl = static_cast<TPicture*>(ResolveControlByTag(kControlTagShip));
  shipControl->AssertValid();

  short slot = GetEnabledIndustryCapabilitySlotByClass(static_cast<short>(controlTag - 0x7330));
  if (slot != 0) {
    shipControl->SetPictureRsrcID(static_cast<short>(slot + 0x5e6), 0);
    LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2716, static_cast<short>(slot + 1),
                                                          controlTag);
    Show(1, 1);
  } else {
    Show(0, 1);
    SetControlHoverHelpText(CString(g_pShipFractionSharedText), this);
  }

  shipCountButton = static_cast<TNumberedArrowButton*>(ResolveControlByTag(kControlTagArro));
  availableShipCount = 1;
  Set(0, -1);
}

// FUNCTION: IMPERIALISM 0x00568eb0
void TShipFractionCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x64) {
    if (selectedShipCount < availableShipCount) {
      selectedShipCount = static_cast<short>(selectedShipCount + 1);
      shipCountButton->SetValue(selectedShipCount, true);
      g_pActiveMapOrderContext->selectedTaskForce->Select(static_cast<short>(controlTag - 0x7330),
                                                          1);
      mainSelectionView->UpdateRoster();
    }
  } else if (commandId == 0x65) {
    if (selectedShipCount > 0) {
      selectedShipCount = static_cast<short>(selectedShipCount - 1);
      shipCountButton->SetValue(selectedShipCount, true);
      g_pActiveMapOrderContext->selectedTaskForce->Select(static_cast<short>(controlTag - 0x7330),
                                                          0);
      mainSelectionView->UpdateRoster();
    }
  } else {
    TCluster::DoEvent(commandId, sourceHandler, event);
  }
}

// FUNCTION: IMPERIALISM 0x00568f90
void TShipFractionCluster::Set(int availableCount, int selectedCount) {
  TView* shipControl = ResolveControlByTag(kControlTagShip);
  if (availableCount != 0) {
    if (availableShipCount == 0) {
      short slot = GetEnabledIndustryCapabilitySlotByClass(static_cast<short>(controlTag - 0x7330));
      shipControl->Show(1, 1);
      shipCountButton->Show(1, 1);
      LoadUiStringByGroupAndIndexToGlobalControlTag(0x2716, static_cast<short>(slot + 1),
                                                    controlTag);
    }
  } else if (availableShipCount != 0) {
    shipControl->Show(0, 1);
    shipCountButton->Show(0, 1);
    SetControlHoverHelpTextAltEntry(CString(g_pShipFractionSharedText), this);
  }

  RefreshControl();
  availableShipCount = static_cast<short>(availableCount);
  selectedShipCount = static_cast<short>(availableCount);
  if (selectedCount > -1) {
    selectedShipCount = static_cast<short>(selectedCount);
  }
  if (availableCount > 0) {
    shipCountButton->SetValue(selectedShipCount, true);
  }
}

// FUNCTION: IMPERIALISM 0x005690d0
void TShipFractionCluster::IncrementSelectedShipCount(unsigned char displayOnly) {
  if (selectedShipCount < availableShipCount) {
    selectedShipCount = static_cast<short>(selectedShipCount + 1);
    shipCountButton->SetValue(selectedShipCount, true);
    if (displayOnly == 0) {
      g_pActiveMapOrderContext->selectedTaskForce->Select(static_cast<short>(controlTag - 0x7330),
                                                          1);
      mainSelectionView->UpdateRoster();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00569150
void TShipFractionCluster::DecrementSelectedShipCount(unsigned char displayOnly) {
  if (selectedShipCount > 0) {
    selectedShipCount = static_cast<short>(selectedShipCount - 1);
    shipCountButton->SetValue(selectedShipCount, true);
    if (displayOnly == 0) {
      g_pActiveMapOrderContext->selectedTaskForce->Select(static_cast<short>(controlTag - 0x7330),
                                                          0);
      mainSelectionView->UpdateRoster();
    }
  }
}
