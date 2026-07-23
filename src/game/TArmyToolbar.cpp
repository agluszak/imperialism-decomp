#include "game/TArmyToolbar.h"

#include <string.h>

#include "game/TArmyPlacard.h"
#include "game/TArmyMgr.h"
#include "game/TMapMgr.h"
#include "game/TMapUberPicture.h"
#include "game/TNumberedArrowButton.h"
#include "game/TPicture.h"
#include "game/TMilitaryUnit.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/ui_control_tags.h"

// SYNTHETIC: IMPERIALISM 0x0058de40
// TArmyToolbar::CreateObject
// SYNTHETIC: IMPERIALISM 0x0058dec0
// TArmyToolbar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyToolbar, TUnitToolbarCluster)

// FUNCTION: IMPERIALISM 0x0058dee0
TArmyToolbar::TArmyToolbar() : TUnitToolbarCluster() {}

// SYNTHETIC: IMPERIALISM 0x0058df10
// TArmyToolbar::`scalar deleting destructor'
TArmyToolbar::~TArmyToolbar() {}

// FUNCTION: IMPERIALISM 0x0058df60
void TArmyToolbar::SetProvince(short provinceIndex) {
  CString unusedCategoryLabel;
  int availableUnitCounts[10];
  memset(availableUnitCounts, 0, sizeof(availableUnitCounts));
  int totalUnitCounts[10];
  unsigned char hasUpgradeableUnit;

  memset(&hasUpgradeableUnit, 0, sizeof(hasUpgradeableUnit));
  selectedProvinceIndex = provinceIndex;
  memset(totalUnitCounts, 0, sizeof(totalUnitCounts));
  if (provinceIndex != -1) {
    TMilitaryUnit* unit;
    if (provinceIndex >= 0 && provinceIndex < 0x180) {
      unit = g_pGlobalMapState->cityScoreTable[provinceIndex].stationedUnitChain98;
    } else {
      unit = 0;
    }

    for (; unit != 0; unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
      short orderState = unit->unitOrder;
      switch (orderState) {
      case 0:
        ++availableUnitCounts[g_anArmyToolbarCategoryByUnitType[unit->orderType]];
      case 2:
      case 3:
      case 4:
        ++totalUnitCounts[g_anArmyToolbarCategoryByUnitType[unit->orderType]];
        break;
      }
      if (unit->CanUpgrade()) {
        hasUpgradeableUnit = 1;
      }
    }
  }

  for (int category = 0; category < 10; ++category) {
    TArmyPlacard* placard =
        static_cast<TArmyPlacard*>(ResolveControlByTag(kTagArmyPlacardMin + category));
    placard->SetValue(static_cast<short>(totalUnitCounts[category]), 1);

    TNumberedArrowButton* arrow =
        static_cast<TNumberedArrowButton*>(ResolveControlByTag(kTagArmyRatioMin + category));
    if (totalUnitCounts[category] != 0 && category != 0) {
      arrow->SetValue(static_cast<short>(availableUnitCounts[category]), 1);
      arrow->SetEnabled(1, 1);
    } else {
      arrow->SetEnabled(0, 1);
    }
  }

  short upgradePictureId = hasUpgradeableUnit ? 0x24d5 : 0x04b5;
  TPicture* upgradePicture = static_cast<TPicture*>(ResolveControlByTag(kTagArmyModeGarrison));
  upgradePicture->AssertValid();
  upgradePicture->SetPictureResourceIdAndRefresh(upgradePictureId, true);
  g_pUiRuntimeContext->RefreshMainViewNationIndicatorForCurrentTurnEvent();
}

// FUNCTION: IMPERIALISM 0x0058e1c0
void TArmyToolbar::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)event;
  unsigned int controlTag = sourceHandler->controlTag;

  if ((kTagArmyRatioMin <= controlTag) && (controlTag <= kTagArmyRatioMax)) {
    short categoryId = static_cast<short>(sourceHandler->controlTag);
    categoryId -= 0x7230;
    short selectedRatioOrMode = 0;
    if (commandId == 100) {
      selectedRatioOrMode =
          g_pMapContextActionManager->ActivateFirstActiveTacticalUnitByCategoryAtTile(
              categoryId, selectedProvinceIndex);
    } else {
      selectedRatioOrMode =
          g_pMapContextActionManager->ActivateFirstIdleTacticalUnitByCategoryAtTile(
              categoryId, selectedProvinceIndex);
    }
    static_cast<TNumberedArrowButton*>(sourceHandler)->SetValue(selectedRatioOrMode, 1);
    g_pUiRuntimeContext->RefreshMainViewNationIndicatorForCurrentTurnEvent();
    return;
  }

  if (controlTag == kTagArmyModeGarrison) {
    unsigned short ctrlState = (unsigned short)GetAsyncKeyState(0x11);
    if ((ctrlState & 0x8000) != 0) {
      g_pUiRuntimeContext->ShowArmyRosterDialogAndActivateProvinceSelection();
      return;
    }

    short mapSelection = g_pMapContextActionManager->pendingMapActionIndex;
    if (mapSelection != -1) {
      g_pUiRuntimeContext->HandleTurnEventDialogFactorySlotEC(mapSelection);
    }
    return;
  }

  if (controlTag == kTagArmyModeDefend) {
    g_pMapContextActionManager->SetOrdersForIdleUnitsOnPendingTile(2);
    g_pUiRuntimeContext->mapUberPictureF0->CycleMapInteractionSelectionAfterHandledClick();
    return;
  }

  if (controlTag == kTagArmyModeLater) {
    g_pMapContextActionManager->SetOrdersForIdleUnitsOnPendingTile(3);
    g_pUiRuntimeContext->mapUberPictureF0->CycleMapInteractionSelectionAfterHandledClick();
    return;
  }

  if (controlTag == kTagArmyModeDone) {
    g_pMapContextActionManager->SetOrdersForIdleUnitsOnPendingTile(4);
    g_pUiRuntimeContext->mapUberPictureF0->CycleMapInteractionSelectionAfterHandledClick();
  }
}
