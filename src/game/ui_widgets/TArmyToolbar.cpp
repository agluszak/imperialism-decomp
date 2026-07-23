#include "game/ui_widgets/TArmyToolbar.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"

#include <string.h>

#include "game/ui_widgets/TArmyPlacard.h"
#include "game/military/TArmyMgr.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_widgets/TNumberedArrowButton.h"
#include "game/ui_core/TPicture.h"
#include "game/military/TMilitaryUnit.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/mfc.h"

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
        static_cast<TArmyPlacard*>(ResolveControlByTag(kControlTagArmyPlacardFirst + category));
    placard->SetValue(static_cast<short>(totalUnitCounts[category]), 1);

    TNumberedArrowButton* arrow = static_cast<TNumberedArrowButton*>(
        ResolveControlByTag(kControlTagArmyRatioFirst + category));
    if (totalUnitCounts[category] != 0 && category != 0) {
      arrow->SetValue(static_cast<short>(availableUnitCounts[category]), 1);
      arrow->SetEnabled(1, 1);
    } else {
      arrow->SetEnabled(0, 1);
    }
  }

  short upgradePictureId = hasUpgradeableUnit ? 0x24d5 : 0x04b5;
  TPicture* upgradePicture = static_cast<TPicture*>(ResolveControlByTag(kControlTagGarr));
  upgradePicture->AssertValid();
  upgradePicture->SetPictureResourceIdAndRefresh(upgradePictureId, true);
  g_pUiRuntimeContext->RefreshMainViewNationIndicatorForCurrentTurnEvent();
}

// FUNCTION: IMPERIALISM 0x0058e1c0
void TArmyToolbar::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)event;
  unsigned int controlTag = sourceHandler->controlTag;

  if ((kControlTagArmyRatioFirst <= controlTag) && (controlTag <= kControlTagArmyRatioLast)) {
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

  if (controlTag == kControlTagGarr) {
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

  if (controlTag == kControlTagDfnd) {
    g_pMapContextActionManager->OrphanCallChain_C1_I34_004a4260(2);
    g_pUiRuntimeContext->mapUberPictureF0->CycleMapInteractionSelectionAfterHandledClick();
    return;
  }

  if (controlTag == kControlTagLatr) {
    g_pMapContextActionManager->OrphanCallChain_C1_I34_004a4260(3);
    g_pUiRuntimeContext->mapUberPictureF0->CycleMapInteractionSelectionAfterHandledClick();
    return;
  }

  if (controlTag == kControlTagDone) {
    g_pMapContextActionManager->OrphanCallChain_C1_I34_004a4260(4);
    g_pUiRuntimeContext->mapUberPictureF0->CycleMapInteractionSelectionAfterHandledClick();
  }
}
