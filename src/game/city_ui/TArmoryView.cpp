#include "game/city_ui/TArmoryView.h"

#include "game/assets/TAssetMgr.h"
#include "game/city/TCity.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/ui_core/TCluster.h"
#include "game/ui_core/TControl.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/city/TUnitOrder.h"
#include "game/globals/prelude.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x004cece0
// TArmoryView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ced80
// TArmoryView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmoryView, TBuildingView)

TArmoryView::TArmoryView() {}

// SYNTHETIC: IMPERIALISM 0x004cedd0
// TArmoryView::`scalar deleting destructor'
TArmoryView::~TArmoryView() {}

// FUNCTION: IMPERIALISM 0x004cee20
void TArmoryView::DoStartup() {}

// FUNCTION: IMPERIALISM 0x004cf350
void TArmoryView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    short index = static_cast<short>(sourceHandler->controlTag) - 0x7630; // 'rec0'..'rec8'
    if (index >= 0 && index < 9) {
      selectedRowIndexA4 = index;
      RefreshCityViewProductionDetails(index);
    }
  } else if (commandId == 0xa) {
    TView* ownerView = static_cast<TView*>(sourceHandler)->ownerContext;
    short index = static_cast<short>(ownerView->controlTag) - 0x7530;
    if (index >= 0 && index < 9) {
      if (selectedRowIndexA4 != index) {
        selectedRowIndexA4 = index;
        RefreshCityViewProductionDetails(index);

        // 'sele' is a TCluster (see TUniversityView::DoEvent's identical tail).
        TCluster* sele = static_cast<TCluster*>(ResolveControlByTag(0x73656c65u)); // 'sele'
        sele->AssertValid();
        sele->SetSelectedChildTagAndRefresh(0x63697630 + index); // 'civ0'+index
      }

      short newValue = selectedUnitOrderA8->quantityField04;
      if (sourceHandler->controlTag == 0x706c7573) { // 'plus'
        newValue++;
      } else {
        newValue--;
      }
      if (selectedUnitOrderA8->SetQuantity(newValue)) {
        TView* numXControl = ResolveControlByTag(0x6e756d30 + selectedRowIndexA4); // 'num0'+idx
        if (numXControl == nullptr) {
          MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
          TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityViews_00696650, 0xb87);
        }
        TNumberText* numbControl =
            static_cast<TNumberText*>(numXControl->ResolveControlByTag(0x6e756d62)); // 'numb'
        if (numbControl == nullptr) {
          MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
          TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityViews_00696650, 0xb88);
        }
        numbControl->SetControlValue(newValue, 0);

        CRect bounds;
        numbControl->QueryBounds(&bounds);
        RECT boundsCopy;
        CopyRect(&boundsCopy, &bounds);
        numXControl->InvalidateCityDialogRectRegion(&boundsCopy, 1);

        UpdateFields();
      }
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004cf5c0
void TArmoryView::UpdateFields() {
  CString treasuryText;
  TView* availabilityPanel = ResolveControlByTag(0x706c6171u); // 'plaq'
  availabilityPanel->AssertValid();

  COLORREF normalTextColor;
  COLORREF warningTextColor;
  ResolveUiThemeColor(0x2b6b, &normalTextColor);
  ResolveUiThemeColor(0x2b69, &warningTextColor);

  if (selectedUnitOrderA8 == 0) {
    return;
  }

  TNumberText* primaryAvailable =
      static_cast<TNumberText*>(ResolveControlByTag(0x61766131u)); // 'ava1'
  primaryAvailable->AssertValid();
  short primaryResource = selectedUnitOrderA8->primaryInputResourceId;
  if (primaryResource != -1) {
    short available = city94->CityStockByType(primaryResource);
    primaryAvailable->SetControlValue(available, 0);
    primaryAvailable->SetTextColorAndMaybeRefresh(
        available < selectedUnitOrderA8->primaryInputPerUnit ? &warningTextColor : &normalTextColor,
        false);
  }
  CRect invalidRect;
  primaryAvailable->QueryBounds(&invalidRect);
  availabilityPanel->InvalidateCityDialogRectRegion(&invalidRect, 1);

  TNumberText* secondaryAvailable =
      static_cast<TNumberText*>(ResolveControlByTag(0x61766132u)); // 'ava2'
  secondaryAvailable->AssertValid();
  short secondaryResource = selectedUnitOrderA8->secondaryInputResourceId;
  if (secondaryResource != -1) {
    short available = city94->CityStockByType(secondaryResource);
    secondaryAvailable->SetControlValue(available, 0);
    secondaryAvailable->SetTextColorAndMaybeRefresh(
        available < selectedUnitOrderA8->primaryInputPerUnit ? &warningTextColor : &normalTextColor,
        false);
  }
  secondaryAvailable->QueryBounds(&invalidRect);
  availabilityPanel->InvalidateCityDialogRectRegion(&invalidRect, 1);

  int treasury = city94->ownerNationAc->treasuryValue10;
  g_pSimMgr->NumToCurrency(treasury, &treasuryText);
  TStaticText* treasuryAvailable =
      static_cast<TStaticText*>(ResolveControlByTag(0x61766133u)); // 'ava3'
  treasuryAvailable->AssertValid();
  treasuryAvailable->SetTextAndMaybeRefresh(&treasuryText, 0);
  treasuryAvailable->SetTextColorAndMaybeRefresh(
      treasury < selectedUnitOrderA8->cashCostPerUnit ? &warningTextColor : &normalTextColor,
      false);
  treasuryAvailable->QueryBounds(&invalidRect);
  availabilityPanel->InvalidateCityDialogRectRegion(&invalidRect, 1);

  TPopulationMgr* population = city94->productionSummary1d8;
  short workforceAvailable;
  if (selectedUnitOrderA8->workforceMode == kLowSkillWorkforceMode) {
    workforceAvailable = population->strength;
    if (population->productionSlots14->lowSkillCount04 < workforceAvailable) {
      workforceAvailable = population->productionSlots14->lowSkillCount04;
    }
  } else if (selectedUnitOrderA8->workforceMode == kMediumSkillWorkforceMode) {
    workforceAvailable = static_cast<short>(population->strength / 2);
    if (population->productionSlots14->mediumSkillCount06 < workforceAvailable) {
      workforceAvailable = population->productionSlots14->mediumSkillCount06;
    }
  } else {
    workforceAvailable = static_cast<short>(population->strength / 4);
    if (population->productionSlots14->highSkillCount08 < workforceAvailable) {
      workforceAvailable = population->productionSlots14->highSkillCount08;
    }
  }

  TNumberText* workforceControl =
      static_cast<TNumberText*>(ResolveControlByTag(0x61766130u)); // 'ava0'
  workforceControl->AssertValid();
  workforceControl->SetControlValue(workforceAvailable, 0);
  workforceControl->SetTextColorAndMaybeRefresh(
      workforceAvailable == 0 ? &warningTextColor : &normalTextColor, false);
  workforceControl->QueryBounds(&invalidRect);
  availabilityPanel->InvalidateCityDialogRectRegion(&invalidRect, 1);

  productionView98->UpdateUnits();
}

// FUNCTION: IMPERIALISM 0x004cfbd0
void TArmoryView::RefreshCityViewProductionDetails(short nBuildingSlotId) {}

// FUNCTION: IMPERIALISM 0x004d0470
void TArmoryView::Free() {
  TView::Free();
  if (g_nSaveFormatVersion != 0x4d6f696c) { // 'Moil'
    g_pUiViewManager->CloseFilesFor(0x23f8);
  }
}
