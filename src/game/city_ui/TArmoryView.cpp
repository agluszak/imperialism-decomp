#include "game/city_ui/TArmoryView.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"

#include "game/assets/TAssetMgr.h"
#include "game/city/TCity.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/ui_core/TCluster.h"
#include "game/ui_core/TControl.h"
#include "game/ui_widgets/TCivilianButton.h"
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

// A standalone out-of-line ctor DOES exist here: 0x4ceda0 is 32 bytes of base-ctor call,
// vptr store (0x652b10), `xor eax,eax` reused for BOTH dword [this+0x94] and [this+0x98],
// then `mov eax,esi` return-this. Zero both fields; claiming the address pairs at 90%.
// FUNCTION: IMPERIALISM 0x004ceda0
TArmoryView::TArmoryView() {
  city94 = 0;
  productionView98 = 0;
}

// SYNTHETIC: IMPERIALISM 0x004cedd0
// TArmoryView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004cee00
TArmoryView::~TArmoryView() {}

// FUNCTION: IMPERIALISM 0x004cee20
void TArmoryView::DoStartup() {
  productionView98 = g_pStrategicMapViewSystem->activeCityProductionView04;

  struct {
    TextStyle desc;
    unsigned char tail[4];
  } style;
  style.tail[0] = 0;
  style.tail[1] = 0;
  style.tail[2] = 0;
  style.tail[3] = 0;

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);

  for (short row = 0; row < 8; ++row) {
    TUnitOrder* order = static_cast<TUnitOrder*>(city94->orderSlotsE4[row + 0x19]);
    short resourceType = order->resourceTypeIndex48;
    short pictureVariant;
    if (g_awTacticalUnitCategoryCodeBySlot[resourceType] == 8) {
      if (resourceType == 0x18) {
        pictureVariant = 8;
      } else {
        pictureVariant = (resourceType == 0x19) ? 0x10 : 0x18;
      }
    } else {
      pictureVariant = (resourceType == 0x19) ? 0x10 : 0x18;
    }

    TCivilianButton* button =
        static_cast<TCivilianButton*>(ResolveControlByTag(kControlTagCiv0 + row)); // 'civ0'+row
    if (button == nullptr) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityViews_00696650, 0xb19);
    }
    button->SetPictureResourceIdAndRefresh(static_cast<short>(0x1d60 + 2 * pictureVariant), 1);

    TView* numRow = ResolveControlByTag(kControlTagNum0 + row); // 'num0'+row
    if (numRow == nullptr) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityViews_00696650, 0xb1c);
    }
    TNumberText* numb =
        static_cast<TNumberText*>(numRow->ResolveControlByTag(kControlTagNumb)); // 'numb'
    if (numb == nullptr) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityViews_00696650, 0xb1d);
    }
    numb->SetState(0, 0);
    numb->InstallTextStyle(style.desc, 1);
    numb->SetControlValue(order->quantityField04, 1);
  }

  BuildUiTextStyleDescriptor(&style.desc, 0, 0x18, 0x2b6b);
  TStaticText* title = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitl)); // 'titl'
  title->AssertValid();
  title->InstallTextStyle(style.desc, 1);
  title->SetTextFromStringResource(0x271c, 0x20, 1);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xc, 0x2b6b);
  TStaticText* unit = static_cast<TStaticText*>(ResolveControlByTag(kControlTagUnit)); // 'unit'
  unit->AssertValid();
  unit->InstallTextStyle(style.desc, 1);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);
  TStaticText* cost = static_cast<TStaticText*>(ResolveControlByTag(kControlTagCost)); // 'cost'
  cost->AssertValid();
  cost->InstallTextStyle(style.desc, 1);
  cost->SetTextFromStringResource(0x271c, 0x1e, 1);

  TStaticText* avai = static_cast<TStaticText*>(ResolveControlByTag(kControlTagAvai)); // 'avai'
  avai->AssertValid();
  avai->InstallTextStyle(style.desc, 1);
  avai->SetTextFromStringResource(0x271c, 0x1f, 1);

  for (short column = 0; column < 4; ++column) {
    TStaticText* current = static_cast<TStaticText*>(
        ResolveControlByTag(IMPERIALISM_FOURCC('c', 'o', 's', '0') + column)); // 'cos0'+column
    current->AssertValid();
    current->InstallTextStyle(style.desc, 1);

    TStaticText* available =
        static_cast<TStaticText*>(ResolveControlByTag(kControlTagAva0 + column)); // 'ava0'+column
    available->AssertValid();
    available->InstallTextStyle(style.desc, 1);

    TStaticText* status =
        static_cast<TStaticText*>(ResolveControlByTag(kControlTagSta0 + column)); // 'sta0'+column
    status->AssertValid();
    status->InstallTextStyle(style.desc, 1);

    TStaticText* label = static_cast<TStaticText*>(
        ResolveControlByTag(IMPERIALISM_FOURCC('l', 'a', 'b', '0') + column)); // 'lab0'+column
    label->AssertValid();
    label->InstallTextStyle(style.desc, 1);
    label->SetTextFromStringResource(0x271c, static_cast<short>(column + 1), 1);
  }

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);
  TStaticText* description =
      static_cast<TStaticText*>(ResolveControlByTag(kControlTagDesc)); // 'desc'
  description->AssertValid();
  description->InstallTextStyle(style.desc, 1);

  selectedRowIndexA4 = -1;
  selectedUnitOrderA8 = 0;
  TCluster* selection = static_cast<TCluster*>(ResolveControlByTag(kControlTagSele)); // 'sele'
  selection->AssertValid();
  selection->SetSelectedChildTagAndRefresh(kControlTagCiv0); // 'civ0'
  RefreshCityViewProductionDetails(0);
}

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
        TCluster* sele = static_cast<TCluster*>(ResolveControlByTag(kControlTagSele)); // 'sele'
        sele->AssertValid();
        sele->SetSelectedChildTagAndRefresh(kControlTagCiv0 + index); // 'civ0'+index
      }

      short newValue = selectedUnitOrderA8->quantityField04;
      if (sourceHandler->controlTag == kControlTagPlus) { // 'plus'
        newValue++;
      } else {
        newValue--;
      }
      if (selectedUnitOrderA8->SetQuantity(newValue)) {
        TView* numXControl =
            ResolveControlByTag(kControlTagNum0 + selectedRowIndexA4); // 'num0'+idx
        if (numXControl == nullptr) {
          MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
          TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityViews_00696650, 0xb87);
        }
        TNumberText* numbControl =
            static_cast<TNumberText*>(numXControl->ResolveControlByTag(kControlTagNumb)); // 'numb'
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
  TView* availabilityPanel = ResolveControlByTag(kControlTagPlaq); // 'plaq'
  availabilityPanel->AssertValid();

  COLORREF normalTextColor;
  COLORREF warningTextColor;
  ResolveUiThemeColor(0x2b6b, &normalTextColor);
  ResolveUiThemeColor(0x2b69, &warningTextColor);

  if (selectedUnitOrderA8 == 0) {
    return;
  }

  TNumberText* primaryAvailable =
      static_cast<TNumberText*>(ResolveControlByTag(kControlTagAva1)); // 'ava1'
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
      static_cast<TNumberText*>(ResolveControlByTag(kControlTagAva2)); // 'ava2'
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
      static_cast<TStaticText*>(ResolveControlByTag(kControlTagAva3)); // 'ava3'
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
      static_cast<TNumberText*>(ResolveControlByTag(kControlTagAva0)); // 'ava0'
  workforceControl->AssertValid();
  workforceControl->SetControlValue(workforceAvailable, 0);
  workforceControl->SetTextColorAndMaybeRefresh(
      workforceAvailable == 0 ? &warningTextColor : &normalTextColor, false);
  workforceControl->QueryBounds(&invalidRect);
  availabilityPanel->InvalidateCityDialogRectRegion(&invalidRect, 1);

  productionView98->UpdateUnits();
}

// FUNCTION: IMPERIALISM 0x004cfbd0
void TArmoryView::RefreshCityViewProductionDetails(short nBuildingSlotId) {
  CString locationText;
  CString terrainText;
  CString resourceText;

  TUnitOrder* order = static_cast<TUnitOrder*>(city94->orderSlotsE4[nBuildingSlotId + 0x19]);
  if (selectedUnitOrderA8 == order) {
    return;
  }
  selectedUnitOrderA8 = order;

  struct {
    TextStyle desc;
    unsigned char tail[4];
  } style;
  style.tail[0] = 0;
  style.tail[1] = 0;
  style.tail[2] = 0;
  style.tail[3] = 0;

  // 'plaq' -- unit-type icon picture (resource base 0x1d9c + the recipe resource index).
  TPicture* plaq =
      static_cast<TPicture*>(ResolveControlByTag(IMPERIALISM_FOURCC('p', 'l', 'a', 'q')));
  plaq->AssertValid();
  plaq->SetPictureResourceIdAndRefresh(static_cast<short>(order->resourceTypeIndex48 + 0x1d9c), 1);

  // 'unit' -- the recipe headline text.
  BuildUiTextStyleDescriptor(&style.desc, 0, 0xc, 0x2b6b);
  TStaticText* unit =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('u', 'n', 'i', 't')));
  if (unit == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityViews_00696650, 0xc1a);
  }
  unit->InstallTextStyle(style.desc, 1);
  unit->SetTextFromStringResource(0x2717, 0, 1);

  // 'cos1' -- primary input per-unit count.
  TNumberText* cos1 =
      static_cast<TNumberText*>(ResolveControlByTag(IMPERIALISM_FOURCC('c', 'o', 's', '1')));
  cos1->AssertValid();
  cos1->SetControlValue(order->primaryInputPerUnit, 1);

  // 'cos2'/'ava2' -- secondary input; disabled when the recipe has no second input.
  TNumberText* ava2 =
      static_cast<TNumberText*>(ResolveControlByTag(IMPERIALISM_FOURCC('a', 'v', 'a', '2')));
  ava2->AssertValid();
  if (order->secondaryInputResourceId == -1) {
    ava2->SetState(0, 0);
    ava2->SetEnabled(0, 0);
  } else {
    ava2->SetState(0, 1);
    ava2->SetEnabled(1, 0);
    ava2->SetControlValue(order->secondaryInputPerUnit, 1);
  }

  // 'cos3' -- cash cost per unit.
  TStaticText* cos3 =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('c', 'o', 's', '3')));
  cos3->AssertValid();
  g_pSimMgr->NumToCurrency(selectedUnitOrderA8->cashCostPerUnit, &resourceText);
  cos3->SetTextAndMaybeRefresh(&resourceText, 1);
}

// FUNCTION: IMPERIALISM 0x004d0470
void TArmoryView::Free() {
  TView::Free();
  if (g_nSaveFormatVersion != kControlTagMoil) { // 'Moil'
    g_pUiViewManager->CloseFilesFor(0x23f8);
  }
}
