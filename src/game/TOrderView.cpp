#include "game/TOrderView.h"

#include "game/TCity.h"
#include "game/TEventHandler.h"
#include "game/TGreatPower.h"
#include "game/TIconBar.h"
#include "game/TIconSlider.h"
#include "game/TItemOrder.h"
#include "game/TPopulationMgr.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
// SYNTHETIC: IMPERIALISM 0x005069d0
// TOrderView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00506a60
// TOrderView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOrderView, TView)

// FUNCTION: IMPERIALISM 0x00506a80
TOrderView::TOrderView() : TView(), city60(0) {}

// SYNTHETIC: IMPERIALISM 0x00506ab0
// TOrderView::`scalar deleting destructor'
TOrderView::~TOrderView() {}

// FUNCTION: IMPERIALISM 0x00506b00
void TOrderView::StuffValues(TGreatPower* power, short orderSlot) {
  city60 = power != 0 ? power->city : 0;
  order64 = static_cast<TItemOrder*>(city60->orderSlotsE4[orderSlot]);
  if (order64 == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x210);
  }

  TIconSlider* slider = static_cast<TIconSlider*>(ResolveControlByTag(kControlTagSlid));
  if (slider == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x213);
  }
  slider->SetNumIcons(static_cast<short>(city60->GetBuildingType(order64->productionSlot)));
  slider->SetPictureResourceIdAndRefresh(static_cast<short>(orderSlot + 700), true);
  slider->value9c = order64->quantityField04;
  slider->SetMax(order64->MaxOrder());

  TIconBar* supplyPrimary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagSup1));
  if (supplyPrimary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x21c);
  }
  supplyPrimary->SetNumIcons(city60->CityStockByType(order64->primaryInputResourceId));
  supplyPrimary->SetPictureResourceIdAndRefresh(
      static_cast<short>(order64->primaryInputResourceId + 700), true);

  TIconBar* supplySecondary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagSup2));
  if (supplySecondary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x221);
  }
  if (order64->secondaryInputResourceId != -1) {
    supplySecondary->SetNumIcons(city60->CityStockByType(order64->secondaryInputResourceId));
    supplySecondary->SetPictureResourceIdAndRefresh(
        static_cast<short>(order64->secondaryInputResourceId + 700), true);
  }

  TIconBar* supplyLabor = static_cast<TIconBar*>(ResolveControlByTag(kControlTagSupl));
  if (supplyLabor == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x229);
  }
  supplyLabor->SetNumIcons(city60->productionSummary1d8->stockLevel1c);
  supplyLabor->SetPictureResourceIdAndRefresh(0x148, true);

  TIconBar* usePrimary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagUse1));
  if (usePrimary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x22e);
  }
  usePrimary->SetPictureResourceIdAndRefresh(
      static_cast<short>(order64->primaryInputResourceId + 700), true);
  usePrimary->SetNumIcons(order64->trackingSlots10[order64->primaryInputResourceId]);

  TIconBar* useSecondary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagUse2));
  if (useSecondary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x233);
  }
  if (order64->secondaryInputResourceId != -1) {
    useSecondary->SetNumIcons(order64->trackingSlots10[order64->secondaryInputResourceId]);
    useSecondary->SetPictureResourceIdAndRefresh(
        static_cast<short>(order64->secondaryInputResourceId + 700), true);
  }

  TIconBar* useLabor = static_cast<TIconBar*>(ResolveControlByTag(kControlTagUsel));
  if (useLabor == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x23b);
  }
  useLabor->SetPictureResourceIdAndRefresh(0x148, true);
  useLabor->SetNumIcons(static_cast<short>(order64->quantityField04 * 2));

  TIconBar* primaryIcon = static_cast<TIconBar*>(ResolveControlByTag(kControlTagIco1));
  primaryIcon->SetPictureResourceIdAndRefresh(
      static_cast<short>(order64->primaryInputResourceId + 700), true);
  TIconBar* secondaryIcon = static_cast<TIconBar*>(ResolveControlByTag(kControlTagIco2));
  secondaryIcon->SetPictureResourceIdAndRefresh(
      static_cast<short>(order64->secondaryInputResourceId + 700), true);
  TIconBar* laborIcon = static_cast<TIconBar*>(ResolveControlByTag(kControlTagIco3));
  laborIcon->SetPictureResourceIdAndRefresh(0x148, true);
}

// FUNCTION: IMPERIALISM 0x00506f90
void TOrderView::UpdateFields() {
  TIconBar* supplyPrimary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagSup1));
  if (supplyPrimary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x255);
  }
  supplyPrimary->SetNumIcons(city60->CityStockByType(order64->primaryInputResourceId));
  supplyPrimary->RefreshControl();

  TIconBar* supplySecondary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagSup2));
  if (supplySecondary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x25a);
  }
  if (order64->secondaryInputResourceId != -1) {
    supplySecondary->SetNumIcons(city60->CityStockByType(order64->secondaryInputResourceId));
    supplySecondary->RefreshControl();
  }

  TIconBar* supplyLabor = static_cast<TIconBar*>(ResolveControlByTag(kControlTagSupl));
  if (supplyLabor == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x262);
  }
  supplyLabor->SetNumIcons(city60->productionSummary1d8->stockLevel1c);
  supplyLabor->RefreshControl();

  TIconBar* usePrimary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagUse1));
  if (usePrimary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x267);
  }
  usePrimary->SetNumIcons(order64->trackingSlots10[order64->primaryInputResourceId]);
  usePrimary->RefreshControl();

  TIconBar* useSecondary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagUse2));
  if (useSecondary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x26c);
  }
  if (order64->secondaryInputResourceId != -1) {
    useSecondary->SetNumIcons(order64->trackingSlots10[order64->secondaryInputResourceId]);
    useSecondary->RefreshControl();
  }

  TIconBar* useLabor = static_cast<TIconBar*>(ResolveControlByTag(kControlTagUsel));
  if (useLabor == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x274);
  }
  useLabor->SetNumIcons(static_cast<short>(order64->quantityField04 * 2));
  useLabor->RefreshControl();
}

// FUNCTION: IMPERIALISM 0x00507240
void TOrderView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x6c) {
    TIconSlider* slider = static_cast<TIconSlider*>(ResolveControlByTag(kControlTagSlid));
    if (slider == nullptr) {
      FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x285);
    }
    order64->SetQuantity(slider->value9c);
    UpdateFields();
    return;
  }
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}
