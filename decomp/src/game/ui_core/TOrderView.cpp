#include "game/ui_core/TOrderView.h"
#include "game/ui_tags_widgets.h"

#include "game/city/TCity.h"
#include "game/ui_core/TEventHandler.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TIconBar.h"
#include "game/ui_screens/TIconSlider.h"
#include "game/city/TItemOrder.h"
#include "game/city/TPopulationMgr.h"
#include "game/gfx/ui_invalidation_guard.h"

IMPLEMENT_DYNCREATE(TOrderView, TView)

// FUNCTION: IMPERIALISM 0x00506a80
TOrderView::TOrderView() : TView(), city60(0) {}

// FUNCTION: IMPERIALISM 0x00506ae0
TOrderView::~TOrderView() {}

// FUNCTION: IMPERIALISM 0x00506b00
void TOrderView::StuffValues(TGreatPower* power, short orderSlot) {
  city60 = power != 0 ? power->city : 0;
  order = static_cast<TItemOrder*>(city60->orderSlots[orderSlot]);
  if (order == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x210);
  }

  TIconSlider* slider = static_cast<TIconSlider*>(ResolveControlByTag(kControlTagSlid));
  if (slider == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x213);
  }
  slider->SetNumIcons(static_cast<short>(city60->GetBuildingType(order->productionSlot)));
  slider->SetPictureRsrcID(static_cast<short>(orderSlot + 700), true);
  slider->value = order->quantity;
  slider->SetMax(order->MaxOrder());

  TIconBar* supplyPrimary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagSup1));
  if (supplyPrimary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x21c);
  }
  supplyPrimary->SetNumIcons(city60->CityStockByType(order->primaryInputResourceId));
  supplyPrimary->SetPictureRsrcID(static_cast<short>(order->primaryInputResourceId + 700), true);

  TIconBar* supplySecondary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagSup2));
  if (supplySecondary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x221);
  }
  if (order->secondaryInputResourceId != -1) {
    supplySecondary->SetNumIcons(city60->CityStockByType(order->secondaryInputResourceId));
    supplySecondary->SetPictureRsrcID(static_cast<short>(order->secondaryInputResourceId + 700),
                                      true);
  }

  TIconBar* supplyLabor = static_cast<TIconBar*>(ResolveControlByTag(kControlTagSupl));
  if (supplyLabor == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x229);
  }
  supplyLabor->SetNumIcons(city60->productionSummary->strength);
  supplyLabor->SetPictureRsrcID(0x148, true);

  TIconBar* usePrimary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagUse1));
  if (usePrimary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x22e);
  }
  usePrimary->SetPictureRsrcID(static_cast<short>(order->primaryInputResourceId + 700), true);
  usePrimary->SetNumIcons(order->trackingSlots[order->primaryInputResourceId]);

  TIconBar* useSecondary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagUse2));
  if (useSecondary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x233);
  }
  if (order->secondaryInputResourceId != -1) {
    useSecondary->SetNumIcons(order->trackingSlots[order->secondaryInputResourceId]);
    useSecondary->SetPictureRsrcID(static_cast<short>(order->secondaryInputResourceId + 700), true);
  }

  TIconBar* useLabor = static_cast<TIconBar*>(ResolveControlByTag(kControlTagUsel));
  if (useLabor == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x23b);
  }
  useLabor->SetPictureRsrcID(0x148, true);
  useLabor->SetNumIcons(static_cast<short>(order->quantity * 2));

  TIconBar* primaryIcon = static_cast<TIconBar*>(ResolveControlByTag(kControlTagIco1));
  primaryIcon->SetPictureRsrcID(static_cast<short>(order->primaryInputResourceId + 700), true);
  TIconBar* secondaryIcon = static_cast<TIconBar*>(ResolveControlByTag(kControlTagIco2));
  secondaryIcon->SetPictureRsrcID(static_cast<short>(order->secondaryInputResourceId + 700), true);
  TIconBar* laborIcon = static_cast<TIconBar*>(ResolveControlByTag(kControlTagIco3));
  laborIcon->SetPictureRsrcID(0x148, true);
}

// FUNCTION: IMPERIALISM 0x00506f90
void TOrderView::UpdateFields() {
  TIconBar* supplyPrimary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagSup1));
  if (supplyPrimary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x255);
  }
  supplyPrimary->SetNumIcons(city60->CityStockByType(order->primaryInputResourceId));
  supplyPrimary->RefreshControl();

  TIconBar* supplySecondary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagSup2));
  if (supplySecondary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x25a);
  }
  if (order->secondaryInputResourceId != -1) {
    supplySecondary->SetNumIcons(city60->CityStockByType(order->secondaryInputResourceId));
    supplySecondary->RefreshControl();
  }

  TIconBar* supplyLabor = static_cast<TIconBar*>(ResolveControlByTag(kControlTagSupl));
  if (supplyLabor == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x262);
  }
  supplyLabor->SetNumIcons(city60->productionSummary->strength);
  supplyLabor->RefreshControl();

  TIconBar* usePrimary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagUse1));
  if (usePrimary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x267);
  }
  usePrimary->SetNumIcons(order->trackingSlots[order->primaryInputResourceId]);
  usePrimary->RefreshControl();

  TIconBar* useSecondary = static_cast<TIconBar*>(ResolveControlByTag(kControlTagUse2));
  if (useSecondary == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x26c);
  }
  if (order->secondaryInputResourceId != -1) {
    useSecondary->SetNumIcons(order->trackingSlots[order->secondaryInputResourceId]);
    useSecondary->RefreshControl();
  }

  TIconBar* useLabor = static_cast<TIconBar*>(ResolveControlByTag(kControlTagUsel));
  if (useLabor == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x274);
  }
  useLabor->SetNumIcons(static_cast<short>(order->quantity * 2));
  useLabor->RefreshControl();
}

// FUNCTION: IMPERIALISM 0x00507240
void TOrderView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x6c) {
    TIconSlider* slider = static_cast<TIconSlider*>(ResolveControlByTag(kControlTagSlid));
    if (slider == nullptr) {
      FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x285);
    }
    order->SetQuantity(slider->value);
    UpdateFields();
    return;
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}
