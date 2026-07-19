#include "game/TOrderView.h"

#include "game/TEventHandler.h"
#include "game/TIconSlider.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
// SYNTHETIC: IMPERIALISM 0x005069d0
// TOrderView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00506a60
// TOrderView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOrderView, TView)

// FUNCTION: IMPERIALISM 0x00506a80
TOrderView::TOrderView() : TView(), field60(0) {}

// SYNTHETIC: IMPERIALISM 0x00506ab0
// TOrderView::`scalar deleting destructor'
TOrderView::~TOrderView() {}

// FUNCTION: IMPERIALISM 0x00506b00
undefined TOrderView::PopulateDialogControlsFromSelectedProductionEntry() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00506f90
undefined TOrderView::RefreshOrderViewSupplyAndUseControlValues() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00507240
void TOrderView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x6c) {
    TIconSlider* slider = static_cast<TIconSlider*>(ResolveControlByTag(kControlTagSlid));
    if (slider == nullptr) {
      FailNilPointerWithAssert("D:\\Ambit\\Cross\\UIcon.cpp", 0x285);
    }
    field64->SetControlValue(slider->field9c);
    RefreshOrderViewSupplyAndUseControlValues();
    return;
  }
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}
