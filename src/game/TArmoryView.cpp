#include "game/TArmoryView.h"

#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/TEditText.h"
#include "game/TNumberText.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
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
undefined TArmoryView::OrphanRetStub_004c6fd0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004cf350
void TArmoryView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
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

        // 'sele' is a TCluster (see TUniversityView::HandleEvent's identical tail).
        TCluster* sele = static_cast<TCluster*>(ResolveControlByTag(0x73656c65u)); // 'sele'
        sele->AssertValid();
        sele->SetControlClassAndRefresh(0x63697630 + index); // 'civ0'+index
      }

      // stepEntryA8 is a step-adjustable numeric edit widget (field04 get/set + a
      // single-int SetControlValue matches TEditText::SetControlValue's real body,
      // 0x4906f0 -- not the base TEventHandler::SetControlValue byte-flag setter).
      short newValue = static_cast<short>(stepEntryA8->field04);
      if (sourceHandler->controlTag == 0x706c7573) { // 'plus'
        newValue++;
      } else {
        newValue--;
      }
      stepEntryA8->SetControlValue(newValue);

      // The original tests AL after this call, which -- since TEditText::SetControlValue
      // ends in the (always-taken here, field_94 unconstructed) DispatchSlot9CToLinkedChildren
      // no-op tail -- is really just the low byte of `newValue` left over in EAX from the
      // value computation above. For the small counts this widget holds, that means the
      // refresh below runs whenever the new value is nonzero.
      if (static_cast<unsigned char>(newValue) != 0) {
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

        RECT bounds;
        numbControl->QueryBounds(&bounds);
        RECT boundsCopy;
        CopyRect(&boundsCopy, &bounds);
        numXControl->InvalidateCityDialogRectRegion(&boundsCopy, 1);

        OrphanRetStub_004c6fb0();
      }
    }
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004cf5c0
undefined TArmoryView::OrphanRetStub_004c6fb0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004cfbd0
void TArmoryView::RefreshCityViewProductionDetails(short nBuildingSlotId) {
}

// FUNCTION: IMPERIALISM 0x004d0470
void TArmoryView::Free() {
}
