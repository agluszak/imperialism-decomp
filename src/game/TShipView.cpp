#include "game/TShipView.h"

#include "game/TMapOrderChildLinkNode.h"
#include "game/TMapUberPicture.h"
#include "game/TShip.h"
#include "game/TStaticText.h"
#include "game/TTaskForce.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"

// SYNTHETIC: IMPERIALISM 0x005653b0
// TShipView::`scalar deleting destructor'
TShipView::~TShipView() {}
// SYNTHETIC: IMPERIALISM 0x00565400
// TShipView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00565470
// TShipView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipView, TView)

TShipView::TShipView() {}

// FUNCTION: IMPERIALISM 0x005654e0
void TShipView::ApplyRectSlot110(RECT* rectBuffer) {
}

// FUNCTION: IMPERIALISM 0x005658d0
void TShipView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (sourceHandler->controlTag == kControlTagChec) {
    TMapOrderChildLinkNode* node = field64->childOrderList->FindNodeMatching(field60);
    int delta;
    if (node->active == 0) {
      field64->SetTaskForceOrderSelectionByNodeId(field60, 1);
      delta = 1;
    } else {
      field64->SetTaskForceOrderSelectionByNodeId(field60, 0);
      delta = -1;
    }

    TMapUberPicture* mapUber = g_pUiRuntimeContext->mapUberPictureF0;
    TView* categoryControl = mapUber->categoryPages[mapUber->activeUnitCategoryIndex96];
    if (categoryControl != nullptr) {
      short resourceType = field60->GetOrderNodeDescriptorWord20ByResourceType();
      TStaticText* slider =
          static_cast<TStaticText*>(categoryControl->ResolveControlByTag(kControlTagCls0 + resourceType));
      // The original also range-checks against slider->field88 (a max-value short packed
      // into a dual-use void* field -- see the UNRESOLVED_FIELD_ATTRIBUTION note on
      // TStaticText::field88) before applying the delta; that guard is not modeled here.
      if (delta > 0) {
        short newValue = slider->field90 + 1;
        slider->field90 = newValue;
        slider->SetTextThemeCodeAndMaybeRefresh(newValue, 1);
      } else if (slider->field90 > 0) {
        short newValue = slider->field90 - 1;
        slider->field90 = newValue;
        slider->SetTextThemeCodeAndMaybeRefresh(newValue, 1);
      }
    }
  } else if (sourceHandler->controlTag == kControlTagName) {
    // Original calls HandleCrossUArmyViewsNameCommand (0x4a9ca0, 498 bytes, unowned
    // stub shared with TArmyUnitView::HandleEvent) here -- not yet ported.
  }
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}
