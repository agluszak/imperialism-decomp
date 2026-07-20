#include "game/TShipView.h"

#include "game/TAssetMgr.h"
#include "game/TEditText.h"
#include "game/TMapOrderChildLinkNode.h"
#include "game/TMapUberPicture.h"
#include "game/TShip.h"
#include "game/TStaticText.h"
#include "game/TTaskForce.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"

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
    RunEngineerOrderNameEditDialogAndApply();
  }
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}

// Same dialog (message context 0xdb4) and control shape as TArmyUnitView::
// HandleCrossUArmyViewsNameCommand (0x4a9ca0), but a genuinely different function (own thunk
// 0x4092ff, not 0x403986) with real differences: no forced default command (no
// SetField84/GetEmbeddedDialogBehavior calls), the title uses string index 5 instead of 1,
// the edited name is field60->displayName18 (TShip's own name field, not TMilitaryUnit's
// name24 -- confirms the earlier field60+offset concern was specific to each class, not a
// shared conflict), and the commit condition is inverted: applies only when the modal result
// is exactly 'okay' (rather than "commit unless 'cncl'").
// FUNCTION: IMPERIALISM 0x00565a40
void TShipView::RunEngineerOrderNameEditDialogAndApply() {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0xdb4));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUOceanViews_00698650, 0x203);
  }

  TUiTextStyleDescriptor style;
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);

  TStaticText* titleControl = static_cast<TStaticText*>(node->ResolveControlByTag(kControlTagTitl));
  titleControl->AssertValid();
  titleControl->LoadUiStringAndDispatchViaVslot1C8(0x2746, 5, 1);
  titleControl->textStyle78 = style;

  TEditText* nameControl = static_cast<TEditText*>(node->ResolveControlByTag(kControlTagName));
  nameControl->AssertValid();
  CString editedName;
  editedName = field60->displayName18;
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&editedName, 1);
  nameControl->textStyle78 = style;

  int modalResult = node->ExecuteViewModalStateWithPushPopChain();
  nameControl->GetCurrentText(&editedName);
  node->CallVoidSlotA0();
  node->Free();
  if (modalResult == 0x6f6b6179 /* 'okay' */) {
    field60->displayName18 = editedName;
  }
  RefreshControl();
}
