#include "game/TIndustryView.h"

#include "game/TControl.h"
#include "game/TDisplayMgr.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
// SYNTHETIC: IMPERIALISM 0x004cc6b0
// TIndustryView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004cc770
// TIndustryView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TIndustryView, TBuildingView)

// FUNCTION: IMPERIALISM 0x004cc790
TIndustryView::TIndustryView() : TBuildingView(), fieldA0(0), fieldA4(static_cast<short>(0xffff)) {}

// SYNTHETIC: IMPERIALISM 0x004cc7d0
// TIndustryView::`scalar deleting destructor'
TIndustryView::~TIndustryView() {}

// FUNCTION: IMPERIALISM 0x004cc820
undefined TIndustryView::OrphanRetStub_004c6fd0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ccf30
void TIndustryView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa && sourceHandler->controlTag == kControlTagExpa) {
    TView* owner = OwnerPanel();
    TWindow* ownerWindow = static_cast<TWindow*>(owner);
    bool wasDisabled = ownerWindow->nativeWindow50->EnableWindow(0) == 0;

    TView* mainControl = g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagMain);
    if (mainControl == nullptr) {
      FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCityViews.cpp", 0x84c);
    }

    g_pUiRuntimeContext->HandleTurnEventDialogFactorySlotB8(field9e, (int)field94, (int)mainControl);

    TView* owner2 = OwnerPanel();
    static_cast<TWindow*>(owner2)->nativeWindow50->EnableWindow(wasDisabled);
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004cd040
undefined TIndustryView::OrphanRetStub_004c6fb0() {
  return 0;
}
