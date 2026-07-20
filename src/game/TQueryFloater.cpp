#include "game/TQueryFloater.h"

#include "game/CString.h"
#include "game/TArmyMgr.h"
#include "game/THelpMgr.h"
#include "game/TNewsMgr.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0043d6a0
// TQueryFloater::`scalar deleting destructor'
TQueryFloater::~TQueryFloater() {}
// SYNTHETIC: IMPERIALISM 0x0056e840
// TQueryFloater::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056e8c0
// TQueryFloater::GetRuntimeClass

IMPLEMENT_DYNCREATE(TQueryFloater, TPicture)

TQueryFloater::TQueryFloater() {}

// FUNCTION: IMPERIALISM 0x0056e8e0
void TQueryFloater::NoOpUiLifecycleHook(int arg) {
  TPicture::NoOpUiLifecycleHook(arg);

  TUiTextStyleDescriptor style;

  TStaticText* titleControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitl));
  titleControl->QueryStepValue();
  titleControl->LoadUiStringAndDispatchViaVslot1C8(0x2757, 1, 1);
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);
  titleControl->SetTextStyleAndMaybeRefresh(&style, 0);
  titleControl->SetTextThemeCodeAndMaybeRefresh(1, 0);

  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6c);
  for (int i = 0; i < 7; ++i) {
    TStaticText* lineControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTex0 + i));
    lineControl->QueryStepValue();
    lineControl->LoadUiStringAndDispatchViaVslot1C8(0x2757, static_cast<short>(i + 2), 1);
    lineControl->SetTextStyleAndMaybeRefresh(&style, 0);
    if (i == 6) {
      lineControl->SetTextThemeCodeAndMaybeRefresh(1, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0056ea20
void TQueryFloater::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  CString text;
  if (commandId != 0xa) {
    return;
  }
  unsigned int tag = sourceHandler->controlTag;
  if (tag == kControlTagAdvi) {
    TWindow* owner = static_cast<TWindow*>(OwnerPanel());
    owner->NotifyDialogBehaviorCommandArmed(kControlTagOkay, 0);
    g_pHelpMgr->SelectAndActivatePendingEventForCurrentView();
  } else if (tag == kControlTagBatt) {
    short activeNationId = g_pSimMgr->GetActiveNationId();
    if (!g_pMapContextActionManager->ScanMapContextActionEntriesForCodeMatch(activeNationId)) {
      if (g_pSimMgr->GetTurnTickSlot3C() == 1) {
        g_pSimMgr->GetString(0x273d, 0x1e, &text);
      } else {
        g_pSimMgr->GetString(0x273d, 0x12, &text);
      }
      g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
          text, &g_cstrQueryFloaterMessageStore, 1, 0);
    } else {
      TWindow* owner = static_cast<TWindow*>(OwnerPanel());
      owner->NotifyDialogBehaviorCommandArmed(kControlTagOkay, 0);
      g_pSimMgr->SetGlobalTurnStateCodeIfAllowed(0x65);
    }
  } else if (tag == kControlTagChar) {
    TWindow* owner = static_cast<TWindow*>(OwnerPanel());
    owner->NotifyDialogBehaviorCommandArmed(kControlTagOkay, 0);
    g_pSimMgr->SetGlobalTurnStateCodeIfAllowed(0x6e);
  } else if (tag == kControlTagClnc) {
    TWindow* owner = static_cast<TWindow*>(OwnerPanel());
    owner->NotifyDialogBehaviorCommandArmed(kControlTagOkay, 0);
  } else if (tag == kControlTagDeal) {
    if (g_pSimMgr->GetTurnTickSlot3C() == 1) {
      g_pSimMgr->GetString(0x2741, 9, &text);
      g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
          text, &g_cstrQueryFloaterMessageStore, 1, 0);
    } else {
      TWindow* owner = static_cast<TWindow*>(OwnerPanel());
      owner->NotifyDialogBehaviorCommandArmed(kControlTagOkay, 0);
      g_pSimMgr->SetGlobalTurnStateCodeIfAllowed(0x64);
    }
  } else if (tag == kControlTagNews) {
    TWindow* owner = static_cast<TWindow*>(OwnerPanel());
    owner->NotifyDialogBehaviorCommandArmed(kControlTagOkay, 0);
    if (g_pInterNationEventQueueManager->perNationStoryLastUsedTick[0] != nullptr) {
      g_pSimMgr->SetGlobalTurnStateCodeIfAllowed(0x66);
    } else {
      g_pUiRuntimeContext->ShowLocalizedUiPromptByGroupAndIndex(0x275e, 6, 2, 0);
    }
  } else if (tag == kControlTagFore) {
    TWindow* owner = static_cast<TWindow*>(OwnerPanel());
    owner->NotifyDialogBehaviorCommandArmed(kControlTagOkay, 0);
    g_pHelpMgr->SelectAndActivatePendingEventType1A0A();
  }
}
