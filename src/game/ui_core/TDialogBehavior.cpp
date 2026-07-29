#include "game/ui_core/TDialogBehavior.h"
#include "game/resource_manifest_tags.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_core/TWindow.h"

#include "game/ui_core/CIncludeView.h"
#include "game/ImperialismApp.h"
#include "game/TEvent.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_core/TUiEvent.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/CMcWindow.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#ifdef IMPERIALISM_RUNTIME_TESTS
#include "RuntimeObservation.h"
#include "RuntimeTestDriver.h"
#endif

// SYNTHETIC: IMPERIALISM 0x00487300
// TDialogBehavior::CreateObject

// SYNTHETIC: IMPERIALISM 0x00487350
// TDialogBehavior::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDialogBehavior, TBehavior)

// FUNCTION: IMPERIALISM 0x00487370
TDialogBehavior::TDialogBehavior()
    : TBehavior(), armed(0), defaultCommandCode(kControlTagSpSpSpSp),
      cancelCommandCode(kControlTagSpSpSpSp), armedCommandCode(kControlTagSpSpSpSp),
      dismissPending(1) {}

// SYNTHETIC: IMPERIALISM 0x004873b0
// TDialogBehavior::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004873e0
TDialogBehavior::~TDialogBehavior() {}

// FUNCTION: IMPERIALISM 0x00487400
void TDialogBehavior::SetUiColorDescriptorGoldTriplet(unsigned char flag, int colorA, int colorB) {
  behaviorTag = kControlTagDlog; // 'gold'
  armed = flag;
  defaultCommandCode = colorA;
  cancelCommandCode = colorB;
}

// FUNCTION: IMPERIALISM 0x00487430
void TDialogBehavior::Dismiss(unsigned long commandCode, unsigned char accepted) {
  (void)accepted;
  if (owner != 0) {
    dismissPending = 1;
    armedCommandCode = commandCode;
    static_cast<TView*>(owner)->nativeWindow50->EndModalLoop(commandCode);
  }
}

// FUNCTION: IMPERIALISM 0x00487470
void TDialogBehavior::DoEvent(long commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)event;
  if (commandId == 0x22) {
    unsigned long commandCode = sourceHandler->controlTag;
    Dismiss(commandCode, commandCode != cancelCommandCode);
  }
}

// FUNCTION: IMPERIALISM 0x004874b0
void TDialogBehavior::DoKeyEvent(TToolboxEvent* event) {
  TView* ownerView = static_cast<TView*>(owner);
  if (ownerView == 0 || ownerView->IsEnabled() == 0) {
    return;
  }

  unsigned long commandCode;
  int fallbackCommand;
  if (event->commandCode == kUiKeyEnter || event->commandCode == kUiKeyReturn) {
    commandCode = defaultCommandCode;
    fallbackCommand = 0x16;
  } else if (event->commandCode == kUiKeyEscape) {
    commandCode = cancelCommandCode;
    fallbackCommand = 0x15;
  } else {
    return;
  }
  if (commandCode == kControlTagSpSpSpSp) {
    return;
  }

  TView* control = ownerView->ResolveControlByTag(commandCode);
  if (control == 0) {
    ownerView->HandleEvent(fallbackCommand, ownerView, 0);
  } else if (control->IsEnabled() != 0) {
    control->HandleEvent(control->GetEventNumber(), ownerView, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004875d0
void TDialogBehavior::DoCommandKeyEvent(TToolboxEvent* event) {
  TView* ownerView = static_cast<TView*>(owner);
  if (ownerView == 0 || ownerView->IsEnabled() == 0 || event->commandCode != kUiKeyPeriod ||
      cancelCommandCode == kControlTagSpSpSpSp) {
    return;
  }

  TView* control = ownerView->ResolveControlByTag(cancelCommandCode);
  if (control == 0) {
    ownerView->HandleEvent(0x15, ownerView, 0);
  } else if (control->IsEnabled() != 0) {
    control->HandleEvent(control->GetEventNumber(), ownerView, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00487660
void TDialogBehavior::PoseModally() {
  CIncludeView* mainView = GetMainViewHostFromActiveThread();
  int wasInteractive = mainView->SetUiInteractiveFlag90(0);

  TView* ownerPanel = owner->GetWindow();
  ownerPanel->Open();
  ownerPanel = owner->GetWindow();
  CWnd* nativeWindow = ownerPanel->nativeWindow50;
  dismissPending = 0;
  armedCommandCode = kControlTagSpSpSpSp;
  nativeWindow->EnableWindow(1);
#ifdef IMPERIALISM_RUNTIME_TESTS
  // The modal is actionable only after its dismissal state has been reset. Posting the
  // observation here guarantees that a semantic activation runs inside RunModalLoop,
  // never during dialog construction before the loop is armed.
  RuntimeTestDriver::ObserveDeferred(kObserveModalPushed);
#endif
  nativeWindow->RunModalLoop(0);

  if (wasInteractive != 0) {
    GetMainViewHostFromActiveThread()->SetUiInteractiveFlag90(1);
  }
}
