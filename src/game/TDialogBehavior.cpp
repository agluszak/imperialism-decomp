#include "game/TDialogBehavior.h"

#include "game/CIncludeView.h"
#include "game/ImperialismApp.h"
#include "game/TEvent.h"
#include "game/TEventHandler.h"
#include "game/TUiEvent.h"
#include "game/TView.h"
#include "game/CMcWindow.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x00487300
// TDialogBehavior::CreateObject

// SYNTHETIC: IMPERIALISM 0x00487350
// TDialogBehavior::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDialogBehavior, TBehavior)

// FUNCTION: IMPERIALISM 0x00487370
TDialogBehavior::TDialogBehavior()
    : TBehavior(), armed(0), defaultCommandCode(0x20202020), cancelCommandCode(0x20202020),
      armedCommandCode(0x20202020), dismissPending(1) {}

// SYNTHETIC: IMPERIALISM 0x004873b0
// TDialogBehavior::`scalar deleting destructor'
TDialogBehavior::~TDialogBehavior() {}

// FUNCTION: IMPERIALISM 0x00487400
void TDialogBehavior::SetUiColorDescriptorGoldTriplet(unsigned char flag, int colorA, int colorB) {
  behaviorTag = 0x646c6f67; // 'gold'
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
    Dismiss(commandCode, commandCode != static_cast<unsigned long>(cancelCommandCode));
  }
}

// FUNCTION: IMPERIALISM 0x004874b0
void TDialogBehavior::DoKeyEvent(TToolboxEvent* event) {
  TView* ownerView = static_cast<TView*>(owner);
  if (ownerView == 0 || ownerView->GetBoolSlot28() == 0) {
    return;
  }

  int commandCode;
  int fallbackCommand;
  if (event->commandCode == 3 || event->commandCode == 0x0d) {
    commandCode = defaultCommandCode;
    fallbackCommand = 0x16;
  } else if (event->commandCode == 0x1b) {
    commandCode = cancelCommandCode;
    fallbackCommand = 0x15;
  } else {
    return;
  }
  if (commandCode == 0x20202020) {
    return;
  }

  TView* control = ownerView->ResolveControlByTag(commandCode);
  if (control == 0) {
    ownerView->DispatchEvent(fallbackCommand, ownerView, 0);
  } else if (control->GetBoolSlot28() != 0) {
    control->DispatchEvent(control->QuerySelectedIndexSlotBC(), ownerView, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004875d0
void TDialogBehavior::DoCommandKeyEvent(TToolboxEvent* event) {
  TView* ownerView = static_cast<TView*>(owner);
  if (ownerView == 0 || ownerView->GetBoolSlot28() == 0 || event->commandCode != 0x2e ||
      cancelCommandCode == 0x20202020) {
    return;
  }

  TView* control = ownerView->ResolveControlByTag(cancelCommandCode);
  if (control == 0) {
    ownerView->DispatchEvent(0x15, ownerView, 0);
  } else if (control->GetBoolSlot28() != 0) {
    control->DispatchEvent(control->QuerySelectedIndexSlotBC(), ownerView, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00487660
void TDialogBehavior::PoseModally() {
  CIncludeView* mainView = GetMainViewHostFromActiveThread();
  int wasInteractive = mainView->SetUiInteractiveFlag90(0);

  TView* ownerPanel = owner->OwnerPanel();
  ownerPanel->Open();
  ownerPanel = owner->OwnerPanel();
  CWnd* nativeWindow = ownerPanel->nativeWindow50;
  dismissPending = 0;
  armedCommandCode = 0x20202020;
  nativeWindow->EnableWindow(1);
  nativeWindow->RunModalLoop(0);

  if (wasInteractive != 0) {
    GetMainViewHostFromActiveThread()->SetUiInteractiveFlag90(1);
  }
}
