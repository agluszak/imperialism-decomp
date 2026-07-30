#include "ModalScreen.h"

#include "RuntimeObservations.h"
#include "RuntimeUiDriver.h"

#include "game/ui_core/TControl.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/globals/view_registries.h"

ModalScreen::ModalScreen() : modal(0) {
  if (!g_ModalViewStack.IsEmpty()) {
    modal = g_ModalViewStack.GetHead();
  }
}

bool ModalScreen::AnyPresent() {
  return !g_ModalViewStack.IsEmpty();
}

int ModalScreen::Depth() {
  return g_ModalViewStack.GetCount();
}

bool ModalScreen::IsPresent() const {
  return modal != 0;
}

TWindow* ModalScreen::Top() const {
  return modal;
}

unsigned long ModalScreen::DefaultCommand() const {
  if (modal == 0) {
    return 0;
  }
  TDialogBehavior* behavior = modal->GetDialogBehavior();
  return behavior != 0 ? behavior->defaultCommandCode : 0;
}

bool ModalScreen::IsTurnAlert() const {
  return DefaultCommand() == static_cast<unsigned long>(kControlTagOkay);
}

bool ModalScreen::IsEndTurnWarning() const {
  return DefaultCommand() == static_cast<unsigned long>(kControlTagPic5);
}

bool ModalScreen::IsRecognised() const {
  if (modal == 0 || (!IsTurnAlert() && !IsEndTurnWarning())) {
    return false;
  }
  // The command code alone is not enough: the control it names has to be there to activate.
  return modal->ResolveControlByTag(static_cast<unsigned int>(DefaultCommand())) != 0;
}

CString ModalScreen::Describe() const {
  CString text;
  if (modal == 0) {
    return CString("no modal is present");
  }
  char command[5];
  unsigned long code = DefaultCommand();
  command[0] = static_cast<char>(code >> 24);
  command[1] = static_cast<char>(code >> 16);
  command[2] = static_cast<char>(code >> 8);
  command[3] = static_cast<char>(code);
  command[4] = 0;
  text.Format("%s with default command '%s' (0x%08lx) at modal depth %d", RuntimeClassName(modal),
              command, code, Depth());
  return text;
}

RuntimeActionResult ModalScreen::AcceptDefault() {
  if (modal == 0) {
    return RuntimeActionResult::Failure("no modal is present to confirm");
  }
  if (!IsRecognised()) {
    CString message;
    message.Format("unrecognised modal: %s", static_cast<LPCSTR>(Describe()));
    return RuntimeActionResult::Failure(message);
  }
  CString failure;
  RuntimeControlSelector selector(static_cast<int>(DefaultCommand()), RUNTIME_CLASS(TControl));
  if (!RuntimeUiDriver::Activate(modal, selector, &failure)) {
    CString message;
    message.Format("cannot confirm %s: %s", static_cast<LPCSTR>(Describe()),
                   static_cast<LPCSTR>(failure));
    return RuntimeActionResult::Failure(message);
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult ModalScreen::PreArmDismiss(const RuntimeControlSelector& selector) {
  CString failure;
  if (!RuntimeUiDriver::PostActivate(selector, &failure)) {
    CString message;
    message.Format("cannot queue a modal dismissal: %s", static_cast<LPCSTR>(failure));
    return RuntimeActionResult::Failure(message);
  }
  return RuntimeActionResult::Success();
}
