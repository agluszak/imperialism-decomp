#include "MainViewScreen.h"

#include "RuntimeObservations.h"
#include "RuntimeUiDriver.h"

#include "game/core/global_data_tables.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/view_registries.h"

bool MainViewScreen::MainViewIsCurrent(CRuntimeClass* expectedClass, int expectedEvent) {
  if (g_pViewMgr == 0 || g_pViewMgr->currentTurnEventCode != expectedEvent) {
    return false;
  }
  // A modal above the screen means an activation would resolve against the modal, so the
  // screen is not usable even though it is still the main view.
  if (!g_ModalViewStack.IsEmpty()) {
    return false;
  }
  return RuntimeIsViewKindOf(RuntimeMainView(), expectedClass);
}

MainViewScreen::MainViewScreen(const MainViewScreenIdentity& identity)
    : root(0), expectedClass(identity.viewClass), expectedEvent(identity.turnEvent),
      screenName(identity.screenName) {
  if (MainViewIsCurrent(identity.viewClass, identity.turnEvent)) {
    root = RuntimeMainView();
  }
}

MainViewScreen::MainViewScreen(CRuntimeClass* viewClass, int eventCode, const char* name)
    : root(0), expectedClass(viewClass), expectedEvent(eventCode), screenName(name) {
  if (MainViewIsCurrent(viewClass, eventCode)) {
    root = RuntimeMainView();
  }
}

bool MainViewScreen::IsValid() const {
  return root != 0;
}

TView* MainViewScreen::Root() const {
  return root;
}

RuntimeActionResult MainViewScreen::InvalidScreen(const char* what) const {
  CString message;
  message.Format("cannot %s: %s is not the current screen (expected %s at event 0x%04x, "
                 "found %s at event 0x%04x, modal depth %d)",
                 what, screenName,
                 expectedClass != 0 && expectedClass->m_lpszClassName != 0
                     ? expectedClass->m_lpszClassName
                     : "?",
                 static_cast<unsigned int>(expectedEvent), RuntimeClassName(RuntimeMainView()),
                 g_pViewMgr != 0 ? static_cast<unsigned int>(g_pViewMgr->currentTurnEventCode) : 0u,
                 g_ModalViewStack.GetCount());
  return RuntimeActionResult::Failure(message);
}

RuntimeActionResult MainViewScreen::ScreenFailure(const char* what, const CString& detail) const {
  CString message;
  message.Format("cannot %s on %s: %s", what, screenName, static_cast<LPCSTR>(detail));
  return RuntimeActionResult::Failure(message);
}

RuntimeActionResult MainViewScreen::ActivateSelected(const RuntimeControlSelector& selector,
                                                     const char* what) {
  CString failure;
  if (!RuntimeUiDriver::Activate(root, selector, &failure)) {
    // RequireControl already explained which of its five checks failed; passing that through
    // is the whole point of returning a result rather than a bool.
    CString message;
    message.Format("cannot %s: %s", what, static_cast<LPCSTR>(failure));
    return RuntimeActionResult::Failure(message);
  }
  // A control activation is delivered through the game's message loop, so its effect is not
  // observable until the game runs. Every screen action that activates a control inherits this,
  // which is what lets a script stop deciding it per call site.
  return RuntimeActionResult::SuccessAfterMessageBarrier();
}

RuntimeActionResult MainViewScreen::Activate(int tag, const char* what) {
  return Activate(tag, RUNTIME_CLASS(TControl), what);
}

RuntimeActionResult MainViewScreen::Activate(int tag, CRuntimeClass* controlClass,
                                             const char* what) {
  if (root == 0) {
    return InvalidScreen(what);
  }
  return ActivateSelected(RuntimeControlSelector(tag, controlClass), what);
}

RuntimeActionResult MainViewScreen::Activate(int tag, CRuntimeClass* controlClass, int eventNumber,
                                             const char* what) {
  if (root == 0) {
    return InvalidScreen(what);
  }
  return ActivateSelected(RuntimeControlSelector(tag, controlClass, eventNumber), what);
}

RuntimeActionResult MainViewScreen::Activate(int tag0, int tag1, const char* what) {
  return Activate(tag0, tag1, RUNTIME_CLASS(TControl), what);
}

RuntimeActionResult MainViewScreen::Activate(int tag0, int tag1, CRuntimeClass* controlClass,
                                             const char* what) {
  if (root == 0) {
    return InvalidScreen(what);
  }
  return ActivateSelected(RuntimeControlSelector(tag0, tag1, controlClass), what);
}

TView* MainViewScreen::Find(int tag) const {
  return root != 0 ? root->ResolveControlByTag(static_cast<unsigned int>(tag)) : 0;
}

TView* MainViewScreen::Find(int tag0, int tag1) const {
  TView* parent = Find(tag0);
  return parent != 0 ? parent->ResolveControlByTag(static_cast<unsigned int>(tag1)) : 0;
}
