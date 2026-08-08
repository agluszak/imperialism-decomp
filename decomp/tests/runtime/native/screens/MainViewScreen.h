#pragma once

#ifndef IMPERIALISM_MAIN_VIEW_SCREEN_H
#define IMPERIALISM_MAIN_VIEW_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error MainViewScreen is test-only and must not be included in the production build
#endif

#include "RuntimeActionResult.h"

class TControl;
class TView;
struct CRuntimeClass;

// Shared machinery for a screen that is the game's current main view.
//
// Every screen driver needs the same three things, and writing them per screen is how the
// suite ended up with 22 hand-copied "is this screen idle" predicates and 92 raw
// ResolveControlByTag calls in test bodies:
//
//   1. Identity: the right main-view class, at the right turn event, with no modal above it.
//      The modal check matters -- an activation resolves against the modal head first, so
//      treating "the map is the main view" as "the map is current" is what let a stray dialog
//      be mistaken for the screen beneath it.
//   2. A well-explained failure when the script is on the wrong screen. Naming what *is*
//      current turns "control is missing" (which sends the reader hunting for a UI defect)
//      into "expected TMapUberPicture at 0x07dd, found TTradeScreenPicture at 0x07d9".
//   3. Activation that propagates RuntimeUiDriver::RequireControl's diagnosis instead of
//      discarding it, which is what the old bool-returning drivers did.
//
// What makes a screen that screen. A concrete screen publishes this as a static, so a script
// can say `RT_OPEN_TO("open the Board of Trade", StrategicMap().OpenTrade(), TradeScreen)` and
// never repeat the production view class or the turn-event code. Before this existed the
// script and the screen each named both, which is two sources of truth for one fact and the
// reason scenarios had to include production UI headers at all.
struct MainViewScreenIdentity {
  MainViewScreenIdentity(CRuntimeClass* viewClass_, int turnEvent_, const char* screenName_)
      : viewClass(viewClass_), turnEvent(turnEvent_), screenName(screenName_) {}

  CRuntimeClass* viewClass;
  int turnEvent;
  const char* screenName;
};

// A concrete screen derives from this, publishes its Identity(), and adds actions and
// predicates. Control-tree mechanics stay on this side of the boundary; scripts see actions.
class MainViewScreen {
public:
  bool IsValid() const;

protected:
  // The identity's `screenName` appears in diagnostics, so give it the name an author would
  // use ("the Board of Trade"), not the class name -- the class name is reported separately.
  MainViewScreen(const MainViewScreenIdentity& identity);
  MainViewScreen(CRuntimeClass* expectedClass, int expectedEvent, const char* screenName);

  // Identity test usable before constructing anything, for a script's IsCurrent().
  static bool MainViewIsCurrent(CRuntimeClass* expectedClass, int expectedEvent);

  TView* Root() const;

  // Activate a control below the root. The one- and two-tag forms cover every path the suite
  // actually uses (the deepest real selector is three, and that case passes `expectedClass`).
  RuntimeActionResult Activate(int tag, const char* what);
  RuntimeActionResult Activate(int tag, CRuntimeClass* expectedClass, const char* what);
  // For a control that publishes a command other than the usual control event: the selector has
  // to name it, or the driver resolves the right control and then refuses it for the wrong event.
  RuntimeActionResult Activate(int tag, CRuntimeClass* expectedClass, int eventNumber,
                               const char* what);
  RuntimeActionResult Activate(int tag0, int tag1, const char* what);
  RuntimeActionResult Activate(int tag0, int tag1, CRuntimeClass* expectedClass, const char* what);

  // Resolve without activating, for predicates. Returns 0 when absent; the caller decides
  // whether that is a failure.
  TView* Find(int tag) const;
  TView* Find(int tag0, int tag1) const;

  // A failure naming what is current instead of what was wanted.
  RuntimeActionResult InvalidScreen(const char* what) const;
  // A failure for something wrong *on* this screen.
  RuntimeActionResult ScreenFailure(const char* what, const CString& detail) const;

private:
  RuntimeActionResult ActivateSelected(const struct RuntimeControlSelector& selector,
                                       const char* what);

  TView* root;
  CRuntimeClass* expectedClass;
  int expectedEvent;
  const char* screenName;
};

#endif
