#pragma once

#ifndef IMPERIALISM_ARMY_BOOK_SCREEN_H
#define IMPERIALISM_ARMY_BOOK_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error ArmyBookScreen is test-only and must not be included in the production build
#endif

#include "RuntimeActionResult.h"

class TGarrisonView;
class TWindow;

// The army book: a standalone TWindow resolved from the asset manager, not the current main
// view, so it is not a MainViewScreen. It still belongs on this side of the boundary -- a script
// should ask it for the garrison page rather than walk a window's children itself.
//
// Open() takes ownership in the same sense the game does: the caller must Close() it, and the
// window is freed there. A scenario that forgets leaks a modal window into the rest of the run.
class ArmyBookScreen {
public:
  ArmyBookScreen();

  // Resolve the book for the garrison turn event. Idempotent within one instance.
  RuntimeActionResult Open();
  bool IsOpen() const;

  // The garrison content page, or 0 when the book did not build one.
  TGarrisonView* GarrisonPage() const;
  // Fill the page from a province, which is what the game does when the book is shown.
  RuntimeActionResult ShowProvince(short province);
  // True once the page holds a real unit sprite atlas rather than an empty frame.
  bool HasUnitSpritePage() const;

  RuntimeActionResult Close();

private:
  TWindow* book;
};

inline ArmyBookScreen ArmyBook() {
  return ArmyBookScreen();
}

#endif
