#pragma once

#ifndef IMPERIALISM_DEAL_BOOK_SCREEN_H
#define IMPERIALISM_DEAL_BOOK_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error DealBookScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

class TDealBookPicture;

// The Deal Book, shown between turns to report the trades that executed.
//
// Leaving it is the single most duplicated step in the suite: the same
// "if this is the Deal Book and I have not left it yet, StartNextPhase" appeared five times
// across four files, each with its own one-shot boolean. It has to be one-shot -- advancing
// the phase twice skips a phase -- which is exactly the kind of bookkeeping the EndTurnFlow
// fragment now owns.
class DealBookScreen : public MainViewScreen {
public:
  DealBookScreen();

  static bool IsCurrent();

  TDealBookPicture* View() const;

  // Advance past the Deal Book. Not a control activation: the game leaves it by starting the
  // next simulation phase, which is what the retail Done path does.
  RuntimeActionResult Leave();

  // The two page modes, and the cached-page identities that distinguish them.
  RuntimeActionResult ShowCategoryPages();
  RuntimeActionResult ShowHistoryPages();
  bool IsShowingHistoryPages() const;
  bool IsShowingCategoryPages() const;

private:
  TDealBookPicture* dealBook;
};

inline DealBookScreen DealBook() {
  return DealBookScreen();
}

#endif
