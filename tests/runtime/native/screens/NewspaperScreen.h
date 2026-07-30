#pragma once

#ifndef IMPERIALISM_NEWSPAPER_SCREEN_H
#define IMPERIALISM_NEWSPAPER_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error NewspaperScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

class TNewspaperView;

// The between-turns newspaper.
//
// Closing it has a readiness step that is easy to get wrong: the view is constructed before its
// controls become actionable, so activating the end control too early fails. Waiting for
// EndControlIsReady() first is what the base's AdvanceNewspaperIfNeeded did by awaiting paint
// and invalidation observations, and it is why that helper existed at all.
class NewspaperScreen : public MainViewScreen {
public:
  NewspaperScreen();

  static bool IsCurrent();

  TNewspaperView* View() const;

  // True once the end control resolves and is actionable. Activating before this is a failure,
  // not a retry.
  bool EndControlIsReady() const;
  RuntimeActionResult Close();

  int SummaryPageIndex() const;
  // How many of the view's text children carry non-empty text, which is how a scenario checks
  // that stories were actually generated rather than that the page merely exists.
  int NonEmptyTextChildCount() const;

private:
  TNewspaperView* newspaper;
};

inline NewspaperScreen Newspaper() {
  return NewspaperScreen();
}

#endif
