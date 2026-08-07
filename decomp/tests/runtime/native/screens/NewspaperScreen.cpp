#include "NewspaperScreen.h"

#include "RuntimeUiDriver.h"

#include "game/turn_event_codes.h"
#include "game/ui_core/TControl.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_core/TView.h"
#include "game/ui_screens/TNewspaperView.h"
#include "game/ui_tags_common.h"

NewspaperScreen::NewspaperScreen()
    : MainViewScreen(RUNTIME_CLASS(TNewspaperView), kTurnEventNewspaperStatus, "the newspaper"),
      newspaper(0) {
  newspaper = static_cast<TNewspaperView*>(Root());
}

bool NewspaperScreen::IsCurrent() {
  return MainViewIsCurrent(RUNTIME_CLASS(TNewspaperView), kTurnEventNewspaperStatus);
}

TNewspaperView* NewspaperScreen::View() const {
  return newspaper;
}

bool NewspaperScreen::EndControlIsReady() const {
  if (newspaper == 0) {
    return false;
  }
  // RequireControl's own actionable/class checks are the readiness test; asking it without a
  // failure buffer is how to probe rather than assert.
  return RuntimeUiDriver::RequireControl(
             newspaper, RuntimeControlSelector(kControlTagEnd, RUNTIME_CLASS(TControl)), 0) != 0;
}

RuntimeActionResult NewspaperScreen::Close() {
  return Activate(kControlTagEnd, "close the newspaper");
}

int NewspaperScreen::SummaryPageIndex() const {
  return newspaper != 0 ? newspaper->summaryPageIndex90 : -1;
}

int NewspaperScreen::NonEmptyTextChildCount() const {
  if (newspaper == 0 || newspaper->childList44 == 0) {
    return 0;
  }
  int count = 0;
  POSITION position = newspaper->childList44->GetHeadPosition();
  while (position != 0) {
    TView* child = newspaper->childList44->GetNext(position);
    if (child == 0 || child->IsKindOf(RUNTIME_CLASS(TDeluxeText)) == 0) {
      continue;
    }
    TDeluxeText* text = static_cast<TDeluxeText*>(child);
    if (text->text != 0 && !text->text->IsEmpty()) {
      ++count;
    }
  }
  return count;
}
