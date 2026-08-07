#include "RandomSetupScreen.h"

#include "RuntimeUiDriver.h"

#include "game/turn_event_codes.h"
#include "game/ui_core/CMcEditWindow.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_core/TView.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

namespace {

// The difficulty radio buttons are consecutive tags from Introductory upwards.
int DifficultyTag(int level) {
  return kControlTagDif0 + level;
}

} // namespace

RandomSetupScreen::RandomSetupScreen()
    : MainViewScreen(RUNTIME_CLASS(TSetupRandomMapPicture), kTurnEventRandomGameSetup,
                     "the random-map setup screen"),
      setupView(0) {
  setupView = static_cast<TSetupRandomMapPicture*>(Root());
}

bool RandomSetupScreen::IsCurrent() {
  return MainViewIsCurrent(RUNTIME_CLASS(TSetupRandomMapPicture), kTurnEventRandomGameSetup);
}

TSetupRandomMapPicture* RandomSetupScreen::View() const {
  return setupView;
}

short RandomSetupScreen::SelectedNationSlot() const {
  return setupView != 0 ? setupView->selectedNationSlot9A : -1;
}

RuntimeActionResult RandomSetupScreen::SetCountryName(const char* name) {
  TView* field = Find(kControlTagCoun);
  if (field == 0 || field->IsKindOf(RUNTIME_CLASS(TEditText)) == 0) {
    if (!IsValid()) {
      return InvalidScreen("set the country name");
    }
    return ScreenFailure("set the country name", CString("the country-name field is missing"));
  }
  TEditText* country = static_cast<TEditText*>(field);
  CString countryName(name);
  // Once the field has its native edit window the text has to go through it; before that the
  // control holds the text itself.
  if (country->editWindow != 0) {
    country->editWindow->SetWindowText(countryName);
  } else {
    country->SetTextAndMaybeRefresh(&countryName, 1);
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult RandomSetupScreen::RegeneratePlanet(const char* planetSeed) {
  if (!IsValid() || setupView == 0) {
    return InvalidScreen("regenerate the planet from its seed text");
  }
  CString failure;
  if (!RuntimeUiDriver::PostSetText(
          RuntimeControlSelector(kControlTagPlan, RUNTIME_CLASS(TEditText)), planetSeed,
          &failure)) {
    CString message;
    message.Format("cannot queue the planet-name edit: %s", static_cast<LPCSTR>(failure));
    return RuntimeActionResult::Failure(message);
  }
  if (!RuntimeUiDriver::PostActivate(RuntimeControlSelector(kControlTagOkay), &failure)) {
    CString message;
    message.Format("cannot queue the planet-name confirmation: %s", static_cast<LPCSTR>(failure));
    return RuntimeActionResult::Failure(message);
  }
  RuntimeActionResult opened =
      Activate(kControlTagKeyP, RUNTIME_CLASS(TControl), "open the planet-name dialog");
  if (!opened.Succeeded()) {
    return opened;
  }
  if (setupView->planetSeed94 != planetSeed) {
    return ScreenFailure("regenerate the planet from its seed text",
                         CString("the setup screen did not retain the requested planet seed"));
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult RandomSetupScreen::SelectDifficulty(int level) {
  RuntimeActionResult activated =
      Activate(kControlTagDiff, DifficultyTag(level), "select a difficulty");
  if (!activated.Succeeded()) {
    return activated;
  }
  // The cluster records the selection, so a click that resolved but did not take is visible here
  // rather than several steps later as the wrong game.
  if (!DifficultyIsSelected(level)) {
    CString detail;
    detail.Format("difficulty level %d did not become the cluster's selection", level);
    return ScreenFailure("select a difficulty", detail);
  }
  return RuntimeActionResult::Success();
}

bool RandomSetupScreen::DifficultyIsSelected(int level) const {
  TView* cluster = Find(kControlTagDiff);
  if (cluster == 0 || cluster->IsKindOf(RUNTIME_CLASS(TRadioTextCluster)) == 0) {
    return false;
  }
  return static_cast<TRadioTextCluster*>(cluster)->selectedTag88 == DifficultyTag(level);
}

RuntimeActionResult RandomSetupScreen::Accept() {
  return Activate(kControlTagOkay, "accept the random-map setup");
}

RuntimeActionResult RandomSetupScreen::Cancel() {
  return Activate(kControlTagCncl, "cancel back to the main menu");
}
