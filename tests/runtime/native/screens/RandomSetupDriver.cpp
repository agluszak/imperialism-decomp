#include "RandomSetupDriver.h"

#include "RuntimeUiDriver.h"
#include "game/ui_core/CMcEditWindow.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_core/TView.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

RandomSetupDriver::RandomSetupDriver(TView* view) : root(view) {}

short RandomSetupDriver::SelectedNationSlot() const {
  return static_cast<TSetupRandomMapPicture*>(root)->selectedNationSlot9A;
}

bool RandomSetupDriver::SetCountryName(const char* name) {
  TEditText* country =
      root != 0 ? static_cast<TEditText*>(root->ResolveControlByTag(kControlTagCoun)) : 0;
  if (country == 0) {
    return false;
  }
  CString countryName(name);
  if (country->editWindow != 0) {
    country->editWindow->SetWindowText(countryName);
  } else {
    country->SetTextAndMaybeRefresh(&countryName, 1);
  }
  return true;
}

bool RandomSetupDriver::SelectDifficulty(unsigned long tag, bool nativeClick) {
  TRadioTextCluster* difficulty =
      root != 0 ? static_cast<TRadioTextCluster*>(root->ResolveControlByTag(kControlTagDiff)) : 0;
  TControl* option =
      difficulty != 0 ? static_cast<TControl*>(difficulty->ResolveControlByTag(tag)) : 0;
  if (option == 0) {
    return false;
  }
  if (nativeClick) {
    if (!RuntimeUiDriver::ClickView(option)) {
      return false;
    }
  } else {
    option->HandleEvent(option->GetEventNumber(), option, 0);
  }
  return difficulty->selectedTag88 == static_cast<int>(tag);
}

bool RandomSetupDriver::Accept(bool nativeClick) {
  if (nativeClick) {
    return RuntimeUiDriver::ClickControl(root, kControlTagOkay);
  }
  return RuntimeUiDriver::ActivateControl(root, kControlTagOkay);
}
