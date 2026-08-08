#include "EngineerDialogScreen.h"

#include "ModalScreen.h"
#include "RuntimeUiDriver.h"

#include "game/ui_screens/TUpDownPictureButton.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"

RuntimeActionResult EngineerDialogScreen::ArmCancel() {
  // The dialog does not exist yet; the cancel is queued against the path it will occupy, and runs
  // from inside the modal loop the click enters.
  return ModalScreen::PreArmDismiss(RuntimeControlSelector(kControlTagDialog, kControlTagCncl,
                                                           RUNTIME_CLASS(TUpDownPictureButton)));
}
