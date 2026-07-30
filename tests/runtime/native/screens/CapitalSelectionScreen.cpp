#include "CapitalSelectionScreen.h"

#include "game/map/TMapUberPicture.h"
#include "game/turn_event_codes.h"
#include "game/ui_tags_common.h"

CapitalSelectionScreen::CapitalSelectionScreen()
    : MainViewScreen(RUNTIME_CLASS(TMapUberPicture), kTurnEventCitySiteSelector,
                     "capital selection") {}

bool CapitalSelectionScreen::IsCurrent() {
  return MainViewIsCurrent(RUNTIME_CLASS(TMapUberPicture), kTurnEventCitySiteSelector);
}

RuntimeActionResult CapitalSelectionScreen::CancelToSetup() {
  return Activate(kControlTagCanc, "cancel back to the random-map setup");
}
