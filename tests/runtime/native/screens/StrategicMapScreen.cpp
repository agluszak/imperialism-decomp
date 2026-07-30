#include "StrategicMapScreen.h"

#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
// The zoom predicates compare subviewAc against goodGoldTagControlA4, so TOceanDialog's
// derivation from TWorldView has to be visible here, not just declared.
#include "game/navy_ui/TOceanDialog.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_widgets/TWorldView.h"

StrategicMapScreen::StrategicMapScreen()
    : MainViewScreen(RUNTIME_CLASS(TMapUberPicture), kTurnEventStrategicMap, "the strategic map"),
      mapView(0) {
  mapView = static_cast<TMapUberPicture*>(Root());
}

bool StrategicMapScreen::IsCurrent() {
  return MainViewIsCurrent(RUNTIME_CLASS(TMapUberPicture), kTurnEventStrategicMap);
}

RuntimeActionResult StrategicMapScreen::EndTurn() {
  return Activate(kControlTagDoneCaps, "end the turn");
}

RuntimeActionResult StrategicMapScreen::OpenTrade() {
  return Activate(kControlTagTool, kControlTagTrad, "open the Board of Trade");
}

RuntimeActionResult StrategicMapScreen::OpenDiplomacy() {
  return Activate(kControlTagTool, kControlTagDipl, "open diplomacy");
}

RuntimeActionResult StrategicMapScreen::OpenCity() {
  return Activate(kControlTagTool, kControlTagCity, "open the city screen");
}

RuntimeActionResult StrategicMapScreen::OpenTransport() {
  return Activate(kControlTagTool, kControlTagTran, "open the transport screen");
}

RuntimeActionResult StrategicMapScreen::ZoomOut() {
  return Activate(kControlTagZmOt, "zoom the map out");
}

RuntimeActionResult StrategicMapScreen::ZoomIn() {
  return Activate(kControlTagZmIn, "zoom the map in");
}

RuntimeActionResult StrategicMapScreen::CancelToSetup() {
  return Activate(kControlTagCanc, "cancel back to random setup");
}

RuntimeActionResult StrategicMapScreen::ScrollBy(int direction) {
  if (mapView == 0) {
    return InvalidScreen("scroll the map");
  }
  mapView->Scroll(static_cast<MapScrollEdgeMaskStorage>(direction));
  return RuntimeActionResult::Success();
}

RuntimeActionResult StrategicMapScreen::SetViewportCell(short cellX, short cellY) {
  TMapDialog* dialog = Dialog();
  if (dialog == 0) {
    return InvalidScreen("set the map viewport cell");
  }
  dialog->SetMapDialogCellCoordinatesAndRefresh(cellX, cellY, 0);
  return RuntimeActionResult::Success();
}

TMapUberPicture* StrategicMapScreen::View() const {
  return mapView;
}

TMapDialog* StrategicMapScreen::Dialog() const {
  return mapView != 0 ? mapView->subview2A8 : 0;
}

bool StrategicMapScreen::IsZoomedOut() const {
  // Zoomed out swaps the active subview to the ocean dialog and clears the invalidation flag;
  // the opposite zoom control being present is the third half of the same observation.
  return mapView != 0 && mapView->invalidationFlag94 == 0 &&
         mapView->subviewAc == mapView->goodGoldTagControlA4 && Find(kControlTagZmIn) != 0;
}

bool StrategicMapScreen::IsZoomedIn() const {
  return mapView != 0 && mapView->invalidationFlag94 != 0 &&
         mapView->subviewAc == mapView->subview2A8 && Find(kControlTagZmOt) != 0;
}

int StrategicMapScreen::ViewportOriginX() const {
  TMapDialog* dialog = Dialog();
  return dialog != 0 ? dialog->viewportOrigin.x : -1;
}

int StrategicMapScreen::ViewportOriginY() const {
  TMapDialog* dialog = Dialog();
  return dialog != 0 ? dialog->viewportOrigin.y : -1;
}
