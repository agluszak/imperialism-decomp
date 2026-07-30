#include "StrategicMapScreen.h"

#include "RuntimeObservations.h"
#include "RuntimeUiDriver.h"

#include "game/core/global_data_tables.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
// The zoom predicates compare subviewAc against goodGoldTagControlA4, so TOceanDialog's
// derivation from TWorldView has to be visible here, not just declared.
#include "game/navy_ui/TOceanDialog.h"
#include "game/ui_widgets/TWorldView.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"
#include "game/ui_tags_widgets.h"
#include "game/globals/view_registries.h"

namespace {

// The screen's identity. The modal check belongs here: a dialog covering the map means an
// activation would resolve against the modal, not the map, so treating "map is the main view"
// as "map is current" is what let a stray dialog be mistaken for the screen beneath it.
bool StrategicMapIsCurrent() {
  if (g_pViewMgr == 0 || g_pViewMgr->currentTurnEventCode != kTurnEventStrategicMap) {
    return false;
  }
  if (!g_ModalViewStack.IsEmpty()) {
    return false;
  }
  return RuntimeIsViewKindOf(RuntimeMainView(), RUNTIME_CLASS(TMapUberPicture));
}

} // namespace

StrategicMapScreen::StrategicMapScreen() : mapView(0) {
  if (StrategicMapIsCurrent()) {
    mapView = static_cast<TMapUberPicture*>(RuntimeMainView());
  }
}

bool StrategicMapScreen::IsCurrent() {
  return StrategicMapIsCurrent();
}

bool StrategicMapScreen::IsValid() const {
  return mapView != 0;
}

RuntimeActionResult StrategicMapScreen::InvalidScreen(const char* what) const {
  // Name what *is* current. "control is missing" sends the reader looking for a UI defect when
  // the real problem is that the script is on the wrong screen.
  CString message;
  message.Format("cannot %s: the strategic map is not the current screen "
                 "(expected TMapUberPicture at event 0x%04x, found %s at event 0x%04x, "
                 "modal depth %d)",
                 what, static_cast<unsigned int>(kTurnEventStrategicMap),
                 RuntimeClassName(RuntimeMainView()),
                 g_pViewMgr != 0 ? static_cast<unsigned int>(g_pViewMgr->currentTurnEventCode) : 0u,
                 g_ModalViewStack.GetCount());
  return RuntimeActionResult::Failure(message);
}

RuntimeActionResult StrategicMapScreen::Activate(int tag, const char* what) {
  if (mapView == 0) {
    return InvalidScreen(what);
  }
  CString failure;
  if (!RuntimeUiDriver::Activate(mapView, RuntimeControlSelector(tag, RUNTIME_CLASS(TControl)),
                                 &failure)) {
    // RequireControl's diagnosis is the useful part; pass it through rather than summarising.
    CString message;
    message.Format("cannot %s: %s", what, static_cast<LPCSTR>(failure));
    return RuntimeActionResult::Failure(message);
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult StrategicMapScreen::ActivateInToolbar(int toolTag, const char* what) {
  if (mapView == 0) {
    return InvalidScreen(what);
  }
  CString failure;
  if (!RuntimeUiDriver::Activate(
          mapView, RuntimeControlSelector(kControlTagTool, toolTag, RUNTIME_CLASS(TControl)),
          &failure)) {
    CString message;
    message.Format("cannot %s: %s", what, static_cast<LPCSTR>(failure));
    return RuntimeActionResult::Failure(message);
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult StrategicMapScreen::EndTurn() {
  return Activate(kControlTagDoneCaps, "end the turn");
}

RuntimeActionResult StrategicMapScreen::OpenTrade() {
  return ActivateInToolbar(kControlTagTrad, "open the Board of Trade");
}

RuntimeActionResult StrategicMapScreen::OpenDiplomacy() {
  return ActivateInToolbar(kControlTagDipl, "open diplomacy");
}

RuntimeActionResult StrategicMapScreen::OpenCity() {
  return ActivateInToolbar(kControlTagCity, "open the city screen");
}

RuntimeActionResult StrategicMapScreen::OpenTransport() {
  return ActivateInToolbar(kControlTagTran, "open the transport screen");
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
  // Zoomed out swaps the active subview to the ocean dialog and clears the invalidation flag.
  return mapView != 0 && mapView->invalidationFlag94 == 0 &&
         mapView->subviewAc == mapView->goodGoldTagControlA4 &&
         mapView->ResolveControlByTag(kControlTagZmIn) != 0;
}

bool StrategicMapScreen::IsZoomedIn() const {
  return mapView != 0 && mapView->invalidationFlag94 != 0 &&
         mapView->subviewAc == mapView->subview2A8 &&
         mapView->ResolveControlByTag(kControlTagZmOt) != 0;
}

int StrategicMapScreen::ViewportOriginX() const {
  TMapDialog* dialog = Dialog();
  return dialog != 0 ? dialog->viewportOrigin.x : -1;
}

int StrategicMapScreen::ViewportOriginY() const {
  TMapDialog* dialog = Dialog();
  return dialog != 0 ? dialog->viewportOrigin.y : -1;
}
