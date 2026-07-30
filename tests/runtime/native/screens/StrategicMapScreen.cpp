#include "StrategicMapScreen.h"

#include "UiAnimationRegistry.h"

#include "game/app/TAnimation.h"
#include "game/app/TAnimator.h"
#include "game/core/global_data_tables.h"
#include "game/globals/ui_core_globals.h"
#include "game/ui_core/TViewMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/military/TArmyMgr.h"
#include "game/ui_widgets/TArmyPlacard.h"
#include "game/ui_widgets/TArmyToolbar.h"
#include "game/ui_widgets/TNumberedArrowButton.h"
#include "game/map_ui/TMapDialog.h"
// The zoom predicates compare subviewAc against goodGoldTagControlA4, so TOceanDialog's
// derivation from TWorldView has to be visible here, not just declared.
#include "game/navy_ui/TOceanDialog.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_widgets/TCivDescription.h"
#include "game/ui_widgets/TCivToolbar.h"
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

RuntimeActionResult StrategicMapScreen::ReopenByTurnEvent(short nationSlot) {
  if (g_pViewMgr == 0) {
    return RuntimeActionResult::Failure("cannot reopen the strategic map: no view manager");
  }
  g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventStrategicMap), nationSlot);
  return RuntimeActionResult::Success();
}

namespace {

// A one-pixel, two-frame animation whose tick interval never elapses: it exists to be found in
// the registry, not to draw anything.
const short kSeededFrameCount = 2;
const short kSeededFrameResourceBase = 0;
const int kSeededTicksPerFrame = 0x7fffffff;

} // namespace

RuntimeActionResult StrategicMapScreen::SeedOwnedAnimation(int tag) {
  if (mapView == 0) {
    return InvalidScreen("give the map an animation to own");
  }
  if (!UiAnimationRegistry::IsReady()) {
    return ScreenFailure("give the map an animation to own",
                         CString("the UI animator has no registry"));
  }
  RECT bounds = {0, 0, 1, 1};
  TAnimation* animation = new TAnimation();
  animation->IAnimation(mapView, &bounds, kSeededFrameCount, kSeededFrameResourceBase,
                        kSeededTicksPerFrame, tag);
  g_pUiAnimator->AddObjectToUiTransientRegistry(animation);
  if (!UiAnimationRegistry::Contains(tag)) {
    return ScreenFailure("give the map an animation to own",
                         CString("the animation did not reach the registry"));
  }
  return RuntimeActionResult::Success();
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

namespace {

// TMapUberPicture::categoryPages index for the army page. 0 is civilian, 1 army, 2 navy.
const int kCivilianCategoryPage = 0;
const int kArmyCategoryPage = 1;
// SetMapInteractionMode argument that puts the map into army-selection mode.
const int kCivilianInteractionMode = 0;
const int kArmyInteractionMode = 1;

// Where the map places the civilian toolbar page once its category is selected.
const int kCivilianToolbarX = 0;
const int kCivilianToolbarY = 0x8f;

} // namespace

RuntimeActionResult StrategicMapScreen::ShowCivilianToolbar() {
  if (mapView == 0) {
    return InvalidScreen("show the civilian toolbar");
  }
  if (mapView->categoryPages[kCivilianCategoryPage] == 0) {
    return ScreenFailure("show the civilian toolbar",
                         CString("the map has no civilian toolbar page"));
  }
  mapView->SetMapInteractionMode(kCivilianInteractionMode);
  return RuntimeActionResult::Success();
}

TCivToolbar* StrategicMapScreen::CivilianToolbar() const {
  if (mapView == 0) {
    return 0;
  }
  TView* page = mapView->categoryPages[kCivilianCategoryPage];
  return page != 0 && page->IsKindOf(RUNTIME_CLASS(TCivToolbar)) != 0
             ? static_cast<TCivToolbar*>(page)
             : 0;
}

bool StrategicMapScreen::CivilianToolbarIsPlaced() const {
  TCivToolbar* toolbar = CivilianToolbar();
  return toolbar != 0 && toolbar->ownerLocalX == kCivilianToolbarX &&
         toolbar->ownerLocalY == kCivilianToolbarY;
}

namespace {

TPicture* CivilianPortrait(TCivToolbar* toolbar) {
  TView* portrait = toolbar != 0 ? toolbar->ResolveControlByTag(kControlTagUnit) : 0;
  return portrait != 0 && portrait->IsKindOf(RUNTIME_CLASS(TPicture)) != 0
             ? static_cast<TPicture*>(portrait)
             : 0;
}

} // namespace

short StrategicMapScreen::CivilianPortraitGlyph() const {
  TPicture* portrait = CivilianPortrait(CivilianToolbar());
  return portrait != 0 ? portrait->glyphBase84 : -1;
}

bool StrategicMapScreen::CivilianPortraitIsLoaded() const {
  TPicture* portrait = CivilianPortrait(CivilianToolbar());
  return portrait != 0 && portrait->cachedBitmap != 0;
}

TCivDescription* StrategicMapScreen::CivilianLegend() const {
  TCivToolbar* toolbar = CivilianToolbar();
  TView* legend = toolbar != 0 ? toolbar->ResolveControlByTag(kControlTagBack) : 0;
  return legend != 0 && legend->IsKindOf(RUNTIME_CLASS(TCivDescription)) != 0
             ? static_cast<TCivDescription*>(legend)
             : 0;
}

RuntimeActionResult StrategicMapScreen::SelectArmyProvince(short province) {
  if (mapView == 0) {
    return InvalidScreen("select an army province");
  }
  if (g_pMapContextActionManager == 0) {
    return ScreenFailure("select an army province", CString("no map context action manager"));
  }
  // The province selection is a model call, not a control activation: the map's own click path
  // resolves a pixel to this province and then does exactly this.
  mapView->SetMapInteractionMode(kArmyInteractionMode);
  g_pMapContextActionManager->SetActiveProvinceSelection(province);
  return RuntimeActionResult::Success();
}

bool StrategicMapScreen::ArmyMenuIsActiveForProvince(short province) const {
  return mapView != 0 && mapView->activeUnitCategoryIndex96 == kArmyInteractionMode &&
         g_pMapContextActionManager != 0 &&
         g_pMapContextActionManager->pendingMapActionIndex == province;
}

TArmyToolbar* StrategicMapScreen::ArmyToolbar() const {
  if (mapView == 0) {
    return 0;
  }
  TView* page = mapView->categoryPages[kArmyCategoryPage];
  return page != 0 && page->IsKindOf(RUNTIME_CLASS(TArmyToolbar)) != 0
             ? static_cast<TArmyToolbar*>(page)
             : 0;
}

TArmyPlacard* StrategicMapScreen::ArmyPlacard(int category) const {
  TArmyToolbar* toolbar = ArmyToolbar();
  TView* placard =
      toolbar != 0 ? toolbar->ResolveControlByTag(kControlTagArmyPlacardFirst + category) : 0;
  return placard != 0 && placard->IsKindOf(RUNTIME_CLASS(TArmyPlacard)) != 0
             ? static_cast<TArmyPlacard*>(placard)
             : 0;
}

TNumberedArrowButton* StrategicMapScreen::ArmyRatioArrow(int category) const {
  TArmyToolbar* toolbar = ArmyToolbar();
  TView* arrow =
      toolbar != 0 ? toolbar->ResolveControlByTag(kControlTagArmyRatioFirst + category) : 0;
  return arrow != 0 && arrow->IsKindOf(RUNTIME_CLASS(TNumberedArrowButton)) != 0
             ? static_cast<TNumberedArrowButton*>(arrow)
             : 0;
}

namespace {

// Both halves click one pixel in from the left edge, at three-quarters or one-quarter height.
// The point is derived from the widget's own bounds, never a literal coordinate.
RuntimeActionResult ClickArrowZone(TNumberedArrowButton* arrow, bool lowerHalf, const char* what) {
  if (arrow == 0) {
    return RuntimeActionResult::Failure("no numbered arrow to click");
  }
  CRect bounds;
  arrow->QueryContentBounds(&bounds);
  const int offsetY = lowerHalf ? arrow->frameHeight38 * 3 / 4 : arrow->frameHeight38 / 4;
  CPoint zone(bounds.left + 1, bounds.top + offsetY); // RUNTIME_COORDINATE_EXPLAINED
  arrow->TrackMouse(kTrackPhaseBegin, zone, zone, zone, 1);
  arrow->TrackMouse(kTrackPhaseEnd, zone, zone, zone, 1);
  (void)what;
  return RuntimeActionResult::Success();
}

} // namespace

RuntimeActionResult StrategicMapScreen::ClickArrowLowerHalf(TNumberedArrowButton* arrow) {
  return ClickArrowZone(arrow, true, "select an idle unit");
}

RuntimeActionResult StrategicMapScreen::ClickArrowUpperHalf(TNumberedArrowButton* arrow) {
  return ClickArrowZone(arrow, false, "return a selected unit");
}

TMapUberPicture* StrategicMapScreen::View() const {
  return mapView;
}

TMapDialog* StrategicMapScreen::Dialog() const {
  return mapView != 0 ? mapView->subview2A8 : 0;
}

bool StrategicMapScreen::HasEndTurnControl() const {
  return Find(kControlTagSend) != 0;
}

bool StrategicMapScreen::HasMiniMap() const {
  return mapView != 0 && mapView->miniMapViewC0 != 0;
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
