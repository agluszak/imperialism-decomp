#include "CityScreen.h"

#include "game/city_ui/TCityProductionView.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TView.h"
#include "game/ui_fourcc.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"
#include "game/ui_widgets/TPlacard.h"

namespace {

// The death-toll placard beside the sickness one. Local to this screen.
const int kControlTagDead = IMPERIALISM_FOURCC('d', 'e', 'a', 'd');

TPlacard* PlacardAt(TView* root, int tag) {
  TView* placard = root != 0 ? root->ResolveControlByTag(tag) : 0;
  return placard != 0 && placard->IsKindOf(RUNTIME_CLASS(TPlacard)) != 0
             ? static_cast<TPlacard*>(placard)
             : 0;
}

} // namespace

MainViewScreenIdentity CityScreen::Identity() {
  return MainViewScreenIdentity(RUNTIME_CLASS(TCityProductionView), kTurnEventCityProduction,
                                "the city production screen");
}

CityScreen::CityScreen() : MainViewScreen(Identity()), cityView(0) {
  cityView = static_cast<TCityProductionView*>(Root());
}

bool CityScreen::IsCurrent() {
  return MainViewIsCurrent(RUNTIME_CLASS(TCityProductionView), kTurnEventCityProduction);
}

TCityProductionView* CityScreen::View() const {
  return cityView;
}

TCityProductionView* CityScreenProductionView() {
  return CityScreen().View();
}

bool CityScreen::HasProductionControls() const {
  return Find(kControlTagLabP) != 0 && Find(kControlTagMeat) != 0;
}

bool CityScreen::SicknessPlacardsAreCleared() const {
  TPlacard* sick = PlacardAt(Root(), kControlTagSick);
  TPlacard* dead = PlacardAt(Root(), kControlTagDead);
  // Both have to exist -- an absent placard is a different defect from a cleared one -- and both
  // have to be drawing nothing and taking no input.
  return sick != 0 && dead != 0 && sick->glyph90 == 0 && sick->enabled == 0 && dead->glyph90 == 0 &&
         dead->enabled == 0;
}

namespace {

HWND CityHostWindow(TView* view) {
  return view != 0 && view->nativeWindow50 != 0 ? view->nativeWindow50->m_hWnd : 0;
}

} // namespace

RuntimeActionResult CityScreen::ForceOnePaint() {
  HWND host = CityHostWindow(cityView);
  if (host == 0) {
    return InvalidScreen("force one city paint");
  }
  // Synchronous on purpose: RDW_UPDATENOW paints before returning, so what the caller checks
  // afterwards is the state the screen settled into, not a repaint still queued behind it.
  if (RedrawWindow(host, 0, 0, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN) == 0) {
    return ScreenFailure("force one city paint", CString("the window refused to repaint"));
  }
  return RuntimeActionResult::Success();
}

bool CityScreen::HasPendingPaint() const {
  HWND host = CityHostWindow(cityView);
  // No window is not "nothing pending": say pending so a caller cannot read a missing host as a
  // settled screen.
  return host == 0 || GetUpdateRect(host, 0, FALSE) != 0;
}

RuntimeActionResult CityScreen::OpenBuilding(short buildingSlot) {
  if (cityView == 0) {
    return InvalidScreen("open a city building");
  }
  // The buildings are hit regions on the city artwork rather than controls with tags, so this is
  // the view's own hit resolution rather than a control activation.
  if (!cityView->ActivateBuildingSlotForRuntimeTest(buildingSlot)) {
    CString detail;
    detail.Format("building slot %d has no active hit region", static_cast<int>(buildingSlot));
    return ScreenFailure("open a city building", detail);
  }
  return RuntimeActionResult::Success();
}

bool CityScreen::BuildingIsOpen(short buildingSlot) const {
  return cityView != 0 && cityView->BuildingViewForRuntimeTest(buildingSlot) != 0;
}

bool CityScreen::HasBuildingAnimation(short buildingSlot) const {
  return cityView != 0 && cityView->BuildingActionAnimationForRuntimeTest(buildingSlot) != 0;
}

RuntimeActionResult CityScreen::Close() {
  return Activate(kControlTagEnd, "leave the city production screen");
}
