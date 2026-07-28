#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"

#include "game/city_ui/TCivMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapUberPicture.h"
#include "game/military/TCivUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TSortedList.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/ui_screens/TNewspaperView.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TDeluxeText.h"

namespace {

class IntroductoryRandomGameTestCase : public RandomGameScenario {
public:
  int DifficultyLevel() const override {
    return 0;
  }
  bool RecordsGameFlow() const override {
    return true;
  }

  bool BeforeInitialNewspaperExit() override {
    if (!ValidateStartingCivilians()) {
      return false;
    }

    TNewspaperView* newspaper = static_cast<TNewspaperView*>(CurrentMainView());
    const int nationSlot = newspaper->summaryPageIndex90;
    int populatedStories = 0;
    for (int column = 0; column < 3; ++column) {
      for (int row = 0; row < 3; ++row) {
        if (g_pNewsMgr->stories[nationSlot][column][row].entry.storyId != 0) {
          ++populatedStories;
        }
      }
    }
    if (populatedStories == 0) {
      CString failure;
      failure.Format("\"Introductory newspaper page %d has no generated stories "
                     "(active nation %d, template count %d)\"",
                     nationSlot, static_cast<int>(g_pSimMgr->activeNationSlot),
                     g_pNewsMgr->storyTemplateCount);
      FailScenario(failure);
      return false;
    }

    int populatedTextEntries = 0;
    if (newspaper->childList44 == 0) {
      FailScenario("\"Introductory newspaper has no content controls\"");
      return false;
    }
    POSITION position = newspaper->childList44->GetHeadPosition();
    while (position != 0) {
      TView* child = newspaper->childList44->GetNext(position);
      if (child->IsKindOf(RUNTIME_CLASS(TDeluxeText)) != 0) {
        TDeluxeText* textEntry = static_cast<TDeluxeText*>(child);
        if (textEntry->text != 0 && !textEntry->text->IsEmpty()) {
          ++populatedTextEntries;
        }
      }
    }
    if (populatedTextEntries < 2) {
      FailScenario("\"Introductory newspaper did not populate its headline and story text\"");
      return false;
    }
    return true;
  }

  void OnMapReadyWithoutCapitalSelection() override {
    if (!ValidateStartingCivilians()) {
      return;
    }

    TGreatPower* nation = g_apNationStates[g_pSimMgr->activeNationSlot];
    TCivUnit* civilian = static_cast<TCivUnit*>(nation->trackedObjectList->GetEntryByOrdinal(1));
    TMapUberPicture* mapView = g_pViewMgr->mapUberPictureF0;
    if (mapView == 0 || mapView->categoryPages[0] == 0) {
      FailScenario("\"Introductory map has no civilian toolbar page\"");
      return;
    }

    mapView->SetMapInteractionMode(0);
    TView* civilianPage = mapView->categoryPages[0];
    if (civilianPage->ownerLocalX != 0 || civilianPage->ownerLocalY != 0x8f) {
      FailScenario("\"Civilian toolbar page did not move to its visible map position\"");
      return;
    }

    g_pSelectedCivilianOrderState->SetActiveCivilianSelection(civilian, 1);
    TPicture* portrait = static_cast<TPicture*>(civilianPage->ResolveControlByTag(kControlTagUnit));
    if (portrait == 0 || portrait->glyphBase84 != civilian->orderType + 0x438 ||
        portrait->cachedBitmap == 0) {
      FailScenario("\"Civilian toolbar did not load the selected civilian portrait\"");
      return;
    }

    Pass();
  }

private:
  bool ValidateStartingCivilians() {
    TGreatPower* nation = g_apNationStates[g_pSimMgr->activeNationSlot];
    if (nation == 0 || nation->trackedObjectList == 0) {
      FailScenario("\"Introductory game has no active-nation order list\"");
      return false;
    }
    if (nation->trackedObjectList->IsKindOf(RUNTIME_CLASS(TSortedList)) == 0) {
      FailScenario("\"Introductory active-nation order-list pointer has the wrong runtime class\"");
      return false;
    }
    int civilianCount = 0;
    for (int ordinal = 1; ordinal <= nation->trackedObjectList->GetCount(); ++ordinal) {
      CObject* entry = static_cast<CObject*>(nation->trackedObjectList->GetEntryByOrdinal(ordinal));
      if (entry == 0 || entry->IsKindOf(RUNTIME_CLASS(TCivUnit)) == 0) {
        FailScenario("\"Introductory active-nation order list contains a non-civilian\"");
        return false;
      }
      TCivUnit* civilian = static_cast<TCivUnit*>(entry);
      ++civilianCount;
      if (civilian->tileIndex06 < 0) {
        FailScenario("\"Introductory starting civilian has no map tile\"");
        return false;
      }
    }
    if (civilianCount < 5) {
      FailScenario("\"Introductory active nation did not receive five starting civilians\"");
      return false;
    }
    return true;
  }
};

IntroductoryRandomGameTestCase g_test;

} // namespace

RuntimeTestCase* IntroductoryRandomGameTest() {
  return &g_test;
}
