#include "RuntimeScenario.h"

#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/military/TCivUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TSortedList.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

class IntroductoryRandomGameTestCase : public RuntimeScenario {
public:
  const char* Name() const override {
    return "random_game_introductory_exits_newspaper";
  }
  bool UsesRandomGameFlow() const override {
    return true;
  }
  int DifficultyLevel() const override {
    return 0;
  }
  bool RecordsGameFlow() const override {
    return true;
  }

  bool BeforeInitialNewspaperExit() override {
    return ValidateStartingCivilians();
  }

  void OnMapReadyWithoutCapitalSelection() override {
    if (ValidateStartingCivilians()) {
      Pass();
    }
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
