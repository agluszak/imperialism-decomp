#include "JsonArray.h"
#include "JsonObject.h"
#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeTestFactory.h"
#include "RuntimeRun.h"
#include "flows/EndTurnFlow.h"
#include "screens/StrategicMapScreen.h"

#include "game/globals/shared_globals.h"
#include "game/ui_screens/TSimMgr.h"

#include "parson.h"

namespace {

JSON_Value* BuildEasyTurnCaseJson() {
  JSON_Value* value = json_value_init_object();
  JSON_Object* object = value != 0 ? json_value_get_object(value) : 0;
  if (object == 0 || json_object_set_boolean(object, "reject_offers", 1) != JSONSuccess ||
      json_object_set_boolean(object, "expect_exactly_one_turn", 1) != JSONSuccess) {
    json_value_free(value);
    return 0;
  }
  return value;
}

// One Easy end-turn from a retail save already on the strategic map. Captures
// before/case/after/result for the Rust differential.
class EasyTurnFromSaveTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_AWAIT(StrategicMap().HasMiniMap(), kObserveUiStateChanged);
    RT_AWAIT(StrategicMap().HasEndTurnControl(), kObserveUiStateChanged);
    RT_REQUIRE(StrategicMap().IsCurrent());
    RT_REQUIRE(g_pSimMgr != 0);

    RT_DO("capture before-state and case", CaptureBefore());
    RT_RUN(endTurn.RejectOffers().ExpectExactlyOneTurn().ToNextStrategicMap(*this));
    RT_REQUIRE_EQ(endTurn.StartingTurn() + 1, endTurn.EndingTurn());
    RT_REQUIRE(!endTurn.SawTurnAlert());
    RT_REQUIRE(!endTurn.SawOfferDesk());
    RT_REQUIRE(endTurn.SawDealBook());
    RT_REQUIRE(endTurn.SawNewspaper());
    RT_DO("capture after-state and result", CaptureAfter());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult CaptureBefore() {
    if (!CaptureSaveBackedGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("could not capture before save-backed state");
    }

    JSON_Value* caseValue = BuildEasyTurnCaseJson();
    if (caseValue == 0) {
      return RuntimeActionResult::Failure("could not build easy-turn case JSON");
    }
    RunState().SetCapture("case", caseValue);
    return RuntimeActionResult::Success();
  }

  RuntimeActionResult CaptureAfter() {
    JsonArray gates;
    gates.Add("deal_book");
    gates.Add("newspaper");
    JsonObject result;
    result.Set("kind", "completed");
    result.Set("from_turn", endTurn.StartingTurn());
    result.Set("to_turn", endTurn.EndingTurn());
    result.Set("gates", gates.Release());
    RunState().SetCapture("result", result.Release());

    if (!RunState().HasCapture("result") || !CaptureSaveBackedGameState(RunState(), "after")) {
      return RuntimeActionResult::Failure("could not capture after save-backed state");
    }
    return RuntimeActionResult::Success();
  }

  EndTurnFlow endTurn;
};

} // namespace

RUNTIME_TEST_FACTORY(EasyTurnFromSaveTestCase, EasyTurnFromSaveTest)
