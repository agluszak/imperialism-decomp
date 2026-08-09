#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeSemanticCapture.h"
#include "RuntimeTestFactory.h"
#include "RuntimeRun.h"

#include "parson.h"

namespace {

// Major-nation trade command against a non-major slot. Rust GameCommand rejects with
// NotMajorNation; C++ records the same gate (g_apNationStates only covers slots 0..6).
class MajorTradeNotMajorTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("reject trade command for a minor nation slot", RejectTradeOnMinor());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult RejectTradeOnMinor() {
    const int nationSlot = 7;

    if (!CaptureNamedGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("could not capture before game_state");
    }

    JSON_Value* caseValue = json_value_init_object();
    JSON_Object* caseObject = caseValue != 0 ? json_value_get_object(caseValue) : 0;
    JSON_Value* settlementsValue = json_value_init_array();
    JSON_Array* settlements =
        settlementsValue != 0 ? json_value_get_array(settlementsValue) : 0;
    JSON_Value* rowValue = json_value_init_object();
    JSON_Object* row = rowValue != 0 ? json_value_get_object(rowValue) : 0;
    if (caseObject == 0 || settlements == 0 || row == 0 ||
        json_object_set_number(caseObject, "nation", nationSlot) != JSONSuccess ||
        json_object_set_string(row, "resource", "fabric") != JSONSuccess ||
        json_object_set_number(row, "amount", 1) != JSONSuccess ||
        json_object_set_number(row, "price", 1) != JSONSuccess ||
        json_array_append_value(settlements, rowValue) != JSONSuccess ||
        json_object_set_value(caseObject, "settlements", settlementsValue) != JSONSuccess) {
      json_value_free(rowValue);
      json_value_free(settlementsValue);
      json_value_free(caseValue);
      return RuntimeActionResult::Failure("could not build rejected trade case JSON");
    }
    RunState().SetCapture("case", caseValue);

    // Slots 0..6 are the only major-nation command targets (g_apNationStates[7]).
    if (nationSlot >= 0 && nationSlot < 7) {
      return RuntimeActionResult::Failure("test fixture nation slot unexpectedly addresses a major");
    }

    JSON_Value* resultValue = BuildRejectedNotMajorOpResult(nationSlot);
    if (resultValue == 0) {
      return RuntimeActionResult::Failure("could not build rejected result JSON");
    }
    RunState().SetCapture("result", resultValue);

    // No mutation: after matches before.
    if (!CaptureNamedGameState(RunState(), "after") ||
        !CaptureNamedGameState(RunState(), "game_state")) {
      return RuntimeActionResult::Failure("could not capture after game_state");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(MajorTradeNotMajorTestCase, MajorTradeNotMajorTest)
