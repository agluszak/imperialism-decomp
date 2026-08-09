#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeSemanticCapture.h"
#include "RuntimeTestFactory.h"
#include "RuntimeRun.h"

#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

#include "parson.h"

namespace {

JSON_Value* BuildMajorTradeCaseJson() {
  JSON_Value* value = json_value_init_object();
  JSON_Object* object = value != 0 ? json_value_get_object(value) : 0;
  JSON_Value* settlementsValue = json_value_init_array();
  JSON_Array* settlements = settlementsValue != 0 ? json_value_get_array(settlementsValue) : 0;
  if (object == 0 || settlements == 0) {
    json_value_free(settlementsValue);
    json_value_free(value);
    return 0;
  }

  const struct {
    const char* resource;
    int amount;
    int price;
  } rows[] = {{"fabric", 3, 7}, {"clothing", -2, 5}, {"fabric", -1, 4}};

  for (int index = 0; index < 3; ++index) {
    JSON_Value* rowValue = json_value_init_object();
    JSON_Object* row = rowValue != 0 ? json_value_get_object(rowValue) : 0;
    if (row == 0 ||
        json_object_set_string(row, "resource", rows[index].resource) != JSONSuccess ||
        json_object_set_number(row, "amount", rows[index].amount) != JSONSuccess ||
        json_object_set_number(row, "price", rows[index].price) != JSONSuccess ||
        json_array_append_value(settlements, rowValue) != JSONSuccess) {
      json_value_free(rowValue);
      json_value_free(settlementsValue);
      json_value_free(value);
      return 0;
    }
  }

  if (json_object_set_value(object, "settlements", settlementsValue) != JSONSuccess) {
    json_value_free(settlementsValue);
    json_value_free(value);
    return 0;
  }
  return value;
}

// Apply one purchase and two sales. Captures before/case/after/result for the Rust
// differential; game_state mirrors after so catalog auto-capture stays satisfied.
class MajorTradeSettlementTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("settle purchase and both sale classes", SettleTrade());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult SettleTrade() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0) {
      return RuntimeActionResult::Failure("the loaded player has no major-nation state");
    }

    if (!CaptureNamedGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("could not capture before game_state");
    }

    JSON_Value* caseValue = BuildMajorTradeCaseJson();
    if (caseValue == 0) {
      return RuntimeActionResult::Failure("could not build trade case JSON");
    }
    RunState().SetCapture("case", caseValue);

    const short previousFabric = nation->purchasedItemsByResource[kResourceFabric];
    const short previousClothing = nation->purchasedItemsByResource[kResourceClothing];
    const int previousTreasury = nation->treasuryValue10;
    const short previousCapacity = nation->availableMerchantCapacity;
    const int previousPoolBase = nation->budgetPoolBase;
    const int previousPoolDelta = nation->budgetPoolDelta;
    const int previousSpecialBalance = nation->field910;

    nation->PurchaseItem(kResourceFabric, 3, 7);
    nation->PurchaseItem(kResourceClothing, -2, 5);
    nation->PurchaseItem(kResourceFabric, -1, 4);

    if (nation->purchasedItemsByResource[kResourceFabric] != previousFabric + 2 ||
        nation->purchasedItemsByResource[kResourceClothing] != previousClothing - 2 ||
        nation->treasuryValue10 != previousTreasury - 7 ||
        nation->availableMerchantCapacity != previousCapacity - 3 ||
        nation->budgetPoolBase != previousPoolBase + 14 ||
        nation->budgetPoolDelta != previousPoolDelta - 21 ||
        nation->field910 != previousSpecialBalance + 2) {
      return RuntimeActionResult::Failure("trade settlement diverged from the retail state update");
    }

    JSON_Value* resultValue = BuildAcceptedOpResult();
    if (resultValue == 0) {
      return RuntimeActionResult::Failure("could not build accepted result JSON");
    }
    RunState().SetCapture("result", resultValue);

    if (!CaptureNamedGameState(RunState(), "after") ||
        !CaptureNamedGameState(RunState(), "game_state")) {
      return RuntimeActionResult::Failure("could not capture after game_state");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(MajorTradeSettlementTestCase, MajorTradeSettlementTest)
