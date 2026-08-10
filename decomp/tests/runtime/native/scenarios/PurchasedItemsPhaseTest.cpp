#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "RuntimeDifferentialCapture.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/city/TCity.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

#include "parson.h"

namespace {

JSON_Value* BuildPurchasedItemsCaseJson(int nationSlot) {
  JSON_Value* value = json_value_init_object();
  JSON_Object* object = value != 0 ? json_value_get_object(value) : 0;
  JSON_Value* purchasesValue = json_value_init_array();
  JSON_Array* purchases = purchasesValue != 0 ? json_value_get_array(purchasesValue) : 0;
  if (object == 0 || purchases == 0) {
    json_value_free(purchasesValue);
    json_value_free(value);
    return 0;
  }

  const struct {
    const char* resource;
    int amount;
    int price;
  } rows[] = {{"fabric", 3, 7}, {"food", -30, 1}};

  for (int index = 0; index < 2; ++index) {
    JSON_Value* rowValue = json_value_init_object();
    JSON_Object* row = rowValue != 0 ? json_value_get_object(rowValue) : 0;
    if (row == 0 || json_object_set_string(row, "resource", rows[index].resource) != JSONSuccess ||
        json_object_set_number(row, "amount", rows[index].amount) != JSONSuccess ||
        json_object_set_number(row, "price", rows[index].price) != JSONSuccess ||
        json_array_append_value(purchases, rowValue) != JSONSuccess) {
      json_value_free(rowValue);
      json_value_free(purchasesValue);
      json_value_free(value);
      return 0;
    }
  }

  if (json_object_set_number(object, "nation", nationSlot) != JSONSuccess ||
      json_object_set_value(object, "purchases", purchasesValue) != JSONSuccess) {
    json_value_free(purchasesValue);
    json_value_free(value);
    return 0;
  }
  return value;
}

// Exercise the retail bid snapshot and purchased-item commit against a retail-produced save.
class PurchasedItemsPhaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("commit filled and unfilled trade bids", CommitPurchasedItems());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult CommitPurchasedItems() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0) {
      return RuntimeActionResult::Failure("the loaded player has no trade-phase city state");
    }

    nation->SetItemPotentials(kResourceFabric, -1);
    nation->SetItemPotentials(kResourceClothing, -1);

    JSON_Value* caseValue = BuildPurchasedItemsCaseJson(nationSlot);
    if (caseValue == 0) {
      return RuntimeActionResult::Failure("could not build purchased-items case JSON");
    }

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(caseValue);
    if (!started.Succeeded()) {
      return started;
    }

    nation->RememberTradeBids();
    nation->PurchaseItem(kResourceFabric, 3, 7);
    nation->PurchaseItem(kResourceFood, -30, 1);
    nation->AddPurchasedItems();
    return capture.Finish();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(PurchasedItemsPhaseTestCase, PurchasedItemsPhaseTest)
