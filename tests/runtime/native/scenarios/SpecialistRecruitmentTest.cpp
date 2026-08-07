#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

#include "game/city/TCity.h"
#include "game/city/TUnitOrder.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/military_ui/TSortedByRelationshipList.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TGreatPower_internal.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Exercise the specialist branch of TUnitOrder::Produce against the retail-produced
// beginning-of-game save. The Rust differential runner applies the same order to its decoded
// GameState and compares the complete semantic state after this scenario finishes.
class SpecialistRecruitmentTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("produce one specialist military unit", ProduceSpecialist());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult ProduceSpecialist() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0 || nation->militaryUnitList44 == 0 ||
        nation->turnSummaryQueue == 0) {
      return RuntimeActionResult::Failure("the loaded player has no recruitment state");
    }

    const int previousCount = nation->militaryUnitList44->GetCount();
    const int previousUnitId = g_pSimMgr->field_64;
    const int previousSummaryCount = nation->turnSummaryQueue->GetSize();
    const short homeTile = nation->city->HomeTownTileId();
    const short homeProvince = g_pGlobalMapState->terrainStateTable[homeTile].cityRecordIndex;

    TUnitOrder order;
    order.IUnitOrder(nation->city, 24, -1, 0, -1, 0, 0, kHighSkillWorkforceMode, 1);
    order.quantity = 1;
    order.Produce();

    if (nation->militaryUnitList44->GetCount() != previousCount + 1 ||
        g_pSimMgr->field_64 != previousUnitId + 1) {
      return RuntimeActionResult::Failure(
          "specialist production did not register one deterministic military unit");
    }
    TMilitaryUnit* unit = TMilitaryUnit::FindUnitByUID(g_pSimMgr->field_64);
    if (unit == 0 || unit->orderType != 24 || unit->tileIndex06 != homeProvince ||
        unit->ownerNationSlot18 != nationSlot || unit->unitOrder != kUnitOrderIdle ||
        unit->orderTargetIndex0C != -1 || unit->unitRosterId1A != 0 ||
        unit->militaryRegistrationFlag1C == 0 || unit->strength34 != 500 || unit->eraIndex36 != 3 ||
        unit->experiencePercent38 != 0 || unit->battleStateFlags3A != 0) {
      return RuntimeActionResult::Failure(
          "the recruited specialist does not have the retail constructor state");
    }
    for (int index = 0; index < 3; ++index) {
      if (unit->orderTargetTiles28[index] != homeProvince ||
          unit->orderTargetTilesMirror2E[index] != homeProvince) {
        return RuntimeActionResult::Failure(
            "the recruited specialist path does not start at its home province");
      }
    }
    if (order.quantity != 0 || nation->pendingActionStatus.byAction[1] != 0 ||
        nation->field8d6[1] != -1 ||
        nation->turnSummaryQueue->GetSize() != previousSummaryCount + 1) {
      return RuntimeActionResult::Failure(
          "specialist production did not preserve its retail order and announcement tail");
    }
    TurnOrderDispatchPacket* summary = static_cast<TurnOrderDispatchPacket*>(
        nation->turnSummaryQueue->GetPtrListEntryByOneBasedIndex(previousSummaryCount + 1));
    if (summary == 0 || summary->turnTick != g_pSimMgr->economicTurn || summary->orderKind != 3 ||
        summary->payload != 24 || summary->flags != 1) {
      return RuntimeActionResult::Failure(
          "specialist production queued the wrong retail announcement record");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(SpecialistRecruitmentTestCase, SpecialistRecruitmentTest)
