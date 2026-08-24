#include "NativeTransition.h"
#include "JsonObject.h"
#include "RuntimeRun.h"

#include "game/globals/shared_globals.h"
#include "game/globals/navy_globals.h"
#include "game/globals/tactical_ui_globals.h"
#include "game/city/TCity.h"
#include "game/city/TShipOrder.h"
#include "game/navy/TAdmiral.h"
#include "game/navy/TShip.h"
#include "game/nation/TGreatPower.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_screens/TSimMgr.h"

#include <string.h>

namespace {

void ClearScheduledUnlocksExcept(int keepTechId, short economicTurn) {
  g_pSimMgr->economicTurn = economicTurn;
  for (int techId = 3; techId < 0x1d; ++techId) {
    if (techId == keepTechId) {
      continue;
    }
    if (g_pTechMgr->perTechUnlockFlag180[techId] == 0) {
      g_pTechMgr->prioritySlots04[techId] = 0;
    }
  }
}

void ClearNationNavy(short nationSlot) {
  TAdmiral* admiral = g_pNavySecondaryOrderListHead;
  while (admiral != 0) {
    TAdmiral* next = admiral->next;
    if (admiral->nationSlot == nationSlot) {
      admiral->Free();
    }
    admiral = next;
  }
  TShip* ship = g_pNavyPrimaryOrderListHead;
  while (ship != 0) {
    TShip* next = ship->next;
    if (ship->nation == nationSlot) {
      ship->Sink();
    }
    ship = next;
  }
}

} // namespace

RuntimeActionResult RunCheckTechnologyAdvances(NativeTransition& transition) {
  if (g_pTechMgr == 0 || g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("technology state is unavailable");
  }

  const short economicTurn = 1234;
  ClearScheduledUnlocksExcept(4, economicTurn);
  g_pTechMgr->perTechUnlockFlag180[4] = 0;
  g_pTechMgr->prioritySlots04[4] = economicTurn;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }
  g_pTechMgr->CheckForAdvances();
  return transition.Finish();
}

RuntimeActionResult RunCheckTechnologyAdvancesAiPurchase(NativeTransition& transition) {
  if (g_pTechMgr == 0 || g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("technology state is unavailable");
  }

  const short activeNationSlot = g_pSimMgr->GetActiveNationId();
  const short aiNationSlot = activeNationSlot == 0 ? 1 : 0;
  TGreatPower* aiNation = g_apNationStates[aiNationSlot];
  if (aiNation == 0) {
    return RuntimeActionResult::Failure("the loaded game has no AI great-power slot");
  }

  g_pSimMgr->economicTurn = 1;
  for (int techId = 3; techId < 0x1d; ++techId) {
    g_pTechMgr->perTechUnlockFlag180[techId] = 0;
    g_pTechMgr->prioritySlots04[techId] = 0;
    g_pTechMgr->orderCapRows277[aiNationSlot].techStatusByTechId[techId] = 2;
  }
  g_pTechMgr->perTechUnlockFlag180[3] = 1;
  g_pTechMgr->orderCapRows277[aiNationSlot].techStatusByTechId[3] = 0;
  aiNation->diplomacyEligibilityA0 = 0;
  aiNation->treasuryValue10 = 50000;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }
  g_pTechMgr->CheckForAdvances();
  return transition.Finish();
}

RuntimeActionResult RunTechnologyNavalCapabilityUpgrade(NativeTransition& transition) {
  const short activeNationSlot = g_pSimMgr->GetActiveNationId();
  const short nationSlot = activeNationSlot == 0 ? 1 : 0;
  TGreatPower* nation = g_apNationStates[nationSlot];
  TZone* zone = g_pMapActionContextListHead;
  if (nation == 0 || nation->city == 0 || zone == 0) {
    return RuntimeActionResult::Failure("technology naval-upgrade fixture is unavailable");
  }

  ClearNationNavy(nationSlot);
  memset(g_pTechMgr->capRowsB333[nationSlot].selectedByResourceType, 1, 5);
  memset(&g_pTechMgr->capRowsB333[nationSlot].selectedByResourceType[5], 0, 9);
  const short initialShipTypes[8] = {1, 2, 0, 0, 3, 4, 0, 0};
  for (int slot = 0; slot < 8; ++slot) {
    nation->city->shipOrderSlots190[slot]->resourceTypeIndex = initialShipTypes[slot];
  }

  TShip* survivorA = new TShip();
  survivorA->IShip(3, zone, nationSlot, "technology-survivor-a");
  survivorA->experience = 100;
  TShip* survivorB = new TShip();
  survivorB->IShip(4, zone, nationSlot, "technology-survivor-b");
  survivorB->experience = 498;
  TShip* obsolete = new TShip();
  obsolete->IShip(1, zone, nationSlot, "technology-obsolete");
  obsolete->experience = 250;
  TAdmiral* admiral = new TAdmiral(nationSlot);
  admiral->displayName = "technology-admiral";
  admiral->experiencePoints = 200;
  admiral->AssignToShip(obsolete);

  const int technologyId = 9;
  g_pTechMgr->orderCapRows277[nationSlot].techStatusByTechId[technologyId] = 1;
  g_pTechMgr->capRowsE4a6[nationSlot].completionYearOffsetByTechId[technologyId] = 77;

  JsonObject args;
  args.Set("nation", nationSlot);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  g_pTechMgr->HandleAbilityUnlock(technologyId, nationSlot);
  return transition.Finish();
}

RuntimeActionResult RunTechnologyNavalCapabilitySequence(NativeTransition& transition) {
  const short activeNationSlot = g_pSimMgr->GetActiveNationId();
  const short nationSlot = activeNationSlot == 0 ? 1 : 0;
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->city == 0) {
    return RuntimeActionResult::Failure("technology naval-sequence fixture is unavailable");
  }

  ClearNationNavy(nationSlot);
  memset(g_pTechMgr->capRowsB333[nationSlot].selectedByResourceType, 1, 5);
  memset(&g_pTechMgr->capRowsB333[nationSlot].selectedByResourceType[5], 0, 9);
  const short initialShipTypes[8] = {1, 2, 0, 0, 3, 4, 0, 0};
  for (int slot = 0; slot < 8; ++slot) {
    nation->city->shipOrderSlots190[slot]->resourceTypeIndex = initialShipTypes[slot];
  }

  const int technologyIds[] = {4, 9, 15, 21, 24, 27};
  for (int index = 0; index < 6; ++index) {
    const int technologyId = technologyIds[index];
    g_pTechMgr->orderCapRows277[nationSlot].techStatusByTechId[technologyId] = 1;
    g_pTechMgr->capRowsE4a6[nationSlot].completionYearOffsetByTechId[technologyId] =
        static_cast<short>(70 + index);
  }

  JsonObject args;
  args.Set("nation", nationSlot);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  for (int unlockIndex = 0; unlockIndex < 6; ++unlockIndex) {
    g_pTechMgr->HandleAbilityUnlock(technologyIds[unlockIndex], nationSlot);
  }
  return transition.Finish();
}

RuntimeActionResult RunTechnologyTurnStop(NativeTransition& transition) {
  if (g_pTechMgr == 0 || g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("technology state is unavailable");
  }

  const int technologyId = 3;
  ClearScheduledUnlocksExcept(-1, 1);
  const short activeNationSlot = g_pSimMgr->GetActiveNationId();
  g_pTechMgr->orderCapRows277[activeNationSlot].techStatusByTechId[technologyId] = 1;
  g_pSimMgr->turnStateCode = 0x11;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }
  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  RuntimeActionResult finished =
      transition.Finish(json_value_init_string("technology_advance"));
  if (!finished.Succeeded()) {
    return finished;
  }

  JsonObject continuation;
  continuation.Set("TechnologyReport", technologyId);
  if (json_object_dotset_value(transition.Run().Captures(), "after.ephemeral.continuation",
                               continuation.Release()) != JSONSuccess) {
    return RuntimeActionResult::Failure("technology continuation capture failed");
  }
  return finished;
}
