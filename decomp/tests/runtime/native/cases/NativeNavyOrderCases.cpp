#include "NativeCases.h"
#include "JsonArray.h"
#include "JsonObject.h"

#include "game/globals/game_session_globals.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map/TZone.h"
#include "game/navy/TNavyMgr.h"
#include "game/navy/TOcean.h"
#include "game/navy/TShip.h"
#include "game/navy/TTaskForce.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

TZone* NationPortZone() {
  if (g_pActiveMapOrderContext == 0) {
    return 0;
  }
  return g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(ActiveNationSlot());
}

int ZoneIndex(TZone* zone) {
  if (zone == 0) {
    return -1;
  }
  return static_cast<int>(zone->contextOrdinal14);
}

TShip* SpawnShip(short type, TZone* zone, const char* name) {
  TShip* ship = new TShip();
  ship->IShip(type, zone, ActiveNationSlot(), name);
  return ship;
}

TTaskForce* CreateCommittedEvadeForce(TZone* zone) {
  SpawnShip(3, zone, "navy-cls1");
  SpawnShip(7, zone, "navy-cls2");
  SpawnShip(9, zone, "navy-cls0");
  SpawnShip(12, zone, "navy-cls3");
  TTaskForce* force = zone->CreateTaskForceFromNavyOrdersForNationIfEligible(ActiveNationSlot());
  if (force != 0) {
    force->SubmitOrders(9, 0);
  }
  return force;
}

JSON_Value* ToolbarCountJson(TTaskForce* force) {
  JsonObject result;
  JsonArray available;
  JsonArray selected;
  int slot;
  if (force == 0) {
    for (slot = 0; slot < 4; ++slot) {
      available.Add(0);
      selected.Add(-1);
    }
  } else {
    for (slot = 0; slot < 4; ++slot) {
      available.Add(static_cast<int>(force->shipCountsByToolbarSlot[slot]));
      selected.Add(force->GetSelected(static_cast<short>(slot)));
    }
  }
  result.Set("available", available.Release());
  result.Set("selected", selected.Release());
  return result.Release();
}

} // namespace

RuntimeActionResult RunNavyCreateForce(NativeTransition& transition) {
  TZone* zone = NationPortZone();
  JsonObject args;
  if (zone == 0) {
    return RuntimeActionResult::Failure("the fixture has no port zone for the active nation");
  }
  SpawnShip(3, zone, "navy-create-cls1");
  SpawnShip(9, zone, "navy-create-cls0");

  args.Set("zone", ZoneIndex(zone));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  TTaskForce* force = zone->CreateTaskForceFromNavyOrdersForNationIfEligible(ActiveNationSlot());
  if (force == 0) {
    return RuntimeActionResult::Failure("CreateTaskForceFromNavyOrdersForNationIfEligible returned null");
  }
  force->defeated = 0;
  force->SubmitOrders(9, 0);
  return transition.Finish();
}

RuntimeActionResult RunNavyToolbarCounts(NativeTransition& transition) {
  TZone* zone = NationPortZone();
  JsonObject args;
  TTaskForce* force;
  if (zone == 0) {
    return RuntimeActionResult::Failure("the fixture has no port zone for the active nation");
  }
  force = CreateCommittedEvadeForce(zone);
  if (force == 0) {
    return RuntimeActionResult::Failure("could not commit a task force");
  }

  args.Set("zone", ZoneIndex(zone));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  return transition.Finish(ToolbarCountJson(force));
}

RuntimeActionResult RunNavySelectShip(NativeTransition& transition) {
  TZone* zone = NationPortZone();
  JsonObject args;
  TTaskForce* force;
  if (zone == 0) {
    return RuntimeActionResult::Failure("the fixture has no port zone for the active nation");
  }
  force = CreateCommittedEvadeForce(zone);
  if (force == 0) {
    return RuntimeActionResult::Failure("could not commit a task force");
  }

  args.Set("zone", ZoneIndex(zone));
  args.Set("class", 0);
  args.Set("selecting", false);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  force->Select(static_cast<short>(0), 0);
  return transition.Finish();
}

RuntimeActionResult RunNavySetAggression(NativeTransition& transition) {
  TZone* zone = NationPortZone();
  JsonObject args;
  TTaskForce* force;
  if (zone == 0) {
    return RuntimeActionResult::Failure("the fixture has no port zone for the active nation");
  }
  force = CreateCommittedEvadeForce(zone);
  if (force == 0) {
    return RuntimeActionResult::Failure("could not commit a task force");
  }

  args.Set("zone", ZoneIndex(zone));
  args.Set("aggression", 2);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  force->SetAggression(2);
  return transition.Finish();
}

RuntimeActionResult RunNavySubmitOrder(NativeTransition& transition) {
  TZone* zone = NationPortZone();
  JsonObject args;
  if (zone == 0) {
    return RuntimeActionResult::Failure("the fixture has no port zone for the active nation");
  }
  SpawnShip(3, zone, "navy-submit-cls1");
  SpawnShip(9, zone, "navy-submit-cls0");

  args.Set("zone", ZoneIndex(zone));
  args.Set("order", 9);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  TTaskForce* force = zone->CreateTaskForceFromNavyOrdersForNationIfEligible(ActiveNationSlot());
  if (force == 0) {
    return RuntimeActionResult::Failure("CreateTaskForceFromNavyOrdersForNationIfEligible returned null");
  }
  force->defeated = 0;
  force->SubmitOrders(9, 0);
  return transition.Finish();
}

RuntimeActionResult RunNavyCancelOrder(NativeTransition& transition) {
  TZone* zone = NationPortZone();
  JsonObject args;
  TTaskForce* force;
  if (zone == 0) {
    return RuntimeActionResult::Failure("the fixture has no port zone for the active nation");
  }
  force = CreateCommittedEvadeForce(zone);
  if (force == 0) {
    return RuntimeActionResult::Failure("could not commit a task force");
  }

  args.Set("zone", ZoneIndex(zone));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  force->CancelOrders(0);
  return transition.Finish();
}

RuntimeActionResult RunNavyZoneTarget(NativeTransition& transition) {
  TZone* zone = NationPortZone();
  JsonObject args;
  TTaskForce* force;
  TZone* other;
  bool legal;
  bool illegal;
  if (zone == 0) {
    return RuntimeActionResult::Failure("the fixture has no port zone for the active nation");
  }
  force = CreateCommittedEvadeForce(zone);
  if (force == 0) {
    return RuntimeActionResult::Failure("could not commit a task force");
  }
  other = zone->prev18;
  if (other == 0) {
    other = g_pMapActionContextListHead;
  }

  args.Set("zone", ZoneIndex(zone));
  args.Set("other", ZoneIndex(other));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  legal = force->IsValidTarget(zone);
  illegal = other != 0 && other != zone ? force->IsValidTarget(other) : false;
  JsonObject result;
  result.Set("legal", legal);
  result.Set("illegal", illegal);
  return transition.Finish(result.Release());
}

RuntimeActionResult RunNavyProvinceTarget(NativeTransition& transition) {
  TZone* zone = NationPortZone();
  JsonObject args;
  TTaskForce* force;
  short province;
  bool legal;
  if (zone == 0 || g_pGlobalMapState == 0) {
    return RuntimeActionResult::Failure("the fixture has no port zone for the active nation");
  }
  force = CreateCommittedEvadeForce(zone);
  if (force == 0) {
    return RuntimeActionResult::Failure("could not commit a task force");
  }
  province = 0;
  for (province = 0; province < 0x180; ++province) {
    if (g_pGlobalMapState->cityScoreTable[province].ownerNationCode00 >= 0) {
      break;
    }
  }
  if (province >= 0x180) {
    return RuntimeActionResult::Failure("the fixture has no owned province");
  }

  args.Set("zone", ZoneIndex(zone));
  args.Set("province", static_cast<int>(province));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  legal = force->IsValidTarget(&g_pGlobalMapState->cityScoreTable[province]) != 0;
  return transition.Finish(legal);
}

RuntimeActionResult RunNavySelectionCycling(NativeTransition& transition) {
  TZone* zone = NationPortZone();
  JsonObject args;
  TZone* next;
  if (zone == 0) {
    return RuntimeActionResult::Failure("the fixture has no port zone for the active nation");
  }
  SpawnShip(3, zone, "navy-cycle-cls1");

  args.Set("zone", ZoneIndex(zone));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  next = 0;
  for (TZone* candidate = zone->prev18; candidate != 0; candidate = candidate->prev18) {
    if (candidate->CanDisplayMapOrderEntryInCurrentContext(ActiveNationSlot(), 0) != 0) {
      next = candidate;
      break;
    }
  }
  return transition.Finish(ZoneIndex(next));
}

RuntimeActionResult RunNavyEmptyToolbar(NativeTransition& transition) {
  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  return transition.Finish(ToolbarCountJson(0));
}
