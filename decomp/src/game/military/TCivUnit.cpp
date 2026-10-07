#include "game/military/TCivUnit.h"
#include "game/city_ui/TCivMgr.h"
#include "game/military/TUnit.h"
#include "game/map/TMapMgr.h"
#include "game/city/TCity.h"
#include "game/city/TPopulationMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/core/TStream.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TCivUnit, TUnit)

// FUNCTION: IMPERIALISM 0x005c28c0
TCivUnit::TCivUnit() {
  unitOrder = kUnitOrderIdle;
}

// FUNCTION: IMPERIALISM 0x005c2940
void TCivUnit::ICivUnit(CivilianUnitKind unitKind, int anchorIndex, int nOrderOwnerNationId) {
  IUnit(EncodeCivilianUnitKind(unitKind), anchorIndex, static_cast<short>(nOrderOwnerNationId), 0);
  remainingTurns = 0;
  completionMarker = -1;
}

// FUNCTION: IMPERIALISM 0x005c2980
bool TCivUnit::CanBeOrdered() {
  if (unitOrder != kUnitOrderIdle &&
      (unitOrder < static_cast<UnitOrder>(2) || unitOrder > static_cast<UnitOrder>(3))) {
    return false;
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x005c29b0
void TCivUnit::TickCivWorkOrderCountdownAndComplete() {
  --remainingTurns;
  if (remainingTurns < 1) {
    g_pSelectedCivilianOrderState->CompletedOrders(this);
    unitOrder = kUnitOrderIdle;
  }
}

// FUNCTION: IMPERIALISM 0x005c29f0
void TCivUnit::SetOrders(UnitOrder order, int payload) {
  const short kRemainingTurnsByMode[14] = {0, 0, 0, 0, 0, 1, 3, 3, 1, 0, 3, 3, 4, 1};
  unitOrder = order;
  orderTargetIndex = static_cast<short>(payload);
  remainingTurns = kRemainingTurnsByMode[order];
}

// FUNCTION: IMPERIALISM 0x005c2a90
void TCivUnit::ContinueOrders() {
  switch (unitOrder) {
  case 2:
    return;
  case 5:
  case 6:
  case 7:
  case 8:
  case 10:
  case 11:
  case 12:
  case 13:
    --remainingTurns;
    if (remainingTurns >= 1) {
      return;
    }
    g_pSelectedCivilianOrderState->CompletedOrders(this);
  }
  unitOrder = kUnitOrderIdle;
}

// FUNCTION: IMPERIALISM 0x005c2b10
void TCivUnit::ReadFrom(TStream* stream) {
  TUnit::ReadFrom(stream);
  stream->ReadBytes(&remainingTurns, 2);
}

// FUNCTION: IMPERIALISM 0x005c2b40
void TCivUnit::WriteTo(TStream* stream) {
  TUnit::WriteTo(stream);
  stream->WriteBytes(&remainingTurns, 2);
}

// FUNCTION: IMPERIALISM 0x005c2b70
void TCivUnit::MoveTo(short newTileIndex) {

  if (tileIndex != -1) {
    if (previousAtLocation == 0) {
      g_pGlobalMapState->terrainStateTable[tileIndex].firstCivilianOrder =
          static_cast<TCivUnit*>(nextAtLocation);
    } else {
      previousAtLocation->nextAtLocation = nextAtLocation;
    }
    if (nextAtLocation != 0) {
      nextAtLocation->previousAtLocation = previousAtLocation;
    }
  }

  if (newTileIndex != -1) {
    TCivUnit* oldHead = g_pGlobalMapState->terrainStateTable[newTileIndex].firstCivilianOrder;
    previousAtLocation = 0;
    nextAtLocation = oldHead;
    g_pGlobalMapState->terrainStateTable[newTileIndex].firstCivilianOrder = this;
    if (nextAtLocation != 0) {
      nextAtLocation->previousAtLocation = this;
    }
  } else {
    previousAtLocation = 0;
    nextAtLocation = 0;
  }

  tileIndex = newTileIndex;
}

// FUNCTION: IMPERIALISM 0x005c2c40
void TCivUnit::Vaporize() {
  MoveTo(-1);
}

// FUNCTION: IMPERIALISM 0x005c2c60
void TCivUnit::ClearOrders() {
  Vaporize();
  if (orderType != kCivilianUnitDeveloper) {
    TGreatPower* nation = g_apNationStates[ownerNationSlot];
    TCity* city = (nation != 0) ? nation->city : 0;
    // The original reads city unconditionally here (no null check), so keep the shape.
    city->productionSummary->AddExpert(1);
  }
  Free();
}
