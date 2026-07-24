#include "game/military/TCivUnit.h"
#include "game/city_ui/TCivMgr.h"
#include "game/military/TUnit.h"
#include "game/map/TMapMgr.h"
#include "game/city/TCity.h"
#include "game/city/TPopulationMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/core/TStream.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// SYNTHETIC: IMPERIALISM 0x005c2860
// TCivUnit::CreateObject

// SYNTHETIC: IMPERIALISM 0x005c28a0
// TCivUnit::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCivUnit, TUnit)

// FUNCTION: IMPERIALISM 0x005c28c0
TCivUnit::TCivUnit() {}

// SYNTHETIC: IMPERIALISM 0x005c28f0
// TCivUnit::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005c2920
TCivUnit::~TCivUnit() {}

// FUNCTION: IMPERIALISM 0x005c2940
void TCivUnit::ICivUnit(CivilianUnitKind unitKind, int anchorIndex, int nOrderOwnerNationId) {
  this->RegisterUnitOrderWithOwnerManager(EncodeCivilianUnitKind(unitKind), anchorIndex,
                                          static_cast<short>(nOrderOwnerNationId), 0);
  this->remainingTurns24 = 0;
  this->completionMarker26 = static_cast<short>(-1);
}

// FUNCTION: IMPERIALISM 0x005c2980
int TCivUnit::IsInIdleSelectionState() {
  if (this->unitOrder != kUnitOrderIdle && (this->unitOrder < static_cast<UnitOrder>(2) ||
                                            this->unitOrder > static_cast<UnitOrder>(3))) {
    return 0;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x005c29b0
void TCivUnit::TickCivWorkOrderCountdownAndComplete() {
  --remainingTurns24;
  if (remainingTurns24 < 1) {
    g_pSelectedCivilianOrderState->ApplyCompletedCivWorkOrderToMapState(this);
    unitOrder = kUnitOrderIdle;
  }
}

// FUNCTION: IMPERIALISM 0x005c29f0
void TCivUnit::SetOrders(UnitOrder order, int payload) {
  const short kRemainingTurnsByMode[14] = {0, 0, 0, 0, 0, 1, 3, 3, 1, 0, 3, 3, 4, 1};
  unitOrder = order;
  field_C = static_cast<short>(payload);
  remainingTurns24 = kRemainingTurnsByMode[order];
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
    --remainingTurns24;
    if (remainingTurns24 >= 1) {
      return;
    }
    g_pSelectedCivilianOrderState->ApplyCompletedCivWorkOrderToMapState(this);
  }
  unitOrder = kUnitOrderIdle;
}

// FUNCTION: IMPERIALISM 0x005c2b10
void TCivUnit::ReadFrom(TStream* stream) {
  TUnit::ReadFrom(stream);
  stream->ReadBytes(&remainingTurns24, 2);
}

// FUNCTION: IMPERIALISM 0x005c2b40
void TCivUnit::WriteTo(TStream* stream) {
  TUnit::WriteTo(stream);
  stream->WriteBytesSlot78(&remainingTurns24, 2);
}

// Moves this unit between two tiles' civilian-order chains (terrainStateTable[tile-
// Index06].firstCivilianOrder20, threaded via nextOnTile/field_10): detaches from the
// current tile (if any) unlinking via field_10's prev-pointer role, then prepends to
// the new tile's chain (if anchorIndex isn't -1 = none).
// FUNCTION: IMPERIALISM 0x005c2b70
void TCivUnit::MoveTo(int anchorIndex) {
  short newTileIndex = static_cast<short>(anchorIndex);

  if (tileIndex06 != -1) {
    if (field_10 == 0) {
      g_pGlobalMapState->terrainStateTable[tileIndex06].firstCivilianOrder20 =
          static_cast<TCivUnit*>(nextOnTile);
    } else {
      field_10->nextOnTile = nextOnTile;
    }
    if (nextOnTile != 0) {
      nextOnTile->field_10 = field_10;
    }
  }

  if (newTileIndex != -1) {
    TCivUnit* oldHead = g_pGlobalMapState->terrainStateTable[newTileIndex].firstCivilianOrder20;
    field_10 = 0;
    nextOnTile = oldHead;
    g_pGlobalMapState->terrainStateTable[newTileIndex].firstCivilianOrder20 = this;
    if (nextOnTile != 0) {
      nextOnTile->field_10 = this;
    }
  } else {
    field_10 = 0;
    nextOnTile = 0;
  }

  tileIndex06 = newTileIndex;
}

// FUNCTION: IMPERIALISM 0x005c2c40
void TCivUnit::DetachUnitOrderFromOwnerAndReset() {}

// FUNCTION: IMPERIALISM 0x005c2c60
void TCivUnit::ResetCivWorkOrderAndRefreshCounters() {
  DetachUnitOrderFromOwnerAndReset();
  if (orderType != kCivilianUnitDeveloper) {
    TGreatPower* nation = g_apNationStates[field_18];
    TCity* city = (nation != 0) ? nation->city : 0;
    // The original reads city unconditionally here (no null check), so keep the shape.
    city->productionSummary1d8->AddExpert(1);
  }
  Free();
}
