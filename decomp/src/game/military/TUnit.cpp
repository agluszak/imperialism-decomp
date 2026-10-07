#include "game/military/TUnit.h"
#include "decomp_types.h"
#include "game/GameAssert.h"

#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/city_ui/TCountry.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TSortedList.h"
#include "game/core/TStream.h"
#include "game/gfx/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x005c2470
void TUnit::Vaporize() {}

IMPLEMENT_DYNCREATE(TUnit, TObject)

// FUNCTION: IMPERIALISM 0x005c2530
void TUnit::IUnit(short nOrderType, int anchorIndex, short nOrderOwnerNationId, short arg3) {
  orderType = nOrderType;
  unitOrder = kUnitOrderIdle;
  MoveTo(anchorIndex);

  TSortedList* ownerManager;
  if (militaryRegistrationFlag) {
    ownerManager = g_apTerrainTypeDescriptorTable[nOrderOwnerNationId]->militaryUnitList;
  } else {
    ownerManager = g_apNationStates[nOrderOwnerNationId]->trackedObjectList;
  }

  if (ownerManager == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UUnit.cpp", 0x11f);
  }

  ownerManager->AddTail(this);

  ownerNationSlot = nOrderOwnerNationId;
  unitRosterId = arg3;
  orderTargetIndex = -1;

  TSimMgr* simMgr = g_pSimMgr;
  ++simMgr->lastPersistentUnitId;
  persistentUnitId = simMgr->lastPersistentUnitId;
}

// FUNCTION: IMPERIALISM 0x005c2610
void TUnit::MoveTo(short anchorIndex) {}

// FUNCTION: IMPERIALISM 0x005c2630
void TUnit::SetOrders(UnitOrder order, int payload) {
  unitOrder = order;
  orderTargetIndex = static_cast<short>(payload);
}

// FUNCTION: IMPERIALISM 0x005c2660
void TUnit::ContinueOrders() {
  if (unitOrder - static_cast<UnitOrder>(2) != 0) {
    unitOrder = kUnitOrderIdle;
  }
}

// FUNCTION: IMPERIALISM 0x005c2680
void TUnit::Free() {
  TSortedList* manager = NULL;
  if (!militaryRegistrationFlag) {
    manager = g_apNationStates[ownerNationSlot]->trackedObjectList;
  } else {
    TCountry* terrain = g_apTerrainTypeDescriptorTable[ownerNationSlot];
    manager = terrain->militaryUnitList;
  }
  if (manager != NULL) {
    POSITION pos = manager->listState.Find(this);
    if (pos != NULL) {
      manager->listState.RemoveAt(pos);
    }
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x005c2700
void TUnit::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&orderType, 2);
  stream->ReadBytes(&tileIndex, 2);
  stream->ReadBytes(&orderTargetIndex, 2);
  stream->ReadBytes(&ownerNationSlot, 2);
  stream->ReadBytes(&unitRosterId, 2);
  stream->ReadBytes(&militaryRegistrationFlag, 1);
  stream->ReadBytes(&unitOrder, 4);
  short savedTileIndex = tileIndex;
  if (savedTileIndex != -1) {
    short savedOrderTargetIndex = orderTargetIndex;
    tileIndex = -1;
    MoveTo(savedTileIndex);
    orderTargetIndex = savedOrderTargetIndex;
  }
  if (g_nSaveFormatVersion > 0x2d) {
    stream->ReadBytes(&persistentUnitId, 4);
  }
}

// FUNCTION: IMPERIALISM 0x005c27d0
void TUnit::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&orderType, 2);
  stream->WriteBytes(&tileIndex, 2);
  stream->WriteBytes(&orderTargetIndex, 2);
  stream->WriteBytes(&ownerNationSlot, 2);
  stream->WriteBytes(&unitRosterId, 2);
  stream->WriteBytes(&militaryRegistrationFlag, 1);
  stream->WriteBytes(&unitOrder, 4);
  stream->WriteBytes(&persistentUnitId, 4);
}
