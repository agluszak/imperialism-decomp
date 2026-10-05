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

// 0x00402eeb is an ILT jmp thunk to TUnit::RegisterUnitOrderWithOwnerManager (0x5c2530);
// per the ILT hard rule it is never hand-written -- it is tracked in config/thunk_map.csv
// like every other ILT slot and paired automatically. No source calls it.

// FUNCTION: IMPERIALISM 0x005c2470
void TUnit::Vaporize() {}

IMPLEMENT_DYNCREATE(TUnit, TObject)

// FUNCTION: IMPERIALISM 0x005c2530
void TUnit::RegisterUnitOrderWithOwnerManager(short nOrderType, int anchorIndex,
                                              short nOrderOwnerNationId, short arg3) {
  this->orderType = nOrderType;
  this->unitOrder = kUnitOrderIdle;
  this->MoveTo(anchorIndex);

  TSortedList* ownerManager;
  if (this->militaryRegistrationFlag != 0) {
    ownerManager = g_apTerrainTypeDescriptorTable[nOrderOwnerNationId]->militaryUnitList44;
  } else {
    ownerManager = g_apNationStates[nOrderOwnerNationId]->trackedObjectList;
  }

  if (ownerManager == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UUnit.cpp", 0x11f);
  }

  ownerManager->AddTail(this);

  this->ownerNationSlot18 = nOrderOwnerNationId;
  this->unitRosterId1A = arg3;
  this->orderTargetIndex = static_cast<short>(-1);

  TSimMgr* simMgr = g_pSimMgr;
  simMgr->field_64 = simMgr->field_64 + 1;
  this->persistentUnitId20 = simMgr->field_64;
}

// FUNCTION: IMPERIALISM 0x005c2610
void TUnit::MoveTo(short anchorIndex) {
  (void)anchorIndex;
}

// FUNCTION: IMPERIALISM 0x005c2630
void TUnit::SetOrders(UnitOrder order, int payload) {
  this->unitOrder = order;
  this->orderTargetIndex = static_cast<short>(payload);
}

// FUNCTION: IMPERIALISM 0x005c2660
void TUnit::ContinueOrders() {
  if (this->unitOrder - static_cast<UnitOrder>(2) != 0) {
    this->unitOrder = kUnitOrderIdle;
  }
}

// FUNCTION: IMPERIALISM 0x005c2680
void TUnit::Free() {
  TSortedList* manager = nullptr;
  if (this->militaryRegistrationFlag == 0) {
    manager = g_apNationStates[this->ownerNationSlot18]->trackedObjectList; // +0x89c
  } else {
    TCountry* terrain = g_apTerrainTypeDescriptorTable[this->ownerNationSlot18];
    manager = terrain->militaryUnitList44;
  }
  if (manager != nullptr) {
    POSITION pos = manager->listState.Find(this);
    if (pos != nullptr) {
      manager->listState.RemoveAt(pos);
    }
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x005c2700
void TUnit::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&orderType, 2);
  stream->ReadBytes(&tileIndex06, 2);
  stream->ReadBytes(&orderTargetIndex, 2);
  stream->ReadBytes(&ownerNationSlot18, 2);
  stream->ReadBytes(&unitRosterId1A, 2);
  stream->ReadBytes(&militaryRegistrationFlag, 1);
  stream->ReadBytes(&unitOrder, 4);
  short savedTileIndex = tileIndex06;
  if (savedTileIndex != -1) {
    short savedOrderTargetIndex = orderTargetIndex;
    tileIndex06 = -1;
    this->MoveTo(savedTileIndex);
    orderTargetIndex = savedOrderTargetIndex;
  }
  if (g_nSaveFormatVersion > 0x2d) {
    stream->ReadBytes(&persistentUnitId20, 4);
  }
}

// FUNCTION: IMPERIALISM 0x005c27d0
void TUnit::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&orderType, 2);
  stream->WriteBytes(&tileIndex06, 2);
  stream->WriteBytes(&orderTargetIndex, 2);
  stream->WriteBytes(&ownerNationSlot18, 2);
  stream->WriteBytes(&unitRosterId1A, 2);
  stream->WriteBytes(&militaryRegistrationFlag, 1);
  stream->WriteBytes(&unitOrder, 4);
  stream->WriteBytes(&persistentUnitId20, 4);
}
