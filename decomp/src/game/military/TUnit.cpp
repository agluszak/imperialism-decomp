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
void TUnit::DetachUnitOrderFromOwnerAndReset() {}
// SYNTHETIC: IMPERIALISM 0x005c2430
// TUnit::CreateObject

// SYNTHETIC: IMPERIALISM 0x005c2490
// TUnit::GetRuntimeClass

IMPLEMENT_DYNCREATE(TUnit, TObject)
// SYNTHETIC: IMPERIALISM 0x005c24e0
// TUnit::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005c2530
void TUnit::RegisterUnitOrderWithOwnerManager(short nOrderType, int anchorIndex,
                                              short nOrderOwnerNationId, short arg3) {
  this->orderType = nOrderType;
  this->unitOrder = kUnitOrderIdle;
  this->MoveTo(anchorIndex);

  // The order-owner "manager" is a real TSortedList: military units (militaryRegistrationFlag1C != 0)
  // register into the owning country's militaryUnitList44; other orders into the
  // nation's trackedObjectList. Both dispatch AddTail(item) at vtable byte 0x30.
  TSortedList* ownerManager;
  if (this->militaryRegistrationFlag1C != 0) {
    ownerManager = g_apTerrainTypeDescriptorTable[nOrderOwnerNationId]->militaryUnitList44;
  } else {
    ownerManager = g_apNationStates[nOrderOwnerNationId]->trackedObjectList;
  }

  if (ownerManager == 0) {
    GAME_FAIL_NIL_POINTER();
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UUnit.cpp", 0x11f);
  }

  ownerManager->AddTail(this);

  this->ownerNationSlot18 = nOrderOwnerNationId;
  this->unitRosterId1A = arg3;
  this->orderTargetIndex0C = static_cast<short>(-1);

  TSimMgr* locTable = g_pSimMgr;
  locTable->field_64 = locTable->field_64 + 1;
  this->persistentUnitId20 = locTable->field_64;
}

// FUNCTION: IMPERIALISM 0x005c2610
void TUnit::MoveTo(short anchorIndex) {
  (void)anchorIndex;
}

// FUNCTION: IMPERIALISM 0x005c2630
void TUnit::SetOrders(UnitOrder order, int payload) {
  this->unitOrder = order;
  this->orderTargetIndex0C = static_cast<short>(payload);
}

// FUNCTION: IMPERIALISM 0x005c2660
void TUnit::ContinueOrders() {
  if (this->unitOrder - static_cast<UnitOrder>(2) != 0) {
    this->unitOrder = kUnitOrderIdle;
  }
}

// FUNCTION: IMPERIALISM 0x005c2680
void TUnit::Free() {
  // The owning list is a TSortedList (TCountry::militaryUnitList44 at terrain+0x44, or the
  // nation's list at +0x89c); +4 reaches its embedded CPtrList listState, so walk that
  // member's real API rather than casting the raw offset.
  TSortedList* manager = nullptr;
  if (this->militaryRegistrationFlag1C == 0) {
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
  stream->ReadBytes(&orderTargetIndex0C, 2);
  stream->ReadBytes(&ownerNationSlot18, 2);
  stream->ReadBytes(&unitRosterId1A, 2);
  stream->ReadBytes(&militaryRegistrationFlag1C, 1);
  stream->ReadBytes(&unitOrder, 4);
  short savedTileIndex = tileIndex06;
  if (savedTileIndex != -1) {
    short savedOrderTargetIndex = orderTargetIndex0C;
    tileIndex06 = -1;
    this->MoveTo(savedTileIndex);
    orderTargetIndex0C = savedOrderTargetIndex;
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
  stream->WriteBytes(&orderTargetIndex0C, 2);
  stream->WriteBytes(&ownerNationSlot18, 2);
  stream->WriteBytes(&unitRosterId1A, 2);
  stream->WriteBytes(&militaryRegistrationFlag1C, 1);
  stream->WriteBytes(&unitOrder, 4);
  stream->WriteBytes(&persistentUnitId20, 4);
}
