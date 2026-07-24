#include "game/military/TUnit.h"
#include "decomp_types.h"
#include "game/GameAssert.h"

#include "game/globals/prelude.h"
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

TUnit::TUnit() {
  field_10 = 0;
  nextOnTile = 0;
  tileIndex06 = static_cast<short>(0xffff);
  unitOrder = kUnitOrderIdle;
  field_1C = 0;
}

// SYNTHETIC: IMPERIALISM 0x005c24e0
// TUnit::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005c2510
TUnit::~TUnit() {}

// FUNCTION: IMPERIALISM 0x005c2530
void TUnit::RegisterUnitOrderWithOwnerManager(short nOrderType, int anchorIndex,
                                              short nOrderOwnerNationId, short arg3) {
  this->orderType = nOrderType;
  this->unitOrder = kUnitOrderIdle;
  this->RelinkIntoAnchorOccupantChain(anchorIndex);

  // The order-owner "manager" is a real TSortedList: military units (field_1C != 0)
  // register into the owning country's militaryUnitList44; other orders into the
  // nation's trackedObjectList. Both dispatch AddTail(item) at vtable byte 0x30.
  TSortedList* ownerManager;
  if (this->field_1C != 0) {
    ownerManager = g_apTerrainTypeDescriptorTable[nOrderOwnerNationId]->militaryUnitList44;
  } else {
    ownerManager = g_apNationStates[nOrderOwnerNationId]->trackedObjectList;
  }

  if (ownerManager == 0) {
    GAME_FAIL_NIL_POINTER();
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UUnit.cpp", 0x11f);
  }

  ownerManager->AddTail(this);

  this->field_18 = nOrderOwnerNationId;
  this->field_1A = arg3;
  this->field_C = static_cast<short>(-1);

  TSimMgr* locTable = g_pSimMgr;
  locTable->field_64 = locTable->field_64 + 1;
  this->field_20 = locTable->field_64;
}

// FUNCTION: IMPERIALISM 0x005c2610
void TUnit::RelinkIntoAnchorOccupantChain(int anchorIndex) {
  (void)anchorIndex;
}

// FUNCTION: IMPERIALISM 0x005c2630
void TUnit::SetOrders(UnitOrder order, int payload) {
  this->unitOrder = order;
  this->field_C = static_cast<short>(payload);
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
  if (this->field_1C == 0) {
    void* nation = g_apNationStates[this->field_18];
    manager = *reinterpret_cast<TSortedList**>(reinterpret_cast<char*>(nation) + 0x89c);
  } else {
    void* terrain = g_apTerrainTypeDescriptorTable[this->field_18];
    manager = *reinterpret_cast<TSortedList**>(reinterpret_cast<char*>(terrain) + 0x44);
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
  stream->ReadBytes(&field_C, 2);
  stream->ReadBytes(&field_18, 2);
  stream->ReadBytes(&field_1A, 2);
  stream->ReadBytes(&field_1C, 1);
  stream->ReadBytes(&unitOrder, 4);
  short savedTileIndex = tileIndex06;
  if (savedTileIndex != -1) {
    short savedField_C = field_C;
    tileIndex06 = -1;
    this->RelinkIntoAnchorOccupantChain(savedTileIndex);
    field_C = savedField_C;
  }
  if (g_nSaveFormatVersion > 0x2d) {
    stream->ReadBytes(&field_20, 4);
  }
}

// FUNCTION: IMPERIALISM 0x005c27d0
void TUnit::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&orderType, 2);
  stream->WriteBytesSlot78(&tileIndex06, 2);
  stream->WriteBytesSlot78(&field_C, 2);
  stream->WriteBytesSlot78(&field_18, 2);
  stream->WriteBytesSlot78(&field_1A, 2);
  stream->WriteBytesSlot78(&field_1C, 1);
  stream->WriteBytesSlot78(&unitOrder, 4);
  stream->WriteBytesSlot78(&field_20, 4);
}
