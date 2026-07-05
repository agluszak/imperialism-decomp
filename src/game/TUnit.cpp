#include "game/TUnit.h"
#include "decomp_types.h"
#include "game/GameAssert.h"

#include "game/global_data_tables.h"
#include "game/TCountry.h"
#include "game/TGreatPower.h"
#include "game/TSimMgr.h"
#include "game/TSortedList.h"
#include "game/TStream.h"
#include "game/ui_invalidation_guard.h"

extern "C" char g_pClassDescTUnit = 0;

// FUNCTION: IMPERIALISM 0x00402eeb
void __fastcall thunk_RegisterUnitOrderWithOwnerManager(TUnit* order, int unusedEdx,
                                                        short nOrderType, int pOwnerContext,
                                                        short nOrderOwnerNationId, short arg3) {
  (void)unusedEdx;
  order->RegisterUnitOrderWithOwnerManager(nOrderType, pOwnerContext, nOrderOwnerNationId, arg3);
}

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
  field_6 = static_cast<short>(0xffff);
  field_8 = 0;
  field_1C = 0;
}

// SYNTHETIC: IMPERIALISM 0x005c24e0
// TUnit::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005c2510
TUnit::~TUnit() {}

// FUNCTION: IMPERIALISM 0x005c2530
void TUnit::RegisterUnitOrderWithOwnerManager(short nOrderType, int pOwnerContext,
                                              short nOrderOwnerNationId, short arg3) {
  this->orderType = nOrderType;
  this->field_8 = 0;
  this->VTableSlot10(pOwnerContext);

  // The order-owner "manager" is a real TSortedList: military units (field_1C != 0)
  // register into the owning country's militaryUnitList44; other orders into the
  // nation's trackedObjectList. Both dispatch AddTailSlot30(item) at vtable byte 0x30.
  TSortedList* ownerManager;
  if (this->field_1C != 0) {
    ownerManager = g_apTerrainTypeDescriptorTable[nOrderOwnerNationId]->militaryUnitList44;
  } else {
    ownerManager = g_apNationStates[nOrderOwnerNationId]->trackedObjectList;
  }

  if (ownerManager == 0) {
    GAME_FAIL_NIL_POINTER();
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }

  ownerManager->AddTailSlot30(this);

  this->field_18 = nOrderOwnerNationId;
  this->field_1A = arg3;
  this->field_C = static_cast<short>(-1);

  TSimMgr* locTable = g_pSimMgr;
  int uniqueId = locTable->field_64 + 1;
  locTable->field_64 = uniqueId;
  this->field_20 = uniqueId;
}

// FUNCTION: IMPERIALISM 0x005c2610
void TUnit::VTableSlot10(int pOwnerContext) {
  (void)pOwnerContext;
}

// FUNCTION: IMPERIALISM 0x005c2630
void TUnit::SetOrderModeSlot34(int mode, int payload) {
  this->field_8 = mode;
  this->field_C = static_cast<short>(payload);
}

// FUNCTION: IMPERIALISM 0x005c2660
void TUnit::DispatchSlot2C() {
  if (this->field_8 != 2) {
    this->field_8 = 0;
  }
}

// FUNCTION: IMPERIALISM 0x005c2680
void TUnit::Free() {
  void* manager = nullptr;
  if (this->field_1C == 0) {
    void* nation = g_apNationStates[this->field_18];
    manager = *reinterpret_cast<void**>(reinterpret_cast<char*>(nation) + 0x89c);
  } else {
    void* terrain = g_apTerrainTypeDescriptorTable[this->field_18];
    manager = *reinterpret_cast<void**>(reinterpret_cast<char*>(terrain) + 0x44);
  }
  if (manager != nullptr) {
    CPtrList* list = reinterpret_cast<CPtrList*>(reinterpret_cast<char*>(manager) + 4);
    POSITION pos = list->Find(this);
    if (pos != nullptr) {
      list->RemoveAt(pos);
    }
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x005c2700
void TUnit::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&orderType, 2);
  stream->ReadBytes(&field_6, 2);
  stream->ReadBytes(&field_C, 2);
  stream->ReadBytes(&field_18, 2);
  stream->ReadBytes(&field_1A, 2);
  stream->ReadBytes(&field_1C, 1);
  stream->ReadBytes(&field_8, 4);
  short savedField_6 = field_6;
  if (savedField_6 != -1) {
    short savedField_C = field_C;
    field_6 = -1;
    this->VTableSlot10(savedField_6);
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
  stream->WriteBytesSlot78(&field_6, 2);
  stream->WriteBytesSlot78(&field_C, 2);
  stream->WriteBytesSlot78(&field_18, 2);
  stream->WriteBytesSlot78(&field_1A, 2);
  stream->WriteBytesSlot78(&field_1C, 1);
  stream->WriteBytesSlot78(&field_8, 4);
  stream->WriteBytesSlot78(&field_20, 4);
}
