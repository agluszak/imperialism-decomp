// TArmyMission implementations.

#include "game/TArmyMission.h"
#include "game/TList.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/CIterator.h"

IMPLEMENT_SERIAL(TArmyMission, TMission, 1)

// Swaps float byte order (Big-Endian <-> Little-Endian)
static inline float SwapFloat(float val) {
  union { float f; unsigned char b[4]; } src, dst;
  src.f = val;
  dst.b[0] = src.b[3];
  dst.b[1] = src.b[2];
  dst.b[2] = src.b[1];
  dst.b[3] = src.b[0];
  return dst.f;
}

// Helper to serialize TArmyMission onto a TStream
void SerializeTArmyMission(TArmyMission* self, TStream* stream) {
  self->TMission::WriteTo(stream);
  stream->WriteBytesSlot78(&self->field_14, 2);
  for (int i = 0; i < 5; ++i) {
    float swapped = SwapFloat(self->resourceWeights[i]);
    stream->WriteBytesSlot78(&swapped, 4);
  }
  
  int count = 0;
  if (self->orderListAt18 != nullptr) {
    count = reinterpret_cast<TList*>(self->orderListAt18)->GetCountSlot48();
  }
  stream->WriteCountSlot88(count);

  TGreatPower* nation = g_apNationStates[self->nationId04];
  TSortedList* unitList = reinterpret_cast<TSortedList*>(nation->militaryUnitList44);
  TSortedList* orderList = reinterpret_cast<TSortedList*>(self->orderListAt18);

  if (orderList != nullptr) {
    CIterator iter(orderList);
    void* currentUnit = iter.Reset();
    while (iter.More()) {
      int index = 1;
      POSITION pos = unitList->listState.GetHeadPosition();
      while (pos != nullptr) {
        if (unitList->listState.GetNext(pos) == currentUnit) {
          break;
        }
        index++;
      }
      stream->WriteCountSlot88(index);
      currentUnit = iter.Advance();
    }
  }
}

// Helper to deserialize TArmyMission from a TStream
void DeserializeTArmyMission(TArmyMission* self, TStream* stream) {
  static const unsigned int kSaveFormatVersionAddr = 0x00695278;
  int saveFormatVersion = *reinterpret_cast<int*>(kSaveFormatVersionAddr);

  self->TMission::ReadFrom(stream);
  stream->ReadBytes(&self->field_14, 2);
  if (saveFormatVersion < 0xb) {
    stream->ReadBytes(&self->resourceWeights[0], 0x10);
    self->resourceWeights[4] = 0.0f;
  } else {
    stream->ReadBytes(&self->resourceWeights[0], 0x14);
    for (int i = 0; i < 5; ++i) {
      self->resourceWeights[i] = SwapFloat(self->resourceWeights[i]);
    }
  }

  short count = stream->ReadShort();
  TGreatPower* nation = g_apNationStates[self->nationId04];
  TList* unitList = reinterpret_cast<TList*>(nation->militaryUnitList44);
  TList* orderList = reinterpret_cast<TList*>(self->orderListAt18);

  for (int i = 0; i < count; ++i) {
    short index = stream->ReadShort();
    void* unit = unitList->GetEntryByOrdinalSlot4C(index);
    if (orderList != nullptr) {
      orderList->AddTailSlot30(unit);
    }
  }
}

// Default constructor
TArmyMission::TArmyMission() : TMission() {
  field_14 = 0;
  padding_16 = 0;
  orderListAt18 = nullptr;
  for (int i = 0; i < 5; ++i) {
    resourceWeights[i] = 0.0f;
  }
}

// FUNCTION: IMPERIALISM 0x0053c0a0
TArmyMission::TArmyMission(int nodeKey) : TMission() {
  nationId04 = 0xffff;
  pathMarker06 = 0xffff;
  field_14 = static_cast<short>(nodeKey);
  padding_16 = static_cast<short>(0xffff);
  
  TList* list = TList::CreateTListInstance();
  orderListAt18 = list;
  if (list == nullptr) {
    MessageBoxA(nullptr, "Nil Pointer", "Failure", 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(
        "D:\\Ambit\\Cross\\UMissionSubs.cpp", 0x842);
  }

  for (int i = 0; i < 5; ++i) {
    resourceWeights[i] = 0.0f;
  }
}

// Destructor
TArmyMission::~TArmyMission() {}

// FUNCTION: IMPERIALISM 0x0053c220
void TArmyMission::CleanupTArmyMissionAndReleaseChildContext() {
  TSortedList* orderList = reinterpret_cast<TSortedList*>(orderListAt18);
  if (orderList != nullptr) {
    CIterator iter(orderList);
    void* current = iter.Reset();
    while (iter.More()) {
      *reinterpret_cast<int*>(reinterpret_cast<char*>(current) + 0x40) = 0;
      current = iter.Advance();
    }
  }
  
  TList* list = reinterpret_cast<TList*>(orderListAt18);
  if (list != nullptr) {
    list->RemoveAllSlot5C();
    list->FreePayloadsAndDestroySlot58();
    orderListAt18 = nullptr;
  }

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x0053c2b0
void TArmyMission::WriteTo(TStream* stream) {
  SerializeTArmyMission(this, stream);
}

// FUNCTION: IMPERIALISM 0x0053c3d0
void TArmyMission::ReadFrom(TStream* stream) {
  DeserializeTArmyMission(this, stream);
}
