#include "game/city_ui/TInteriorMinister.h"

#include <string.h>

#include "game/nation/TGreatPower.h"
#include "game/core/stream_byteswap.h"
#include "game/core/TStream.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

// Slots 0x16-0x1f own bodies (honest stubs; slot ownership drives vtable matching).
// FUNCTION: IMPERIALISM 0x004be150
short TInteriorMinister::GetExteriorNeedFor(int arg) {
  return static_cast<short>(arg);
}

// FUNCTION: IMPERIALISM 0x004be170
short TInteriorMinister::GetHistoricalNeedFor(int arg) {
  return static_cast<short>(arg);
}

// FUNCTION: IMPERIALISM 0x004be190
void TInteriorMinister::ResetHistoricalNeedFor(int) {}

IMPLEMENT_DYNCREATE(TInteriorMinister, TMinister)

// FUNCTION: IMPERIALISM 0x004be250
void TInteriorMinister::IInteriorMinister(TGreatPower* owner) {
  TMinister::IMinister(owner);
  needTargetCursor = 0;
  field12 = 0;
  memset(persistedReservedTable, 0, sizeof(persistedReservedTable));
}

// FUNCTION: IMPERIALISM 0x004be290
void TInteriorMinister::ReadFrom(TStream* stream) {
  TMinister::ReadFrom(stream);
  stream->ReadBytes(&needTargetCursor, 2);
  stream->ReadBytes(&field12, 2);
  stream->ReadBytes(&capabilityFlag14, 2);
  stream->ReadBytes(&capabilityFlag16, 2);
  unsigned char* table = static_cast<unsigned char*>(static_cast<void*>(persistedReservedTable));
  stream->ReadBytes(table, sizeof(persistedReservedTable));
  for (int i = 0; i < 7; ++i) {
    unsigned char lo = table[i * 2];
    table[i * 2] = table[i * 2 + 1];
    table[i * 2 + 1] = lo;
  }
}

// FUNCTION: IMPERIALISM 0x004be320
void TInteriorMinister::WriteTo(TStream* stream) {
  TMinister::WriteTo(stream);
  stream->WriteBytes(&needTargetCursor, 2);
  stream->WriteBytes(&field12, 2);
  stream->WriteBytes(&capabilityFlag14, 2);
  stream->WriteBytes(&capabilityFlag16, 2);
  WriteShortArrayElems(stream, persistedReservedTable, 7);
}

// The interior minister ranks a nation purely by its remaining need capacity.
// FUNCTION: IMPERIALISM 0x004be3c0
short TInteriorMinister::GetRankingCriterionForGP(short nationSlot) {
  if (g_apNationStates[nationSlot] != 0) {
    return g_apNationStates[nationSlot]->transportCapacity;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004be3f0
void TInteriorMinister::PleaseBuildShip(short) {}

// FUNCTION: IMPERIALISM 0x004be410
void TInteriorMinister::IndustryOrder(short) {}

// FUNCTION: IMPERIALISM 0x004be430
void TInteriorMinister::PleaseBuildLandUnit(short) {}

// FUNCTION: IMPERIALISM 0x004be450
void TInteriorMinister::SetParameters(short firstParameter, short secondParameter) {
  field12 = firstParameter;
  needTargetCursor = secondParameter;
}

// FUNCTION: IMPERIALISM 0x004be480
short TInteriorMinister::GetNumShipsToBuild() {
  short needCap;
  if (greatPower != 0) {
    needCap = greatPower->transportCapacity;
  } else {
    needCap = 0;
  }
  if (needCap > 0x31) {
    capabilityFlag16 = 0;
  }
  return capabilityFlag16;
}

// FUNCTION: IMPERIALISM 0x004be4c0
short TInteriorMinister::GetNumCarsToBuild() {
  if (greatPower->merchantCapacity > 0x31) {
    capabilityFlag14 = 0;
  }
  return capabilityFlag14;
}

// FUNCTION: IMPERIALISM 0x004be4f0
void TInteriorMinister::ClearPersistedReservedTable() {
  memset(persistedReservedTable, 0, sizeof(persistedReservedTable));
}

// FUNCTION: IMPERIALISM 0x004be520
void TInteriorMinister::SetCityPolicies() {
  short i = 0;
  do {
    short capRemaining =
        static_cast<short>(greatPower->transportCapacity - greatPower->reservedTransportCapacity);
    if (capRemaining == 0) {
      break;
    }
    short needIndex = g_aInteriorMinisterNeedPriorityOrder[i];
    ++i;
    short current = greatPower->needCurrentByType[needIndex];
    short value = (current <= capRemaining) ? current : capRemaining;
    greatPower->UpdateNeedTargetAndAccumulateOverCap(needIndex, value);
  } while (i < 10);
}

// FUNCTION: IMPERIALISM 0x004be5b0
void TInteriorMinister::FillOrders() {
  int accumulated = 0;
  int i = 0;
  short count = GetNumCarsToBuild();
  if (count > 0) {
    do {
      DoIncreasedTransport();
      ++i;
      count = GetNumCarsToBuild();
    } while (i < count);
    accumulated = 0;
  }

  if (greatPower->IsTransportCapacityExceeded()) {
    short count2 = GetNumShipsToBuild();
    if (count2 > 0) {
      int remaining = count2;
      do {
        accumulated += greatPower->IncreaseRollingStock();
        --remaining;
      } while (remaining != 0);
    }
    if (accumulated > 0) {
      int remaining = accumulated;
      do {
        AdvanceNeedTargetRoundRobin();
        --remaining;
      } while (remaining != 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004be650
bool TInteriorMinister::DoIncreasedTransport() {
  char result = 0;
  if (greatPower->GetMerchantCapacity() == 0) {
    result = greatPower->IncreaseMerchantMarine();
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x004be690
void TInteriorMinister::AdvanceNeedTargetRoundRobin() {
  greatPower->TryIncrementNationResourceNeedTargetTowardCurrent(needTargetCursor);
  ++needTargetCursor;
  if (needTargetCursor > 4) {
    needTargetCursor = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004be6d0
void TInteriorMinister::MakeNewCity(TCity* city) {}
