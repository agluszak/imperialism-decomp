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
// SYNTHETIC: IMPERIALISM 0x004be0d0
// TInteriorMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x004be1b0
// TInteriorMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInteriorMinister, TMinister)

// SYNTHETIC: IMPERIALISM 0x004be200
// TInteriorMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004be290
void TInteriorMinister::ReadFrom(TStream* stream) {
  TMinister::ReadFrom(stream);
  stream->ReadBytes(&field10, 2);
  stream->ReadBytes(&field12, 2);
  stream->ReadBytes(&capabilityFlag14, 2);
  stream->ReadBytes(&capabilityFlag16, 2);
  unsigned char* table = static_cast<unsigned char*>(static_cast<void*>(trailingTable));
  stream->ReadBytes(table, sizeof(trailingTable));
  for (int i = 0; i < 7; ++i) {
    unsigned char lo = table[i * 2];
    table[i * 2] = table[i * 2 + 1];
    table[i * 2 + 1] = lo;
  }
}

// FUNCTION: IMPERIALISM 0x004be320
void TInteriorMinister::WriteTo(TStream* stream) {
  TMinister::WriteTo(stream);
  stream->WriteBytes(&field10, 2);
  stream->WriteBytes(&field12, 2);
  stream->WriteBytes(&capabilityFlag14, 2);
  stream->WriteBytes(&capabilityFlag16, 2);
  WriteShortArrayElems(stream, trailingTable, 7);
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
  field10 = secondParameter;
}

// FUNCTION: IMPERIALISM 0x004be480
short TInteriorMinister::GetNumShipsToBuild() {
  short needCap;
  if (ownerContextAt04 != 0) {
    needCap = ownerContextAt04->transportCapacity;
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
  if (ownerContextAt04->merchantCapacity > 0x31) {
    capabilityFlag14 = 0;
  }
  return capabilityFlag14;
}

// FUNCTION: IMPERIALISM 0x004be4f0
void TInteriorMinister::ClearTrailingTable() {
  memset(trailingTable, 0, sizeof(trailingTable));
}

// Mac oracle name (on both TInteriorMinister and TCityInteriorMinister). Tops up up
// to 10 of the nation's needs (in the fixed priority order
// g_aInteriorMinisterNeedPriorityOrder_00696408) toward their current reading, stopping
// as soon as the nation's need-cap headroom (transportCapacity - reservedTransportCapacity) hits zero.
// FUNCTION: IMPERIALISM 0x004be520
void TInteriorMinister::SetCityPolicies() {
  short i = 0;
  do {
    short capRemaining = static_cast<short>(ownerContextAt04->transportCapacity -
                                            ownerContextAt04->reservedTransportCapacity);
    if (capRemaining == 0) {
      break;
    }
    short needIndex = g_aInteriorMinisterNeedPriorityOrder_00696408[i];
    ++i;
    short current = ownerContextAt04->needCurrentByType[needIndex];
    short value = (current <= capRemaining) ? current : capRemaining;
    ownerContextAt04->UpdateNeedTargetAndAccumulateOverCap(needIndex, value);
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

  if (ownerContextAt04->IsTransportCapacityExceeded()) {
    short count2 = GetNumShipsToBuild();
    if (count2 > 0) {
      int remaining = count2;
      do {
        accumulated += ownerContextAt04->IncreaseRollingStock();
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
char TInteriorMinister::DoIncreasedTransport() {
  char result = 0;
  if (ownerContextAt04->GetMerchantCapacity() == 0) {
    result = ownerContextAt04->IncreaseMerchantMarine();
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x004be690
void TInteriorMinister::AdvanceNeedTargetRoundRobin() {
  ownerContextAt04->TryIncrementNationResourceNeedTargetTowardCurrent(field10);
  ++field10;
  if (field10 > 4) {
    field10 = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004be6d0
void TInteriorMinister::MakeNewCity(TCity* city) {
  (void)city;
}
