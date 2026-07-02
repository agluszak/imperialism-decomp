#include "game/TShip.h"

#include "game/TAdmiral.h"
#include "game/TGreatPower.h"
#include "game/TZone.h"
#include "game/TStream.h"
#include "game/GameAssert.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/CString.h"

#include <new>

extern "C" TShip* g_pNavyPrimaryOrderListHead = 0;
extern short g_industryActionCostWeightResCode10[16];

static short SignedMod100(short value) {
  return (short)((value / 100 + (value >> 15)) -
                 (short)(((__int64)(int)value * 0x51eb851f) >> 0x3f));
}

static short SignedDiv10(int value) {
  return (short)(((short)(value / 10) + (short)(value >> 0x1f)) -
                 (short)(((__int64)value * 0x66666667) >> 0x3f));
}

// FUNCTION: IMPERIALISM 0x004e0460
int SumNavyOrderPriorityForNationAndNodeType(TGreatPower* nationObj, int nodeType) {
  int sum = 0;
  for (TShip* node = GetNavyPrimaryOrderListHead(); node != 0; node = node->nextOlder24) {
    if (node->ownerNationSlot14 == nationObj->nationSlot && node->field08 == (void*)nodeType) {
      sum += ComputeOrderNodeCompositeEconomicScore(node);
    }
  }
  return sum;
}

// FUNCTION: IMPERIALISM 0x004e04b0
int SumNavyOrderPriorityForNation(TGreatPower* nationObj) {
  int sum = 0;
  for (TShip* node = GetNavyPrimaryOrderListHead(); node != 0; node = node->nextOlder24) {
    if (node->ownerNationSlot14 == nationObj->nationSlot) {
      sum += ComputeOrderNodeCompositeEconomicScore(node);
    }
  }
  return sum;
}
// SYNTHETIC: IMPERIALISM 0x0054f460
// TShip::CreateObject

// SYNTHETIC: IMPERIALISM 0x0054f4e0
// TShip::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShip, TObject)

// FUNCTION: IMPERIALISM 0x0054f500
TShip::TShip()
    : TObject(), displayName18(), resourceType04(0), pad06(0), field08(0), field0c(0),
      quantityFlag10(1), ownerNationSlot14(static_cast<short>(-1)), stockLevel1c(0), pad1e(0),
      field20(0), nextOlder24(g_pNavyPrimaryOrderListHead), prevNewer28(0), field2c(0), field30(0),
      field34(0) {
  g_pNavyPrimaryOrderListHead = this;
  if (nextOlder24 != 0) {
    nextOlder24->prevNewer28 = this;
  }
}

// SYNTHETIC: IMPERIALISM 0x0054f5c0
// TShip::`scalar deleting destructor'
TShip::~TShip() {}

// FUNCTION: IMPERIALISM 0x0054f640
void TShip::Free() {
  if (g_pNavyPrimaryOrderListHead == this) {
    g_pNavyPrimaryOrderListHead = this->nextOlder24;
  }
  if (this->nextOlder24 != 0) {
    this->nextOlder24->prevNewer28 = this->prevNewer28;
  }
  if (this->prevNewer28 != 0) {
    this->prevNewer28->nextOlder24 = this->nextOlder24;
  }
  displayName18.~CString();
  delete this;
}

// FUNCTION: IMPERIALISM 0x0054fab0
void TShip::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&resourceType04, 2);
  stream->WriteBytesSlot78(&quantityFlag10, 4);
  stream->WriteBytesSlot78(&ownerNationSlot14, 2);
  stream->streamSlotAc(&displayName18);
  stream->WriteBytesSlot78(&stockLevel1c, 2);
  stream->WriteBytesSlot78(&field34, 4);
  stream->WriteBytesSlot78(&field30, 2);
  short zoneIndex = field08->GetContextOrdinalOrInvalid();
  stream->WriteBytesSlot78(&zoneIndex, 2);
}

// FUNCTION: IMPERIALISM 0x0054fb50
void TShip::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&resourceType04, 2);
  stream->ReadBytes(&quantityFlag10, 4);
  stream->ReadBytes(&ownerNationSlot14, 2);
  stream->ReadBytes(&displayName18, 0x20);
  stream->ReadBytes(&stockLevel1c, 2);
  stream->ReadBytes(&field34, 4);
  stream->ReadBytes(&field30, 2);
  short zoneIndex = 0;
  stream->ReadBytes(&zoneIndex, 2);
  field08 = FindMapActionContextByNodeId(zoneIndex);
}

// FUNCTION: IMPERIALISM 0x0054fbf0
void __fastcall RegenerateNavyPrimaryOrderDisplayNameUntilUnique(TShip* shipNode) {
  do {
    TAdmiral::GenerateMappedFlavorTextByNationSlotField0C(
        static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[shipNode->resourceType04]),
        &shipNode->displayName18);
    for (TShip* existing = g_pNavyPrimaryOrderListHead; existing != 0;
         existing = existing->nextOlder24) {
      if (existing == shipNode) {
        continue;
      }
      if (CompareAnsiStringsWithMbcsAwareness(
              reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(existing->displayName18)),
              reinterpret_cast<unsigned char*>(
                  (char*)static_cast<LPCSTR>(shipNode->displayName18))) == 0) {
        goto retry;
      }
    }
    return;
  retry:;
  } while (1);
}

// Receiver-agnostic: also called directly on a TMapOrderEntry's own
// order_type/required_count/tiebreak_strength fields (TNavyMission::ReturnZeroSlot2C),
// which happen to share these same 3 offsets with TShip -- see the header comment.
// FUNCTION: IMPERIALISM 0x0054ff00
int ComputeNavyOrderPriorityContributionPercentByCategory(short resourceType,
                                                          short stockOrRequiredCount,
                                                          short tiebreakField, int category) {
  // Category-normalization divisor table; not yet a catalogued global (sits
  // between g_pNavySecondaryOrderListHead and g_pCachedMapActionContext).
  int divisor = reinterpret_cast<const int*>(0x006a3ec8)[category];
  const TNavyOrderResourceDescriptor& descriptor = g_NavyOrderResourceDescriptorTable[resourceType];

  switch (category) {
  case 0: {
    int quantityTerm =
        static_cast<int>(SignedMod100(tiebreakField)) + 5 + descriptor.resolveWeight * 10;
    int weight = descriptor.calculateWeight;
    return (SignedDiv10(quantityTerm) * weight * weight * 100) / divisor;
  }
  case 1: {
    int weight = descriptor.calculateWeight;
    return (weight * static_cast<int>(stockOrRequiredCount) * 10000) /
           (descriptor.taskForceWeight * divisor);
  }
  case 2:
    return (static_cast<int>(descriptor.descriptorWeight) * 100) / divisor;
  case 3:
    if (stockOrRequiredCount < 1) {
      return 0;
    }
    return (static_cast<int>(GetIndustryActionCostWeightByResourceType(resourceType)) * 100) /
           divisor;
  default:
    return 0;
  }
}

int TShip::ComputeNavyOrderPriorityContributionPercentByCategory(int category) {
  return ::ComputeNavyOrderPriorityContributionPercentByCategory(resourceType04, stockLevel1c,
                                                                 field30, category);
}

// FUNCTION: IMPERIALISM 0x00550550
short TShip::ComputeOrderNodeDistanceQuotientByDescriptorWord24(TZone* otherZone) {
  short hopDistance = field08->GetCachedMapActionContextDistanceOrRecompute(otherZone);
  short descriptorWeight = g_NavyOrderResourceDescriptorTable[resourceType04].descriptorWeight;
  return static_cast<short>((descriptorWeight - 1 + hopDistance) / descriptorWeight);
}

// FUNCTION: IMPERIALISM 0x005505a0
short GetNavyOrderNormalizationBaseByResourceType(short resourceType) {
  return g_NavyOrderResourceDescriptorTable[resourceType].stockCap;
}

short TShip::GetNavyOrderNormalizationBaseByNationType() {
  return GetNavyOrderNormalizationBaseByResourceType(resourceType04);
}

// FUNCTION: IMPERIALISM 0x005505c0
TShip* GetNavyPrimaryOrderListHead(void) {
  return g_pNavyPrimaryOrderListHead;
}

// FUNCTION: IMPERIALISM 0x00550610
int TShip::GetIndexInPrimaryOrderList() {
  int index = 0;
  for (TShip* node = g_pNavyPrimaryOrderListHead; node != 0 && node != this;
       node = node->nextOlder24) {
    ++index;
  }
  return index;
}

// FUNCTION: IMPERIALISM 0x00550970
short GetIndustryActionCostWeightByResourceType(short resourceType) {
  return g_industryActionCostWeightResCode10[resourceType];
}

// FUNCTION: IMPERIALISM 0x00550b60
int ComputeOrderNodeCompositeEconomicScore(TShip* node) {
  const TNavyOrderResourceDescriptor& descriptor =
      g_NavyOrderResourceDescriptorTable[node->resourceType04];
  int quantityTerm = static_cast<int>(SignedMod100(node->field30));
  int navyTerm = quantityTerm + 5 + descriptor.navyPriorityWeight * 10;
  int resolveTerm = quantityTerm + 5 + descriptor.resolveWeight * 10;
  return (SignedDiv10(resolveTerm) + (SignedDiv10(navyTerm) + descriptor.calculateWeight) * 100 +
          static_cast<int>(node->stockLevel1c)) /
         descriptor.taskForceWeight;
}

// FUNCTION: IMPERIALISM 0x00550e70
short GetResourceDescriptorWeightWord0ByType(short resourceType) {
  return g_NavyOrderResourceDescriptorTable[resourceType].resourceDescriptorWeightWord0;
}
