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

// FUNCTION: IMPERIALISM 0x0053b800
float ComputeNavyOrderDistributionScoreForNation(short nation) {
  float categoryVector[4] = {
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8,
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8};
  for (TShip* ship = GetNavyPrimaryOrderListHead(); ship != nullptr; ship = ship->nextOlder24) {
    if (ship->ownerNationSlot14 == nation && ship->field08->QueryPortZoneCapability() &&
        ship->GetNavyOrderNormalizationBaseByNationType() <= ship->stockLevel1c) {
      AccumulateNavyOrderCategoryVectorWithScale(
          ship, categoryVector, static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08));
    }
  }
  float total = categoryVector[0] + categoryVector[1] + categoryVector[2] + categoryVector[3];
  if (total == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  float diffSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int i = 0; i < 4; ++i) {
    float diff = categoryVector[i] / total -
                 static_cast<float>(g_NavyOrderDistributionCategoryWeights_00697978[i]) *
                     static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
    if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
      diff = -diff;
    }
    diffSum += diff;
  }
  return total * (static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08) -
                  diffSum * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA00));
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
      if (_mbscmp(
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

// Recompute the four per-category capability metric baseline averages
// (g_aCategoryMetricBaselineAverage) read back as normalization divisors by the
// navy/map-order scoring helpers. Iterates resource descriptors 1..13, including only
// capabilities enabled in g_pCityOrderCapabilityState's +0x19d per-slot flag array,
// accumulates four metric channels (weighted products / ratios / priority / industry
// cost), then normalizes each channel by the active-capability count with rounding.
// 0x0054fd50.
// FUNCTION: IMPERIALISM 0x0054fd50
void RecomputeGlobalCapabilityAverages() {
  if (g_pCityOrderCapabilityState != 0) {
    g_aCategoryMetricBaselineAverage[0] = 0;
    g_aCategoryMetricBaselineAverage[1] = 0;
    g_aCategoryMetricBaselineAverage[2] = 0;
    g_aCategoryMetricBaselineAverage[3] = 0;
    int activeCount = 0;
    short rec = 1;
    TNavyOrderResourceDescriptor* d = &g_NavyOrderResourceDescriptorTable[1];
    do {
      // The descriptor's leading dword doubles as an enabled/present gate.
      if ((0 < *reinterpret_cast<int*>(d)) &&
          (reinterpret_cast<unsigned char*>(g_pCityOrderCapabilityState)[0x19d + (int)rec] !=
           '\0')) {
        activeCount = activeCount + 1;
        int channel = 0;
        do {
          int value;
          switch (channel) {
          case 0:
            value = (int)d->resolveWeight * (int)d->calculateWeight * (int)d->calculateWeight;
            break;
          case 1:
            value = ((int)d->calculateWeight * (int)d->stockCap * 100) / (int)d->taskForceWeight;
            break;
          case 2:
            value = (int)(short)d->navyPriorityWeight;
            break;
          case 3:
            value = (int)g_industryActionCostWeightResCode10[(int)rec];
            break;
          default:
            value = 0;
          }
          g_aCategoryMetricBaselineAverage[channel] =
              g_aCategoryMetricBaselineAverage[channel] + value;
          channel = channel + 1;
        } while (channel < 4);
      }
      d = d + 1;
      rec = rec + 1;
    } while (d < &g_NavyOrderResourceDescriptorTable[14]);
    int c = 0;
    do {
      g_aCategoryMetricBaselineAverage[c] =
          (activeCount / 2 + g_aCategoryMetricBaselineAverage[c]) / activeCount;
      c = c + 1;
    } while (c < 4);
  }
}

// FUNCTION: IMPERIALISM 0x0054fee0
int GetNavyContextPointerFromGlobalTableByIndex(int index) {
  return g_aCategoryMetricBaselineAverage[index];
}

// Receiver-agnostic: also called directly on a TTaskForce's own
// order_type/required_count/tiebreak_strength fields (TNavyMission::ReturnZeroSlot2C),
// which happen to share these same 3 offsets with TShip -- see the header comment.

// FUNCTION: IMPERIALISM 0x0054ff00
short TShip::ComputeNavyOrderPriorityContributionPercentByCategory(int category) {
  int divisor = g_aCategoryMetricBaselineAverage[category];

  switch (category) {
  case 0: {
    const TNavyOrderResourceDescriptor& descriptor =
        g_NavyOrderResourceDescriptorTable[resourceType04];
    int quantityTerm = static_cast<int>(SignedMod100(field30)) + 5 + descriptor.resolveWeight * 10;
    int weight = descriptor.calculateWeight;
    return (SignedDiv10(quantityTerm) * weight * weight * 100) / divisor;
  }
  case 1: {
    const TNavyOrderResourceDescriptor& descriptor =
        g_NavyOrderResourceDescriptorTable[resourceType04];
    int weight = descriptor.calculateWeight;
    return (weight * static_cast<int>(stockLevel1c) * 10000) /
           (descriptor.taskForceWeight * divisor);
  }
  case 2:
    return (static_cast<int>(g_NavyOrderResourceDescriptorTable[resourceType04].descriptorWeight) *
            100) /
           divisor;
  case 3:
    if (stockLevel1c < 1) {
      return 0;
    }
    return (static_cast<int>(GetIndustryActionCostWeightByResourceType(resourceType04)) * 100) /
           divisor;
  default:
    return 0;
  }
}

// Per-category normalized cost percent for a resource type, used by the AI
// city/industry development selectors (0x4eb45a, 0x535d8e/0x535e26). Same
// category-0..3 divisor table (g_aCategoryMetricBaselineAverage) and resource-descriptor
// table as ComputeNavyOrderPriorityContributionPercentByCategory, but a distinct blend per
// category; the original inlines the descriptor-field reads, so they are reproduced
// inline here.

// FUNCTION: IMPERIALISM 0x00550090
int GetNormalizedIndustryActionResourceCostPercent(int nCategory, short nResourceType) {
  int divisor = g_aCategoryMetricBaselineAverage[nCategory];
  const TNavyOrderResourceDescriptor& desc = g_NavyOrderResourceDescriptorTable[nResourceType];
  switch (nCategory) {
  case 0:
    return (static_cast<int>(desc.resolveWeight) * static_cast<int>(desc.calculateWeight) *
            static_cast<int>(desc.calculateWeight) * 100) /
           divisor;
  case 1:
    return (((static_cast<int>(desc.calculateWeight) * static_cast<int>(desc.stockCap) * 100) /
             static_cast<int>(desc.taskForceWeight)) *
            100) /
           divisor;
  case 2:
    return (static_cast<short>(desc.navyPriorityWeight) * 100) / divisor;
  case 3:
    return (g_industryActionCostWeightResCode10[nResourceType] * 100) / divisor;
  default:
    return 0 / divisor;
  }
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

// FUNCTION: IMPERIALISM 0x00550640
TShip* GetNavyPrimaryOrderNodeByIndex(short index) {
  TShip* node = g_pNavyPrimaryOrderListHead;
  while (node != nullptr && index != 0) {
    node = node->nextOlder24;
    --index;
  }
  return node;
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

// FUNCTION: IMPERIALISM 0x005519d0
int FindCumulativeWeightBucketIndex(short* weightTable, short roll) {
  int index = -1;
  do {
    ++index;
    roll = static_cast<short>(roll - weightTable[index]);
  } while (roll > 0);
  return index;
}
