#include "game/TShip.h"

#include "game/TGreatPower.h"

#include <new>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" TShip* g_pNavyPrimaryOrderListHead = 0;
extern char g_industryActionCostWeightResCode10;
char g_ResourceDescriptorWeightWord0Base0069811c[0x24 * 64] = {0};

extern "C" {
extern short g_Resolve_Map_Order_LookupTable_00698108[];
extern short g_Calculate_Mission_Order_LookupTable_0069810C[];
extern short g_Navy_Order_Priority_LookupTable_00698118[];
extern short g_Task_Force_Order_LookupTable_00698110[];
}

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
  for (TShip* node = static_cast<TShip*>(GetNavyPrimaryOrderListHead()); node != 0;
       node = node->nextOlder24) {
    if (node->ownerNationSlot14 == nationObj->nationSlot && node->field08 == (void*)nodeType) {
      sum += ComputeOrderNodeCompositeEconomicScore(node);
    }
  }
  return sum;
}


// FUNCTION: IMPERIALISM 0x004e04b0
int SumNavyOrderPriorityForNation(TGreatPower* nationObj) {
  int sum = 0;
  for (TShip* node = static_cast<TShip*>(GetNavyPrimaryOrderListHead()); node != 0;
       node = node->nextOlder24) {
    if (node->ownerNationSlot14 == nationObj->nationSlot) {
      sum += ComputeOrderNodeCompositeEconomicScore(node);
    }
  }
  return sum;
}


// FUNCTION: IMPERIALISM 0x0054f500
void TShip::ConstructAndLinkNavyPrimaryOrderNode() {
  new (this) RefCountedObjectBase();
  resourceType04 = 0;
  field08 = 0;
  linkContext0c = 0;
  linkTag0e = 0;
  quantityFlag10 = 1;
  ownerNationSlot14 = static_cast<short>(-1);
  new (&displayName18) CString();
  field20 = 0;
  nextOlder24 = g_pNavyPrimaryOrderListHead;
  prevNewer28 = 0;
  field2c = 0;
  field30 = 0;
  field34 = 0;
  g_pNavyPrimaryOrderListHead = this;
  if (nextOlder24 != 0) {
    nextOlder24->prevNewer28 = this;
  }
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif


// FUNCTION: IMPERIALISM 0x005505c0
void* GetNavyPrimaryOrderListHead(void) {
  return g_pNavyPrimaryOrderListHead;
}


// FUNCTION: IMPERIALISM 0x00550970
short GetIndustryActionCostWeightByResourceType(short resourceType) {
  return *reinterpret_cast<short*>(&g_industryActionCostWeightResCode10 + resourceType * 2);
}

// FUNCTION: IMPERIALISM 0x00550e70
short GetResourceDescriptorWeightWord0ByType(short resourceType) {
  return *reinterpret_cast<short*>(&g_ResourceDescriptorWeightWord0Base0069811c +
                                   resourceType * 0x24);
}

// FUNCTION: IMPERIALISM 0x00550b60
int ComputeOrderNodeCompositeEconomicScore(TShip* node) {
  int resourceType = (int)node->resourceType04;
  short quantityField = node->field30;
  int quantityTerm = (int)SignedMod100(quantityField);
  int navyTerm = quantityTerm + 5 + g_Navy_Order_Priority_LookupTable_00698118[resourceType * 9] * 10;
  int resolveTerm =
      quantityTerm + 5 + g_Resolve_Map_Order_LookupTable_00698108[resourceType * 9] * 10;
  short stockAt1c = *reinterpret_cast<short*>(reinterpret_cast<char*>(node) + 0x1c);
  return (SignedDiv10(resolveTerm) +
          (SignedDiv10(navyTerm) + g_Calculate_Mission_Order_LookupTable_0069810C[resourceType * 9]) *
              100 +
          (int)stockAt1c) /
         (int)*(short*)(reinterpret_cast<char*>(&g_Task_Force_Order_LookupTable_00698110) +
                        resourceType * 0x24);
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
