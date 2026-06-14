#pragma once

#include "game/CString.h"
#include "game/RefCountedObjectBase.h"

class TGreatPower;

int AllocateWithFallbackHandler(undefined4 size_bytes);

// Navy primary-order list node (global head g_pNavyPrimaryOrderListHead @ 0x6A3EDC).
// ConstructAndLinkNavyPrimaryOrderNode prepends to the intrusive doubly-linked list;
// SumNavyOrderPriorityForNation walks nextOlder24.
// VTABLE: IMPERIALISM 0x0065c438
class TShip : public RefCountedObjectBase {
public:
  short resourceType04;
  short pad06;
  void* field08;
  short linkContext0c;
  short linkTag0e;
  int quantityFlag10;
  short ownerNationSlot14;
  CString displayName18;
  void* field20;
  TShip* nextOlder24;
  TShip* prevNewer28;
  void* field2c;
  short field30;
  unsigned char pad32[2];
  int field34;

  void ConstructAndLinkNavyPrimaryOrderNode();
  void DestroyAndUnlinkNavyPrimaryOrderNode();
};

extern "C" TShip* g_pNavyPrimaryOrderListHead;

void* GetNavyPrimaryOrderListHead(void);
short GetIndustryActionCostWeightByResourceType(short resourceType);
short GetResourceDescriptorWeightWord0ByType(short resourceType);
int ComputeOrderNodeCompositeEconomicScore(TShip* node);
int SumNavyOrderPriorityForNation(TGreatPower* nationObj);
int SumNavyOrderPriorityForNationAndNodeType(TGreatPower* nationObj, int nodeType);
