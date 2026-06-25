#pragma once

#include "game/CString.h"
#include "game/TObject.h"

class TGreatPower;
class TStream;
class TZone;
struct CRuntimeClass;

// Navy primary-order list node (global head g_pNavyPrimaryOrderListHead @ 0x6A3EDC).
// TShip() prepends to the intrusive doubly-linked list; SumNavyOrderPriorityForNation
// walks nextOlder24.
// VTABLE: IMPERIALISM 0x0065c438
class TShip : public TObject {
public:
  short resourceType04;
  short pad06;
  void* field08;
  short linkContext0c;
  short linkTag0e;
  int quantityFlag10;
  short ownerNationSlot14;
  CString displayName18;
  short stockLevel1c;
  short pad1e;
  void* field20;
  TShip* nextOlder24;
  TShip* prevNewer28;
  void* field2c;
  short field30;
  unsigned char pad32[2];
  int field34;

  TShip();
  ~TShip() override;

  CRuntimeClass* GetRuntimeClass() const override;
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;
};

ASSERT_SIZE(TShip, 0x38);

extern "C" TShip* g_pNavyPrimaryOrderListHead;

void* GetNavyPrimaryOrderListHead(void);
short GetIndustryActionCostWeightByResourceType(short resourceType);
short GetResourceDescriptorWeightWord0ByType(short resourceType);
int ComputeOrderNodeCompositeEconomicScore(TShip* node);
int SumNavyOrderPriorityForNation(TGreatPower* nationObj);
int SumNavyOrderPriorityForNationAndNodeType(TGreatPower* nationObj, int nodeType);

TShip* CreateNavyPrimaryOrderNodeAndAssignDisplayName(short zoneIndex, TZone* portZoneContext,
                                                      int nationSlot, char* displayNameOverride);
void __fastcall RegenerateNavyPrimaryOrderDisplayNameUntilUnique(TShip* shipNode);
