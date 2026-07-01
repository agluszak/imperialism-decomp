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
  TZone* field08;
  int field0c; // single dword (ctor writes it as one `mov dword ptr [this+0xc], 0`)
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

  DECLARE_DYNCREATE(TShip)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  // Per-category (0-3) priority-contribution percentage for this order node,
  // used by callers that accumulate a 4-component category vector (see e.g.
  // TControlSeaZoneMission::NoOpSlot3C). Sibling of ComputeOrderNodeCompositeEconomicScore
  // (same lookup tables, different blend per category). Thin wrapper over the
  // receiver-agnostic ComputeNavyOrderPriorityContributionPercentByCategory
  // free function -- the same body is also called on a plain TMapOrderEntry*
  // (TNavyMission::ReturnZeroSlot2C), so the shared logic takes values, not `this`.
  int ComputeNavyOrderPriorityContributionPercentByCategory(int category);
  // Per-resourceType-04 normalization base (the "stock cap" field of the
  // shared per-resource-type descriptor table, TNavyOrderResourceDescriptor).
  // Thin wrapper, same receiver-agnostic reasoning as above.
  short GetNavyOrderNormalizationBaseByNationType();
  // Position of `this` in the primary navy order list, counted from
  // g_pNavyPrimaryOrderListHead (used when serializing orderList24 nodes by index).
  int GetIndexInPrimaryOrderList();
};

ASSERT_SIZE(TShip, 0x38);

extern "C" TShip* g_pNavyPrimaryOrderListHead;

TShip* GetNavyPrimaryOrderListHead(void);
short GetIndustryActionCostWeightByResourceType(short resourceType);
short GetResourceDescriptorWeightWord0ByType(short resourceType);
int ComputeOrderNodeCompositeEconomicScore(TShip* node);
int SumNavyOrderPriorityForNation(TGreatPower* nationObj);
int SumNavyOrderPriorityForNationAndNodeType(TGreatPower* nationObj, int nodeType);

// Shared navy-order-priority helper (0x54ff00): reads the per-resourceType
// TNavyOrderResourceDescriptor and blends it with the caller's own
// stock/tiebreak field. Called both on TShip nodes (the primary navy order
// list, via TShip::ComputeNavyOrderPriorityContributionPercentByCategory) and
// on plain TMapOrderEntry nodes (TNavyMission::ReturnZeroSlot2C's orderList24
// chain) -- both classes happen to carry the same 3 fields at the offsets the
// original reads (+0x04 resource/order type, +0x1c stock/required-count,
// +0x30 a tiebreak/context field), so this takes them by value instead of by
// receiver type.
int ComputeNavyOrderPriorityContributionPercentByCategory(short resourceType,
                                                          short stockOrRequiredCount,
                                                          short tiebreakField, int category);
short GetNavyOrderNormalizationBaseByResourceType(short resourceType);

TShip* CreateNavyPrimaryOrderNodeAndAssignDisplayName(short resourceType, TZone* portZoneContext,
                                                      int nationSlot, char* displayNameOverride);
void __fastcall RegenerateNavyPrimaryOrderDisplayNameUntilUnique(TShip* shipNode);
