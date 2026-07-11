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
  // free function -- the same body is also called on a plain TTaskForce*
  // (TNavyMission::ReturnZeroSlot2C), so the shared logic takes values, not `this`.
  short ComputeNavyOrderPriorityContributionPercentByCategory(int category);
  // Per-resourceType-04 normalization base (the "stock cap" field of the
  // shared per-resource-type descriptor table, TNavyOrderResourceDescriptor).
  // Thin wrapper, same receiver-agnostic reasoning as above.
  short GetNavyOrderNormalizationBaseByNationType();
  // Position of `this` in the primary navy order list, counted from
  // g_pNavyPrimaryOrderListHead (used when serializing orderList24 nodes by index).
  int GetIndexInPrimaryOrderList();
  // BFS zone-graph "hop" distance from this ship's own zone (field08) to
  // `otherZone`, blended against this resource type's descriptorWeight column
  // (g_NavyOrderResourceDescriptorTable[resourceType04].descriptorWeight).
  short ComputeOrderNodeDistanceQuotientByDescriptorWord24(TZone* otherZone);
};

ASSERT_SIZE(TShip, 0x38);

extern "C" TShip* g_pNavyPrimaryOrderListHead;

TShip* GetNavyPrimaryOrderListHead(void);
// Walks g_pNavyPrimaryOrderListHead's nextOlder24 chain `index` steps (stopping early at
// the list's end); returns the node reached.
TShip* GetNavyPrimaryOrderNodeByIndex(short index);
// Cumulative-weight roll-table search: subtracts weightTable[0], [1], ... from `roll`
// until it drops to <= 0, returning the index reached (same shape as the inlined
// DAT_0065c25e/DAT_0065c264 walks in AccumulateRandomizedNavyOrderResourceDeltasByNationAndOwner).
int FindCumulativeWeightBucketIndex(short* weightTable, short roll);
short GetIndustryActionCostWeightByResourceType(short resourceType);
short GetResourceDescriptorWeightWord0ByType(short resourceType);
int ComputeOrderNodeCompositeEconomicScore(TShip* node);
int SumNavyOrderPriorityForNation(TGreatPower* nationObj);
int SumNavyOrderPriorityForNationAndNodeType(TGreatPower* nationObj, int nodeType);

// Shared navy-order-priority helper (0x54ff00): reads the per-resourceType
// TNavyOrderResourceDescriptor and blends it with the caller's own
// stock/tiebreak field. Called both on TShip nodes (the primary navy order
// list, via TShip::ComputeNavyOrderPriorityContributionPercentByCategory) and
// on plain TTaskForce nodes (TNavyMission::ReturnZeroSlot2C's orderList24
// chain) -- the original dispatches 0x54ff00 __thiscall on BOTH receiver types,
// which share the read offsets (+0x04 resource/order type, +0x1c
// stock/required-count, +0x30 a tiebreak/context field). It is modelled as a
// TShip method; the one TTaskForce call site keeps the original's receiver pun.
short GetNavyOrderNormalizationBaseByResourceType(short resourceType);

// Per-category (0..3) normalized cost percent for a resource type, over the same
// divisor + TNavyOrderResourceDescriptor tables as the helper above but a distinct
// per-category blend. Used by the AI city/industry development selectors.
int GetNormalizedIndustryActionResourceCostPercent(int nCategory, short nResourceType);

TShip* CreateNavyPrimaryOrderNodeAndAssignDisplayName(short resourceType, TZone* portZoneContext,
                                                      int nationSlot, char* displayNameOverride);
void __fastcall RegenerateNavyPrimaryOrderDisplayNameUntilUnique(TShip* shipNode);
