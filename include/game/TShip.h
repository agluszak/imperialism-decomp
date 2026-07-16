#pragma once

#include "game/CString.h"
#include "game/TObject.h"

class TAdmiral;
class TGreatPower;
class TStream;
class TTaskForce;
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
  // Parent map-order entry this primary-order node is queued under (same +0xc "owner"
  // slot TTaskForce::owner models; TShip::PruneOrPromoteOrderNodeWhenChildCostDepleted
  // walks its childOrderList/activeChildEntry, and TAdmiral's backlink helpers read it).
  TTaskForce* ownerOrderEntry0c;
  int quantityFlag10;
  short ownerNationSlot14;
  CString displayName18;
  short stockLevel1c;
  short pad1e;
  // Backlink to the TAdmiral whose primaryOrderNode08 is this node (TAdmiral::
  // SetTaskForcePrimaryOrderLinkAndRefreshChildBacklinks writes `this` here).
  TAdmiral* admiralBacklink20;
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
  // 0x00550b60 — composite economic score of this order node (quantity + descriptor
  // weights, normalized by the task-force weight). Real __thiscall (reads
  // [ecx+4]/[ecx+0x30]; the SumNavyOrderPriority loops call it with ecx = node).
  int ComputeOrderNodeCompositeEconomicScore();
  // Position of `this` in the primary navy order list, counted from
  // g_pNavyPrimaryOrderListHead (used when serializing orderList24 nodes by index).
  int GetIndexInPrimaryOrderList();
  // BFS zone-graph "hop" distance from this ship's own zone (field08) to
  // `otherZone`, blended against this resource type's descriptorWeight column
  // (g_NavyOrderResourceDescriptorTable[resourceType04].descriptorWeight).
  short ComputeOrderNodeDistanceQuotientByDescriptorWord24(TZone* otherZone);
  // 0x005509c0 -- marks this node depleted (stockLevel1c = -666) and re-prunes the
  // owning order entry's child list (same body TTaskForce::PruneInactiveTaskForceOrderHead
  // runs on itself, minus the return flag); with no owner it just Free()s this node.
  void PruneOrPromoteOrderNodeWhenChildCostDepleted();
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
// 0x004e04b0 / 0x004e0460 moved to TGreatPower::SumNavyOrderPriorityForNation[AndNodeType]
// — both bodies compare the ship owner tag against [ecx+0xc] (real __thiscall methods).

// Walks the primary navy order list for `nation`'s eligible port-owner ships (owner
// matches, the order's zone is a port zone, and the ship's normalization base doesn't
// exceed its stock), accumulates a 4-category priority vector (categories 0..2 scaled
// by stockLevel1c/normalizationBase, category 3 unscaled), then scores the vector's
// divergence from g_NavyOrderDistributionCategoryWeights_00697978's target percentages
// (same divergence-score shape as TNavyMission's NormalizeFourComponentNavyVector).
// Returns 0 if the vector sums to zero. 0x53b800.
float ComputeNavyOrderDistributionScoreForNation(short nation);

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
void __cdecl AccumulateNavyOrderCategoryVectorWithScale(TShip* orderNode, float* vector,
                                                        float scale);

// Per-category (0..3) normalized cost percent for a resource type, over the same
// divisor + TNavyOrderResourceDescriptor tables as the helper above but a distinct
// per-category blend. Used by the AI city/industry development selectors.
int GetNormalizedIndustryActionResourceCostPercent(int nCategory, short nResourceType);

TShip* CreateNavyPrimaryOrderNodeAndAssignDisplayName(short resourceType, TZone* portZoneContext,
                                                      int nationSlot, char* displayNameOverride);
void __fastcall RegenerateNavyPrimaryOrderDisplayNameUntilUnique(TShip* shipNode);
