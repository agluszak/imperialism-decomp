#pragma once

// UNavy free functions: navy-order scoring, the primary-order roster utilities, and
// the per-resource-type descriptor lookups. These lived in the same original TU as
// TShip (D:\Ambit\Cross\UNavy.cpp) but are not TShip members -- kept out of
// TShip.h so the ship class header stays a class contract (see
// docs/reference/navy_order_model.md).

class TShip;
class TZone;

// Head of the global primary navy-order roster (Mac oracle: TShip::GetFirst).
TShip* GetNavyPrimaryOrderListHead(void);
// Walks g_pNavyPrimaryOrderListHead's nextOlder24 chain `index` steps (stopping early
// at the list's end); returns the node reached (Mac oracle: TShip::GetNth).
TShip* GetNavyPrimaryOrderNodeByIndex(short index);
// Cumulative-weight roll-table search: subtracts weightTable[0], [1], ... from `roll`
// until it drops to <= 0, returning the index reached.
int FindCumulativeWeightBucketIndex(short* weightTable, short roll);
short GetIndustryActionCostWeightByResourceType(short resourceType);
short GetResourceDescriptorWeightWord0ByType(short resourceType);

// Walks the primary navy order list for `nation`'s eligible port-owner ships (owner
// matches, the order's zone is a port zone, and the ship's normalization base doesn't
// exceed its stock), accumulates a 4-category priority vector (categories 0..2 scaled
// by stockLevel1c/normalizationBase, category 3 unscaled), then scores the vector's
// divergence from g_NavyOrderDistributionCategoryWeights_00697978's target percentages
// (same divergence-score shape as TNavyMission's NormalizeFourComponentNavyVector).
// Returns 0 if the vector sums to zero. 0x53b800.
float ComputeNavyOrderDistributionScoreForNation(short nation);

// Per-resourceType normalization base (the "stock cap" field of the shared
// per-resource-type descriptor table, TNavyOrderResourceDescriptor). 0x5505a0.
void __cdecl AccumulateNavyOrderCategoryVectorWithScale(TShip* orderNode, float* vector,
                                                        float scale);

// Per-category (0..3) normalized cost percent for a resource type, over the same
// divisor + TNavyOrderResourceDescriptor tables as TShip's per-category contribution
// scorer but a distinct per-category blend. Used by the AI city/industry development
// selectors. 0x550090.
int GetNormalizedIndustryActionResourceCostPercent(int nCategory, short nResourceType);

TShip* CreateNavyPrimaryOrderNodeAndAssignDisplayName(short resourceType, TZone* portZoneContext,
                                                      int nationSlot, char* displayNameOverride);
void __fastcall RegenerateNavyPrimaryOrderDisplayNameUntilUnique(TShip* shipNode);
