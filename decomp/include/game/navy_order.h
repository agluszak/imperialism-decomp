#pragma once

// UNavy free functions: navy-order scoring, the primary-order roster utilities, and
// the per-resource-type descriptor lookups. These lived in the same original TU as
// TShip (D:\Ambit\Cross\UNavy.cpp) but are not TShip members -- kept out of
// TShip.h so the ship class header stays a class contract (see
// docs/reference/navy_order_model.md).

class TShip;
class TZone;
// Cumulative-weight roll-table search: subtracts weightTable[0], [1], ... from `roll`
// until it drops to <= 0, returning the index reached.
int FindCumulativeWeightBucketIndex(short* weightTable, short roll);
short GetIndustryActionCostWeightByResourceType(short resourceType);
short GetResourceDescriptorWeightWord0ByType(int resourceType);

// Walks the primary navy order list for `nation`'s eligible port-owner ships (owner
// matches, the order's zone is a port zone, and the ship's normalization base doesn't
// exceed its stock), accumulates a 4-category priority vector (categories 0..2 scaled
// by strength/normalizationBase, category 3 unscaled), then scores the vector's
// divergence from g_NavyOrderDistributionCategoryWeights_00697978's target percentages.
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
