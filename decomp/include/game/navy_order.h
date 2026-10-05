#pragma once

// UNavy free functions: navy-order scoring, the primary-order roster utilities, and
// the per-resource-type descriptor lookups. These lived in the same original TU as
// TShip (D:\Ambit\Cross\UNavy.cpp) but are not TShip members -- kept out of
// TShip.h so the ship class header stays a class contract (see
// docs/reference/navy_order_model.md).

class TShip;
class TZone;
int FindCumulativeWeightBucketIndex(short* weightTable, short roll);
short GetIndustryActionCostWeightByResourceType(short resourceType);

float ComputeNavyOrderDistributionScoreForNation(short nation);

void __cdecl AccumulateNavyOrderCategoryVectorWithScale(TShip* orderNode, float* vector,
                                                        float scale);

int GetNormalizedIndustryActionResourceCostPercent(int nCategory, short nResourceType);

TShip* CreateNavyPrimaryOrderNodeAndAssignDisplayName(short resourceType, TZone* portZoneContext,
                                                      int nationSlot, char* displayNameOverride);
