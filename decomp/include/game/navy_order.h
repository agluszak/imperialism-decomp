#pragma once

// UNavy free functions: navy-order scoring, primary-order roster utilities and the
// per-resource-type descriptor lookups.

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
