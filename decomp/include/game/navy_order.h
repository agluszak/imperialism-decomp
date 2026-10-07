#pragma once

// UNavy free functions: navy-order scoring, primary-order roster utilities and the
// per-resource-type descriptor lookups.

class TShip;
class TZone;
int FindCumulativeWeightBucketIndex(short* weightTable, short roll);
short GetIndustryCostWeight(short resourceType);

float ScoreNavyDistribution(short nation);

void __cdecl AddShipToCategoryVector(TShip* orderNode, float* vector, float scale);

int GetIndustryCostPercent(int nCategory, short nResourceType);

TShip* CreateAdmiral(short resourceType, TZone* portZoneContext, int nationSlot,
                     char* displayNameOverride);
