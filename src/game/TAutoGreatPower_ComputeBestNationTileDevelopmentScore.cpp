#include "game/TAutoGreatPower.h"

#include "game/TDiplomacyMgr.h"
#include "game/TDefendProvinceMission.h"
#include "game/TLongintList.h"
#include "game/TMapMgr.h"
#include "game/TTechMgr.h"
#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x00540440
int ComputeBestNationTileDevelopmentScore(short nationSlot) {
  TAutoGreatPower* nation = static_cast<TAutoGreatPower*>(g_apNationStates[nationSlot]);
  if (nation == 0 || nation->diplomacyEligibilityA0 != 0) {
    return -1;
  }

  nation->AssertValid();

  float averageUnitDivergence = nation->averageUnitDivergencePerOwnedRegionB68;
  if (!(averageUnitDivergence > 0.0)) {
    averageUnitDivergence = g_MissionPositiveFallback_0065A9B8;
  }

  int bestRegionId = -1;
  float bestScore = -1.0f;
  TLongintList* ownedRegions = nation->ownedRegionList;
  long regionOrdinal = 1;
  int ownedRegionCount = ownedRegions->GetSize();
  while (regionOrdinal <= ownedRegionCount) {
    short regionId = static_cast<short>(ownedRegions->At(regionOrdinal));
    TGlobalMapCityScoreRecord* region = &g_pGlobalMapState->cityScoreTable[regionId];

    if (region->fortLevel03 < g_pCityOrderCapabilityState->GetNationFortLevelCap(nationSlot)) {
      float developmentPressure = averageUnitDivergence;
      if (IsMapTileCompatibleWithCurrentTerrainOrActionContext(regionId)) {
        developmentPressure =
            nation->expansionPressurePerCompatibleRegionB64 + averageUnitDivergence;
        if (g_pDiplomacyTurnStateManager->HasAnyWarRelationForNation(nationSlot)) {
          developmentPressure +=
              TDefendProvinceMission::ComputeCrossNationSupportVectorScore(regionId) *
              g_DefendProvinceMissionCrossSupportFloorScale_0065A8F8;
        }
      }

      float cityScore = static_cast<float>(region->cityScoreValue);
      if (region->adjacentRegionCount08 > 0) {
        int sameOwnerAdjacentRegionCount = 0;
        int adjacentOrdinal = 0;
        while (adjacentOrdinal < region->adjacentRegionCount08) {
          if (g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(
                  region->adjacentRegionIds0A[adjacentOrdinal]) == nationSlot) {
            ++sameOwnerAdjacentRegionCount;
          }
          ++adjacentOrdinal;
        }

        cityScore *= static_cast<float>(sameOwnerAdjacentRegionCount) /
                         static_cast<float>(region->adjacentRegionCount08) -
                     static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9E0);
      }

      float score = cityScore / g_fMissionScoreNormalizationDivisor * developmentPressure;
      if (score > bestScore || bestRegionId == -1) {
        bestScore = score;
        bestRegionId = regionId;
      }
    }

    ++regionOrdinal;
    ownedRegionCount = ownedRegions->GetSize();
  }

  return bestRegionId;
}
