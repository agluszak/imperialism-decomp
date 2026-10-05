#include "game/city/TPopulationMgr.h"

#include <string.h>

#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"
#include "game/core/TStream.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TPopulationMgr, TObject)

// FUNCTION: IMPERIALISM 0x004b5be0
TPopulationMgr::~TPopulationMgr() {}

// FUNCTION: IMPERIALISM 0x004b5c00
void TPopulationMgr::IPopulationMgr(TCity* city) {
  city04 = city;
  baselineSlots = new TLaborPool();
  productionSlots = new TLaborPool();
  pendingDeltaSlots = new TLaborPool();
  populationCount = 0;
  populationCountFloat = 0.0f;
  extraAt1e = 0;
  memset(predictedNeedByResource22, 0, sizeof(predictedNeedByResource22));
}

// FUNCTION: IMPERIALISM 0x004b5d10
void TPopulationMgr::Copy(TLaborPool* source, TLaborPool* destination) {
  destination->lowSkillCount04 = source->lowSkillCount04;
  destination->mediumSkillCount06 = source->mediumSkillCount06;
  destination->highSkillCount08 = source->highSkillCount08;
}

// FUNCTION: IMPERIALISM 0x004b5d50
void TPopulationMgr::SetPopulation(short lowSkillCount) {
  baselineSlots->lowSkillCount04 = lowSkillCount;
  productionSlots->lowSkillCount04 = lowSkillCount;
  strength = lowSkillCount;
  populationCount = lowSkillCount;
  populationCountFloat = static_cast<float>(lowSkillCount);
  pendingDeltaSlots->highSkillCount08 = 0;
  pendingDeltaSlots->mediumSkillCount06 = 0;
  pendingDeltaSlots->lowSkillCount04 = 0;
  fieldAt20 = 0;
}

// FUNCTION: IMPERIALISM 0x004b5dc0
void TPopulationMgr::SetPopulation(short lowSkillCount, short mediumSkillCount,
                                   short highSkillCount) {
  baselineSlots->lowSkillCount04 = lowSkillCount;
  productionSlots->lowSkillCount04 = lowSkillCount;
  baselineSlots->mediumSkillCount06 = mediumSkillCount;
  productionSlots->mediumSkillCount06 = mediumSkillCount;
  baselineSlots->highSkillCount08 = highSkillCount;
  productionSlots->highSkillCount08 = highSkillCount;

  strength = static_cast<short>(
      productionSlots->lowSkillCount04 +
      (productionSlots->mediumSkillCount06 + productionSlots->highSkillCount08 * 2) * 2);
  short total = static_cast<short>(mediumSkillCount + highSkillCount + lowSkillCount);
  populationCount = total;
  populationCountFloat = static_cast<float>(total);

  pendingDeltaSlots->highSkillCount08 = 0;
  pendingDeltaSlots->mediumSkillCount06 = 0;
  pendingDeltaSlots->lowSkillCount04 = 0;
  fieldAt20 = 0;
}

// FUNCTION: IMPERIALISM 0x004b5e80
void TPopulationMgr::StartProductionPhase() {
  Copy(baselineSlots, productionSlots);
  Eat();
  strength = static_cast<short>(
      productionSlots->lowSkillCount04 +
      (productionSlots->mediumSkillCount06 + productionSlots->highSkillCount08 * 2) * 2);
  extraAt1e = 0;
}

// FUNCTION: IMPERIALISM 0x004b5ed0
void TPopulationMgr::Eat() {
  int substitutedFoodCount = 0;
  int starvationLoss = 0;

  productionSlots->lowSkillCount04 =
      static_cast<short>(productionSlots->lowSkillCount04 + pendingDeltaSlots->lowSkillCount04);
  productionSlots->mediumSkillCount06 = static_cast<short>(productionSlots->mediumSkillCount06 +
                                                           pendingDeltaSlots->mediumSkillCount06);
  productionSlots->highSkillCount08 =
      static_cast<short>(productionSlots->highSkillCount08 + pendingDeltaSlots->highSkillCount08);

  int population = populationCount;
  short grainRemaining = city04->cityStockGrain;
  short fruitRemaining = city04->cityStockFruit;
  short animalFoodRemaining =
      static_cast<short>(city04->cityStockFish + city04->cityStockLivestock);
  short unmetFoodNeed = 0;

  short grainNeed = static_cast<short>((population + 1) / 2);
  if (grainRemaining < grainNeed) {
    unmetFoodNeed = static_cast<short>(grainNeed - grainRemaining);
    grainRemaining = 0;
  } else {
    grainRemaining = static_cast<short>(grainRemaining - grainNeed);
  }

  short fruitNeed = static_cast<short>((population + 2) / 4);
  if (fruitRemaining < fruitNeed) {
    unmetFoodNeed = static_cast<short>(unmetFoodNeed + fruitNeed - fruitRemaining);
    fruitRemaining = 0;
  } else {
    fruitRemaining = static_cast<short>(fruitRemaining - fruitNeed);
  }

  short animalFoodNeed = static_cast<short>(population / 4);
  if (animalFoodRemaining < animalFoodNeed) {
    unmetFoodNeed = static_cast<short>(unmetFoodNeed + animalFoodNeed - animalFoodRemaining);
    animalFoodRemaining = 0;
  } else {
    animalFoodRemaining = static_cast<short>(animalFoodRemaining - animalFoodNeed);
  }

  if (unmetFoodNeed != 0) {
    if (unmetFoodNeed < city04->cityStockCannedFoodC4) {
      city04->cityStockCannedFoodC4 =
          static_cast<short>(city04->cityStockCannedFoodC4 - unmetFoodNeed);
      city04->VerifyStocks();
      unmetFoodNeed = 0;
    } else {
      unmetFoodNeed = static_cast<short>(unmetFoodNeed - city04->cityStockCannedFoodC4);
      city04->cityStockCannedFoodC4 = 0;
      city04->VerifyStocks();
    }

    if (unmetFoodNeed != 0) {
      short deficitBeforeSubstitution = unmetFoodNeed;
      if (grainRemaining < unmetFoodNeed) {
        unmetFoodNeed = static_cast<short>(unmetFoodNeed - grainRemaining);
        grainRemaining = 0;
        if (fruitRemaining < unmetFoodNeed) {
          unmetFoodNeed = static_cast<short>(unmetFoodNeed - fruitRemaining);
          fruitRemaining = 0;
          if (animalFoodRemaining < unmetFoodNeed) {
            unmetFoodNeed = static_cast<short>(unmetFoodNeed - animalFoodRemaining);
            animalFoodRemaining = 0;
          } else {
            animalFoodRemaining = static_cast<short>(animalFoodRemaining - unmetFoodNeed);
            unmetFoodNeed = 0;
          }
        } else {
          fruitRemaining = static_cast<short>(fruitRemaining - unmetFoodNeed);
          unmetFoodNeed = 0;
        }
      } else {
        grainRemaining = static_cast<short>(grainRemaining - unmetFoodNeed);
        unmetFoodNeed = 0;
      }
      substitutedFoodCount = deficitBeforeSubstitution - unmetFoodNeed;
    }
  }

  city04->cityStockGrain = grainRemaining;
  city04->VerifyStocks();
  city04->cityStockFruit = fruitRemaining;
  city04->VerifyStocks();

  if (animalFoodRemaining != 0) {
    short livestockRemaining;
    short fishRemaining;
    if ((animalFoodRemaining & 1) != 0) {
      livestockRemaining = static_cast<short>(animalFoodRemaining / 2 + 1);
      fishRemaining = static_cast<short>(livestockRemaining - 1);
    } else {
      livestockRemaining = static_cast<short>(animalFoodRemaining / 2);
      fishRemaining = livestockRemaining;
    }

    if (city04->cityStockLivestock < livestockRemaining) {
      short shift = static_cast<short>(livestockRemaining - city04->cityStockLivestock);
      livestockRemaining = static_cast<short>(livestockRemaining - shift);
      fishRemaining = static_cast<short>(fishRemaining + shift);
    } else if (city04->cityStockFish < fishRemaining) {
      short shift = static_cast<short>(fishRemaining - city04->cityStockFish);
      fishRemaining = static_cast<short>(fishRemaining - shift);
      livestockRemaining = static_cast<short>(livestockRemaining + shift);
    }
    city04->cityStockLivestock = livestockRemaining;
    city04->VerifyStocks();
    city04->cityStockFish = fishRemaining;
    city04->VerifyStocks();
  } else {
    city04->cityStockLivestock = 0;
    city04->VerifyStocks();
    city04->cityStockFish = 0;
    city04->VerifyStocks();
  }

  if (unmetFoodNeed != 0) {
    TLaborPool* lostPopulation = new TLaborPool();
    lostPopulation->mediumSkillCount06 = 0;
    lostPopulation->lowSkillCount04 = 0;
    lostPopulation->highSkillCount08 = 0;
    baselineSlots->TransferToLowSkillFirst(lostPopulation, unmetFoodNeed);
    lostPopulation->Free();
    populationCount = static_cast<short>(populationCount - unmetFoodNeed);
    populationCountFloat -= static_cast<float>(unmetFoodNeed);
    starvationLoss = unmetFoodNeed > 0 ? unmetFoodNeed : 0;
  }

  Copy(baselineSlots, productionSlots);
  if (substitutedFoodCount != 0) {
    productionSlots->TransferToLowSkillFirst(pendingDeltaSlots,
                                             static_cast<short>(substitutedFoodCount));
  }
  city04->foodSubstitutionCount06 = static_cast<short>(substitutedFoodCount);
  city04->starvationPopulationLoss08 = static_cast<short>(starvationLoss);
}

// FUNCTION: IMPERIALISM 0x004b6260
void TPopulationMgr::PretendToEat(short& substitutionCount, short& starvationCount) {
  int population = populationCount;
  substitutionCount = 0;
  starvationCount = 0;

  TGreatPower* owner = city04->ownerNationAc;
  short grainRemaining = owner->needTargetByType[0x11];
  short fruitRemaining = owner->needTargetByType[0x12];
  short animalFoodRemaining =
      static_cast<short>(owner->needTargetByType[0x13] + owner->needTargetByType[0x14]);
  short unmetFoodNeed = 0;

  short grainNeed = static_cast<short>((population + 1) / 2);
  if (grainRemaining < grainNeed) {
    unmetFoodNeed = static_cast<short>(grainNeed - grainRemaining);
    grainRemaining = 0;
  } else {
    grainRemaining = static_cast<short>(grainRemaining - grainNeed);
  }

  short fruitNeed = static_cast<short>((population + 2) / 4);
  if (fruitRemaining < fruitNeed) {
    unmetFoodNeed = static_cast<short>(unmetFoodNeed + fruitNeed - fruitRemaining);
    fruitRemaining = 0;
  } else {
    fruitRemaining = static_cast<short>(fruitRemaining - fruitNeed);
  }

  short animalFoodNeed = static_cast<short>(population / 4);
  if (animalFoodRemaining < animalFoodNeed) {
    unmetFoodNeed = static_cast<short>(unmetFoodNeed + animalFoodNeed - animalFoodRemaining);
    animalFoodRemaining = 0;
  } else {
    animalFoodRemaining = static_cast<short>(animalFoodRemaining - animalFoodNeed);
  }

  if (unmetFoodNeed != 0) {
    if (unmetFoodNeed < city04->cityStockCannedFoodC4) {
      unmetFoodNeed = 0;
    } else {
      unmetFoodNeed = static_cast<short>(unmetFoodNeed - city04->cityStockCannedFoodC4);
    }

    if (unmetFoodNeed != 0) {
      short deficitBeforeSubstitution = unmetFoodNeed;
      if (grainRemaining < unmetFoodNeed) {
        unmetFoodNeed = static_cast<short>(unmetFoodNeed - grainRemaining);
        if (fruitRemaining < unmetFoodNeed) {
          unmetFoodNeed = static_cast<short>(unmetFoodNeed - fruitRemaining);
          if (animalFoodRemaining < unmetFoodNeed) {
            unmetFoodNeed = static_cast<short>(unmetFoodNeed - animalFoodRemaining);
          } else {
            unmetFoodNeed = 0;
          }
        } else {
          unmetFoodNeed = 0;
        }
      } else {
        unmetFoodNeed = 0;
      }
      substitutionCount = static_cast<short>(deficitBeforeSubstitution - unmetFoodNeed);
      if (unmetFoodNeed != 0) {
        starvationCount = unmetFoodNeed;
      }
    }
  }

  if (starvationCount != 0) {
    starvationCount = starvationCount > 0 ? starvationCount : 0;
  }
}

// FUNCTION: IMPERIALISM 0x004b63e0
float TPopulationMgr::GrowthRate() {
  float rate;
  if (populationCount < 10) {
    rate = g_PopulationGrowthRateUnder10;
  } else if (populationCount < 15) {
    rate = g_PopulationGrowthRateUnder15;
  } else if (populationCount < 20) {
    rate = g_PopulationGrowthRateUnder20;
  } else if (populationCount < 30) {
    rate = g_PopulationGrowthRateUnder30;
  } else if (populationCount < 40) {
    rate = g_PopulationGrowthRateUnder40;
  } else if (populationCount < 60) {
    rate = g_PopulationGrowthRateUnder60;
  } else if (populationCount < 80) {
    rate = g_PopulationGrowthRateUnder80;
  } else if (populationCount < 400) {
    rate = g_PopulationGrowthRateUnder400;
  } else {
    return g_PopulationGrowthRateAtOrAbove400;
  }

  if (city04->populationGrowthPenaltyTicks < 20) {
    return static_cast<float>(rate - city04->populationGrowthPenaltyTicks *
                                         g_PopulationGrowthPenaltyPerRetry);
  }
  return static_cast<float>(rate - g_PopulationGrowthMaximumRetryPenalty);
}

// FUNCTION: IMPERIALISM 0x004b64c0
short* TPopulationMgr::PredictedNeeds() {
  int skilledPopulation = baselineSlots->mediumSkillCount06 + baselineSlots->highSkillCount08;
  short rotationCounts[4];
  rotationCounts[0] = 0;
  rotationCounts[1] = 0;
  rotationCounts[2] = 0;

  short cycles = static_cast<short>(skilledPopulation / 10);
  short rotation = fieldAt20;
  while (cycles != 0) {
    ++rotationCounts[rotation];
    rotation = rotation == 3 ? 0 : static_cast<short>(rotation + 1);
    --cycles;
  }

  for (int i = 0; i < 3; ++i) {
    predictedNeedByResource22[g_cityPredictedNeedResetResourceIds[i]] = 0;
  }

  short supportedPopulation =
      static_cast<short>(populationCount + city04->trailingOrderSlots[9]->quantity);
  predictedNeedByResource22[17] = static_cast<short>((supportedPopulation + 1) / 2);
  predictedNeedByResource22[18] = static_cast<short>((supportedPopulation + 2) / 4);
  predictedNeedByResource22[20] = static_cast<short>(supportedPopulation / 4);
  return predictedNeedByResource22;
}

// FUNCTION: IMPERIALISM 0x004b65b0
char TPopulationMgr::Strike() {
  bool shortage = false;
  int skilledPopulation = baselineSlots->mediumSkillCount06 + baselineSlots->highSkillCount08;
  short consumptionByResource[4];
  consumptionByResource[0] = 0;
  consumptionByResource[1] = 0;
  consumptionByResource[2] = 0;

  short cycles = static_cast<short>(skilledPopulation / 10);
  while (cycles != 0) {
    ++consumptionByResource[fieldAt20];
    fieldAt20 = fieldAt20 == 3 ? 0 : static_cast<short>(fieldAt20 + 1);
    --cycles;
  }

  int resourceIndex;
  for (resourceIndex = 0; resourceIndex < 3; ++resourceIndex) {
    short resourceType = g_cityPredictedNeedResetResourceIds[resourceIndex];
    short amount = consumptionByResource[resourceIndex];
    if (city04->CityStockByType(resourceType) < amount) {
      city04->CityStockByType(resourceType) = 0;
      city04->VerifyStocks();
      shortage = true;
    } else {
      city04->CityStockByType(resourceType) =
          static_cast<short>(city04->CityStockByType(resourceType) - amount);
      city04->VerifyStocks();
    }
  }
  return shortage;
}

// FUNCTION: IMPERIALISM 0x004b66a0
void TPopulationMgr::RemovePopulation(short startingSkillBand, short amount) {
  short remaining = amount;

  if (startingSkillBand == 1) {
    short available = baselineSlots->lowSkillCount04;
    if (remaining <= available) {
      baselineSlots->lowSkillCount04 = static_cast<short>(available - remaining);
      productionSlots->lowSkillCount04 =
          static_cast<short>(productionSlots->lowSkillCount04 - remaining);
      strength = static_cast<short>(strength - remaining);
      remaining = 0;
    } else {
      remaining = static_cast<short>(remaining - available);
      baselineSlots->lowSkillCount04 = 0;
      productionSlots->lowSkillCount04 = 0;
      startingSkillBand = 2;
      strength = static_cast<short>(strength - remaining);
    }
  }

  if (startingSkillBand == 2) {
    short available = baselineSlots->mediumSkillCount06;
    if (remaining <= available) {
      baselineSlots->mediumSkillCount06 = static_cast<short>(available - remaining);
      productionSlots->mediumSkillCount06 =
          static_cast<short>(productionSlots->mediumSkillCount06 - remaining);
      strength = static_cast<short>(strength - remaining * 2);
      remaining = 0;
    } else {
      remaining = static_cast<short>(remaining - available);
      baselineSlots->mediumSkillCount06 = 0;
      productionSlots->mediumSkillCount06 = 0;
      startingSkillBand = 4;
      strength = static_cast<short>(strength - remaining * 2);
    }
  }

  if (startingSkillBand == 4) {
    short available = baselineSlots->highSkillCount08;
    if (remaining <= available) {
      baselineSlots->highSkillCount08 = static_cast<short>(available - remaining);
      productionSlots->highSkillCount08 =
          static_cast<short>(productionSlots->highSkillCount08 - remaining);
      strength = static_cast<short>(strength - remaining * 4);
      remaining = 0;
    } else {
      remaining = static_cast<short>(remaining - available);
      baselineSlots->highSkillCount08 = 0;
      productionSlots->highSkillCount08 = 0;
      strength = static_cast<short>(strength - remaining * 4);
    }
  }

  short removed = static_cast<short>(amount - remaining);
  populationCount = static_cast<short>(populationCount - removed);
  populationCountFloat -= static_cast<float>(removed);
}

// FUNCTION: IMPERIALISM 0x004b67e0
void TPopulationMgr::MakeUnavailable(short skillBand, short amount) {
  switch (skillBand) {
  case 1:
    productionSlots->lowSkillCount04 =
        static_cast<short>(productionSlots->lowSkillCount04 - amount);
    strength = static_cast<short>(strength - amount);
    break;
  case 2:
    productionSlots->mediumSkillCount06 =
        static_cast<short>(productionSlots->mediumSkillCount06 - amount);
    strength = static_cast<short>(strength - amount * 2);
    break;
  case 4:
    productionSlots->highSkillCount08 =
        static_cast<short>(productionSlots->highSkillCount08 - amount);
    strength = static_cast<short>(strength - amount * 4);
    break;
  }
}

// FUNCTION: IMPERIALISM 0x004b6850
void TPopulationMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&populationCount, 2);
  stream->WriteBytes(&strength, 2);
  stream->WriteBytes(&extraAt1e, 2);
  stream->WriteBytes(&fieldAt20, 2);
  stream->WriteBytes(predictedNeedByResource22, sizeof(predictedNeedByResource22));
  stream->WriteBytes(&populationCountFloat, 4);
  baselineSlots->WriteTo(stream);
  productionSlots->WriteTo(stream);
  pendingDeltaSlots->WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x004b68f0
void TPopulationMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&populationCount, 2);
  stream->ReadBytes(&strength, 2);
  stream->ReadBytes(&extraAt1e, 2);
  stream->ReadBytes(&fieldAt20, 2);
  stream->ReadBytes(predictedNeedByResource22, sizeof(predictedNeedByResource22));
  stream->ReadBytes(&populationCountFloat, 4);
  baselineSlots->ReadFrom(stream);
  productionSlots->ReadFrom(stream);
  pendingDeltaSlots->ReadFrom(stream);
}

// FUNCTION: IMPERIALISM 0x004b6990
void TPopulationMgr::Free() {
  if (baselineSlots != 0) {
    baselineSlots->Free();
  }
  baselineSlots = 0;
  if (productionSlots != 0) {
    productionSlots->Free();
  }
  productionSlots = 0;
  if (pendingDeltaSlots != 0) {
    pendingDeltaSlots->Free();
  }
  pendingDeltaSlots = 0;
  delete this;
}

// Mac CodeWarrior oracle: AddExpert(short). Adds `count` workers to the high-skill
// band of both the baseline and working labor pools, to the aggregate population
// count, and 4x to strength. Sole caller is TCivUnit::ResetCivWorkOrderAndRefreshCounters
// (disbanding a civilian specialist returns an expert).
// FUNCTION: IMPERIALISM 0x004b6a00
void TPopulationMgr::AddUntrained(short count) {
  baselineSlots->lowSkillCount04 = baselineSlots->lowSkillCount04 + count;
  productionSlots->lowSkillCount04 = productionSlots->lowSkillCount04 + count;
  populationCount = populationCount + count;
}

// FUNCTION: IMPERIALISM 0x004b6a30
void TPopulationMgr::AddExpert(short count) {
  baselineSlots->highSkillCount08 = baselineSlots->highSkillCount08 + count;
  productionSlots->highSkillCount08 = productionSlots->highSkillCount08 + count;
  populationCount = populationCount + count;
  strength = static_cast<short>(strength + count * 4);
}
