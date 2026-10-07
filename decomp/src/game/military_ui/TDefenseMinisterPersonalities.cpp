#include "game/military_ui/TDefenseMinisterPersonalities.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"
#include "game/military/TMilitaryUnit.h"
#include "game/mfc.h"

// Each MakeNewCity override seeds the personality's opening population, production stock,
// and military recruitment mix for a newly created city.

// Slot 24 (0x60) override — factory hook on this minister variant.
// FUNCTION: IMPERIALISM 0x004ed490
double TNapoleonMinister::GetStategicEscalationMultiplier(bool flag) {
  return flag ? g_MinisterWeightHalf : g_MinisterWeightOne;
}

IMPLEMENT_DYNCREATE(TNapoleonMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004ed4e0
TNapoleonMinister::TNapoleonMinister() : TDefenseMinister() {}

// FUNCTION: IMPERIALISM 0x004ed620
void TNapoleonMinister::MakeNewCity(TCity* city) {
  city->productionSummary->SetPopulation(10, 4, 0);
  city->orderCountByType[3] = 1;

  int infantryOrdersRemaining = 3;
  do {
    TMilitaryUnit* recruitOrder = new TMilitaryUnit();
    recruitOrder->IMilitaryUnit(2, 0, greatPower->nationSlot, 0);
    ++recruitOrderCountByType[2];
    --infantryOrdersRemaining;
  } while (infantryOrdersRemaining != 0);

  int artilleryOrdersRemaining = 2;
  do {
    TMilitaryUnit* recruitOrder = new TMilitaryUnit();
    recruitOrder->IMilitaryUnit(4, 0, greatPower->nationSlot, 0);
    ++recruitOrderCountByType[4];
    --artilleryOrdersRemaining;
  } while (artilleryOrdersRemaining != 0);
}

// FUNCTION: IMPERIALISM 0x004ed7c0
double TBismarckMinister::GetStategicEscalationMultiplier(bool flag) {
  return flag ? g_BismarckWeightHigh : g_BismarckWeightLow;
}

IMPLEMENT_DYNCREATE(TBismarckMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004ed810
TBismarckMinister::TBismarckMinister() : TDefenseMinister() {}

// FUNCTION: IMPERIALISM 0x004ed950
void TBismarckMinister::MakeNewCity(TCity* city) {
  city->productionSummary->SetPopulation(9, 4, 1);
  city->orderCountByType[3] = 1;

  int recruitOrdersRemaining = 2;
  do {
    TMilitaryUnit* recruitOrder = new TMilitaryUnit();
    recruitOrder->IMilitaryUnit(2, 0, greatPower->nationSlot, 0);
    ++recruitOrderCountByType[2];
    --recruitOrdersRemaining;
  } while (recruitOrdersRemaining != 0);

  city->cityStockArms = static_cast<short>(city->cityStockArms + 5);
  city->VerifyStocks();
}

// FUNCTION: IMPERIALISM 0x004edab0
double TPirateMinister::GetStategicEscalationMultiplier(bool flag) {
  return flag ? g_MinisterWeightHalf : g_MinisterWeightOne;
}

IMPLEMENT_DYNCREATE(TPirateMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004edb00
TPirateMinister::TPirateMinister() : TDefenseMinister() {}

// FUNCTION: IMPERIALISM 0x004edc40
void TPirateMinister::MakeNewCity(TCity* city) {
  city->productionSummary->SetPopulation(8, 4, 1);
  city->orderCountByType[3] = 2;

  int recruitOrdersRemaining = 3;
  do {
    TMilitaryUnit* recruitOrder = new TMilitaryUnit();
    recruitOrder->IMilitaryUnit(2, 0, greatPower->nationSlot, 0);
    ++recruitOrderCountByType[2];
    --recruitOrdersRemaining;
  } while (recruitOrdersRemaining != 0);

  city->cityStockArms = static_cast<short>(city->cityStockArms + 2);
  city->VerifyStocks();
}

// FUNCTION: IMPERIALISM 0x004edda0
double TDefenderMinister::GetStategicEscalationMultiplier(bool) {
  return g_DefenderMinisterWeight;
}

IMPLEMENT_DYNCREATE(TDefenderMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004edde0
TDefenderMinister::TDefenderMinister() : TDefenseMinister() {}

// FUNCTION: IMPERIALISM 0x004edf20
void TDefenderMinister::MakeNewCity(TCity* city) {
  city->productionSummary->SetPopulation(8, 4, 1);
  city->orderCountByType[4] = 1;

  int recruitOrdersRemaining = 3;
  do {
    TMilitaryUnit* recruitOrder = new TMilitaryUnit();
    recruitOrder->IMilitaryUnit(2, 0, greatPower->nationSlot, 0);
    ++recruitOrderCountByType[2];
    --recruitOrdersRemaining;
  } while (recruitOrdersRemaining != 0);

  city->cityStockArms = static_cast<short>(city->cityStockArms + 2);
  city->VerifyStocks();
}

// FUNCTION: IMPERIALISM 0x004ee080
double TBullyMinister::GetStategicEscalationMultiplier(bool flag) {
  return flag ? g_BullyWeightLow : g_BullyWeightHigh;
}

IMPLEMENT_DYNCREATE(TBullyMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004ee0d0
TBullyMinister::TBullyMinister() : TDefenseMinister() {}

// FUNCTION: IMPERIALISM 0x004ee210
void TBullyMinister::MakeNewCity(TCity* city) {
  city->productionSummary->SetPopulation(10, 4, 0);
  city->orderCountByType[4] = 2;

  int infantryOrdersRemaining = 2;
  do {
    TMilitaryUnit* recruitOrder = new TMilitaryUnit();
    recruitOrder->IMilitaryUnit(2, 0, greatPower->nationSlot, 0);
    ++recruitOrderCountByType[2];
    --infantryOrdersRemaining;
  } while (infantryOrdersRemaining != 0);

  int artilleryOrdersRemaining = 3;
  do {
    TMilitaryUnit* recruitOrder = new TMilitaryUnit();
    recruitOrder->IMilitaryUnit(4, 0, greatPower->nationSlot, 0);
    ++recruitOrderCountByType[4];
    --artilleryOrdersRemaining;
  } while (artilleryOrdersRemaining != 0);

  city->cityStockArms = 2;
  city->VerifyStocks();
}
