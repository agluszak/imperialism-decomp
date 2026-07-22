#include "game/TDefenseMinisterPersonalities.h"
#include "game/global_data_tables.h"

#include "game/TCity.h"
#include "game/TGreatPower.h"
#include "game/TMilitaryUnit.h"
#include "game/mfc.h"

// Each MakeNewCity override seeds the personality's opening population, production stock,
// and military recruitment mix for a newly created city.

// Slot 24 (0x60) override — factory hook on this minister variant.
// FUNCTION: IMPERIALISM 0x004ed490
double TNapoleonMinister::GetPersonalityWeightByFlag(char flag) {
  return flag ? g_MinisterWeightHalf_006548E8 : g_MinisterWeightOne_006548F0;
}
// SYNTHETIC: IMPERIALISM 0x004ed400
// TNapoleonMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ed4c0
// TNapoleonMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNapoleonMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004ed4e0
TNapoleonMinister::TNapoleonMinister() : TDefenseMinister() {}

// SYNTHETIC: IMPERIALISM 0x004ed510
// TNapoleonMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004ed620
void TNapoleonMinister::MakeNewCity(TCity* city) {
  city->productionSummary1d8->SetPopulation(10, 4, 0);
  city->orderCountByType5c[3] = 1;

  int infantryOrdersRemaining = 3;
  do {
    TMilitaryUnit* recruitOrder = new TMilitaryUnit();
    recruitOrder->IMilitaryUnit(2, 0, ownerContextAt04->nationSlot, 0);
    ++recruitOrderCountByType[2];
    --infantryOrdersRemaining;
  } while (infantryOrdersRemaining != 0);

  int artilleryOrdersRemaining = 2;
  do {
    TMilitaryUnit* recruitOrder = new TMilitaryUnit();
    recruitOrder->IMilitaryUnit(4, 0, ownerContextAt04->nationSlot, 0);
    ++recruitOrderCountByType[4];
    --artilleryOrdersRemaining;
  } while (artilleryOrdersRemaining != 0);
}

// FUNCTION: IMPERIALISM 0x004ed7c0
double TBismarckMinister::GetPersonalityWeightByFlag(char flag) {
  return flag ? g_BismarckWeightHigh_006548F8 : g_BismarckWeightLow_00654900;
}
// SYNTHETIC: IMPERIALISM 0x004ed740
// TBismarckMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ed7f0
// TBismarckMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBismarckMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004ed810
TBismarckMinister::TBismarckMinister() : TDefenseMinister() {}

// SYNTHETIC: IMPERIALISM 0x004ed840
// TBismarckMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004ed950
void TBismarckMinister::MakeNewCity(TCity* city) {
  city->productionSummary1d8->SetPopulation(9, 4, 1);
  city->orderCountByType5c[3] = 1;

  int recruitOrdersRemaining = 2;
  do {
    TMilitaryUnit* recruitOrder = new TMilitaryUnit();
    recruitOrder->IMilitaryUnit(2, 0, ownerContextAt04->nationSlot, 0);
    ++recruitOrderCountByType[2];
    --recruitOrdersRemaining;
  } while (recruitOrdersRemaining != 0);

  city->cityStockArmsD6 = static_cast<short>(city->cityStockArmsD6 + 5);
  city->VerifyStocks();
}

// FUNCTION: IMPERIALISM 0x004edab0
double TPirateMinister::GetPersonalityWeightByFlag(char flag) {
  return flag ? g_MinisterWeightHalf_006548E8 : g_MinisterWeightOne_006548F0;
}
// SYNTHETIC: IMPERIALISM 0x004eda30
// TPirateMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x004edae0
// TPirateMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPirateMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004edb00
TPirateMinister::TPirateMinister() : TDefenseMinister() {}

// SYNTHETIC: IMPERIALISM 0x004edb30
// TPirateMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004edc40
void TPirateMinister::MakeNewCity(TCity* city) {
  city->productionSummary1d8->SetPopulation(8, 4, 1);
  city->orderCountByType5c[3] = 2;

  int recruitOrdersRemaining = 3;
  do {
    TMilitaryUnit* recruitOrder = new TMilitaryUnit();
    recruitOrder->IMilitaryUnit(2, 0, ownerContextAt04->nationSlot, 0);
    ++recruitOrderCountByType[2];
    --recruitOrdersRemaining;
  } while (recruitOrdersRemaining != 0);

  city->cityStockArmsD6 = static_cast<short>(city->cityStockArmsD6 + 2);
  city->VerifyStocks();
}

// FUNCTION: IMPERIALISM 0x004edda0
double TDefenderMinister::GetPersonalityWeightByFlag(char) {
  return g_DefenderMinisterWeight_00654908;
}
// SYNTHETIC: IMPERIALISM 0x004edd20
// TDefenderMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x004eddc0
// TDefenderMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDefenderMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004edde0
TDefenderMinister::TDefenderMinister() : TDefenseMinister() {}

// SYNTHETIC: IMPERIALISM 0x004ede10
// TDefenderMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004edf20
void TDefenderMinister::MakeNewCity(TCity* city) {
  city->productionSummary1d8->SetPopulation(8, 4, 1);
  city->orderCountByType5c[4] = 1;

  int recruitOrdersRemaining = 3;
  do {
    TMilitaryUnit* recruitOrder = new TMilitaryUnit();
    recruitOrder->IMilitaryUnit(2, 0, ownerContextAt04->nationSlot, 0);
    ++recruitOrderCountByType[2];
    --recruitOrdersRemaining;
  } while (recruitOrdersRemaining != 0);

  city->cityStockArmsD6 = static_cast<short>(city->cityStockArmsD6 + 2);
  city->VerifyStocks();
}

// FUNCTION: IMPERIALISM 0x004ee080
double TBullyMinister::GetPersonalityWeightByFlag(char flag) {
  return flag ? g_BullyWeightLow_00654910 : g_BullyWeightHigh_00654918;
}
// SYNTHETIC: IMPERIALISM 0x004ee000
// TBullyMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ee0b0
// TBullyMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBullyMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004ee0d0
TBullyMinister::TBullyMinister() : TDefenseMinister() {}

// SYNTHETIC: IMPERIALISM 0x004ee100
// TBullyMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004ee210
void TBullyMinister::MakeNewCity(TCity* city) {
  city->productionSummary1d8->SetPopulation(10, 4, 0);
  city->orderCountByType5c[4] = 2;

  int infantryOrdersRemaining = 2;
  do {
    TMilitaryUnit* recruitOrder = new TMilitaryUnit();
    recruitOrder->IMilitaryUnit(2, 0, ownerContextAt04->nationSlot, 0);
    ++recruitOrderCountByType[2];
    --infantryOrdersRemaining;
  } while (infantryOrdersRemaining != 0);

  int artilleryOrdersRemaining = 3;
  do {
    TMilitaryUnit* recruitOrder = new TMilitaryUnit();
    recruitOrder->IMilitaryUnit(4, 0, ownerContextAt04->nationSlot, 0);
    ++recruitOrderCountByType[4];
    --artilleryOrdersRemaining;
  } while (artilleryOrdersRemaining != 0);

  city->cityStockArmsD6 = 2;
  city->VerifyStocks();
}
