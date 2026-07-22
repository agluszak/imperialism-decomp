#include "game/TDefenseMinisterPersonalities.h"
#include "game/global_data_tables.h"

#include "game/mfc.h"

// NOTE: MakeNewCity (slot 0x44, the InitializeRecruitQueuePattern* recruit-queue setup)
// and DefenseSlot18 (slot 0x60, a per-personality float aggressiveness multiplier whose
// real signature returns float) are promoted here as real virtual overrides owning their
// original addresses (previously return-0 autogen stubs). Bodies are honest partial ports.

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
  (void)city;
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
  (void)city;
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
  (void)city;
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
  (void)city;
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
  (void)city;
}
