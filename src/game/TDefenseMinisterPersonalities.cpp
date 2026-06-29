#include "game/TDefenseMinisterPersonalities.h"

#include "game/mfc.h"

// NOTE: NoOpForeignMinisterUtilityStub (slot 0x44, the InitializeRecruitQueuePattern* recruit-queue setup)
// and DefenseSlot18 (slot 0x60, a per-personality float aggressiveness multiplier whose
// real signature returns float) are promoted here as real virtual overrides owning their
// original addresses (previously return-0 autogen stubs). Bodies are honest partial ports.

// Slot 24 (0x60) override — factory hook on this minister variant.
// FUNCTION: IMPERIALISM 0x004ed490
undefined TNapoleonMinister::CreateTDefenseMinisterInstance() { return 0; }
IMPLEMENT_DYNCREATE(TNapoleonMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004ed4e0
TNapoleonMinister::TNapoleonMinister() : TDefenseMinister() {}

// SYNTHETIC: IMPERIALISM 0x004ed510
// TNapoleonMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004ed620
void TNapoleonMinister::NoOpForeignMinisterUtilityStub(void* receiver) {
  (void)receiver;
}

// FUNCTION: IMPERIALISM 0x004ed7c0
undefined TBismarckMinister::CreateTDefenseMinisterInstance() {
  // Partial port: original returns a float aggressiveness multiplier.
  return 0;
}
IMPLEMENT_DYNCREATE(TBismarckMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004ed810
TBismarckMinister::TBismarckMinister() : TDefenseMinister() {}

// SYNTHETIC: IMPERIALISM 0x004ed840
// TBismarckMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004ed950
void TBismarckMinister::NoOpForeignMinisterUtilityStub(void* receiver) {
  (void)receiver;
}

// FUNCTION: IMPERIALISM 0x004edab0
undefined TPirateMinister::CreateTDefenseMinisterInstance() {
  // Partial port: original returns a float aggressiveness multiplier.
  return 0;
}
IMPLEMENT_DYNCREATE(TPirateMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004edb00
TPirateMinister::TPirateMinister() : TDefenseMinister() {}

// SYNTHETIC: IMPERIALISM 0x004edb30
// TPirateMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004edc40
void TPirateMinister::NoOpForeignMinisterUtilityStub(void* receiver) {
  (void)receiver;
}

// FUNCTION: IMPERIALISM 0x004edda0
undefined TDefenderMinister::CreateTDefenseMinisterInstance() {
  // Partial port: original returns a float aggressiveness multiplier.
  return 0;
}
IMPLEMENT_DYNCREATE(TDefenderMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004edde0
TDefenderMinister::TDefenderMinister() : TDefenseMinister() {}

// SYNTHETIC: IMPERIALISM 0x004ede10
// TDefenderMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004edf20
void TDefenderMinister::NoOpForeignMinisterUtilityStub(void* receiver) {
  (void)receiver;
}

// FUNCTION: IMPERIALISM 0x004ee080
undefined TBullyMinister::CreateTDefenseMinisterInstance() {
  // Partial port: original returns a float aggressiveness multiplier.
  return 0;
}
IMPLEMENT_DYNCREATE(TBullyMinister, TDefenseMinister)

// FUNCTION: IMPERIALISM 0x004ee0d0
TBullyMinister::TBullyMinister() : TDefenseMinister() {}

// SYNTHETIC: IMPERIALISM 0x004ee100
// TBullyMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004ee210
void TBullyMinister::NoOpForeignMinisterUtilityStub(void* receiver) {
  (void)receiver;
}

