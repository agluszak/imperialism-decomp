#include "game/TMinor.h"

#include <new>

static const unsigned int kAddrClassDescTMinor = 0x006536a0;

// FUNCTION: IMPERIALISM 0x00406ee7
void* TMinor::thunk_GetTMinorClassNamePointer_At00406ee7(void) {
  return GetTMinorClassNamePointer();
}

// FUNCTION: IMPERIALISM 0x004e3660
void* TMinor::CreateTMinorInstance() {
  return new TMinor();
}

// FUNCTION: IMPERIALISM 0x004e36f0
void* TMinor::GetTMinorClassNamePointer() {
  return reinterpret_cast<void*>(kAddrClassDescTMinor);
}

// FUNCTION: IMPERIALISM 0x004e3710
TMinor::TMinor() {
  encodedNationSlot = 0;
}

CRuntimeClass* TMinor::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(GetTMinorClassNamePointer());
}

void TMinor::WriteTo(TStream* stream) {
  SerializeDiplomacyNationStateToStream(stream);
}

void TMinor::ReadFrom(TStream* stream) {
  DeserializeDiplomacyNationStateFromStream(stream);
}

void TMinor::Free() {
  TCountry::Free();
}

void TMinor::SetDiplomacyStandingSlot48(int targetNation, int standing) {
  (void)targetNation;
  (void)standing;
}

char TMinor::HasMinorStandingLinkSlot5C(int sourceNation) {
  (void)sourceNation;
  return 0;
}

void TMinor::ApplyTerrainDiplomacyRelationFlagSlot8c(int sourceNation, int packedRelationCode) {
  (void)sourceNation;
  (void)packedRelationCode;
}

char TMinor::HasStandingPropagationBridgeSlot90(int targetNation) {
  (void)targetNation;
  return 0;
}

void TMinor::NotifyActionSlot94(int sourceNation, int actionCode) {
  (void)sourceNation;
  (void)actionCode;
}

void TMinor::NotifyNationAuxRuntimeFinalizeSlotC0(void) {}

void TMinor::ClearNationAuxRuntimeGrantSlotC4(int grantValue) {
  (void)grantValue;
}

// SYNTHETIC: IMPERIALISM 0x004e3790
// TMinor::`scalar deleting destructor'
