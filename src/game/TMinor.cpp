#include "game/TMinor.h"

#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/turn_event_packets.h"

#include <new>

static const unsigned int kAddrClassDescTMinor = 0x006536a0;

undefined4 thunk_QueueInterNationEventRecordDeduped(void);

// FUNCTION: IMPERIALISM 0x004e3660
void* TMinor::CreateTMinorInstance() {
  return new TMinor();
}

// FUNCTION: IMPERIALISM 0x004e36f0
CRuntimeClass* TMinor::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(kAddrClassDescTMinor);
}

void* TMinor::GetTMinorClassNamePointer() {
  return reinterpret_cast<void*>(kAddrClassDescTMinor);
}

// FUNCTION: IMPERIALISM 0x004e3710
TMinor::TMinor() {
  encodedNationSlot = 0;
}

// FUNCTION: IMPERIALISM 0x004e41c0
void TMinor::ReadFrom(TStream* stream) {
  TCountry::DeserializeDiplomacyNationStateFromStream(stream);
}

// FUNCTION: IMPERIALISM 0x004e4390
void TMinor::WriteTo(TStream* stream) {
  TCountry::SerializeDiplomacyNationStateToStream(stream);
}

// FUNCTION: IMPERIALISM 0x004e45f0
char TMinor::ReturnFalseNationStateCapabilityFlag90(int arg) {
  return (arg > 0xc && arg < 0x11) ? 1 : 0;
}

// FUNCTION: IMPERIALISM 0x004e4630
int TMinor::SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot) {
  (void)nationSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e4660
short TMinor::GetDiplomacyExternalStateB6ByTarget(short nationSlot) {
  (void)nationSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e4680
short TMinor::QueryNationMetricBySlot7C(short metricSlot) {
  (void)metricSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e49b0
void TMinor::ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                            int multiplier) {
  (void)resourceIndex;
  (void)delta;
  (void)multiplier;
}

// FUNCTION: IMPERIALISM 0x004e4ee0
bool TMinor::IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot) {
  if (targetNationSlot <= 0xc || targetNationSlot >= 0x11) {
    return false;
  }
  TGreatPower* nation = reinterpret_cast<TGreatPower*>(this);
  if (targetNationSlot == nation->field8d6[0]) {
    return nation->field8d6[1] == 0;
  }
  if (targetNationSlot == nation->field8d6[2]) {
    return nation->field8d6[3] == 0;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004e4f50
char TMinor::TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                           int arg4) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e4fa0
void TMinor::ResetDiplomacyLevelForNationSlot12(NationSlot nationSlot, int resetLevel) {
  short targetNationSlot = static_cast<short>(nationSlot);
  short policyValue = static_cast<short>(resetLevel);
  if (targetNationSlot != this->nationSlot) {
    if (policyValue != this->needLevelByNation[targetNationSlot]) {
      this->needLevelByNation[targetNationSlot] = policyValue;
      if (policyValue == 300) {
        this->NotifyActionSlot94(-1, 0);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e50d0
void TMinor::QueueDiplomacyProposalCodeForTargetNation(short proposalCode, short targetNationId) {
  (void)proposalCode;
  (void)targetNationId;
}

// FUNCTION: IMPERIALISM 0x004e5300
void TMinor::NotifyActionSlot94(int sourceNation, int actionCode) {
  (void)sourceNation;
  (void)actionCode;
}

// FUNCTION: IMPERIALISM 0x004e5340
void TMinor::SetNationTransferTargetCodeAndNotifyEligiblePeers(int targetNationSlot) {
  (void)targetNationSlot;
}

// FUNCTION: IMPERIALISM 0x004e5840
void TMinor::ApplyJoinEmpireMode1TargetTransition(int targetNationSlot) {
  TCountry::ApplyJoinEmpireMode1TargetTransition(targetNationSlot);
  reinterpret_cast<void(__cdecl*)(int, int, int, int)>(thunk_QueueInterNationEventRecordDeduped)(
      0x1b, this->nationSlot, targetNationSlot, 0);
}

// FUNCTION: IMPERIALISM 0x004e59d0
CString* TMinor::GetIdentitySharedString1Slot58(void) {
  return &this->identitySharedString1;
}

// FUNCTION: IMPERIALISM 0x004e64a0
void TMinor::RemoveRegionIdFromNationOwnedRegionList(int regionId) {
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->RemoveIntSlot34(regionId);
  }
}

// FUNCTION: IMPERIALISM 0x004e64f0
void TMinor::AddRegionIdToNationOwnedRegionList(int regionId) {
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->WriteTo(reinterpret_cast<TStream*>(regionId));
  }
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

void TMinor::NotifyNationAuxRuntimeFinalizeSlotC0(void) {}

void TMinor::ClearNationAuxRuntimeGrantSlotC4(int grantValue) {
  (void)grantValue;
}

// SYNTHETIC: IMPERIALISM 0x004e3790
// TMinor::`scalar deleting destructor'
