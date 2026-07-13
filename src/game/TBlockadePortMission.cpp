// TBlockadePortMission implementations.
//
// Real base is TControlSeaZoneMission (RTTI ancestry: TBlockadePortMission ->
// TControlSeaZoneMission -> TNavyMission -> TMission -> TObject -> CObject).
// ResetValue0CToZero and RefreshMissionPortZoneContextForNation are NOT
// overridden here -- they're inherited unchanged from TControlSeaZoneMission,
// which owns their `// FUNCTION:` markers. Call30 here is a genuinely distinct
// own override (RecomputeAndClearMissionScoreUsingPortZoneContextAverageVariantB).

#include "game/TBlockadePortMission.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TTaskForce.h"
#include "game/TZone.h"

IMPLEMENT_SERIAL(TBlockadePortMission, TControlSeaZoneMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053a990
// TBlockadePortMission::CreateObject

// FUNCTION: IMPERIALISM 0x0053aa50
char TBlockadePortMission::ReturnFalseSlot64() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053aa70
char TBlockadePortMission::ReturnFalseSlot60() {
  return 0;
}
// SYNTHETIC: IMPERIALISM 0x0053aa90
// TBlockadePortMission::`scalar deleting destructor'

TBlockadePortMission::TBlockadePortMission()
    : TControlSeaZoneMission(), portZoneContext3c(nullptr) {}

// SYNTHETIC: IMPERIALISM 0x0053aae0
// TBlockadePortMission::GetRuntimeClass

// The mission factory (CreateMissionObjectByKindAndNodeContext, case 4) builds a
// blockade mission from a map-order context node (a TZone). It lazily ensures the
// context's primaryNeighbors array has slot 0 allocated -- that first entry is the
// target port zone -- constructs the TControlSeaZoneMission base on it, back-links
// the context node into portZoneContext3c (+0x3c), and validates the context.
// FUNCTION: IMPERIALISM 0x0053ab50
TBlockadePortMission::TBlockadePortMission(TZone* context)
    : TControlSeaZoneMission(*context->primaryNeighbors.EnsureSlotAllocatedAndReturnPointer(0)),
      portZoneContext3c(context) {
  context->AssertValid();
}

// FUNCTION: IMPERIALISM 0x0053ac60
void TBlockadePortMission::WriteTo(TStream* stream) {
  TNavyMission::WriteTo(stream);
  stream->WriteCountSlot88(portZoneContext3c->GetContextOrdinalOrInvalid());
}

// FUNCTION: IMPERIALISM 0x0053aca0
void TBlockadePortMission::ReadFrom(TStream* stream) {
  TNavyMission::ReadFrom(stream);
  portZoneContext3c = FindMapActionContextByNodeId(stream->ReadShort());
}

// FUNCTION: IMPERIALISM 0x0053ace0
void TBlockadePortMission::Call30() {
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(targetZone14);
  float score = static_cast<float>(owner->ComputeMapActionContextNodeValueAverage());

  for (TZone* zone = TZone::GetFirstPortZone(); zone != nullptr; zone = zone->GetNextPortZone()) {
    // See TControlSeaZoneMission::Call30 -- per-zone owner cache not yet modeled.
    (void)zone;
  }

  marker11 = 0;
  *reinterpret_cast<float*>(&value0c) = score / g_fMissionScoreNormalizationDivisor;
}

// Same overall shape as TControlSeaZoneMission::GetReplacementSlot48, but the coverage
// check here indexes this nation's per-context byte gate array (this+0x8a0, same region
// SetByteFlagAtOffsetAF0ByIndex writes) by portZoneContext3c's owner-nation-code ordinal,
// instead of scanning g_apTerrainTypeDescriptorTable.
// FUNCTION: IMPERIALISM 0x0053adf0
TMission* TBlockadePortMission::GetReplacementSlot48() {
  TGreatPower* nation = g_apNationStates[nationId04];
  nation->AssertValid();
  short ownerCode = portZoneContext3c->GetPortZoneOwnerNationCodeFromMissionField48();
  bool hasCoverage = *(reinterpret_cast<char*>(nation) + 0x8a0 + ownerCode) != 0;

  if (!hasCoverage) {
    short contextOrdinal = portZoneContext3c->GetContextOrdinalOrInvalid();
    nation->SetByteFlagAtOffsetAF0ByIndex(contextOrdinal, 0);
    return nullptr;
  }

  if (targetZone18 != nullptr && targetZone18->QueryPortZoneCapability() &&
      !targetZone18->QueryZoneCapabilityFlagD(nationId04)) {
    targetZone18 = RefreshMissionPortZoneContextForNation();
  }

  return (targetZone18 != nullptr) ? this : nullptr;
}

// FUNCTION: IMPERIALISM 0x0053ae90
void TBlockadePortMission::SetStateByte8To2() {
  state08 = 3;
}

// TODO: promote body (bd 1uj.16.5) -- 935 bytes, the largest unported function in this
// family; several sub-calls not yet identified (func_0x0040793c order-list iteration,
// func_0x00407c75/0x4063e3/0x405272/0x4027e3, and the vftable[8].slot_0x04 diplomacy
// dispatch also seen in TEscortMission's own unported NoOpSlot3C). Shape: computes a
// 4-category weighted base score the same way TControlSeaZoneMission::NoOpSlot3C /
// TEscortMission::ResetValue0CToZero do (accumulate per-order contributions, normalize
// against the g_Populate_Beachhead_Mission_LookupTable_00697958 profile, spread across
// resourceWeights2c[4]), then computes a second "threat" score -- either from a single
// target nation (targetZone18's owner-nation-code, if < 7) or maxed over every nation
// g_apNationStates -- and uses max(threat*0.5, 10.0) to raise (never lower) each
// resourceWeights2c[i] via a second DAT_00697960 lookup table. Left unported pending a
// dedicated follow-up; see bd 1uj.16.5 notes.
// FUNCTION: IMPERIALISM 0x0053aeb0
void TBlockadePortMission::NoOpSlot3C() {
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = 0.0f;
  }
}

// FUNCTION: IMPERIALISM 0x0053ba10
char TBlockadePortMission::MatchesMissionKeySlot4C(int kind, int key, int mode) {
  (void)key;
  // Original (0x53ba10) compares the third argument against the inherited
  // targetZone14 pointer, not the second argument against portZoneContext3c.
  if (kind == 4 && mode == reinterpret_cast<int>(targetZone14)) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053ba40
void TBlockadePortMission::NoOpSlot9C(void* pMapOrderEntry) {
  static_cast<TTaskForce*>(pMapOrderEntry)
      ->SetMapOrderType6AndQueue(reinterpret_cast<int>(portZoneContext3c));
}
