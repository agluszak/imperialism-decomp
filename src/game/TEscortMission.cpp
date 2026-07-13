// TEscortMission implementations.

#include "game/TEscortMission.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TZone.h"

IMPLEMENT_SERIAL(TEscortMission, TNavyMission, 1)

// SYNTHETIC: IMPERIALISM 0x00539840
// TEscortMission::CreateObject

// FUNCTION: IMPERIALISM 0x00539900
TMission* TEscortMission::GetReplacementSlot48() {
  return this;
}

// FUNCTION: IMPERIALISM 0x00539920
char TEscortMission::ReturnFalseSlot64() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x00539940
char TEscortMission::ReturnFalseSlot60() {
  return 0;
}
// SYNTHETIC: IMPERIALISM 0x00539960
// TEscortMission::`scalar deleting destructor'

TEscortMission::TEscortMission() : TNavyMission() {}

// FUNCTION: IMPERIALISM 0x00539990
TEscortMission::~TEscortMission() {}

// SYNTHETIC: IMPERIALISM 0x005399b0
// TEscortMission::GetRuntimeClass

// The original inlines the whole TNavyMission(TZone*) body here (only the TMission()
// base ctor stays an out-of-line call); the recompile emits a call to 0x535470 instead,
// which is the accepted architectural shape until ctor-inlining is modeled.
// FUNCTION: IMPERIALISM 0x00539a20
TEscortMission::TEscortMission(TZone* targetZone) : TNavyMission(targetZone) {}

// FUNCTION: IMPERIALISM 0x00539a70
void TEscortMission::Call30() {
  marker11 = 0;
  targetZone18 = targetZone14;
}

// FUNCTION: IMPERIALISM 0x00539ca0
void TEscortMission::ResetValue0CToZero() {
  // TODO: ComputeNationScaledMissionScoreUsingPrimaryPortContextAverage --
  // pending recovery of the per-zone owner cache and needCapA6 scaling.
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(targetZone14);
  float score = static_cast<float>(owner->ComputeMapActionContextNodeValueAverage());
  *reinterpret_cast<float*>(&value0c) = score / g_fMissionScoreNormalizationDivisor;
}

// FUNCTION: IMPERIALISM 0x00539e70
void TEscortMission::NoOpSlot3C() {
  // TODO: PopulateEscortMissionResourceWeightsFromEligibleNationNavyPressure --
  // pending recovery of the eligible-nation navy-pressure aggregation.
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = 0.0f;
  }
}

// FUNCTION: IMPERIALISM 0x0053a250
char TEscortMission::MatchesMissionKeySlot4C(int kind, int key, int mode) {
  (void)mode;
  if ((kind == 0 || kind == 3) && key == reinterpret_cast<int>(targetZone14)) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053a290
void TEscortMission::MissionSlot44() {
  if (orderList24 != nullptr) {
    orderList24->active_flag = 0;
    // TODO: also clears flags on the linked child node (SetMapOrderEntryChildFlags);
    // pending recovery of that helper's real receiver type.
  }
  ConsolidateMissionOrderEntriesByTargetAndQueue(reinterpret_cast<int*>(targetZone14));
}
