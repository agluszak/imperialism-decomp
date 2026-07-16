// TEscortMission implementations.

#include "game/TEscortMission.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TOcean.h"
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

// Scales this mission's score by home-nation trade capacity and need pressure: starts from
// the current home port zone's cached-owner (primaryNeighbors slot 0, punned to TGreatPower*
// -- same convention Call30/ResetValue0CToZero use elsewhere in this file)
// ComputeMapActionContextNodeValueAverage(), then for every OTHER port zone sharing that same
// cached owner multiplies the running score by 1.5 (if that zone's own mission-field-48 owner
// nation matches this mission's nation) or 1.25 (otherwise), and finally scales by
// nation->tradeCapacity / max(nation->needCapA6, 1) / 5000.
// FUNCTION: IMPERIALISM 0x00539ca0
void TEscortMission::ResetValue0CToZero() {
  TGreatPower* nation = g_apNationStates[nationId04];
  short needCap = (nation != nullptr) ? nation->needCapA6 : 0;
  if (needCap == 0) {
    needCap = 1;
  }

  TZone* homePortZone = g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(nationId04);
  TZone** cachedOwnerSlot = homePortZone->primaryNeighbors.EnsureSlotAllocatedAndReturnPointer(0);
  TZone* cachedOwner = *cachedOwnerSlot;
  float score = static_cast<float>(
      reinterpret_cast<TGreatPower*>(cachedOwner)->ComputeMapActionContextNodeValueAverage());

  for (TZone* zone = TZone::GetFirstPortZone(); zone != nullptr; zone = zone->GetNextPortZone()) {
    TZone** zoneOwnerSlot = zone->primaryNeighbors.EnsureSlotAllocatedAndReturnPointer(0);
    if (*zoneOwnerSlot == cachedOwner) {
      short ownerNationCode = zone->GetPortZoneOwnerNationCodeFromMissionField48();
      score *= (ownerNationCode == nationId04) ? 1.5f : 1.25f;
    }
  }

  value0c =
      (score / 5000.0f) * static_cast<float>(nation->tradeCapacity) / static_cast<float>(needCap);
}

// TODO: promote body (bd 1uj.16.3) -- 770-byte function, heavily corrupted Ghidra decompile
// (register-carried loop state via CONCAT44/CONCAT22; several sub-calls not yet identified:
// 0x40793c/0x4063e3/0x40605f family and the vtable slot 8 index 0x04 diplomacy dispatch). Shape: walks
// g_apSecondaryNationStateSlots[7..22] (TMinor*), gates each by an eligibility/diplomacy
// check against this mission's nation (needCapA6-like threshold vs. a
// g_pDiplomacyTurnStateManager field), then for eligible nations accumulates a 4-category
// weighted sum (same category-weight-table shape as TControlSeaZoneMission::NoOpSlot3C) into
// an accumulator, and finally spreads a lookup table (DAT_00697978) scaled by that
// accumulator across resourceWeights2c[4] -- the same tail shape TControlSeaZoneMission's
// own NoOpSlot3C uses. Left unported pending a dedicated follow-up; see bd 1uj.16.3 notes.
// FUNCTION: IMPERIALISM 0x00539e70
void TEscortMission::NoOpSlot3C() {
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
    orderList24->next->SetChainActiveFlag(0);
  }
  ConsolidateMissionOrderEntriesByTargetAndQueue(reinterpret_cast<int*>(targetZone14));
}
