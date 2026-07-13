// TBeachheadMission implementations.
//
// Real base is TControlSeaZoneMission (RTTI ancestry: TBeachheadMission ->
// TControlSeaZoneMission -> TNavyMission -> TMission -> TObject -> CObject).
// Call30 / SetStateByte8To2 / ResetValue0CToZero / GetReplacementSlot48 /
// RefreshMissionPortZoneContextForNation are NOT overridden here -- they're
// inherited unchanged from TControlSeaZoneMission, which owns their
// `// FUNCTION:` markers.

#include "game/TBeachheadMission.h"
#include "game/TAttackProvinceMission.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TZone.h"

IMPLEMENT_SERIAL(TBeachheadMission, TControlSeaZoneMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053a2d0
// TBeachheadMission::CreateObject

// SYNTHETIC: IMPERIALISM 0x0053a420
// TBeachheadMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x0053a3d0 (approx -- see symbols.csv)
// TBeachheadMission::`scalar deleting destructor'

TBeachheadMission::TBeachheadMission() : TControlSeaZoneMission(), parentMission3c(nullptr) {}

TBeachheadMission::TBeachheadMission(TZone* targetZone, TAttackProvinceMission* parentMission)
    : TControlSeaZoneMission(targetZone), parentMission3c(parentMission) {}

// FUNCTION: IMPERIALISM 0x0053a390
char TBeachheadMission::ReturnFalseSlot64() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053a3b0
char TBeachheadMission::ReturnFalseSlot60() {
  return 0;
}

// TODO: promote body (bd 1uj.16.6) -- 531 bytes; shares the same unresolved sub-call
// cluster as TBlockadePortMission::NoOpSlot3C and TEscortMission::NoOpSlot3C (order-list
// iteration helpers, vtable slot 8 index 0x04 diplomacy dispatch). Left unported pending a
// dedicated follow-up covering all three siblings together.
// FUNCTION: IMPERIALISM 0x0053a500
void TBeachheadMission::NoOpSlot3C() {
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = 0.0f;
  }
}

// FUNCTION: IMPERIALISM 0x0053a7b0
char TBeachheadMission::MatchesMissionKeySlot4C(int kind, int key, int mode) {
  (void)mode;
  if (kind == 2 && key != -1 && parentMission3c != nullptr &&
      static_cast<short>(key) ==
          *reinterpret_cast<short*>(reinterpret_cast<char*>(parentMission3c) + 0x30)) {
    return 1;
  }
  return 0;
}

// TODO: promote body (bd 1uj.16.6) -- 40 bytes but a genuinely two-branch diplomacy
// decision, not yet fully resolved. Confirmed pieces: this->parentMission3c->field_0x30
// (already established elsewhere in this file as a node/city id, see MatchesMissionKeySlot4C)
// indexes g_pGlobalMapState->cityScoreTable (TMapMgr+0x10) at stride 21*8=168 bytes to read
// one byte (likely an owner-nation-ish field, TGlobalMapCityScoreRecord isn't ASSERT_SIZE'd
// yet so the stride is unconfirmed); that byte and this->nationId04 feed
// g_pDiplomacyTurnStateManager->IsNationPairAtWar (slot 0x44). On the true branch, calls
// TTaskForce::SetMapOrderType5AndQueue(0x553840, a confirmed sibling of SetMapOrderType6And-
// Queue/SetMapOrderType3Or4AndQueue -- not yet ported) on the passed-in pMapOrderEntry. On
// the false branch, a second lookup compares against g_apNationStates[nationId04]-relative
// state (word at [nation-array-entry]+0xb2 vs 0x131) before an unidentified vtable dispatch
// (slot 0x1d0). Left unported pending the city-record stride + that final dispatch.
// FUNCTION: IMPERIALISM 0x0053a800
void TBeachheadMission::NoOpSlot9C(void* pMapOrderEntry) {
  (void)pMapOrderEntry;
}

// FUNCTION: IMPERIALISM 0x0053a920
int TBeachheadMission::ReturnZeroSlot58() {
  return reinterpret_cast<int>(parentMission3c);
}

// FUNCTION: IMPERIALISM 0x0053a940
char TBeachheadMission::ReturnFalseSlot98() {
  // ClearBlockadePortMissionChildOrderLinksIfReady: clears each queued
  // order-child's owner-back-pointer, then frees the chain.
  if (marker11 == 0 && navyField20 != nullptr) {
    return 0;
  }
  orderList24 = nullptr;
  return 1;
}
