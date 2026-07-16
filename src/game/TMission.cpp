#include "game/TMission.h"
#include "game/TOcean.h"
#include "game/global_data_tables.h"

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/TAttackProvinceMission.h"
#include "game/TBlockadePortMission.h"
#include "game/TControlSeaZoneMission.h"
#include "game/TDefendProvinceMission.h"
#include "game/TEscortMission.h"
#include "game/TInvadeMission.h"
#include "game/TScatteredShipsMission.h"
#include "game/TStream.h"
#include "game/TZone.h"

// SYNTHETIC: IMPERIALISM 0x00534bc0
// TMission::CreateObject

IMPLEMENT_SERIAL(TMission, TObject, 1)

// --- TMission default-mission virtual stubs (concrete missions override) ---
// FUNCTION: IMPERIALISM 0x00534c00
char TMission::ReturnFalseSlot28() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534c20
int TMission::ReturnZeroSlot2C(int* outBuffer, int unused) {
  (void)outBuffer;
  (void)unused;
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534c40
void TMission::Call30() {}

// FUNCTION: IMPERIALISM 0x00534c60
void TMission::SetStateByte8To2() {
  state08 = 2;
}
// FUNCTION: IMPERIALISM 0x00534c80
void TMission::ResetValue0CToZero() {
  value0c = 0;
}
// FUNCTION: IMPERIALISM 0x00534ca0
void TMission::NoOpSlot3C() {}
// FUNCTION: IMPERIALISM 0x00534cc0
void TMission::RefreshSlot40() {
  SetStateByte8To2();
  ResetValue0CToZero();
  NoOpSlot3C();
}
// FUNCTION: IMPERIALISM 0x00534cf0
void TMission::MissionSlot44() {}
// FUNCTION: IMPERIALISM 0x00534d10
TMission* TMission::GetReplacementSlot48() {
  return this;
}
// FUNCTION: IMPERIALISM 0x00534d30
char TMission::MatchesMissionKeySlot4C(int a, int b, int c) {
  (void)a;
  (void)b;
  (void)c;
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534d50
char TMission::ReturnFalseSlot50() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534d70
char TMission::ReturnFalseSlot54() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534d90
int TMission::ReturnZeroSlot58() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534db0
int TMission::ReturnZeroSlot5C() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534dd0
char TMission::ReturnFalseSlot60() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534df0
char TMission::ReturnFalseSlot64() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534e10
float TMission::ReturnZeroFloatSlot68() {
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534e30
float TMission::ReturnZeroFloatSlot6C() {
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534e50
float TMission::ReturnZeroFloatSlot74(void* candidate) {
  (void)candidate;
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534e70
float TMission::ReturnZeroFloatSlot70(TMilitaryUnit* candidateUnit) {
  (void)candidateUnit;
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534e90
float TMission::ReturnZeroFloatSlot7C(void* candidate, void* targetProfile) {
  (void)candidate;
  (void)targetProfile;
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534eb0
float TMission::ReturnZeroFloatSlot78(TMilitaryUnit* candidateUnit, float* referenceVector) {
  (void)candidateUnit;
  (void)referenceVector;
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534ed0
void TMission::NoOpSlot84(int a, int b) {
  (void)a;
  (void)b;
}
// FUNCTION: IMPERIALISM 0x00534ef0
void TMission::NoOpSlot80(TMilitaryUnit* unit, int notify) {
  (void)unit;
  (void)notify;
}
// FUNCTION: IMPERIALISM 0x00534f10
void TMission::NoOpSlot8C(int a, int b) {
  (void)a;
  (void)b;
}
// FUNCTION: IMPERIALISM 0x00534f30
void TMission::NoOpSlot88(TMilitaryUnit* unit, int unused) {
  (void)unit;
  (void)unused;
}
// FUNCTION: IMPERIALISM 0x00534f50
void TMission::NoOpSlot90(int a) {
  (void)a;
}
// FUNCTION: IMPERIALISM 0x00534f70
void TMission::SetFlag10FromArgSlot94(unsigned char value) {
  flag10 = value;
}
// FUNCTION: IMPERIALISM 0x00534f90
char TMission::ReturnFalseSlot98() {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x00534fb0
// TMission::GetRuntimeClass

// FUNCTION: IMPERIALISM 0x00535020
TMission::TMission() {
  state08 = 2;
  value0c = 0;
  marker11 = 0xff;
}

// SYNTHETIC: IMPERIALISM 0x00535050
// TMission::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00535080
TMission::~TMission() {}

// Mission factory: allocates and constructs the concrete mission subtype selected by
// missionKind, then stamps the common owner/marker fields and runs the mission's
// Call30 initializer. Each arm is real construction (new T(...)); the compiler emits
// the operator-new + construction-unwind frame. contextArg is the map-order context /
// target port zone (a TZone) for the navy missions; nodeKey/keyArg carry the province
// or amassing keys for the army missions.
// FUNCTION: IMPERIALISM 0x005350d0
TMission* CreateMissionObjectByKindAndNodeContext(int sourceNation, eMissionType missionKind,
                                                  int nodeKey, int contextArg, int keyArg) {
  TMission* mission = nullptr;
  switch (missionKind) {
  case kMissionTypeAttackProvince:
    if (contextArg == 0) {
      mission = new TAttackProvinceMission(static_cast<short>(nodeKey), -1);
    } else {
      mission = new TControlSeaZoneMission(reinterpret_cast<TZone*>(contextArg));
    }
    break;
  case kMissionTypeAmassProvince:
    mission = new TAttackProvinceMission(static_cast<short>(nodeKey), static_cast<short>(keyArg));
    break;
  case kMissionTypeInvadeProvince:
    if (keyArg != -1) {
      mission =
          new TInvadeMission(static_cast<short>(contextArg), reinterpret_cast<TZone*>(keyArg));
    } else {
      mission = new TControlSeaZoneMission(reinterpret_cast<TZone*>(contextArg));
    }
    break;
  case kMissionTypeDefendProvince:
    if (contextArg == 0) {
      mission = new TDefendProvinceMission(nodeKey);
    } else if (reinterpret_cast<TZone*>(contextArg) ==
               g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(
                   static_cast<short>(sourceNation))) {
      mission = new TEscortMission(reinterpret_cast<TZone*>(contextArg));
    } else {
      mission = new TControlSeaZoneMission(reinterpret_cast<TZone*>(contextArg));
    }
    break;
  case kMissionTypeBlockadePort:
    mission = new TBlockadePortMission(reinterpret_cast<TZone*>(contextArg));
    break;
  case kMissionTypeScatteredShips:
    mission = new TScatteredShipsMission();
    break;
  }
  mission->nationId04 = static_cast<short>(sourceNation);
  mission->pathMarker06 = -1;
  mission->Call30();
  return mission;
}

// --- slot 0x05/0x06 serializers (TStream* fast-path; same vtable offsets as WriteTo/ReadFrom) ---
// FUNCTION: IMPERIALISM 0x00535820
void TMission::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  char* raw = reinterpret_cast<char*>(this);
  stream->WriteBytesSlot78(raw + 0x04, 2);
  stream->WriteBytesSlot78(raw + 0x08, 1);
  stream->WriteBytesSlot78(raw + 0x0c, 4);
  stream->WriteBytesSlot78(raw + 0x10, 1);
  stream->WriteBytesSlot78(raw + 0x06, 2);
  stream->WriteBytesSlot78(raw + 0x11, 1);
}

// FUNCTION: IMPERIALISM 0x005358a0
void TMission::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&nationId04, 2);
  stream->ReadBytes(&state08, 1);
  stream->ReadBytes(&value0c, 4);
  stream->ReadBytes(&flag10, 1);
  if (g_nSaveFormatVersion < 0x10) {
    pathMarker06 = static_cast<short>(0xffff);
  } else {
    stream->ReadBytes(&pathMarker06, 2);
  }
  if (g_nSaveFormatVersion < 9) {
    Call30();
    return;
  }
  stream->ReadBytes(&marker11, 1);
}

// qsort-style comparator: descending order by a "remaining priority" score --
// (1.0 - ReturnZeroFloatSlot68()) scaled by value0c (multiplied when that difference is
// >= 0, divided when negative). Call30() is invoked on both sides first (a no-op in the
// base TMission; concrete missions override it), matching the ground truth's double-
// dispatch shape before the scores are read.
// FUNCTION: IMPERIALISM 0x00536090
short __cdecl CompareMissionOrderEntriesByPriorityScore(TMission* a, TMission* b) {
  a->Call30();
  b->Call30();

  float diffA = static_cast<float>(g_MissionScoreOneConstant_0065a470) - a->ReturnZeroFloatSlot68();
  float weightedA = (diffA >= g_MissionDefaultScore_0065a468)
                        ? diffA * *reinterpret_cast<float*>(&a->value0c)
                        : diffA / *reinterpret_cast<float*>(&a->value0c);

  float diffB = static_cast<float>(g_MissionScoreOneConstant_0065a470) - b->ReturnZeroFloatSlot68();
  float weightedB = (diffB >= g_MissionDefaultScore_0065a468)
                        ? diffB * *reinterpret_cast<float*>(&b->value0c)
                        : diffB / *reinterpret_cast<float*>(&b->value0c);

  if (weightedB < weightedA) {
    return -1;
  }
  if (weightedA < weightedB) {
    return 1;
  }
  return 0;
}
