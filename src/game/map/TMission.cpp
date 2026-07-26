#include "game/map/TMission.h"
#include "game/navy/TOcean.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/ui_core/CIterator.h"
#include "game/military/TAttackProvinceMission.h"
#include "game/map/TBlockadePortMission.h"
#include "game/map/TControlSeaZoneMission.h"
#include "game/military/TDefendProvinceMission.h"
#include "game/map/TEscortMission.h"
#include "game/military/TInvadeMission.h"
#include "game/map/TScatteredShipsMission.h"
#include "game/core/TStream.h"
#include "game/ui_screens/TZone.h"

// SYNTHETIC: IMPERIALISM 0x00534bc0
// TMission::CreateObject

// The archive extraction operator below is emitted by IMPLEMENT_SERIAL:
//   CArchive& AFXAPI operator>>(CArchive&, TMission*&)
// SYNTHETIC: IMPERIALISM 0x00534ff0
// operator>>
IMPLEMENT_SERIAL(TMission, TObject, 1)

// --- TMission default-mission virtual stubs (concrete missions override) ---
// FUNCTION: IMPERIALISM 0x00534c00
bool TMission::IsANoBrainer() const {
  return false;
}
// FUNCTION: IMPERIALISM 0x00534c20
int TMission::AccumulateLack(int* accumulatedLack, unsigned char includeExistingLack) const {
  (void)accumulatedLack;
  (void)includeExistingLack;
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534c40
void TMission::Initialize() {}

// FUNCTION: IMPERIALISM 0x00534c60
void TMission::SetStateByte8To2() {
  state08 = 2;
}
// FUNCTION: IMPERIALISM 0x00534c80
void TMission::CalculateImportance() {
  importanceScore0c = 0.0f;
}
// FUNCTION: IMPERIALISM 0x00534ca0
void TMission::CalculateNeeds() {}
// FUNCTION: IMPERIALISM 0x00534cc0
void TMission::Reassess() {
  SetStateByte8To2();
  CalculateImportance();
  CalculateNeeds();
}
// FUNCTION: IMPERIALISM 0x00534cf0
void TMission::GiveOrders() {}
// FUNCTION: IMPERIALISM 0x00534d10
TMission* TMission::GetReplacementSlot48() {
  return this;
}
// FUNCTION: IMPERIALISM 0x00534d30
bool TMission::Matches(eMissionType missionType, int key, TZone* zoneContext) const {
  (void)missionType;
  (void)key;
  (void)zoneContext;
  return false;
}
// FUNCTION: IMPERIALISM 0x00534d50
bool TMission::IsArmyMission() const {
  return false;
}
// FUNCTION: IMPERIALISM 0x00534d70
bool TMission::IsNavyMission() const {
  return false;
}
// FUNCTION: IMPERIALISM 0x00534d90
TMission* TMission::GetArmyMission() {
  return nullptr;
}
// FUNCTION: IMPERIALISM 0x00534db0
TMission* TMission::GetNavyMission() {
  return nullptr;
}
// FUNCTION: IMPERIALISM 0x00534dd0
bool TMission::IsDefensiveSeaZoneMission() const {
  return false;
}
// FUNCTION: IMPERIALISM 0x00534df0
bool TMission::IsHospitalMission() const {
  return false;
}
// FUNCTION: IMPERIALISM 0x00534e10
float TMission::GetWeightedSatisfaction() {
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534e30
float TMission::IndustrialCostOfNeeds() {
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534e50
float TMission::ValueOf(TShip* candidate) {
  (void)candidate;
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534e70
float TMission::ValueOf(TMilitaryUnit* candidateUnit) {
  (void)candidateUnit;
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534e90
float TMission::FitnessOf(TShip* candidate, float* targetProfile) {
  (void)candidate;
  (void)targetProfile;
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534eb0
float TMission::FitnessOf(TMilitaryUnit* candidateUnit, float* referenceVector) {
  (void)candidateUnit;
  (void)referenceVector;
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534ed0
void TMission::AcceptReenforcement(TShip* ship, unsigned char notify) {
  (void)ship;
  (void)notify;
}
// FUNCTION: IMPERIALISM 0x00534ef0
void TMission::AcceptReenforcement(TMilitaryUnit* unit, unsigned char notify) {
  (void)unit;
  (void)notify;
}
// FUNCTION: IMPERIALISM 0x00534f10
void TMission::RejectConstituent(TShip* ship, unsigned char notify) {
  (void)ship;
  (void)notify;
}
// FUNCTION: IMPERIALISM 0x00534f30
void TMission::RejectConstituent(TMilitaryUnit* unit, unsigned char notify) {
  (void)unit;
  (void)notify;
}
// FUNCTION: IMPERIALISM 0x00534f50
void TMission::ForgetTaskForce(TTaskForce* taskForce) {
  (void)taskForce;
}
// FUNCTION: IMPERIALISM 0x00534f70
void TMission::Hold(unsigned char value) {
  flag10 = value;
}
// FUNCTION: IMPERIALISM 0x00534f90
char TMission::SmokeEmIfYouGotEm() {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x00534fb0
// TMission::GetRuntimeClass

// FUNCTION: IMPERIALISM 0x00535020
TMission::TMission() {
  state08 = 2;
  importanceScore0c = 0.0f;
  marker11 = 0xff;
}

// SYNTHETIC: IMPERIALISM 0x00535050
// TMission::`scalar deleting destructor'

// Sets the common mission owner and path sentinel, then dispatches the concrete
// mission's initialization hook. TInvadeMission uses this to initialize its
// owned beachhead mission with the same nation.
// FUNCTION: IMPERIALISM 0x005350a0
void TMission::InitializeMissionWithNationIdAndResetPathMarker(NationSlot nationSlot) {
  nationId04 = nationSlot;
  pathMarker06 = -1;
  Initialize();
}

// Mission factory: allocates and constructs the concrete mission subtype selected by
// missionKind, then stamps the common owner/marker fields and runs the mission's
// Initialize initializer. Each arm is real construction (new T(...)); the compiler emits
// the operator-new + construction-unwind frame. contextArg is the map-order context /
// target port zone (a TZone) for the navy missions; nodeKey/keyArg carry the province
// or amassing keys for the army missions.
// FUNCTION: IMPERIALISM 0x005350d0
TMission* TMission::CreateMission(NationSlot sourceNation, eMissionType missionKind, int nodeKey,
                                  TZone* zoneContext, int relatedNodeKey) {
  TMission* mission = nullptr;
  switch (missionKind) {
  case kMissionTypeAttackProvince:
    if (zoneContext == 0) {
      mission = new TAttackProvinceMission(static_cast<short>(nodeKey), -1);
    } else {
      mission = new TControlSeaZoneMission(zoneContext);
    }
    break;
  case kMissionTypeAmassProvince:
    mission =
        new TAttackProvinceMission(static_cast<short>(nodeKey), static_cast<short>(relatedNodeKey));
    break;
  case kMissionTypeInvadeProvince:
    if (relatedNodeKey != -1) {
      mission = new TInvadeMission(zoneContext, static_cast<short>(relatedNodeKey));
    } else {
      mission = new TControlSeaZoneMission(zoneContext);
    }
    break;
  case kMissionTypeDefendProvince:
    if (zoneContext == 0) {
      mission = new TDefendProvinceMission(nodeKey);
    } else if (zoneContext ==
               g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(sourceNation)) {
      mission = new TEscortMission(zoneContext);
    } else {
      mission = new TControlSeaZoneMission(zoneContext);
    }
    break;
  case kMissionTypeBlockadePort:
    mission = new TBlockadePortMission(zoneContext);
    break;
  case kMissionTypeScatteredShips:
    mission = new TScatteredShipsMission();
    break;
  }
  mission->nationId04 = sourceNation;
  mission->pathMarker06 = -1;
  mission->Initialize();
  return mission;
}

// --- slot 0x05/0x06 serializers (TStream* fast-path; same vtable offsets as WriteTo/ReadFrom) ---
// FUNCTION: IMPERIALISM 0x00535820
void TMission::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&nationId04, 2);
  stream->WriteBytes(&state08, 1);
  stream->WriteBytes(&importanceScore0c, 4);
  stream->WriteBytes(&flag10, 1);
  stream->WriteBytes(&pathMarker06, 2);
  stream->WriteBytes(&marker11, 1);
}

// FUNCTION: IMPERIALISM 0x005358a0
void TMission::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&nationId04, 2);
  stream->ReadBytes(&state08, 1);
  stream->ReadBytes(&importanceScore0c, 4);
  stream->ReadBytes(&flag10, 1);
  if (g_nSaveFormatVersion < 0x10) {
    pathMarker06 = static_cast<short>(0xffff);
  } else {
    stream->ReadBytes(&pathMarker06, 2);
  }
  if (g_nSaveFormatVersion < 9) {
    Initialize();
    return;
  }
  stream->ReadBytes(&marker11, 1);
}

// Mac: TMission::Find(TList*, eMissionType, short, TZone*). Walks the Windows
// TSortedList equivalent, returning the first mission whose virtual Matches accepts
// the requested mission identity.
// FUNCTION: IMPERIALISM 0x00535940
TMission* TMission::Find(TSortedList* missions, eMissionType missionType, short key,
                         TZone* zoneContext) {
  CIterator iter(missions);
  for (TMission* entry = static_cast<TMission*>(iter.Reset()); iter.More();
       entry = static_cast<TMission*>(iter.Advance())) {
    entry->AssertValid();
    if (entry->Matches(missionType, key, zoneContext)) {
      return entry;
    }
  }
  return nullptr;
}

// Orders missions first by their signed state byte, then by cached value per unit-cost
// score. A non-null callback context reverses both comparisons.
// FUNCTION: IMPERIALISM 0x00535f80
short __cdecl CompareMissionOrderEntriesByMovementClassThenEfficiency(void* a, void* b,
                                                                      void* reverseOrder) {
  TMission* missionA = static_cast<TMission*>(a);
  TMission* missionB = static_cast<TMission*>(b);
  missionA->AssertValid();
  missionB->AssertValid();

  short greaterResult = (reverseOrder != nullptr) ? 1 : -1;
  short lesserResult = (reverseOrder != nullptr) ? -1 : 1;
  if (static_cast<char>(missionB->state08) < static_cast<char>(missionA->state08)) {
    return greaterResult;
  }
  if (static_cast<char>(missionA->state08) < static_cast<char>(missionB->state08)) {
    return lesserResult;
  }

  float ratioA = missionA->importanceScore0c / missionA->IndustrialCostOfNeeds();
  float ratioB = missionB->importanceScore0c / missionB->IndustrialCostOfNeeds();
  if (ratioA < ratioB) {
    return greaterResult;
  }
  if (ratioB < ratioA) {
    return lesserResult;
  }
  return 0;
}

// qsort-style comparator: descending order by a "remaining priority" score --
// (1.0 - GetWeightedSatisfaction()) scaled by importanceScore0c (multiplied when that difference is
// >= 0, divided when negative). AssertValid() is invoked on both sides first (the
// inherited CObject/MFC debug-assert virtual, a no-op in release builds), matching the
// ground truth's double-dispatch shape before the scores are read.
// FUNCTION: IMPERIALISM 0x00536090
short __cdecl CompareMissionOrderEntriesByPriorityScore(TMission* a, TMission* b) {
  a->AssertValid();
  b->AssertValid();

  float diffA =
      static_cast<float>(g_MissionScoreOneConstant_0065a470) - a->GetWeightedSatisfaction();
  float weightedA = (diffA >= g_MissionDefaultScore_0065a468) ? diffA * a->importanceScore0c
                                                              : diffA / a->importanceScore0c;

  float diffB =
      static_cast<float>(g_MissionScoreOneConstant_0065a470) - b->GetWeightedSatisfaction();
  float weightedB = (diffB >= g_MissionDefaultScore_0065a468) ? diffB * b->importanceScore0c
                                                              : diffB / b->importanceScore0c;

  if (weightedB < weightedA) {
    return -1;
  }
  if (weightedA < weightedB) {
    return 1;
  }
  return 0;
}
